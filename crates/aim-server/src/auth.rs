use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{GroupConfig, KeyEntry};

#[derive(Clone, Debug)]
pub struct AuthenticatedHost(pub String);

#[derive(Clone)]
struct HashedKey {
    host: String,
    digest: [u8; 32],
}

#[derive(Clone)]
pub struct KeyRing {
    snapshot: Arc<ArcSwap<AuthSnapshot>>,
}

struct AuthSnapshot {
    entries: Vec<HashedKey>,
    groups: Vec<GroupConfig>,
}

impl KeyRing {
    pub fn from_entries(entries: &[KeyEntry]) -> Result<Self, String> {
        Self::from_config(entries, &[])
    }

    pub fn from_config(entries: &[KeyEntry], groups: &[GroupConfig]) -> Result<Self, String> {
        let parsed = AuthSnapshot {
            entries: parse_entries(entries)?,
            groups: groups.to_vec(),
        };
        Ok(Self {
            snapshot: Arc::new(ArcSwap::from_pointee(parsed)),
        })
    }

    /// Hot-reload keys from a new config. Returns the number of enabled keys.
    pub fn reload(&self, entries: &[KeyEntry]) -> Result<usize, String> {
        let groups = self.snapshot.load().groups.clone();
        self.reload_config(entries, &groups)
    }

    /// Atomically reload keys and group policy from one validated server config.
    pub fn reload_config(
        &self,
        entries: &[KeyEntry],
        groups: &[GroupConfig],
    ) -> Result<usize, String> {
        let parsed = AuthSnapshot {
            entries: parse_entries(entries)?,
            groups: groups.to_vec(),
        };
        let count = parsed.entries.len();
        self.snapshot.store(Arc::new(parsed));
        Ok(count)
    }

    pub fn group_policy(&self, name: &str) -> Option<(GroupConfig, HashSet<String>)> {
        let snapshot = self.snapshot.load();
        let group = snapshot
            .groups
            .iter()
            .find(|group| group.name == name)?
            .clone();
        let enabled_hosts = snapshot
            .entries
            .iter()
            .map(|entry| entry.host.clone())
            .collect();
        Some((group, enabled_hosts))
    }

    /// Constant-time lookup across every enabled key hash. Returns the host
    /// bound to the matching key.
    pub fn authenticate(&self, token: &str) -> Option<String> {
        let bytes = token.as_bytes();
        if bytes.is_empty() || bytes.len() > 256 {
            return None;
        }
        if !bytes.iter().all(|b| b.is_ascii_graphic()) {
            return None;
        }
        let candidate: [u8; 32] = Sha256::digest(bytes).into();
        let guard = self.snapshot.load();
        let entries = &guard.entries;
        let mut matched_idx: usize = 0;
        let mut found: u8 = 0;
        for (idx, entry) in entries.iter().enumerate() {
            let eq = candidate.ct_eq(&entry.digest).unwrap_u8();
            let mask = (eq as usize).wrapping_neg();
            matched_idx = (matched_idx & !mask) | (idx & mask);
            found |= eq;
        }
        if found == 1 {
            entries.get(matched_idx).map(|e| e.host.clone())
        } else {
            None
        }
    }
}

fn parse_entries(entries: &[KeyEntry]) -> Result<Vec<HashedKey>, String> {
    let mut parsed = Vec::new();
    for entry in entries {
        if !entry.enabled {
            continue;
        }
        let digest = decode_hex_32(&entry.sha256)?;
        parsed.push(HashedKey {
            host: entry.host.clone(),
            digest,
        });
    }
    Ok(parsed)
}

pub fn generate_token() -> String {
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *raw);
    let encoded = URL_SAFE_NO_PAD.encode(*raw);
    raw.zeroize();
    format!("aim1_{encoded}")
}

pub fn hash_token_hex(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("key sha256 must be 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex character in sha256".into()),
    }
}

// ---------------------------------------------------------------------------
// Auth rate limiter
// ---------------------------------------------------------------------------

const RATE_WINDOW_SECS: u64 = 60;
const MAX_LIMITER_ENTRIES: usize = 4096;

#[derive(Clone)]
pub struct AuthRateLimiter {
    state: Arc<Mutex<HashMap<IpAddr, (Instant, u32)>>>,
    max_failures: u32,
}

impl AuthRateLimiter {
    pub fn new(max_failures_per_minute: u32) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_failures: max_failures_per_minute,
        }
    }

    /// Returns `true` if the IP has exceeded the failure budget.
    fn is_blocked(&self, ip: IpAddr) -> bool {
        let map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((ts, count)) = map.get(&ip) {
            if ts.elapsed().as_secs() < RATE_WINDOW_SECS {
                return *count >= self.max_failures;
            }
        }
        false
    }

    fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Evict expired entries before inserting a new IP.
        if map.len() >= MAX_LIMITER_ENTRIES && !map.contains_key(&ip) {
            map.retain(|_, (ts, _)| ts.elapsed().as_secs() < RATE_WINDOW_SECS);
        }
        // If still at capacity, prefer evicting the oldest unblocked entry so decoy IPs cannot evict a blocked IP.
        if map.len() >= MAX_LIMITER_ENTRIES && !map.contains_key(&ip) {
            let max_fail = self.max_failures;
            let victim = map
                .iter()
                .filter(|(_, (_, count))| *count < max_fail)
                .min_by_key(|(_, (ts, _))| *ts)
                .or_else(|| map.iter().min_by_key(|(_, (ts, _))| *ts))
                .map(|(k, _)| *k);
            if let Some(k) = victim {
                map.remove(&k);
            }
        }
        let entry = map.entry(ip).or_insert((now, 0));
        if entry.0.elapsed().as_secs() >= RATE_WINDOW_SECS {
            *entry = (now, 1);
        } else {
            entry.1 = entry.1.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Auth state & middleware
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuthState {
    pub keyring: KeyRing,
    pub limiter: AuthRateLimiter,
}

pub async fn require_bearer(
    State(auth): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    // Rate-limit check first (before any crypto).
    if let Some(ip) = peer_ip {
        if auth.limiter.is_blocked(ip) {
            return too_many_requests();
        }
    }

    // Exactly one Authorization header.
    let auth_count = req.headers().get_all(AUTHORIZATION).iter().count();
    if auth_count != 1 {
        log_auth_failure(peer_ip, &req);
        if let Some(ip) = peer_ip {
            auth.limiter.record_failure(ip);
        }
        return unauthorized();
    }

    let header_val = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let Some(raw) = header_val else {
        log_auth_failure(peer_ip, &req);
        if let Some(ip) = peer_ip {
            auth.limiter.record_failure(ip);
        }
        return unauthorized();
    };

    // Expect "Bearer <token>" with exactly one space.
    let Some((scheme, token)) = raw.split_once(' ') else {
        log_auth_failure(peer_ip, &req);
        if let Some(ip) = peer_ip {
            auth.limiter.record_failure(ip);
        }
        return unauthorized();
    };
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || token.contains(' ') {
        log_auth_failure(peer_ip, &req);
        if let Some(ip) = peer_ip {
            auth.limiter.record_failure(ip);
        }
        return unauthorized();
    }

    let Some(host) = auth.keyring.authenticate(token) else {
        log_auth_failure(peer_ip, &req);
        if let Some(ip) = peer_ip {
            auth.limiter.record_failure(ip);
        }
        return unauthorized();
    };
    req.extensions_mut().insert(AuthenticatedHost(host));
    next.run(req).await
}

fn log_auth_failure(peer_ip: Option<IpAddr>, req: &Request) {
    let ip_str = peer_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    let method = req.method();
    let path = req.uri().path();
    eprintln!("aim-server: auth failed peer={ip_str} method={method} path={path}");
}

fn unauthorized() -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response();
    resp.headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

fn too_many_requests() -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error": "too many authentication failures"})),
    )
        .into_response();
    resp.headers_mut()
        .insert("Retry-After", HeaderValue::from_static("60"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GroupMemberConfig, GroupPostingPermission, GroupRole};

    #[test]
    fn token_generation_and_constant_time_auth() {
        let tok_a = generate_token();
        let tok_b = generate_token();
        assert!(tok_a.starts_with("aim1_"));
        assert_ne!(tok_a, tok_b);

        let ring = KeyRing::from_entries(&[
            KeyEntry {
                host: "host-a".into(),
                sha256: hash_token_hex(&tok_a),
                enabled: true,
            },
            KeyEntry {
                host: "host-b".into(),
                sha256: hash_token_hex(&tok_b),
                enabled: false,
            },
        ])
        .unwrap();

        assert_eq!(ring.authenticate(&tok_a).as_deref(), Some("host-a"));
        assert_eq!(ring.authenticate(&tok_b), None); // disabled
        assert_eq!(ring.authenticate("aim1_wrong"), None);
        assert_eq!(ring.authenticate(""), None);
    }

    #[test]
    fn reload_adds_and_removes_keys() {
        let tok_a = generate_token();
        let tok_b = generate_token();
        let ring = KeyRing::from_entries(&[KeyEntry {
            host: "host-a".into(),
            sha256: hash_token_hex(&tok_a),
            enabled: true,
        }])
        .unwrap();
        assert_eq!(ring.authenticate(&tok_a).as_deref(), Some("host-a"));
        assert_eq!(ring.authenticate(&tok_b), None);

        // Reload: revoke A, add B.
        let count = ring
            .reload(&[
                KeyEntry {
                    host: "host-a".into(),
                    sha256: hash_token_hex(&tok_a),
                    enabled: false,
                },
                KeyEntry {
                    host: "host-b".into(),
                    sha256: hash_token_hex(&tok_b),
                    enabled: true,
                },
            ])
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(ring.authenticate(&tok_a), None);
        assert_eq!(ring.authenticate(&tok_b).as_deref(), Some("host-b"));
    }

    #[test]
    fn reload_config_switches_keys_and_group_membership_together() {
        let tok_a = generate_token();
        let tok_b = generate_token();
        let first_group = GroupConfig {
            name: "reviewers".into(),
            members: vec![GroupMemberConfig {
                agent: "host-a:codex:reviewer".into(),
                role: GroupRole::Reviewer,
                responsibilities: vec!["platform-verification".into()],
            }],
            posting_permissions: vec![GroupPostingPermission {
                host: "host-a".into(),
                task_categories: vec!["platform-verification".into()],
                max_expires_in_secs: 3600,
                max_schedule_delay_secs: 0,
            }],
        };
        let ring = KeyRing::from_config(
            &[KeyEntry {
                host: "host-a".into(),
                sha256: hash_token_hex(&tok_a),
                enabled: true,
            }],
            &[first_group],
        )
        .unwrap();

        let second_group = GroupConfig {
            name: "reviewers".into(),
            members: vec![GroupMemberConfig {
                agent: "host-b:codex:reviewer".into(),
                role: GroupRole::Reviewer,
                responsibilities: vec!["platform-verification".into()],
            }],
            posting_permissions: vec![GroupPostingPermission {
                host: "host-b".into(),
                task_categories: vec!["platform-verification".into()],
                max_expires_in_secs: 3600,
                max_schedule_delay_secs: 0,
            }],
        };
        ring.reload_config(
            &[KeyEntry {
                host: "host-b".into(),
                sha256: hash_token_hex(&tok_b),
                enabled: true,
            }],
            &[second_group],
        )
        .unwrap();

        assert_eq!(ring.authenticate(&tok_a), None);
        assert_eq!(ring.authenticate(&tok_b).as_deref(), Some("host-b"));
        let (group, enabled_hosts) = ring.group_policy("reviewers").unwrap();
        assert!(!enabled_hosts.contains("host-a"));
        assert!(enabled_hosts.contains("host-b"));
        assert_eq!(group.members[0].agent, "host-b:codex:reviewer");
    }

    #[test]
    fn rejects_oversized_and_non_graphic_tokens() {
        let tok = generate_token();
        let ring = KeyRing::from_entries(&[KeyEntry {
            host: "host-a".into(),
            sha256: hash_token_hex(&tok),
            enabled: true,
        }])
        .unwrap();
        // Token with control char.
        assert_eq!(ring.authenticate("aim1_good\x01bad"), None);
        // Token with space.
        assert_eq!(ring.authenticate("aim1 bad"), None);
        // Over 256 bytes.
        let long = "a".repeat(257);
        assert_eq!(ring.authenticate(&long), None);
    }

    #[test]
    fn rate_limiter_blocks_after_threshold() {
        let limiter = AuthRateLimiter::new(3);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!limiter.is_blocked(ip));
        limiter.record_failure(ip);
        limiter.record_failure(ip);
        assert!(!limiter.is_blocked(ip));
        limiter.record_failure(ip);
        assert!(limiter.is_blocked(ip));
    }
}
