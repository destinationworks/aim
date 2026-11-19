use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aim_proto::names::{check_name, valid_name};
use aim_proto::wire::{check_sha256, MAX_CLAIM_TTL_SECS, MAX_EXPIRY_SECS, MAX_LEASE_SECS};
use aim_proto::AgentId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub host: String,
    pub sha256: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    pub name: String,
    pub members: Vec<String>,
    pub posting_hosts: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_base_path")]
    pub base_path: String,
    pub data_dir: PathBuf,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    #[serde(default = "default_agent_ttl")]
    pub agent_ttl_secs: u64,
    #[serde(default = "default_message_ttl")]
    pub default_message_ttl_secs: u64,
    #[serde(default = "default_claim_ttl")]
    pub default_claim_ttl_secs: u64,
    #[serde(default = "default_accept_lease")]
    pub default_accept_lease_secs: u64,
    #[serde(default = "default_max_messages")]
    pub max_messages: usize,
    #[serde(default = "default_max_agents")]
    pub max_agents: usize,
    #[serde(default = "default_max_claims_per_host")]
    pub max_claims_per_host: usize,
    #[serde(default = "default_max_artifacts_total_bytes")]
    pub max_artifacts_total_bytes: u64,
    #[serde(default = "default_max_concurrent_waiters")]
    pub max_concurrent_waiters: usize,
    #[serde(default = "default_max_waiters_per_host")]
    pub max_waiters_per_host: usize,
    #[serde(default = "default_auth_failures_per_minute")]
    pub auth_failures_per_minute: u32,
    #[serde(default = "default_agent_retention")]
    pub agent_retention_secs: u64,
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
    #[serde(default)]
    pub groups: Vec<GroupConfig>,
}

fn default_listen() -> String {
    "0.0.0.0:11460".into()
}
fn default_base_path() -> String {
    "/aim".into()
}
fn default_agent_ttl() -> u64 {
    300
}
fn default_message_ttl() -> u64 {
    7 * 24 * 3600
}
fn default_claim_ttl() -> u64 {
    3600
}
fn default_accept_lease() -> u64 {
    900
}
fn default_max_messages() -> usize {
    50_000
}
fn default_max_agents() -> usize {
    2_000
}
fn default_max_claims_per_host() -> usize {
    256
}
fn default_max_artifacts_total_bytes() -> u64 {
    512 * 1024 * 1024
}
fn default_max_concurrent_waiters() -> usize {
    64
}
fn default_max_waiters_per_host() -> usize {
    8
}
fn default_auth_failures_per_minute() -> u32 {
    30
}
fn default_agent_retention() -> u64 {
    30 * 24 * 3600
}

pub fn normalize_base_path(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Ok(String::new());
    }
    if !trimmed.starts_with('/') {
        return Err("base_path must start with '/'".into());
    }
    let cleaned = trimmed.trim_end_matches('/');
    for seg in cleaned[1..].split('/') {
        if !valid_name(seg) || seg == "." || seg == ".." {
            return Err(format!(
                "base_path segment '{seg}' is invalid (use letters, digits, '.', '_' or '-')"
            ));
        }
    }
    Ok(cleaned.to_string())
}

impl ServerConfig {
    /// A configuration with every tunable at its secure default.
    pub fn defaults_for(data_dir: PathBuf, tls_cert: PathBuf, tls_key: PathBuf) -> Self {
        Self {
            listen: default_listen(),
            base_path: default_base_path(),
            data_dir,
            tls_cert,
            tls_key,
            agent_ttl_secs: default_agent_ttl(),
            default_message_ttl_secs: default_message_ttl(),
            default_claim_ttl_secs: default_claim_ttl(),
            default_accept_lease_secs: default_accept_lease(),
            max_messages: default_max_messages(),
            max_agents: default_max_agents(),
            max_claims_per_host: default_max_claims_per_host(),
            max_artifacts_total_bytes: default_max_artifacts_total_bytes(),
            max_concurrent_waiters: default_max_concurrent_waiters(),
            max_waiters_per_host: default_max_waiters_per_host(),
            auth_failures_per_minute: default_auth_failures_per_minute(),
            agent_retention_secs: default_agent_retention(),
            keys: Vec::new(),
            groups: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = aim_fs::read_private_string(path, 256 * 1024)?;
        let mut cfg: Self = toml::from_str(&text)
            .map_err(|e| format!("invalid server config {}: {e}", path.display()))?;
        let base_dir = path.parent();
        cfg.data_dir = resolve_rel(base_dir, cfg.data_dir);
        cfg.tls_cert = resolve_rel(base_dir, cfg.tls_cert);
        cfg.tls_key = resolve_rel(base_dir, cfg.tls_key);
        cfg.base_path = normalize_base_path(&cfg.base_path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save_atomic(&self, path: &Path, overwrite: bool) -> Result<(), String> {
        self.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        aim_fs::write_private_atomic(path, text.as_bytes(), overwrite)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.listen_addr()?;
        normalize_base_path(&self.base_path)?;
        let ranged = [
            ("agent_ttl_secs", self.agent_ttl_secs, 86_400),
            (
                "default_message_ttl_secs",
                self.default_message_ttl_secs,
                MAX_EXPIRY_SECS,
            ),
            (
                "default_claim_ttl_secs",
                self.default_claim_ttl_secs,
                MAX_CLAIM_TTL_SECS,
            ),
            (
                "default_accept_lease_secs",
                self.default_accept_lease_secs,
                MAX_LEASE_SECS,
            ),
            (
                "agent_retention_secs",
                self.agent_retention_secs,
                365 * 24 * 3600,
            ),
        ];
        for (name, value, max) in ranged {
            if value == 0 || value > max {
                return Err(format!("{name} must be between 1 and {max}"));
            }
        }
        let positive = [
            ("max_messages", self.max_messages as u64),
            ("max_agents", self.max_agents as u64),
            ("max_claims_per_host", self.max_claims_per_host as u64),
            ("max_artifacts_total_bytes", self.max_artifacts_total_bytes),
            ("max_concurrent_waiters", self.max_concurrent_waiters as u64),
            ("max_waiters_per_host", self.max_waiters_per_host as u64),
            (
                "auth_failures_per_minute",
                u64::from(self.auth_failures_per_minute),
            ),
        ];
        for (name, value) in positive {
            if value == 0 {
                return Err(format!("{name} must be > 0"));
            }
        }
        let mut seen = HashSet::new();
        let known_hosts: HashSet<&str> = self.keys.iter().map(|key| key.host.as_str()).collect();
        for key in &self.keys {
            check_name("key host", &key.host)?;
            check_sha256(&key.sha256)?;
            if !seen.insert(key.sha256.to_ascii_lowercase()) {
                return Err(format!(
                    "duplicate key sha256 in keys (host '{}'); every key must be unique",
                    key.host
                ));
            }
        }
        if self.groups.len() > 256 {
            return Err("at most 256 groups may be configured".into());
        }
        let mut group_names = HashSet::new();
        for group in &self.groups {
            check_name("group", &group.name)?;
            if !group_names.insert(&group.name) {
                return Err(format!("duplicate group name '{}'", group.name));
            }
            if group.members.is_empty() || group.members.len() > 128 {
                return Err(format!("group '{}' must have 1-128 members", group.name));
            }
            if group.posting_hosts.is_empty() || group.posting_hosts.len() > 128 {
                return Err(format!(
                    "group '{}' must have 1-128 posting_hosts",
                    group.name
                ));
            }
            let mut members = HashSet::new();
            for member in &group.members {
                let parsed = AgentId::parse_full(member)?;
                if parsed.to_string() != *member {
                    return Err(format!(
                        "group '{}' member '{member}' is not a canonical agent ID",
                        group.name
                    ));
                }
                if !members.insert(member) {
                    return Err(format!(
                        "group '{}' contains duplicate member '{member}'",
                        group.name
                    ));
                }
                if !known_hosts.contains(parsed.host.as_str()) {
                    return Err(format!(
                        "group '{}' member '{member}' uses unconfigured host '{}'",
                        group.name, parsed.host
                    ));
                }
            }
            let mut posting_hosts = HashSet::new();
            for host in &group.posting_hosts {
                check_name("group posting host", host)?;
                if !posting_hosts.insert(host) {
                    return Err(format!(
                        "group '{}' contains duplicate posting host '{host}'",
                        group.name
                    ));
                }
                if !known_hosts.contains(host.as_str()) {
                    return Err(format!(
                        "group '{}' posting host '{host}' has no configured key",
                        group.name
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, String> {
        self.listen
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid listen address '{}': {e}", self.listen))
    }
}

fn resolve_rel(base: Option<&Path>, p: PathBuf) -> PathBuf {
    if p.is_absolute() {
        return p;
    }
    match base {
        Some(dir) => dir.join(p),
        None => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_base_paths() {
        assert_eq!(normalize_base_path("/aim").unwrap(), "/aim");
        assert_eq!(normalize_base_path("/aim/").unwrap(), "/aim");
        assert_eq!(normalize_base_path("/a/b").unwrap(), "/a/b");
        assert_eq!(normalize_base_path("/").unwrap(), "");
        assert_eq!(normalize_base_path("").unwrap(), "");
        assert!(normalize_base_path("aim").is_err());
        assert!(normalize_base_path("/aim?x=1").is_err());
        assert!(normalize_base_path("/a//b").is_err());
        assert!(normalize_base_path("/../x").is_err());
        assert!(normalize_base_path("/{x}").is_err());
    }

    #[test]
    fn validates_bounds_and_duplicates() {
        let mut cfg = ServerConfig::defaults_for("d".into(), "c".into(), "k".into());
        cfg.validate().unwrap();
        cfg.agent_ttl_secs = 86_401;
        assert!(cfg.validate().is_err());
        cfg.agent_ttl_secs = 300;
        cfg.max_messages = 0;
        assert!(cfg.validate().is_err());
        cfg.max_messages = 10;
        let sha = "ab".repeat(32);
        cfg.keys = vec![
            KeyEntry {
                host: "host-a".into(),
                sha256: sha.clone(),
                enabled: true,
            },
            KeyEntry {
                host: "host-b".into(),
                sha256: sha.clone(),
                enabled: true,
            },
        ];
        assert!(cfg.validate().unwrap_err().contains("duplicate"));
    }

    #[test]
    fn validates_group_names_members_and_posting_hosts() {
        let mut cfg = ServerConfig::defaults_for("d".into(), "c".into(), "k".into());
        cfg.groups = vec![GroupConfig {
            name: "reviewers".into(),
            members: vec!["macbook:codex:reviewer".into()],
            posting_hosts: vec!["workstation".into()],
        }];
        cfg.keys = vec![
            KeyEntry {
                host: "macbook".into(),
                sha256: "ab".repeat(32),
                enabled: true,
            },
            KeyEntry {
                host: "workstation".into(),
                sha256: "cd".repeat(32),
                enabled: true,
            },
            KeyEntry {
                host: "win-dev".into(),
                sha256: "ef".repeat(32),
                enabled: true,
            },
        ];
        cfg.validate().unwrap();

        cfg.groups[0].members.push("macbook:codex:reviewer".into());
        assert!(cfg.validate().unwrap_err().contains("duplicate member"));

        cfg.groups[0].members = vec!["not-a-full-agent-id".into()];
        assert!(cfg.validate().unwrap_err().contains("HOST:HARNESS:SESSION"));

        cfg.groups[0].members = vec!["macbook:codex:reviewer".into()];
        cfg.groups[0].posting_hosts.clear();
        assert!(cfg.validate().unwrap_err().contains("posting_hosts"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let raw = "data_dir = \"d\"\ntls_cert = \"c\"\ntls_key = \"k\"\nbogus = 1\n";
        assert!(toml::from_str::<ServerConfig>(raw).is_err());
    }
}
