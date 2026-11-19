//! Request and response bodies of the HTTP API.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::address::{AgentId, Selector};
use crate::guard::{check_fields, check_json_value};
use crate::names::{check_name, check_text, is_forbidden_unicode};
use crate::performative::Performative;
use crate::{MAX_BODY, MAX_CLAIM_PATHS, MAX_MULTI_INBOX_AGENTS, MAX_PAYLOAD, MAX_RECIPIENTS};

/// Longest a message may be kept before it expires: 30 days.
pub const MAX_EXPIRY_SECS: u64 = 30 * 24 * 3600;
/// Longest claim lease or accept lease: 24 hours.
pub const MAX_CLAIM_TTL_SECS: u64 = 24 * 3600;
pub const MAX_LEASE_SECS: u64 = 24 * 3600;

fn check_opt_text(field: &str, value: &Option<String>, max: usize) -> Result<(), String> {
    value
        .as_deref()
        .map_or(Ok(()), |v| check_text(field, v, max))
}

pub fn check_sha256(hex: &str) -> Result<(), String> {
    if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err("sha256 must be 64 lowercase hex characters".into())
    }
}

pub fn check_artifact_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err("artifact name must be 1-128 ASCII characters".into());
    }
    if matches!(bytes[0], b'.' | b'-') || name.contains("..") {
        return Err("artifact name must not start with '.'/'-' or contain '..'".into());
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(
            "artifact name may contain only ASCII letters, digits, '.', '_' and '-'".into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub protocol: String,
}

/// Build and capability metadata returned by version commands and `/v1/version`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    pub build_version: String,
    pub git_sha: String,
    pub git_dirty: bool,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// `HARNESS:SESSION`; the hub adds the host from the key.
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl RegisterRequest {
    pub fn validate(&self) -> Result<(), String> {
        AgentId::validate_identity(&self.agent)?;
        if let Some(repo) = &self.repo {
            check_name("repo", repo)?;
        }
        check_opt_text("worktree", &self.worktree, 512)?;
        check_opt_text("branch", &self.branch, 256)?;
        check_opt_text("head", &self.head, 64)?;
        check_opt_text("note", &self.note, 1024)?;
        if self.caps.len() > 32 {
            return Err("at most 32 capabilities".into());
        }
        for cap in &self.caps {
            check_name("capability", cap)?;
        }
        check_fields(
            [
                ("note", self.note.as_deref()),
                ("worktree", self.worktree.as_deref()),
                ("branch", self.branch.as_deref()),
                ("head", self.head.as_deref()),
            ]
            .into_iter()
            .filter_map(|(f, v)| v.map(|v| (f, v))),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub agent: String,
    pub host: String,
    pub seq_head: u64,
    pub read_position: u64,
    pub live_agents: usize,
    pub conflicts: Vec<ClaimInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendRequest {
    pub agent: String,
    pub to: Vec<String>,
    pub performative: Performative,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<u64>,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// Sending the same key twice stores the message once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
    /// Category requested from a configured worker group or declared for a
    /// categorized exact-recipient root request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_category: Option<String>,
    /// Earliest time a wake consumer should dispatch a scheduled root request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_ms: Option<i64>,
}

impl SendRequest {
    /// Checks everything that does not need the hub's state and returns the
    /// parsed recipients.
    pub fn validate(&self) -> Result<Vec<Selector>, String> {
        AgentId::validate_identity(&self.agent)?;
        if self.body.trim().is_empty() {
            return Err("body is empty".into());
        }
        if self.body.len() > MAX_BODY {
            return Err(format!(
                "body is longer than {MAX_BODY} bytes; attach details in fewer words"
            ));
        }
        if self.body.chars().any(|c| {
            (c.is_control() && !matches!(c, '\n' | '\t' | '\r')) || is_forbidden_unicode(c)
        }) {
            return Err("body contains forbidden control or Unicode characters".into());
        }
        if let Some(reply_to) = self.reply_to {
            if i64::try_from(reply_to).is_err() || reply_to == 0 {
                return Err("reply_to sequence number is out of range".into());
            }
        }
        if self.to.is_empty() || self.to.len() > MAX_RECIPIENTS {
            return Err(format!("name 1-{MAX_RECIPIENTS} recipients"));
        }
        let selectors = self
            .to
            .iter()
            .map(|t| Selector::parse(t))
            .collect::<Result<Vec<_>, _>>()?;
        let group_request = selectors
            .iter()
            .any(|selector| matches!(selector, Selector::Group(_)));
        let root_request = self.performative.is_request() && self.reply_to.is_none();
        if group_request && (selectors.len() != 1 || !root_request) {
            return Err(
                "group recipient must be the sole recipient of a root REQUEST or REQUEST_VERIFY"
                    .into(),
            );
        }
        let exact_agent_request = root_request
            && selectors.len() == 1
            && matches!(selectors.first(), Some(Selector::Agent(_)));
        if let Some(category) = &self.task_category {
            check_name("task category", category)?;
            if !group_request && !exact_agent_request {
                return Err(
                    "task_category requires a root group or exact-recipient request".into(),
                );
            }
        }
        if group_request {
            if self.task_category.is_none() {
                return Err("group request requires task_category".into());
            }
            if self.expires_in_secs.is_none() {
                return Err("group request requires expires_in_secs".into());
            }
        }
        if let Some(not_before_ms) = self.not_before_ms {
            if not_before_ms <= 0 {
                return Err(
                    "not_before_ms must be a positive Unix timestamp in milliseconds".into(),
                );
            }
            if !group_request && !(exact_agent_request && self.task_category.is_some()) {
                return Err(
                    "not_before_ms requires a group or categorized exact-recipient request".into(),
                );
            }
        }
        if let Some(thread) = &self.thread {
            check_name("thread", thread)?;
        }
        if let Some(key) = &self.idempotency_key {
            if key.is_empty() {
                return Err("idempotency_key is empty".into());
            }
            check_text("idempotency_key", key, 128)?;
        }
        if self
            .expires_in_secs
            .is_some_and(|s| s == 0 || s > MAX_EXPIRY_SECS)
        {
            return Err(format!("expires_in_secs must be 1-{MAX_EXPIRY_SECS}"));
        }
        if let Some(lease) = self.lease_secs {
            if lease == 0 || lease > MAX_LEASE_SECS {
                return Err(format!("lease_secs must be 1-{MAX_LEASE_SECS}"));
            }
            if !matches!(
                self.performative,
                Performative::Accept | Performative::Progress
            ) {
                return Err("lease_secs is only valid with ACCEPT or PROGRESS".into());
            }
        }
        if self.reply_to.is_none() && !self.performative.may_start_thread() {
            return Err(format!(
                "{} must answer a message: set reply_to to its seq",
                self.performative.as_str()
            ));
        }
        let payload_text = match &self.payload {
            Some(value) => {
                if !value.is_object() {
                    return Err("payload must be a JSON object".into());
                }
                check_json_value("payload", value)?;
                let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
                if text.len() > MAX_PAYLOAD {
                    return Err(format!("payload is larger than {MAX_PAYLOAD} bytes"));
                }
                text
            }
            None => String::new(),
        };
        check_fields(
            [
                ("body", Some(self.body.as_str())),
                ("payload", Some(payload_text.as_str())),
                ("idempotency_key", self.idempotency_key.as_deref()),
            ]
            .into_iter()
            .filter_map(|(f, v)| v.map(|v| (f, v))),
        )?;
        Ok(selectors)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub seq: u64,
    pub msg_id: String,
    pub thread: String,
    /// The idempotency key was seen before; nothing new was stored.
    pub duplicate: bool,
    /// Worker selected for a server-configured group request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub seq: u64,
    pub msg_id: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub sender: String,
    pub to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_ms: Option<i64>,
    pub performative: Performative,
    pub thread: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<u64>,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxResponse {
    #[serde(default)]
    pub notice: String,
    pub messages: Vec<Message>,
    /// Highest stored message sequence in this SQLite read snapshot.
    #[serde(default)]
    pub seq_head: u64,
    /// Pass as `after` to continue this reader's scan. Reading with an
    /// explicit `after` does not advance the agent's interactive read position.
    pub next_after: u64,
    /// The read position stored on the hub for this agent.
    pub read_position: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiInboxAgentQuery {
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(default)]
    pub include_self: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiInboxRequest {
    pub agents: Vec<MultiInboxAgentQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_secs: Option<u64>,
}

impl MultiInboxRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.agents.is_empty() || self.agents.len() > MAX_MULTI_INBOX_AGENTS {
            return Err(format!("name 1-{MAX_MULTI_INBOX_AGENTS} agents"));
        }
        for entry in &self.agents {
            AgentId::validate_identity(&entry.agent)?;
            if let Some(after) = entry.after {
                if i64::try_from(after).is_err() {
                    return Err("after sequence number is out of range".into());
                }
            }
            if let Some(thread) = &entry.thread {
                check_name("thread", thread)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiInboxEntry {
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    pub messages: Vec<Message>,
    pub seq_head: u64,
    pub next_after: u64,
    pub read_position: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiInboxResponse {
    #[serde(default)]
    pub notice: String,
    pub seq_head: u64,
    pub inboxes: Vec<MultiInboxEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AckRequest {
    pub agent: String,
    pub read_to: u64,
}

impl AckRequest {
    pub fn validate(&self) -> Result<(), String> {
        AgentId::validate_identity(&self.agent)?;
        if i64::try_from(self.read_to).is_err() {
            return Err("read_to sequence number is out of range".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AckResponse {
    pub agent: String,
    pub read_position: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadResponse {
    #[serde(default)]
    pub notice: String,
    pub thread: String,
    pub messages: Vec<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_expires_ms: Option<i64>,
    pub closed: bool,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub sha256: String,
    pub name: String,
    pub raw_bytes: u64,
    pub br_bytes: u64,
    pub sender: String,
    pub created_ms: i64,
    pub expires_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub agent: String,
    pub repo: String,
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ClaimRequest {
    pub fn validate(&self) -> Result<(), String> {
        AgentId::validate_identity(&self.agent)?;
        check_name("repo", &self.repo)?;
        if self.paths.is_empty() || self.paths.len() > MAX_CLAIM_PATHS {
            return Err(format!("name 1-{MAX_CLAIM_PATHS} paths"));
        }
        for path in &self.paths {
            if path.trim().is_empty() {
                return Err("a claimed path is empty".into());
            }
            check_text("path", path, 256)?;
            if path.split(['/', '\\']).any(|seg| seg == "..") {
                return Err("claimed path must not contain '..'".into());
            }
            if normalize_claim_path(path).is_empty() {
                return Err("claimed path must name a file, directory, or pattern".into());
            }
            check_fields([("path", path.as_str())])?;
        }
        if self
            .ttl_secs
            .is_some_and(|s| s == 0 || s > MAX_CLAIM_TTL_SECS)
        {
            return Err(format!("ttl_secs must be 1-{MAX_CLAIM_TTL_SECS}"));
        }
        check_opt_text("note", &self.note, 1024)?;
        check_fields(self.note.as_deref().map(|n| ("note", n)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimInfo {
    pub id: i64,
    pub agent: String,
    pub repo: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub expires_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub claims: Vec<ClaimInfo>,
    /// Live claims by other agents that overlap the new ones. The claim is
    /// still recorded: overlapping work is a warning, not a lock.
    pub conflicts: Vec<ClaimInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
}

impl ReleaseRequest {
    pub fn validate(&self) -> Result<(), String> {
        AgentId::validate_identity(&self.agent)?;
        if let Some(repo) = &self.repo {
            check_name("repo", repo)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub host: String,
    pub harness: String,
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub seen_ms: i64,
    pub live: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenRequest {
    pub seq: u64,
    pub thread: String,
    pub sender: String,
    pub to: Vec<String>,
    pub performative: Performative,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_expires_ms: Option<i64>,
    pub created_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    #[serde(default)]
    pub notice: String,
    pub host: String,
    pub seq_head: u64,
    pub agents: Vec<AgentInfo>,
    pub claims: Vec<ClaimInfo>,
    pub open_requests: Vec<OpenRequest>,
}

pub fn normalize_claim_path(pattern: &str) -> String {
    let unified = pattern.trim().replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in unified.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        parts.push(seg);
    }
    parts.join("/")
}

/// One side of a path-overlap comparison: the normalized literal part before
/// any wildcard, and whether a wildcard followed.
fn stem(pattern: &str) -> (String, bool) {
    let norm = normalize_claim_path(pattern);
    match norm.find(['*', '?', '[']) {
        Some(i) => (norm[..i].to_string(), true),
        None => (norm, false),
    }
}

fn covers(general: (&str, bool), specific: &str) -> bool {
    let (stem, wild) = general;
    if wild {
        specific.starts_with(stem)
    } else {
        specific == stem
            || stem.is_empty()
            || specific
                .strip_prefix(stem)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// Could two claimed paths or patterns name the same file? Conservative:
/// `src/ui` covers `src/ui/x.rs`, `src/ui*` covers `src/ui2`, and Windows `\`
/// separators are treated identically to `/`.
pub fn paths_overlap(a: &str, b: &str) -> bool {
    let (sa, sa_w) = stem(a);
    let (sb, sb_w) = stem(b);
    covers((sa.as_str(), sa_w), sb.as_str()) || covers((sb.as_str(), sb_w), sa.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(performative: Performative, body: &str) -> SendRequest {
        SendRequest {
            agent: "agy:s1".into(),
            to: vec!["host:host-b".into()],
            performative,
            thread: None,
            reply_to: None,
            body: body.into(),
            payload: None,
            idempotency_key: None,
            expires_in_secs: None,
            lease_secs: None,
            task_category: None,
            not_before_ms: None,
        }
    }

    #[test]
    fn send_validation() {
        assert!(send(Performative::Announce, "pushed 1234abcd")
            .validate()
            .is_ok());
        assert!(send(Performative::Announce, "  ").validate().is_err());
        assert!(send(Performative::Announce, "hi\u{202E}there")
            .validate()
            .is_err());
        assert!(send(Performative::Announce, &"x".repeat(MAX_BODY + 1))
            .validate()
            .is_err());
        assert!(send(Performative::Result, "done")
            .validate()
            .unwrap_err()
            .contains("reply_to"));
        let mut r = send(Performative::Query, "q");
        r.to = vec![];
        assert!(r.validate().is_err());
        r.to = vec!["planet:mars".into()];
        assert!(r.validate().is_err());
        let mut r = send(Performative::Query, "q");
        r.payload = Some(serde_json::json!({"password": "supersecretpassword123"}));
        assert!(r.validate().unwrap_err().starts_with("payload"));
        let mut r = send(Performative::Query, "q");
        r.payload = Some(serde_json::json!({"ok": "bad\u{E0041}tag"}));
        assert!(r.validate().is_err());
        let mut r = send(Performative::Query, "q");
        r.payload = Some(serde_json::json!({"x": "y".repeat(MAX_PAYLOAD)}));
        assert!(r.validate().is_err());
        let mut r = send(Performative::Query, "q");
        r.expires_in_secs = Some(0);
        assert!(r.validate().is_err());
        let mut r = send(Performative::Reply, "ans");
        r.reply_to = Some(u64::MAX);
        assert!(r.validate().is_err());
        assert!(AckRequest {
            agent: "agy:s1".into(),
            read_to: u64::MAX
        }
        .validate()
        .is_err());
        assert!(check_artifact_name("ok-file_1.log").is_ok());
        assert!(check_artifact_name("bad file.log").is_err());
        assert!(check_artifact_name("bad\u{00e9}.log").is_err());
        assert!(check_artifact_name("../secret.log").is_err());
    }

    #[test]
    fn group_requests_require_a_category_and_explicit_expiry() {
        let mut request = send(Performative::Request, "run verification");
        request.to = vec!["group:reviewers".into()];
        assert!(request.validate().unwrap_err().contains("task_category"));

        request.task_category = Some("platform-verification".into());
        assert!(request.validate().unwrap_err().contains("expires_in_secs"));

        request.expires_in_secs = Some(3600);
        request.not_before_ms = Some(1_800_000_000_000);
        assert!(request.validate().is_ok());

        request.task_category = Some("invalid category".into());
        assert!(request.validate().is_err());
    }

    #[test]
    fn direct_request_categories_and_schedules_require_an_exact_root_request() {
        let mut request = send(Performative::Request, "run verification");
        request.to = vec!["macbook:codex:reviewer".into()];
        assert!(request.validate().is_ok());

        request.task_category = Some("platform-verification".into());
        request.not_before_ms = Some(1_800_000_000_000);
        assert!(request.validate().is_ok());

        request.to = vec!["host:macbook".into()];
        assert!(request.validate().unwrap_err().contains("task_category"));

        request.to = vec!["macbook:codex:reviewer".into()];
        request.performative = Performative::Reply;
        request.reply_to = Some(42);
        assert!(request.validate().unwrap_err().contains("task_category"));
    }

    #[test]
    fn inbox_snapshot_head_is_serialized_and_defaults_for_older_hubs() {
        let response = InboxResponse {
            notice: "untrusted".into(),
            messages: Vec::new(),
            seq_head: 12,
            next_after: 12,
            read_position: 3,
        };
        let encoded = serde_json::to_value(&response).unwrap();
        assert_eq!(encoded["seq_head"], 12);

        let older_response: InboxResponse = serde_json::from_value(serde_json::json!({
            "notice": "untrusted",
            "messages": [],
            "next_after": 12,
            "read_position": 3
        }))
        .unwrap();
        assert_eq!(older_response.seq_head, 0);
    }

    #[test]
    fn overlap_rules() {
        let yes = [
            ("src/ui", "src/ui/widget.rs"),
            ("src/ui/", "src/ui/widget.rs"),
            (r"src\ui\widget.rs", "src/ui"),
            (r".\src\ui\*", "src/ui/widget.rs"),
            ("./src/ui/*", "src/ui/widget.rs"),
            ("src/ui*", "src/ui2/x.rs"),
            ("src/ui*", "src/u*"),
            ("*", "anything"),
            ("Cargo.lock", "Cargo.lock"),
            ("src/ui/a.rs", "src/ui"),
        ];
        for (a, b) in yes {
            assert!(paths_overlap(a, b), "{a} vs {b}");
            assert!(paths_overlap(b, a), "{b} vs {a}");
        }
        let no = [
            ("src/ui", "src/ui2"),
            ("src/a*", "src/b*"),
            ("docs/x.md", "docs/y.md"),
        ];
        for (a, b) in no {
            assert!(!paths_overlap(a, b), "{a} vs {b}");
            assert!(!paths_overlap(b, a), "{b} vs {a}");
        }
    }

    #[test]
    fn multi_inbox_validation() {
        let empty = MultiInboxRequest {
            agents: Vec::new(),
            limit: None,
            wait_secs: None,
        };
        assert!(empty.validate().is_err());

        let too_many = MultiInboxRequest {
            agents: (0..=MAX_MULTI_INBOX_AGENTS)
                .map(|idx| MultiInboxAgentQuery {
                    agent: format!("codex:s{idx}"),
                    after: None,
                    thread: None,
                    include_self: false,
                })
                .collect(),
            limit: None,
            wait_secs: None,
        };
        assert!(too_many.validate().is_err());

        let bad_after = MultiInboxRequest {
            agents: vec![MultiInboxAgentQuery {
                agent: "lubuntu:codex:s1".into(),
                after: Some(u64::MAX),
                thread: None,
                include_self: false,
            }],
            limit: None,
            wait_secs: None,
        };
        assert!(bad_after.validate().is_err());

        let bad_thread = MultiInboxRequest {
            agents: vec![MultiInboxAgentQuery {
                agent: "codex:s1".into(),
                after: Some(5),
                thread: Some("bad thread".into()),
                include_self: false,
            }],
            limit: None,
            wait_secs: None,
        };
        assert!(bad_thread.validate().is_err());

        let valid = MultiInboxRequest {
            agents: vec![
                MultiInboxAgentQuery {
                    agent: "lubuntu:codex:s1".into(),
                    after: Some(5),
                    thread: Some("thr-1".into()),
                    include_self: true,
                },
                MultiInboxAgentQuery {
                    agent: "codex:s2".into(),
                    after: None,
                    thread: None,
                    include_self: false,
                },
            ],
            limit: Some(50),
            wait_secs: Some(10),
        };
        assert!(valid.validate().is_ok());
    }
}
