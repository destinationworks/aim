use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use aim_proto::guard::find_secret;
use aim_proto::names::{check_name, valid_name};
use aim_proto::{AgentId, Performative, MAX_MULTI_INBOX_AGENTS, MAX_WAIT_SECS};
use serde::{Deserialize, Serialize};

use crate::config::default_config_path;

pub const MAX_POLICY_BYTES: usize = 128 * 1024;
pub const MAX_SESSIONS: usize = MAX_MULTI_INBOX_AGENTS;
pub const MAX_CONCURRENT_SPAWNS: u32 = 8;
pub const MAX_SCHEDULE_DELAY_SECS: u64 = 7 * 24 * 3600;
pub const DEFAULT_WAIT_SECS: u64 = 25;
pub const DEFAULT_HEARTBEAT_SECS: u64 = 300;
pub const MIN_HEARTBEAT_SECS: u64 = 10;
pub const MAX_HEARTBEAT_SECS: u64 = 3600;
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 120;
pub const DEFAULT_SPAWN_TIMEOUT_SECS: u64 = 600;
pub const MAX_DISPATCH_TIMEOUT_SECS: u64 = 3600;

const FORBIDDEN_POLICY_KEYS: &[&str] = &[
    "key",
    "token",
    "bearer",
    "secret",
    "api_key",
    "apikey",
    "auth_token",
    "password",
    "private_key",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllowedPerformative {
    Announce,
    Query,
    Reply,
    Request,
    RequestVerify,
    Accept,
    Reject,
    Progress,
    Result,
    Cancel,
    Alert,
    Blocker,
    Conflict,
}

impl AllowedPerformative {
    pub fn matches(self, perf: Performative) -> bool {
        matches!(
            (self, perf),
            (Self::Announce, Performative::Announce)
                | (Self::Query, Performative::Query)
                | (Self::Reply, Performative::Reply)
                | (Self::Request, Performative::Request)
                | (Self::RequestVerify, Performative::RequestVerify)
                | (Self::Accept, Performative::Accept)
                | (Self::Reject, Performative::Reject)
                | (Self::Progress, Performative::Progress)
                | (Self::Result, Performative::Result)
                | (Self::Cancel, Performative::Cancel)
                | (Self::Alert, Performative::Alert)
                | (Self::Blocker, Performative::Blocker)
                | (Self::Conflict, Performative::Conflict)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Agentapi,
    AgyCli,
    ClaudeCli,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agentapi => "agentapi",
            Self::AgyCli => "agy_cli",
            Self::ClaudeCli => "claude_cli",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakePolicyFile {
    /// Fail-closed global enable flag: must be explicitly `true` before polling or dispatching.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wait_secs")]
    pub wait_secs: u64,
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
    #[serde(default)]
    pub agentapi_bin: Option<PathBuf>,
    #[serde(default)]
    pub agy_bin: Option<PathBuf>,
    #[serde(default)]
    pub claude_bin: Option<PathBuf>,
    #[serde(default)]
    pub sessions: BTreeMap<String, SessionPolicy>,
    #[serde(default)]
    pub spawners: BTreeMap<String, SpawnerPolicy>,
}

fn default_wait_secs() -> u64 {
    DEFAULT_WAIT_SECS
}

fn default_heartbeat_secs() -> u64 {
    DEFAULT_HEARTBEAT_SECS
}

fn default_harness() -> String {
    "agy".to_string()
}

fn default_true() -> bool {
    true
}

fn default_max_concurrent() -> u32 {
    1
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_harness")]
    pub harness: String,
    #[serde(default)]
    pub backend: Option<BackendKind>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub trusted_sender_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_performatives: Vec<AllowedPerformative>,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub require_group: bool,
    #[serde(default)]
    pub allowed_task_categories: Vec<String>,
    #[serde(default)]
    pub max_schedule_delay_secs: u64,
    #[serde(default)]
    pub ack_on_dispatch: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnerPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_harness")]
    pub harness: String,
    #[serde(default)]
    pub backend: Option<BackendKind>,
    pub cwd: PathBuf,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub title_prefix: Option<String>,
    #[serde(default)]
    pub trusted_sender_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_performatives: Vec<AllowedPerformative>,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default = "default_true")]
    pub require_group: bool,
    #[serde(default)]
    pub allowed_task_categories: Vec<String>,
    #[serde(default)]
    pub max_schedule_delay_secs: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    #[serde(default = "default_true")]
    pub ack_on_dispatch: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct MessageRule<'a> {
    pub harness: &'a str,
    pub trusted_sender_hosts: &'a [String],
    pub allowed_performatives: &'a [AllowedPerformative],
    pub allowed_groups: &'a [String],
    pub require_group: bool,
    pub allowed_task_categories: &'a [String],
    pub max_schedule_delay_secs: u64,
}

impl SessionPolicy {
    pub fn resolve_backend(&self) -> Result<BackendKind, String> {
        resolve_backend(&self.harness, self.backend)
    }

    pub fn effective_timeout_secs(&self) -> u64 {
        self.timeout_secs.unwrap_or(DEFAULT_SESSION_TIMEOUT_SECS)
    }

    pub fn as_rule(&self) -> MessageRule<'_> {
        MessageRule {
            harness: &self.harness,
            trusted_sender_hosts: &self.trusted_sender_hosts,
            allowed_performatives: &self.allowed_performatives,
            allowed_groups: &self.allowed_groups,
            require_group: self.require_group,
            allowed_task_categories: &self.allowed_task_categories,
            max_schedule_delay_secs: self.max_schedule_delay_secs,
        }
    }
}

impl SpawnerPolicy {
    pub fn resolve_backend(&self) -> Result<BackendKind, String> {
        resolve_backend(&self.harness, self.backend)
    }

    pub fn effective_timeout_secs(&self) -> u64 {
        self.timeout_secs.unwrap_or(DEFAULT_SPAWN_TIMEOUT_SECS)
    }

    pub fn as_rule(&self) -> MessageRule<'_> {
        MessageRule {
            harness: &self.harness,
            trusted_sender_hosts: &self.trusted_sender_hosts,
            allowed_performatives: &self.allowed_performatives,
            allowed_groups: &self.allowed_groups,
            require_group: self.require_group,
            allowed_task_categories: &self.allowed_task_categories,
            max_schedule_delay_secs: self.max_schedule_delay_secs,
        }
    }
}

pub fn default_policy_path(config_override: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(explicit) = config_override {
        return Ok(explicit.to_path_buf());
    }
    if let Ok(env_path) = std::env::var("AIM_WAKE_CONFIG") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let cfg_path = default_config_path()?;
    let parent = cfg_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("cannot determine parent directory for aim wake policy")?;
    Ok(parent.join("wake.toml"))
}

pub fn default_state_path(state_override: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(explicit) = state_override {
        return Ok(explicit.to_path_buf());
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                return Ok(PathBuf::from(local).join("aim").join("wake-state.json"));
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return Ok(PathBuf::from(profile)
                .join(".local")
                .join("state")
                .join("aim")
                .join("wake-state.json"));
        }
        Err("cannot locate %LOCALAPPDATA% or %USERPROFILE% for aim wake state".into())
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
            if !xdg.trim().is_empty() {
                return Ok(PathBuf::from(xdg).join("aim").join("wake-state.json"));
            }
        }
        let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
        #[cfg(target_os = "macos")]
        {
            Ok(PathBuf::from(&home)
                .join("Library")
                .join("Application Support")
                .join("aim")
                .join("wake-state.json"))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(PathBuf::from(&home)
                .join(".local")
                .join("state")
                .join("aim")
                .join("wake-state.json"))
        }
    }
}

/// Loads `wake.toml`, returning a disabled default policy when the file does not exist.
pub fn load_policy_file(path: &Path) -> Result<WakePolicyFile, String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!("refusing symlink policy file {}", path.display()));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WakePolicyFile::default());
        }
        Err(e) => return Err(format!("cannot inspect {}: {e}", path.display())),
    }
    let raw = aim_fs::read_private_string(path, MAX_POLICY_BYTES)?;
    parse_policy_toml(&raw)
}

pub fn parse_policy_toml(raw: &str) -> Result<WakePolicyFile, String> {
    if let Some(rule) = find_secret(raw) {
        return Err(format!(
            "wake.toml looks like it contains a secret ({rule}); wake policy must not embed credentials"
        ));
    }
    let val: toml::Value =
        toml::from_str(raw).map_err(|e| format!("invalid wake policy TOML: {e}"))?;
    check_toml_value(&val)?;
    let policy: WakePolicyFile =
        toml::from_str(raw).map_err(|e| format!("invalid wake policy schema: {e}"))?;
    validate_policy(&policy)?;
    Ok(policy)
}

fn check_toml_value(val: &toml::Value) -> Result<(), String> {
    match val {
        toml::Value::String(s) => {
            if let Some(rule) = find_secret(s) {
                return Err(format!(
                    "wake.toml looks like it contains a secret ({rule}); store keys only in key_file"
                ));
            }
            Ok(())
        }
        toml::Value::Array(items) => {
            for item in items {
                check_toml_value(item)?;
            }
            Ok(())
        }
        toml::Value::Table(table) => {
            for (k, v) in table {
                let lower = k.to_ascii_lowercase();
                if FORBIDDEN_POLICY_KEYS.contains(&lower.as_str()) {
                    return Err(format!(
                        "wake.toml must not contain `{k}`; credentials belong only in key_file"
                    ));
                }
                check_toml_value(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn validate_policy(policy: &WakePolicyFile) -> Result<(), String> {
    if policy.wait_secs > MAX_WAIT_SECS {
        return Err(format!("wait_secs must be 0-{MAX_WAIT_SECS}"));
    }
    if policy.heartbeat_secs < MIN_HEARTBEAT_SECS || policy.heartbeat_secs > MAX_HEARTBEAT_SECS {
        return Err(format!(
            "heartbeat_secs must be {MIN_HEARTBEAT_SECS}-{MAX_HEARTBEAT_SECS}"
        ));
    }
    if policy.sessions.len() + policy.spawners.len() > MAX_SESSIONS {
        return Err(format!(
            "total configured sessions + spawners cannot exceed {MAX_SESSIONS}"
        ));
    }

    let mut seen_agents = BTreeSet::new();
    for (id, sess) in &policy.sessions {
        check_name("session ID", id)?;
        let agent_id = format!("{}:{id}", sess.harness);
        AgentId::validate_identity(&agent_id)?;
        if !seen_agents.insert(agent_id.clone()) {
            return Err(format!("duplicate wake target '{agent_id}'"));
        }
        if !matches!(sess.harness.as_str(), "agy" | "claude") {
            return Err(format!(
                "session '{id}' has unsupported harness '{}' (standalone `aim wake` supports `agy` and `claude`; Orust owns `codex`)",
                sess.harness
            ));
        }
        let _ = sess.resolve_backend()?;
        if let Some(target_id) = &sess.target_id {
            validate_safe_arg("target_id", target_id, 128)?;
        }
        validate_common_options(
            id,
            sess.model.as_deref(),
            sess.mode.as_deref(),
            sess.project.as_deref(),
            sess.timeout_secs,
        )?;
        if sess.enabled {
            validate_rule(id, &sess.as_rule(), false)?;
            if let Some(cwd) = &sess.cwd {
                if !cwd.is_dir() {
                    return Err(format!(
                        "session '{id}' cwd {} does not exist or is not a directory",
                        cwd.display()
                    ));
                }
            }
        }
    }

    for (id, spawner) in &policy.spawners {
        check_name("spawner ID", id)?;
        let agent_id = format!("{}:{id}", spawner.harness);
        AgentId::validate_identity(&agent_id)?;
        if !seen_agents.insert(agent_id.clone()) {
            return Err(format!(
                "spawner '{agent_id}' conflicts with an existing session ID on the same harness"
            ));
        }
        if !matches!(spawner.harness.as_str(), "agy" | "claude") {
            return Err(format!(
                "spawner '{id}' has unsupported harness '{}' (expected `agy` or `claude`)",
                spawner.harness
            ));
        }
        let _ = spawner.resolve_backend()?;
        if spawner.max_concurrent == 0 || spawner.max_concurrent > MAX_CONCURRENT_SPAWNS {
            return Err(format!(
                "spawner '{id}' max_concurrent must be 1-{MAX_CONCURRENT_SPAWNS}"
            ));
        }
        validate_common_options(
            id,
            spawner.model.as_deref(),
            spawner.mode.as_deref(),
            spawner.project.as_deref(),
            spawner.timeout_secs,
        )?;
        if let Some(profile) = &spawner.profile {
            validate_safe_arg("profile", profile, 64)?;
        }
        if spawner
            .allowed_performatives
            .contains(&AllowedPerformative::Announce)
        {
            return Err(format!(
                "spawner '{id}' must not allow ANNOUNCE broadcasts to trigger auto-spawn"
            ));
        }
        if spawner.enabled {
            validate_rule(id, &spawner.as_rule(), true)?;
            if !spawner.cwd.is_dir() {
                return Err(format!(
                    "spawner '{id}' cwd {} does not exist or is not a directory",
                    spawner.cwd.display()
                ));
            }
        }
    }

    Ok(())
}

fn resolve_backend(harness: &str, explicit: Option<BackendKind>) -> Result<BackendKind, String> {
    match (harness, explicit) {
        ("agy", None) | ("agy", Some(BackendKind::Agentapi)) => Ok(BackendKind::Agentapi),
        ("agy", Some(BackendKind::AgyCli)) => Ok(BackendKind::AgyCli),
        ("agy", Some(other)) => Err(format!(
            "harness `agy` does not support backend `{}`",
            other.as_str()
        )),
        ("claude", None) | ("claude", Some(BackendKind::ClaudeCli)) => Ok(BackendKind::ClaudeCli),
        ("claude", Some(other)) => Err(format!(
            "harness `claude` does not support backend `{}`",
            other.as_str()
        )),
        (other, _) => Err(format!("unsupported harness `{other}`")),
    }
}

fn validate_common_options(
    label: &str,
    model: Option<&str>,
    mode: Option<&str>,
    project: Option<&str>,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    if let Some(model) = model {
        validate_safe_arg(&format!("{label}.model"), model, 128)?;
    }
    if let Some(mode) = mode {
        if !matches!(mode, "accept-edits" | "auto" | "plan") {
            return Err(format!(
                "{label}.mode must be `accept-edits`, `auto`, or `plan`"
            ));
        }
    }
    if let Some(project) = project {
        validate_safe_arg(&format!("{label}.project"), project, 128)?;
    }
    if let Some(t) = timeout_secs {
        if t == 0 || t > MAX_DISPATCH_TIMEOUT_SECS {
            return Err(format!(
                "{label}.timeout_secs must be 1-{MAX_DISPATCH_TIMEOUT_SECS}"
            ));
        }
    }
    Ok(())
}

fn validate_rule(id: &str, rule: &MessageRule<'_>, is_spawner: bool) -> Result<(), String> {
    if rule.trusted_sender_hosts.is_empty() {
        return Err(format!(
            "{id}: enabled wake target must list at least one trusted_sender_hosts entry"
        ));
    }
    for host in rule.trusted_sender_hosts {
        if !valid_name(host) {
            return Err(format!("{id}: invalid trusted sender host `{host}`"));
        }
    }
    if rule.allowed_performatives.is_empty() {
        return Err(format!(
            "{id}: enabled wake target must list allowed_performatives explicitly"
        ));
    }
    if rule.require_group && rule.allowed_groups.is_empty() {
        return Err(format!(
            "{id}: require_group=true requires non-empty allowed_groups"
        ));
    }
    if is_spawner
        && rule.allowed_performatives.iter().any(|p| {
            !matches!(
                p,
                AllowedPerformative::Request
                    | AllowedPerformative::RequestVerify
                    | AllowedPerformative::Query
            )
        })
    {
        return Err(format!(
            "{id}: spawner allowed_performatives may only include REQUEST, REQUEST_VERIFY, or QUERY"
        ));
    }
    for group in rule.allowed_groups {
        check_name("allowed_groups entry", group)?;
    }
    for cat in rule.allowed_task_categories {
        check_name("allowed_task_categories entry", cat)?;
    }
    if rule.max_schedule_delay_secs > MAX_SCHEDULE_DELAY_SECS {
        return Err(format!(
            "{id}: max_schedule_delay_secs cannot exceed {MAX_SCHEDULE_DELAY_SECS}"
        ));
    }
    Ok(())
}

pub fn validate_safe_arg(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        return Err(format!("{field} must be 1-{max_len} characters"));
    }
    if trimmed.starts_with('-') {
        return Err(format!("{field} must not start with '-'"));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
    {
        return Err(format!("{field} contains unsupported characters"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterDecision {
    DeliverNow,
    DeferUntil(i64),
    Skip(String),
}

pub fn evaluate_message(
    rule: &MessageRule<'_>,
    msg: &aim_proto::wire::Message,
    now_ms: i64,
) -> FilterDecision {
    let Ok(sender) = AgentId::parse_full(&msg.sender) else {
        return FilterDecision::Skip("invalid sender ID".into());
    };
    if !rule.trusted_sender_hosts.iter().any(|h| h == &sender.host) {
        return FilterDecision::Skip(format!("untrusted sender host `{}`", sender.host));
    }
    if !rule
        .allowed_performatives
        .iter()
        .any(|p| p.matches(msg.performative))
    {
        return FilterDecision::Skip(format!(
            "performative {} not permitted",
            msg.performative.as_str()
        ));
    }
    if rule.require_group && msg.assigned_group.is_none() {
        return FilterDecision::Skip("message lacks required server-assigned group".into());
    }
    if !rule.allowed_groups.is_empty() {
        let Some(group) = msg.assigned_group.as_deref() else {
            return FilterDecision::Skip(
                "message missing assigned_group required by policy".into(),
            );
        };
        if !rule.allowed_groups.iter().any(|g| g == group) {
            return FilterDecision::Skip(format!("group `{group}` not permitted"));
        }
    }
    if !rule.allowed_task_categories.is_empty() {
        let Some(cat) = msg.task_category.as_deref() else {
            return FilterDecision::Skip("message missing task_category required by policy".into());
        };
        if !rule.allowed_task_categories.iter().any(|c| c == cat) {
            return FilterDecision::Skip(format!("task_category `{cat}` not permitted"));
        }
    }
    if msg.expires_ms <= now_ms {
        return FilterDecision::Skip("message already expired".into());
    }
    if let Some(not_before) = msg.not_before_ms {
        if not_before > now_ms {
            let max_horizon =
                now_ms.saturating_add((rule.max_schedule_delay_secs as i64).saturating_mul(1000));
            if rule.max_schedule_delay_secs == 0 || not_before > max_horizon {
                return FilterDecision::Skip(
                    "not_before_ms exceeds policy max_schedule_delay_secs".into(),
                );
            }
            return FilterDecision::DeferUntil(not_before);
        }
    }
    FilterDecision::DeliverNow
}
