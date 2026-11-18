use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use aim_proto::guard::find_secret;
use aim_proto::names::valid_name;
use aim_proto::AgentId;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

const FORBIDDEN_CONFIG_KEYS: &[&str] = &[
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

/// Holds a bearer key in memory wrapped in `Zeroizing` without ever printing it
/// in logs or debug output.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<String>);

impl SecretKey {
    pub fn from_raw(raw: impl Into<Zeroizing<String>>) -> Result<Self, String> {
        let raw = raw.into();
        let trimmed = Zeroizing::new(raw.trim().to_string());
        if trimmed.is_empty() {
            return Err("AIM key file is empty".into());
        }
        if trimmed.len() > 256 || !trimmed.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(
                "AIM key file must contain a single graphic-ASCII token without spaces or extra lines".into(),
            );
        }
        Ok(Self(trimmed))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn bearer_header(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.as_str()))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub url: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ResolvedConfig {
    pub url: Url,
    pub ca_cert: PathBuf,
    pub key_file: PathBuf,
    pub default_agent: Option<String>,
    pub caps: Vec<String>,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Overrides {
    pub config_path: Option<PathBuf>,
    pub url: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

pub fn default_config_path() -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("AIM_CONFIG") {
        if !explicit.trim().is_empty() {
            return Ok(PathBuf::from(explicit));
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.trim().is_empty() {
                return Ok(PathBuf::from(appdata).join("aim").join("config.toml"));
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return Ok(PathBuf::from(profile)
                .join(".config")
                .join("aim")
                .join("config.toml"));
        }
        Err("cannot locate %APPDATA% or %USERPROFILE% for aim config".into())
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.trim().is_empty() {
                return Ok(PathBuf::from(xdg).join("aim").join("config.toml"));
            }
        }
        let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
        let dot_config = PathBuf::from(&home)
            .join(".config")
            .join("aim")
            .join("config.toml");
        #[cfg(target_os = "macos")]
        {
            if !dot_config.exists() {
                let app_support = PathBuf::from(&home)
                    .join("Library")
                    .join("Application Support")
                    .join("aim")
                    .join("config.toml");
                if app_support.exists() {
                    return Ok(app_support);
                }
            }
        }
        Ok(dot_config)
    }
}

fn check_toml_value(val: &toml::Value) -> Result<(), String> {
    match val {
        toml::Value::String(s) => {
            if let Some(rule) = find_secret(s) {
                return Err(format!(
                    "config.toml looks like it contains a secret ({rule}); store the key only in a 0600 file referenced by key_file"
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
            for (key, value) in table {
                let lower = key.to_ascii_lowercase();
                if FORBIDDEN_CONFIG_KEYS.contains(&lower.as_str()) {
                    return Err(format!(
                        "config.toml must not contain `{key}`; put your key in a 0600 file and set `key_file = \"...\"`"
                    ));
                }
                check_toml_value(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn parse_config_toml(raw: &str) -> Result<ConfigFile, String> {
    if let Some(rule) = find_secret(raw) {
        return Err(format!(
            "config.toml looks like it contains a secret ({rule}); store the key only in a 0600 file referenced by key_file"
        ));
    }
    let val: toml::Value = toml::from_str(raw).map_err(|e| format!("invalid config TOML: {e}"))?;
    check_toml_value(&val)?;
    toml::from_str(raw).map_err(|e| format!("invalid config schema: {e}"))
}

pub fn normalize_base_url(raw: &str) -> Result<Url, String> {
    let mut url = Url::parse(raw.trim()).map_err(|e| format!("invalid AIM URL: {e}"))?;
    if url.scheme() != "https" {
        return Err("AIM URL must use https:// (plain http is refused)".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("AIM URL must not contain credentials".into());
    }
    if url.host_str().is_none() {
        return Err("AIM URL must include a host".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("AIM base URL must not contain query parameters or fragments".into());
    }
    let trimmed_path = url.path().trim_end_matches('/').to_string();
    url.set_path(&trimmed_path);
    Ok(url)
}

fn resolve_rel(base_dir: Option<&Path>, p: PathBuf) -> PathBuf {
    if p.is_absolute() {
        return p;
    }
    match base_dir {
        Some(dir) => dir.join(p),
        None => p,
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl ResolvedConfig {
    pub fn load(overrides: &Overrides) -> Result<Self, String> {
        let cfg_path = match &overrides.config_path {
            Some(p) => p.clone(),
            None => default_config_path()?,
        };
        let cfg_dir = cfg_path.parent().map(Path::to_path_buf);

        let file_cfg = match std::fs::symlink_metadata(&cfg_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!("refusing symlinked config {}", cfg_path.display()));
                }
                let bytes = aim_fs::read_trusted_config_bytes(&cfg_path, 64 * 1024)?;
                let text = String::from_utf8(bytes)
                    .map_err(|_| format!("{} is not valid UTF-8", cfg_path.display()))?;
                Some(parse_config_toml(&text)?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("cannot read {}: {e}", cfg_path.display())),
        };

        let env_url = non_empty_env("AIM_URL");
        let env_ca = non_empty_env("AIM_CA_CERT").map(PathBuf::from);
        let env_key = non_empty_env("AIM_KEY_FILE").map(PathBuf::from);

        let raw_url = overrides
            .url
            .clone()
            .or(env_url)
            .or_else(|| file_cfg.as_ref().and_then(|c| c.url.clone()))
            .ok_or_else(|| {
                format!(
                    "AIM URL is not configured; run `aim init --url https://aim.example.internal:11460/aim --ca-cert ... --key-file ...` or create {}",
                    cfg_path.display()
                )
            })?;
        let url = normalize_base_url(&raw_url)?;

        let ca_cert = overrides
            .ca_cert
            .clone()
            .or(env_ca)
            .or_else(|| {
                file_cfg
                    .as_ref()
                    .and_then(|c| c.ca_cert.clone())
                    .map(|p| resolve_rel(cfg_dir.as_deref(), p))
            })
            .ok_or("AIM ca_cert is not configured (set ca_cert in config.toml or AIM_CA_CERT)")?;

        let key_file = overrides
            .key_file
            .clone()
            .or(env_key)
            .or_else(|| {
                file_cfg
                    .as_ref()
                    .and_then(|c| c.key_file.clone())
                    .map(|p| resolve_rel(cfg_dir.as_deref(), p))
            })
            .ok_or(
                "AIM key_file is not configured (set key_file in config.toml or AIM_KEY_FILE)",
            )?;

        let (default_agent, caps, timeout_secs) = match file_cfg {
            Some(c) => (
                c.default_agent,
                c.caps,
                c.timeout_secs.unwrap_or(15).clamp(2, 120),
            ),
            None => (None, Vec::new(), 15),
        };

        Ok(Self {
            url,
            ca_cert,
            key_file,
            default_agent,
            caps,
            timeout_secs,
        })
    }

    pub fn load_key(&self) -> Result<SecretKey, String> {
        let raw = Zeroizing::new(aim_fs::read_private_string(&self.key_file, 4096)?);
        SecretKey::from_raw(raw)
    }

    pub fn resolve_agent(&self, explicit: Option<&str>) -> Result<String, String> {
        resolve_agent(explicit, self.default_agent.as_deref())
    }
}

pub fn resolve_agent(
    explicit: Option<&str>,
    config_default: Option<&str>,
) -> Result<String, String> {
    if let Some(a) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        AgentId::parse_local(a)?;
        return Ok(a.to_string());
    }
    if let Some(a) = non_empty_env("AIM_AGENT") {
        AgentId::parse_local(&a)?;
        return Ok(a);
    }
    if let Some(a) = config_default.map(str::trim).filter(|s| !s.is_empty()) {
        AgentId::parse_local(a)?;
        return Ok(a.to_string());
    }
    let harness_override = non_empty_env("AIM_HARNESS");
    if let Some(tid) = non_empty_env("CODEX_THREAD_ID") {
        let candidate = format!("{}:{tid}", harness_override.as_deref().unwrap_or("codex"));
        AgentId::parse_local(&candidate)?;
        return Ok(candidate);
    }
    if let Some(sid) = non_empty_env("CLAUDE_SESSION_ID") {
        let candidate = format!("{}:{sid}", harness_override.as_deref().unwrap_or("claude"));
        AgentId::parse_local(&candidate)?;
        return Ok(candidate);
    }
    if let Some(sid) =
        non_empty_env("ANTIGRAVITY_CONVERSATION_ID").or_else(|| non_empty_env("AGY_SESSION_ID"))
    {
        let candidate = format!("{}:{sid}", harness_override.as_deref().unwrap_or("agy"));
        AgentId::parse_local(&candidate)?;
        return Ok(candidate);
    }
    Err("missing agent identity: pass --agent HARNESS:SESSION (for example agy:session1, codex:session2, claude:session3) or set AIM_AGENT".into())
}

#[derive(Clone, Debug, Default)]
pub struct GitContext {
    pub repo: Option<String>,
    pub worktree: Option<String>,
    pub branch: Option<String>,
    pub head: Option<String>,
}

fn git_line(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["-c", "core.fsmonitor=false"])
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

pub fn detect_git_context(cwd: &Path) -> GitContext {
    let Some(top) = git_line(cwd, &["rev-parse", "--show-toplevel"]) else {
        return GitContext::default();
    };
    let repo = git_line(
        cwd,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    .and_then(|common| {
        let p = Path::new(&common);
        let candidate = if p.file_name().and_then(|n| n.to_str()) == Some(".git") {
            p.parent().unwrap_or(p)
        } else {
            p
        };
        candidate
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.strip_suffix(".git").unwrap_or(s))
            .filter(|n| valid_name(n))
            .map(str::to_string)
    })
    .or_else(|| {
        Path::new(&top)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| valid_name(n))
            .map(str::to_string)
    });
    let branch = git_line(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let head = git_line(cwd, &["rev-parse", "--short=12", "HEAD"]);
    GitContext {
        repo,
        worktree: None,
        branch,
        head,
    }
}

pub fn default_os_caps() -> Vec<String> {
    vec![
        std::env::consts::OS.to_string(),
        std::env::consts::ARCH.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_enforces_https_and_no_secrets() {
        assert_eq!(
            normalize_base_url("https://aim.example.internal:11460/aim/")
                .unwrap()
                .as_str(),
            "https://aim.example.internal:11460/aim"
        );
        assert!(normalize_base_url("http://aim.example.internal:11460/aim").is_err());
        assert!(normalize_base_url("https://user:pass@aim.example.internal:11460/aim").is_err());
        assert!(normalize_base_url("https://aim.example.internal:11460/aim?token=abc").is_err());
        assert!(normalize_base_url("https://aim.example.internal:11460/aim#frag").is_err());
    }

    #[test]
    fn config_rejects_embedded_keys_and_unknown_fields() {
        let bad_field = r#"
url = "https://aim.example.internal:11460/aim"
key = "not-even-aim-format"
"#;
        assert!(parse_config_toml(bad_field)
            .unwrap_err()
            .contains("key_file"));

        let bad_token = r#"
url = "https://aim.example.internal:11460/aim"
default_agent = "agy:aim1_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
"#;
        assert!(parse_config_toml(bad_token).unwrap_err().contains("secret"));

        let bad_unknown = r#"
url = "https://aim.example.internal:11460/aim"
ca_cert = "ca.crt"
key_file = "host.key"
unexpected_option = true
"#;
        assert!(parse_config_toml(bad_unknown).is_err());

        let good = r#"
url = "https://aim.example.internal:11460/aim"
ca_cert = "ca.crt"
key_file = "host.key"
"#;
        let parsed = parse_config_toml(good).unwrap();
        assert_eq!(
            parsed.url.as_deref(),
            Some("https://aim.example.internal:11460/aim")
        );
    }

    #[test]
    fn secret_key_never_prints() {
        let key =
            SecretKey::from_raw(String::from("  aim1_secret_value_1234567890abcdef  \n")).unwrap();
        assert_eq!(format!("{key}"), "[REDACTED]");
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
        assert_eq!(
            key.bearer_header().as_str(),
            "Bearer aim1_secret_value_1234567890abcdef"
        );
        assert!(SecretKey::from_raw(String::from("   \n")).is_err());
        assert!(SecretKey::from_raw(String::from("a b")).is_err());
    }
}
