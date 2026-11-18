//! Refuses messages that look like they carry credentials.
//!
//! This is a safety net, not a guarantee: it catches the common shapes of
//! keys and tokens so an agent cannot casually paste one to another computer.
//! The error names the rule, never the matched text.

use std::sync::OnceLock;

use regex::RegexSet;
use serde_json::Value;

use crate::names::is_forbidden_unicode;

const RULES: &[(&str, &str)] = &[
    (
        "private key block",
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----",
    ),
    ("AIM key", r"aim1_[A-Za-z0-9_-]{20,}"),
    (
        "OpenAI/Anthropic-style API key",
        r"sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}",
    ),
    ("Stripe restricted key", r"rk_live_[A-Za-z0-9]{16,}"),
    (
        "GitHub token",
        r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
    ),
    ("GitLab token", r"glpat-[A-Za-z0-9_-]{20,}"),
    ("npm token", r"npm_[A-Za-z0-9]{20,}"),
    ("PyPI token", r"pypi-[A-Za-z0-9_-]{20,}"),
    ("HuggingFace token", r"hf_[A-Za-z0-9]{20,}"),
    ("Slack token", r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}"),
    (
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    (
        "bearer or basic credential",
        r"(?i)\b(?:authorization:\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}",
    ),
    (
        "credentialed URL",
        r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]{6,}@[^\s/]+",
    ),
    (
        "assigned secret",
        r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|signing[_-]?key)["']?\s*[:=]\s*["']?[^\s"'<>]{8,}"#,
    ),
];

fn rules() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        RegexSet::new(RULES.iter().map(|(_, pattern)| *pattern)).expect("valid guard rules")
    })
}

fn strip_invisible(text: &str) -> String {
    text.chars()
        .filter(|&c| !matches!(c, '\u{200B}'..='\u{200F}' | '\u{FEFF}'))
        .collect()
}

/// Returns the name of the first rule `text` trips, if any.
pub fn find_secret(text: &str) -> Option<&'static str> {
    if let Some(m) = rules().matches(text).iter().next() {
        return Some(RULES[m].0);
    }
    if text
        .chars()
        .any(|c| matches!(c, '\u{200B}'..='\u{200F}' | '\u{FEFF}'))
    {
        let stripped = strip_invisible(text);
        return rules().matches(&stripped).iter().next().map(|i| RULES[i].0);
    }
    None
}

/// Scans arbitrary bytes (including non-UTF-8 binary blobs) for credential patterns.
pub fn find_secret_bytes(raw: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(raw);
    find_secret(&text)
}

/// Checks every field of a message. `Err` names the field and the rule.
pub fn check_fields<'a>(
    fields: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), String> {
    for (field, text) in fields {
        if let Some(rule) = find_secret(text) {
            return Err(format!(
                "{field} looks like it contains a credential ({rule}); AIM never carries secrets. Remove it and send again."
            ));
        }
    }
    Ok(())
}

/// Recursively verifies every string key and string value inside a JSON payload
/// contains no forbidden control/Unicode characters and no credential patterns.
pub fn check_json_value(field: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(s) => {
            if s.chars().any(|c| {
                (c.is_control() && !matches!(c, '\n' | '\t' | '\r')) || is_forbidden_unicode(c)
            }) {
                return Err(format!(
                    "{field} contains forbidden control or Unicode characters"
                ));
            }
            if let Some(rule) = find_secret(s) {
                return Err(format!(
                    "{field} looks like it contains a credential ({rule}); AIM never carries secrets."
                ));
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                check_json_value(field, item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (k, v) in map {
                if k.chars().any(|c| c.is_control() || is_forbidden_unicode(c)) {
                    return Err(format!(
                        "{field} key contains forbidden control or Unicode characters"
                    ));
                }
                if let Some(rule) = find_secret(k) {
                    return Err(format!(
                        "{field} looks like it contains a credential ({rule}); AIM never carries secrets."
                    ));
                }
                check_json_value(field, v)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_common_credentials() {
        let samples = [
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "key is aim1_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
            "glpat-abcdefghijklmnopqrstuvwxyz",
            "npm_abcdefghijklmnopqrstuvwxyz012345",
            "hf_abcdefghijklmnopqrstuvwxyz012345",
            "xoxb-1234567890-abcdefghij",
            "AKIAIOSFODNN7EXAMPLE",
            "AIzaSyA-abcdefghijklmnopqrstuvwxyz012345",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "Authorization: Basic dXNlcjpwYXNzd29yZA==",
            "postgres://alice:supersecretpass@db.example.internal/app",
            "password=correct-horse-battery",
            "API_KEY: \"0123456789abcdef\"",
            r#"{"password":"supersecretpassword123"}"#,
            "ghp_\u{200B}abcdefghijklmnopqrstuvwxyz0123456789",
        ];
        for sample in samples {
            assert!(find_secret(sample).is_some(), "missed: {sample}");
        }
        let binary_with_secret = b"\xff\xfe\x00ghp_abcdefghijklmnopqrstuvwxyz0123456789\xff";
        assert!(find_secret_bytes(binary_with_secret).is_some());
    }

    #[test]
    fn leaves_ordinary_engineering_text_alone() {
        let samples = [
            "Clippy and 14 tests pass on 1234abcd; need macOS QA of the dialog.",
            "Use the Authorization header with a bearer key from the key file.",
            "token=short",
            "set password via the key file, never in the message",
            "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "commit 0000000000000000000000000000000000000000 deployed to host-a",
            "skip-checks were not used",
        ];
        for sample in samples {
            assert_eq!(find_secret(sample), None, "false positive: {sample}");
        }
    }

    #[test]
    fn errors_name_the_field_not_the_secret() {
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let err = check_fields([("body", "fine"), ("payload", secret)]).unwrap_err();
        assert!(err.starts_with("payload"));
        assert!(err.contains("GitHub token"));
        assert!(!err.contains(secret));
    }
}
