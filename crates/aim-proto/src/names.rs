//! Name rules for hosts, harnesses, sessions, repositories and capabilities.

/// A host, harness, session, repository or capability name: 1–64 ASCII
/// letters, digits, `.`, `_` or `-`, not starting with `.` or `-`.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && !matches!(bytes[0], b'.' | b'-')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates a name and names the field in the error.
pub fn check_name(field: &str, name: &str) -> Result<(), String> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(format!(
            "{field} must be 1-64 characters of letters, digits, '.', '_' or '-' (not starting with '.' or '-')"
        ))
    }
}

/// Rejects Unicode BiDi overrides, invisible zero-width chars, and Unicode Tag
/// characters commonly abused for display spoofing or invisible prompt injection.
pub fn is_forbidden_unicode(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Strips control, ANSI escape sequences, and forbidden Unicode characters and
/// truncates to `max_chars` Unicode scalar values for safe terminal/error display.
pub fn sanitize_display(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    let mut count = 0usize;
    while let Some(c) = chars.next() {
        if count >= max_chars {
            break;
        }
        // Drop ANSI CSI/OSC escape sequences cleanly.
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for esc in chars.by_ref() {
                    if ('@'..='~').contains(&esc) {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() || is_forbidden_unicode(c) {
            continue;
        }
        out.push(c);
        count += 1;
    }
    out
}

/// A free-text field (note, branch, worktree, path): bounded, no control
/// characters except tab, and no forbidden invisible/BiDi Unicode.
pub fn check_text(field: &str, text: &str, max: usize) -> Result<(), String> {
    if text.len() > max {
        return Err(format!("{field} is longer than {max} bytes"));
    }
    if text
        .chars()
        .any(|c| (c.is_control() && c != '\t') || is_forbidden_unicode(c))
    {
        return Err(format!(
            "{field} contains forbidden control or Unicode characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_names() {
        for name in [
            "host-a",
            "host-b",
            "WORKSTATION-01",
            "agy",
            "codex",
            "example-repo",
            "a.b_c",
            "0",
        ] {
            assert!(valid_name(name), "{name}");
        }
        assert!(valid_name(&"x".repeat(64)));
    }

    #[test]
    fn refuses_bad_names() {
        for name in ["", ".hidden", "-flag", "a b", "a:b", "a/b", "ü", "a\n"] {
            assert!(!valid_name(name), "{name:?}");
        }
        assert!(!valid_name(&"x".repeat(65)));
    }

    #[test]
    fn text_rules() {
        assert!(check_text("note", "fine\twith tab", 20).is_ok());
        assert!(check_text("note", "line\nbreak", 20).is_err());
        assert!(check_text("note", "too long", 3).is_err());
        assert!(check_text("note", "bidi\u{202E}hide", 30).is_err());
        assert!(check_text("note", "tag\u{E0041}", 30).is_err());
        assert_eq!(sanitize_display("\x1b[31merr\x1b[0m\u{202E}!", 20), "err!");
    }
}
