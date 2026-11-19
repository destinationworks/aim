use std::path::Path;
use std::process::Command;

fn run_git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn sanitize_single_line(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .collect::<String>()
        .trim()
        .to_string()
}

fn emit_git_rerun_hints() {
    for git_item in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = run_git(&["rev-parse", "--git-path", git_item]) {
            if Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
    if let Some(sym_ref) = run_git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = run_git(&["rev-parse", "--git-path", &sym_ref]) {
            if Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
}

fn resolve_git_sha() -> String {
    if let Ok(raw) = std::env::var("AIM_BUILD_GIT_SHA") {
        let cleaned = sanitize_single_line(&raw);
        if !cleaned.is_empty() {
            return cleaned;
        }
    }
    if let Some(sha) = run_git(&["rev-parse", "--short=12", "HEAD"]) {
        let cleaned = sanitize_single_line(&sha);
        if !cleaned.is_empty() {
            return cleaned;
        }
    }
    "unknown".to_string()
}

fn resolve_git_dirty(git_sha: &str) -> &'static str {
    if let Ok(raw) = std::env::var("AIM_BUILD_GIT_DIRTY") {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" => return "true",
            "0" | "false" => return "false",
            _ => {}
        }
    }
    if git_sha == "unknown" {
        return "false";
    }
    let Ok(out) = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
    else {
        return "false";
    };
    if !out.status.success() {
        return "false";
    }
    if String::from_utf8_lossy(&out.stdout).trim().is_empty() {
        "false"
    } else {
        "true"
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=AIM_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=AIM_BUILD_GIT_DIRTY");
    emit_git_rerun_hints();

    let git_sha = resolve_git_sha();
    let git_dirty = resolve_git_dirty(&git_sha);
    let target =
        sanitize_single_line(&std::env::var("TARGET").unwrap_or_else(|_| "unknown".into()));
    let target = if target.is_empty() {
        "unknown".to_string()
    } else {
        target
    };
    let pkg_version = sanitize_single_line(
        &std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into()),
    );
    let pkg_version = if pkg_version.is_empty() {
        "0.0.0".to_string()
    } else {
        pkg_version
    };

    let build_version = if git_sha == "unknown" {
        pkg_version
    } else if git_dirty == "true" {
        format!("{pkg_version} ({git_sha}-dirty)")
    } else {
        format!("{pkg_version} ({git_sha})")
    };

    println!("cargo:rustc-env=AIM_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=AIM_GIT_DIRTY={git_dirty}");
    println!("cargo:rustc-env=AIM_BUILD_TARGET={target}");
    println!("cargo:rustc-env=AIM_BUILD_VERSION={build_version}");
}
