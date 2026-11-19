use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aim_proto::guard::find_secret_bytes;
use aim_proto::names::check_name;
use aim_proto::wire::{
    check_artifact_name, check_sha256, AckRequest, ClaimRequest, InboxResponse, RegisterRequest,
    ReleaseRequest, SendRequest,
};
use aim_proto::{Performative, MAX_ARTIFACT_RAW_BYTES, MAX_INBOX_LIMIT, MAX_WAIT_SECS};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::client::AimClient;
use crate::config::{
    default_config_path, default_os_caps, detect_git_context, normalize_base_url,
    registration_git_context, ConfigFile, Overrides, ResolvedConfig,
};
use crate::mcp;

#[derive(Parser)]
#[command(
    name = "aim",
    version = aim_proto::BUILD_VERSION,
    about = "AIM (AI Messages) cross-computer agent messaging client"
)]
pub struct Cli {
    /// Path to config.toml (defaults to OS config dir or AIM_CONFIG)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Override AIM hub URL (https://...)
    #[arg(long, global = true)]
    pub url: Option<String>,

    /// Override private CA certificate PEM path
    #[arg(long, global = true)]
    pub ca_cert: Option<PathBuf>,

    /// Override 0600 / private key file path (never pass keys on the CLI)
    #[arg(long, global = true)]
    pub key_file: Option<PathBuf>,

    /// Agent identity as HARNESS:SESSION (e.g. agy:session1, codex:session2, claude:session3)
    #[arg(long, global = true)]
    pub agent: Option<String>,

    /// Pretty-print JSON output
    #[arg(long, global = true)]
    pub pretty: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Write AIM client config.toml and verify key_file permissions
    Init(InitArgs),
    /// Check HTTPS reachability and CA trust of the AIM hub
    Health,
    /// Print client build version and optionally query the AIM hub version
    Version(VersionArgs),
    /// Register or refresh this agent on the AIM hub
    Register(RegisterArgs),
    /// Send a typed message across computers
    Send(SendArgs),
    /// Read messages addressed to this agent (supports long-poll --wait)
    Inbox(InboxArgs),
    /// Block on a pooled connection until unread messages arrive or timeout elapses
    Watch(WatchArgs),
    /// Advance the hub-stored read position for this agent
    Ack(AckArgs),
    /// Claim repo file or directory patterns to warn remote peers of overlaps
    Claim(ClaimArgs),
    /// Release one or all path claims held by this agent
    Release(ReleaseArgs),
    /// Show agents, active path claims, and open requests across all computers
    Status(StatusArgs),
    /// Inspect every message in a thread
    Thread {
        thread: String,
        #[arg(long)]
        after: Option<u64>,
    },
    /// Upload or download Brotli Q6 compressed artifacts
    Artifact {
        #[command(subcommand)]
        action: ArtifactCommand,
    },
    /// Run a stdio MCP server exposing AIM tools to agy, codex, and claude
    Mcp,
}

#[derive(Args)]
pub struct VersionArgs {
    /// Also query the configured AIM hub's version/health
    #[arg(long)]
    pub hub: bool,
}

#[derive(Args)]
pub struct InitArgs {
    /// AIM hub URL (e.g. https://aim.example.internal:11460/aim)
    #[arg(long)]
    pub url: String,
    /// Path to the AIM CA certificate (ca.crt)
    #[arg(long)]
    pub ca_cert: PathBuf,
    /// Path to the owner-only (0600) key file for this computer
    #[arg(long)]
    pub key_file: PathBuf,
    /// Optional default HARNESS:SESSION
    #[arg(long)]
    pub default_agent: Option<String>,
    /// Extra capability tags (comma-separated or repeated)
    #[arg(long, value_delimiter = ',')]
    pub cap: Vec<String>,
    /// Overwrite an existing config.toml
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RegisterArgs {
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long)]
    pub worktree: Option<String>,
    #[arg(long)]
    pub branch: Option<String>,
    #[arg(long)]
    pub head: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub cap: Vec<String>,
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Args)]
pub struct SendArgs {
    /// Recipient selector(s): *, host:NAME, harness:NAME, repo:NAME, cap:NAME, group:NAME, SESSION, HOST:HARNESS:SESSION
    #[arg(long, required = true, value_delimiter = ',')]
    pub to: Vec<String>,
    /// Message type: ANNOUNCE, QUERY, REPLY, REQUEST, REQUEST_VERIFY, ACCEPT, REJECT, PROGRESS, RESULT, CANCEL, ALERT, BLOCKER, CONFLICT
    #[arg(long, default_value = "ANNOUNCE")]
    pub performative: String,
    /// Message text (omit when passing --stdin)
    #[arg(long)]
    pub message: Option<String>,
    /// Read message text from stdin
    #[arg(long)]
    pub stdin: bool,
    /// Parent message seq being answered
    #[arg(long)]
    pub reply_to: Option<u64>,
    /// Thread identifier
    #[arg(long)]
    pub thread: Option<String>,
    /// Structured JSON payload object
    #[arg(long)]
    pub payload: Option<String>,
    /// Attach file(s), compressed with Brotli Q6 and stored on the hub
    #[arg(long = "attach")]
    pub attach: Vec<PathBuf>,
    /// Idempotency key for safe retries
    #[arg(long)]
    pub idempotency_key: Option<String>,
    /// Expiry in seconds
    #[arg(long)]
    pub expires: Option<u64>,
    /// Task category required for group:NAME, optional for exact-recipient root requests
    #[arg(long)]
    pub task_category: Option<String>,
    /// Earliest wake time as a Unix timestamp in milliseconds
    #[arg(long)]
    pub not_before_ms: Option<i64>,
    /// Lease duration in seconds for ACCEPT or PROGRESS
    #[arg(long)]
    pub lease: Option<u64>,
}

#[derive(Args)]
pub struct InboxArgs {
    /// Read messages with seq > AFTER (defaults to hub-stored read_position)
    #[arg(long)]
    pub after: Option<u64>,
    /// Long-poll wait in seconds (0-30) if no matching messages exist yet
    #[arg(long)]
    pub wait: Option<u64>,
    /// Max messages to return (1-200)
    #[arg(long)]
    pub limit: Option<u32>,
    /// Filter to a single thread
    #[arg(long)]
    pub thread: Option<String>,
    /// Include broadcast messages sent by this same agent
    #[arg(long)]
    pub include_self: bool,
    /// Advance hub-stored read_position to next_after after reading
    #[arg(long)]
    pub ack: bool,
}

#[derive(Args)]
pub struct WatchArgs {
    /// Start watching after sequence number (defaults to hub-stored read_position)
    #[arg(long)]
    pub after: Option<u64>,
    /// Filter to a single thread
    #[arg(long)]
    pub thread: Option<String>,
    /// Total watch timeout in seconds (1-3600)
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,
    /// Include broadcast messages sent by this same agent
    #[arg(long)]
    pub include_self: bool,
    /// Advance hub-stored read_position to next_after when messages arrive
    #[arg(long)]
    pub ack: bool,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Return only live agents whose registration TTL has not expired
    #[arg(long)]
    pub live_only: bool,
}

#[derive(Args)]
pub struct AckArgs {
    /// Sequence number to record as read
    pub read_to: u64,
}

#[derive(Args)]
pub struct ClaimArgs {
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long)]
    pub ttl: Option<u64>,
    #[arg(long)]
    pub note: Option<String>,
    #[arg(required = true)]
    pub paths: Vec<String>,
}

#[derive(Args)]
pub struct ReleaseArgs {
    #[arg(long)]
    pub claim_id: Option<i64>,
    #[arg(long)]
    pub repo: Option<String>,
}

#[derive(Subcommand)]
pub enum ArtifactCommand {
    /// Compress a file with Brotli Q6 and upload it to the hub
    Put { file: PathBuf },
    /// Download and verify an artifact by SHA-256
    Get {
        sha256: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

pub fn run(cli: Cli) -> Result<i32, String> {
    let pretty = cli.pretty;
    if let Command::Init(args) = cli.command {
        return run_init(cli.config.as_deref(), args, pretty);
    }

    let overrides = Overrides {
        config_path: cli.config,
        url: cli.url,
        ca_cert: cli.ca_cert,
        key_file: cli.key_file,
    };

    if matches!(cli.command, Command::Health) {
        let cfg = ResolvedConfig::load(&overrides);
        let res = match cfg {
            Ok(c) => AimClient::health_unauth(&c.url, &c.ca_cert, c.timeout_secs)?,
            Err(err) => {
                let raw_url = overrides.url.clone().or_else(|| {
                    std::env::var("AIM_URL")
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                });
                let ca = overrides.ca_cert.clone().or_else(|| {
                    std::env::var("AIM_CA_CERT")
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from)
                });
                if let (Some(u_str), Some(ca_path)) = (raw_url, ca) {
                    let u = normalize_base_url(&u_str)?;
                    AimClient::health_unauth(&u, &ca_path, 15)?
                } else {
                    return Err(err);
                }
            }
        };
        print_json(&res, pretty)?;
        return Ok(0);
    }

    if let Command::Version(args) = cli.command {
        let mut out = serde_json::Map::new();
        out.insert(
            "client".into(),
            serde_json::to_value(aim_proto::local_build_info(true)).map_err(|e| e.to_string())?,
        );
        if args.hub {
            let cfg = ResolvedConfig::load(&overrides)?;
            let client = AimClient::from_config(&cfg)?;
            let (hub, hub_error) = client.probe_hub_version();
            out.insert("hub".into(), hub.unwrap_or(Value::Null));
            if let Some(err) = hub_error {
                out.insert("hub_error".into(), Value::String(err));
            }
        }
        print_json(&Value::Object(out), pretty)?;
        return Ok(0);
    }

    let cfg = ResolvedConfig::load(&overrides)?;
    if matches!(cli.command, Command::Mcp) {
        return mcp::run(&cfg);
    }

    let client = AimClient::from_config(&cfg)?;
    let agent_arg = cli.agent.as_deref();

    match cli.command {
        Command::Init(_) | Command::Health | Command::Version(_) | Command::Mcp => unreachable!(),
        Command::Register(args) => {
            let agent = cfg.resolve_agent(agent_arg)?;
            let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
            let git = registration_git_context(&cwd, args.repo.as_deref());
            let mut caps = if cfg.caps.is_empty() {
                default_os_caps()
            } else {
                cfg.caps.clone()
            };
            for c in args.cap {
                if !caps.contains(&c) {
                    caps.push(c);
                }
            }
            let req = RegisterRequest {
                agent,
                repo: args.repo.or(git.repo),
                worktree: args.worktree.or(git.worktree),
                branch: args.branch.or(git.branch),
                head: args.head.or(git.head),
                caps,
                note: args.note,
            };
            let res = client.register(&req)?;
            print_json(&res, pretty)?;
        }
        Command::Send(args) => {
            let agent = cfg.resolve_agent(agent_arg)?;
            let performative = Performative::parse(&args.performative)
                .ok_or_else(|| format!("unknown performative '{}'", args.performative))?;
            let body = read_message_body(args.message, args.stdin)?;
            let payload = match args.payload {
                Some(raw) => {
                    let val: Value = serde_json::from_str(&raw)
                        .map_err(|e| format!("invalid --payload JSON: {e}"))?;
                    if !val.is_object() {
                        return Err("--payload must be a JSON object".into());
                    }
                    Some(val)
                }
                None => None,
            };

            // Pre-validate the message request and any attached files BEFORE uploading artifacts.
            let mut req = SendRequest {
                agent: agent.clone(),
                to: args.to,
                performative,
                thread: args.thread,
                reply_to: args.reply_to,
                body,
                payload,
                idempotency_key: args.idempotency_key,
                expires_in_secs: args.expires,
                lease_secs: args.lease,
                task_category: args.task_category,
                not_before_ms: args.not_before_ms,
            };
            req.validate()?;

            if !args.attach.is_empty() {
                let mut staged = Vec::with_capacity(args.attach.len());
                for path in &args.attach {
                    staged.push(prepare_attachment(path)?);
                }
                let mut uploaded = Vec::with_capacity(staged.len());
                for (name, raw) in staged {
                    let info = client.put_artifact(&agent, &name, &raw)?;
                    uploaded.push(json!({
                        "name": info.name,
                        "sha256": info.sha256,
                        "raw_bytes": info.raw_bytes,
                        "br_bytes": info.br_bytes,
                        "encoding": "br-q6"
                    }));
                }
                let mut map = match req.payload.take() {
                    Some(Value::Object(m)) => m,
                    _ => serde_json::Map::new(),
                };
                map.insert("artifacts".into(), Value::Array(uploaded));
                req.payload = Some(Value::Object(map));
                req.validate()?;
            }

            let res = client.send(&req)?;
            print_json(&res, pretty)?;
        }
        Command::Inbox(args) => {
            if args.ack && args.thread.is_some() {
                return Err(
                    "--ack cannot be combined with --thread (would skip unread messages)".into(),
                );
            }
            let agent = cfg.resolve_agent(agent_arg)?;
            let mut res = client.inbox(
                &agent,
                args.after,
                args.wait,
                args.limit,
                args.thread.as_deref(),
                args.include_self,
            )?;
            if args.ack {
                if args.after.is_some_and(|cursor| cursor > res.read_position) {
                    return Err(
                        "--ack with --after > read_position would skip unread messages; omit --after or run `aim ack` explicitly"
                            .into(),
                    );
                }
                if res.next_after > res.read_position {
                    let acked = client.ack(&AckRequest {
                        agent,
                        read_to: res.next_after,
                    })?;
                    res.read_position = acked.read_position;
                }
            }
            print_json(&res, pretty)?;
        }
        Command::Watch(args) => {
            return run_watch(&cfg, &client, agent_arg, args, pretty);
        }
        Command::Ack(args) => {
            let agent = cfg.resolve_agent(agent_arg)?;
            let res = client.ack(&AckRequest {
                agent,
                read_to: args.read_to,
            })?;
            print_json(&res, pretty)?;
        }
        Command::Claim(args) => {
            let agent = cfg.resolve_agent(agent_arg)?;
            let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
            let git = detect_git_context(&cwd);
            let repo = args
                .repo
                .or(git.repo)
                .ok_or("pass --repo NAME when running outside a git repository")?;
            let res = client.claim(&ClaimRequest {
                agent,
                repo,
                paths: args.paths,
                ttl_secs: args.ttl,
                note: args.note,
            })?;
            print_json(&res, pretty)?;
        }
        Command::Release(args) => {
            let agent = cfg.resolve_agent(agent_arg)?;
            let res = client.release(&ReleaseRequest {
                agent,
                claim_id: args.claim_id,
                repo: args.repo,
            })?;
            print_json(&res, pretty)?;
        }
        Command::Status(args) => {
            let res = client.status_filtered(args.live_only)?;
            print_json(&res, pretty)?;
        }
        Command::Thread { thread, after } => {
            check_name("thread", &thread)?;
            let res = client.thread_after(&thread, after)?;
            print_json(&res, pretty)?;
        }
        Command::Artifact { action } => match action {
            ArtifactCommand::Put { file } => {
                let agent = cfg.resolve_agent(agent_arg)?;
                let (name, raw) = prepare_attachment(&file)?;
                let info = client.put_artifact(&agent, &name, &raw)?;
                print_json(&info, pretty)?;
            }
            ArtifactCommand::Get { sha256, out, force } => {
                check_sha256(&sha256)?;
                let raw = client.get_artifact(&sha256)?;
                aim_fs::write_public_atomic(&out, &raw, force)?;
                print_json(
                    &json!({
                        "sha256": sha256,
                        "bytes": raw.len(),
                        "path": out.display().to_string(),
                    }),
                    pretty,
                )?;
            }
        },
    }
    Ok(0)
}

fn run_init(config_override: Option<&Path>, args: InitArgs, pretty: bool) -> Result<i32, String> {
    let cfg_path = match config_override {
        Some(p) => p.to_path_buf(),
        None => default_config_path()?,
    };
    let url = normalize_base_url(&args.url)?;

    let ca_cert = std::path::absolute(&args.ca_cert).map_err(|e| {
        format!(
            "cannot resolve ca_cert path {}: {e}",
            args.ca_cert.display()
        )
    })?;
    let key_file = std::path::absolute(&args.key_file).map_err(|e| {
        format!(
            "cannot resolve key_file path {}: {e}",
            args.key_file.display()
        )
    })?;

    let ca_bytes = aim_fs::read_trusted_config_bytes(&ca_cert, 1024 * 1024)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut &ca_bytes[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid CA certificate {}: {e}", ca_cert.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "CA cert {} contains no PEM certificates",
            ca_cert.display()
        ));
    }

    // Validate key_file safety (owner-only 0600 / private DACL) before writing config.
    let key_raw = Zeroizing::new(aim_fs::read_private_string(&key_file, 4096)?);
    crate::config::SecretKey::from_raw(key_raw)?;

    if let Some(ref agent) = args.default_agent {
        aim_proto::AgentId::validate_identity(agent)?;
    }
    for c in &args.cap {
        check_name("capability", c)?;
    }

    let caps = if args.cap.is_empty() {
        default_os_caps()
    } else {
        args.cap
    };
    let file = ConfigFile {
        url: Some(url.to_string()),
        ca_cert: Some(ca_cert.clone()),
        key_file: Some(key_file.clone()),
        default_agent: args.default_agent,
        caps,
        timeout_secs: Some(15),
    };
    let toml_text = toml::to_string_pretty(&file).map_err(|e| e.to_string())?;
    aim_fs::write_private_atomic(&cfg_path, toml_text.as_bytes(), args.force)?;
    print_json(
        &json!({
            "config": cfg_path.display().to_string(),
            "url": url.to_string(),
            "ca_cert": ca_cert.display().to_string(),
            "key_file": key_file.display().to_string(),
        }),
        pretty,
    )?;
    Ok(0)
}

fn read_message_body(message: Option<String>, from_stdin: bool) -> Result<String, String> {
    match (message, from_stdin) {
        (Some(_), true) => Err("pass either --message or --stdin, not both".into()),
        (Some(m), false) => Ok(m),
        (None, true) => {
            let mut buf = String::new();
            let mut limited = std::io::stdin().take((aim_proto::MAX_BODY as u64) + 1);
            limited
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed reading stdin: {e}"))?;
            if buf.len() > aim_proto::MAX_BODY {
                return Err(format!(
                    "stdin message exceeds {} bytes",
                    aim_proto::MAX_BODY
                ));
            }
            Ok(buf)
        }
        (None, false) => Err("pass --message \"...\" or --stdin".into()),
    }
}

fn prepare_attachment(path: &Path) -> Result<(String, Vec<u8>), String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("cannot determine filename for {}", path.display()))?
        .to_string();
    check_artifact_name(&name)?;
    let raw = aim_fs::read_public_bytes(path, MAX_ARTIFACT_RAW_BYTES)?;
    if let Some(rule) = find_secret_bytes(&raw) {
        return Err(format!(
            "attachment {} looks like it contains a credential ({rule}); AIM never carries secrets",
            path.display()
        ));
    }
    Ok((name, raw))
}

fn print_json<T: serde::Serialize>(val: &T, pretty: bool) -> Result<(), String> {
    let out = if pretty {
        serde_json::to_string_pretty(val)
    } else {
        serde_json::to_string(val)
    }
    .map_err(|e| e.to_string())?;
    println!("{out}");
    Ok(())
}

fn run_watch(
    cfg: &ResolvedConfig,
    client: &AimClient,
    agent_arg: Option<&str>,
    args: WatchArgs,
    pretty: bool,
) -> Result<i32, String> {
    if args.ack && args.thread.is_some() {
        return Err("--ack cannot be combined with --thread (would skip unread messages)".into());
    }
    if let Some(ref t) = args.thread {
        check_name("thread", t)?;
    }
    let agent = cfg.resolve_agent(agent_arg)?;
    let total_timeout = Duration::from_secs(args.timeout.clamp(1, 3600));
    let deadline = Instant::now() + total_timeout;
    let mut scan_after = args.after;
    let mut error_backoff = Duration::from_secs(1);
    let mut last_empty: Option<InboxResponse> = None;
    let mut last_err: Option<String> = None;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = remaining.as_secs().min(MAX_WAIT_SECS);
        match client.inbox(
            &agent,
            scan_after,
            Some(wait),
            Some(MAX_INBOX_LIMIT),
            args.thread.as_deref(),
            args.include_self,
        ) {
            Ok(mut res) => {
                error_backoff = Duration::from_secs(1);
                if args.ack && args.after.is_some_and(|cursor| cursor > res.read_position) {
                    return Err(
                        "--ack with --after > read_position would skip unread messages; omit --after or run `aim ack` explicitly"
                            .into(),
                    );
                }
                if !res.messages.is_empty() {
                    if args.ack && res.next_after > res.read_position {
                        let acked = client.ack(&AckRequest {
                            agent,
                            read_to: res.next_after,
                        })?;
                        res.read_position = acked.read_position;
                    }
                    print_json(&res, pretty)?;
                    return Ok(0);
                }
                if args.thread.is_none() && res.next_after > 0 {
                    scan_after =
                        Some(scan_after.map_or(res.next_after, |prev| prev.max(res.next_after)));
                }
                last_empty = Some(res);
                if Instant::now() >= deadline {
                    break;
                }
            }
            Err(err) => {
                last_err = Some(err);
                let sleep_for =
                    error_backoff.min(deadline.saturating_duration_since(Instant::now()));
                if sleep_for.is_zero() {
                    break;
                }
                std::thread::sleep(sleep_for);
                error_backoff = (error_backoff * 2).min(Duration::from_secs(8));
            }
        }
    }

    if let Some(empty) = last_empty {
        print_json(&empty, pretty)?;
        Ok(0)
    } else {
        Err(last_err.unwrap_or_else(|| "AIM watch timed out".into()))
    }
}
