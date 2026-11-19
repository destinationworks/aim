use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use aim_proto::names::check_name;
use aim_proto::wire::{AckRequest, ClaimRequest, RegisterRequest, ReleaseRequest, SendRequest};
use aim_proto::{Performative, UNTRUSTED_NOTICE};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::client::AimClient;
use crate::config::{
    default_os_caps, detect_git_context, registration_git_context, ResolvedConfig,
};

const MAX_MCP_LINE_BYTES: usize = 256 * 1024;
const MAX_CONCURRENT_TOOL_CALLS: usize = 16;
const SUPPORTED_PROTOCOLS: &[&str] = &["2024-11-05", "2025-03-26"];

struct McpRuntimeInfo {
    pid: u32,
    started_at_ms: Option<u64>,
    exe_path: Option<PathBuf>,
    binary_sha256: Option<String>,
    tool_names: Vec<String>,
}

fn hash_file_sha256(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    Some(out)
}

fn fallback_exe_sha256(exe_path: Option<&Path>) -> Option<String> {
    if let Some(hash) = exe_path.and_then(hash_file_sha256) {
        return Some(hash);
    }
    #[cfg(target_os = "linux")]
    {
        hash_file_sha256(Path::new("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn detect_binary_replaced(
    startup_path: &Path,
    startup_sha256: &str,
    current_exe: Option<&Path>,
) -> bool {
    if current_exe.is_some_and(|cur| cur != startup_path) {
        return true;
    }
    match hash_file_sha256(startup_path) {
        Some(h) => h != startup_sha256,
        None => true,
    }
}

impl McpRuntimeInfo {
    fn capture(tools: &[Value]) -> Self {
        let pid = std::process::id();
        let started_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok());
        let exe_path = std::env::current_exe().ok();
        let binary_sha256 = fallback_exe_sha256(exe_path.as_deref());
        let tool_names = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();
        Self {
            pid,
            started_at_ms,
            exe_path,
            binary_sha256,
            tool_names,
        }
    }

    fn binary_replaced_on_disk(&self) -> Option<bool> {
        let path = self.exe_path.as_deref()?;
        let hash = self.binary_sha256.as_deref()?;
        let current = std::env::current_exe().ok();
        Some(detect_binary_replaced(path, hash, current.as_deref()))
    }
}

enum ReadLine {
    Line(String),
    TooLong,
    Eof,
}

fn read_bounded_line(reader: &mut impl BufRead) -> io::Result<ReadLine> {
    let mut buf = Vec::new();
    let mut over_limit = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() && !over_limit {
                return Ok(ReadLine::Eof);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if !over_limit {
                if buf.len().saturating_add(pos) <= MAX_MCP_LINE_BYTES {
                    buf.extend_from_slice(&available[..pos]);
                } else {
                    over_limit = true;
                }
            }
            reader.consume(pos + 1);
            break;
        } else {
            let len = available.len();
            if !over_limit {
                if buf.len().saturating_add(len) <= MAX_MCP_LINE_BYTES {
                    buf.extend_from_slice(available);
                } else {
                    over_limit = true;
                    buf.clear();
                }
            }
            reader.consume(len);
        }
    }
    if over_limit {
        return Ok(ReadLine::TooLong);
    }
    let text = String::from_utf8(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(ReadLine::Line(text))
}

pub fn run(cfg: &ResolvedConfig) -> Result<i32, String> {
    let client = AimClient::from_config(cfg)?;
    let tools = Arc::new(tool_definitions());
    let runtime = Arc::new(McpRuntimeInfo::capture(&tools));
    let cfg = Arc::new(cfg.clone());
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let active_workers = Arc::new(AtomicUsize::new(0));
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();

    let stdin = io::stdin();
    let mut reader = stdin.lock();

    loop {
        let line = match read_bounded_line(&mut reader) {
            Ok(ReadLine::Eof) => break,
            Ok(ReadLine::TooLong) => {
                write_reply(
                    &stdout,
                    Value::Null,
                    Err((-32600, "JSON-RPC line exceeds 256 KiB limit".into())),
                )?;
                continue;
            }
            Ok(ReadLine::Line(l)) => l,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                write_reply(
                    &stdout,
                    Value::Null,
                    Err((-32700, "JSON-RPC line is not valid UTF-8".into())),
                )?;
                continue;
            }
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_reply(
                    &stdout,
                    Value::Null,
                    Err((-32700, format!("JSON parse error: {e}"))),
                )?;
                continue;
            }
        };
        let Some(obj) = req.as_object() else {
            write_reply(
                &stdout,
                Value::Null,
                Err((-32600, "JSON-RPC request must be an object".into())),
            )?;
            continue;
        };

        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            let err_id = obj
                .get("id")
                .filter(|v| v.is_string() || v.is_number() || v.is_null())
                .cloned()
                .unwrap_or(Value::Null);
            write_reply(
                &stdout,
                err_id,
                Err((-32600, "jsonrpc field must be \"2.0\"".into())),
            )?;
            continue;
        }

        // Notifications have no `id` and expect no reply.
        let Some(id) = obj.get("id").cloned() else {
            continue;
        };
        if !(id.is_string() || id.is_number() || id.is_null()) {
            write_reply(
                &stdout,
                Value::Null,
                Err((
                    -32600,
                    "JSON-RPC id must be a string, number, or null".into(),
                )),
            )?;
            continue;
        }

        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            write_reply(&stdout, id, Err((-32600, "missing method".into())))?;
            continue;
        };

        if method == "tools/call" {
            let Some(params) = obj.get("params").and_then(Value::as_object) else {
                write_reply(&stdout, id, Err((-32602, "missing params".into())))?;
                continue;
            };
            let Some(tool_name) = params
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                write_reply(&stdout, id, Err((-32602, "missing tool name".into())))?;
                continue;
            };
            let args = match params.get("arguments") {
                None | Some(Value::Null) => json!({}),
                Some(v) if v.is_object() => v.clone(),
                Some(_) => {
                    write_reply(
                        &stdout,
                        id,
                        Err((-32602, "tool arguments must be a JSON object".into())),
                    )?;
                    continue;
                }
            };

            // Reap finished thread handles periodically.
            handles.retain(|h| !h.is_finished());

            if active_workers.load(Ordering::Relaxed) >= MAX_CONCURRENT_TOOL_CALLS {
                let res = dispatch_tool(&cfg, &client, &runtime, &tool_name, &args);
                write_reply(&stdout, id, Ok(res))?;
            } else {
                active_workers.fetch_add(1, Ordering::Relaxed);
                let cfg_c = cfg.clone();
                let client_c = client.clone();
                let runtime_c = runtime.clone();
                let out_c = stdout.clone();
                let workers_c = active_workers.clone();
                handles.push(thread::spawn(move || {
                    let res = dispatch_tool(&cfg_c, &client_c, &runtime_c, &tool_name, &args);
                    let _ = write_reply(&out_c, id, Ok(res));
                    workers_c.fetch_sub(1, Ordering::Relaxed);
                }));
            }
            continue;
        }

        let resp = handle_sync_rpc(method, obj.get("params"), &tools);
        write_reply(&stdout, id, resp)?;
    }

    for h in handles {
        let _ = h.join();
    }
    Ok(0)
}

fn write_reply(
    out: &Arc<Mutex<io::Stdout>>,
    id: Value,
    res: Result<Value, (i64, String)>,
) -> Result<(), String> {
    let payload = match res {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    };
    let mut guard = out
        .lock()
        .map_err(|_| "stdout mutex poisoned".to_string())?;
    writeln!(guard, "{payload}").map_err(|e| format!("stdout write failed: {e}"))?;
    guard
        .flush()
        .map_err(|e| format!("stdout flush failed: {e}"))
}

fn handle_sync_rpc(
    method: &str,
    params: Option<&Value>,
    tools: &[Value],
) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => {
            let requested = params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05");
            let negotiated = if SUPPORTED_PROTOCOLS.contains(&requested) {
                requested
            } else {
                "2024-11-05"
            };
            Ok(json!({
                "protocolVersion": negotiated,
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "aim",
                    "version": aim_proto::BUILD_VERSION,
                }
            }))
        }
        "ping" | "logging/setLevel" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools })),
        "resources/list" => Ok(json!({ "resources": [] })),
        "prompts/list" => Ok(json!({ "prompts": [] })),
        _ => Err((-32601, format!("method not found: {method}"))),
    }
}

fn strip_wire_notice(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("notice");
    }
    value
}

fn dispatch_tool(
    cfg: &ResolvedConfig,
    client: &AimClient,
    runtime: &McpRuntimeInfo,
    name: &str,
    args: &Value,
) -> Value {
    match execute_tool(cfg, client, runtime, name, args) {
        Ok((notice, value)) => {
            let json_text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".into());
            let mut content = Vec::new();
            if let Some(n) = notice {
                content.push(json!({ "type": "text", "text": n }));
            }
            content.push(json!({ "type": "text", "text": json_text }));
            json!({ "content": content, "isError": false })
        }
        Err(err) => json!({
            "content": [{ "type": "text", "text": err }],
            "isError": true
        }),
    }
}

fn opt_str(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Some(_) => Err(format!("'{key}' must be a string")),
    }
}

fn opt_u64(args: &Value, key: &str) -> Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("'{key}' must be a non-negative integer")),
    }
}

fn opt_i64(args: &Value, key: &str) -> Result<Option<i64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| format!("'{key}' must be an integer")),
    }
}

fn opt_bool(args: &Value, key: &str) -> Result<Option<bool>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("'{key}' must be a boolean")),
    }
}

fn opt_object(args: &Value, key: &str) -> Result<Option<Value>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) if v.is_object() => Ok(Some(v.clone())),
        Some(_) => Err(format!("'{key}' must be a JSON object")),
    }
}

fn str_list(args: &Value, key: &str) -> Result<Vec<String>, String> {
    let Some(val) = args.get(key) else {
        return Ok(Vec::new());
    };
    if val.is_null() {
        return Ok(Vec::new());
    }
    let arr = val
        .as_array()
        .ok_or_else(|| format!("'{key}' must be an array of strings"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.trim().to_string())
                .ok_or_else(|| format!("'{key}' entries must be strings"))
        })
        .collect()
}

fn execute_tool(
    cfg: &ResolvedConfig,
    client: &AimClient,
    runtime: &McpRuntimeInfo,
    name: &str,
    args: &Value,
) -> Result<(Option<&'static str>, Value), String> {
    let resolve = |explicit: Option<String>| cfg.resolve_agent(explicit.as_deref());

    match name {
        "aim_register" => {
            let agent = resolve(opt_str(args, "agent")?)?;
            let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
            let explicit_repo = opt_str(args, "repo")?;
            let git = registration_git_context(&cwd, explicit_repo.as_deref());
            let mut caps = cfg.caps.clone();
            if caps.is_empty() {
                caps = default_os_caps();
            }
            for extra in str_list(args, "caps")? {
                if !caps.contains(&extra) {
                    caps.push(extra);
                }
            }
            let req = RegisterRequest {
                agent,
                repo: explicit_repo.or(git.repo),
                worktree: opt_str(args, "worktree")?.or(git.worktree),
                branch: opt_str(args, "branch")?.or(git.branch),
                head: opt_str(args, "head")?.or(git.head),
                caps,
                note: opt_str(args, "note")?,
            };
            let res = client.register(&req)?;
            let notice = if res.conflicts.is_empty() {
                None
            } else {
                Some(UNTRUSTED_NOTICE)
            };
            Ok((
                notice,
                serde_json::to_value(res).map_err(|e| e.to_string())?,
            ))
        }
        "aim_send" => {
            let agent = resolve(opt_str(args, "agent")?)?;
            let to = str_list(args, "to")?;
            let perf_str = opt_str(args, "performative")?.unwrap_or_else(|| "ANNOUNCE".into());
            let performative = Performative::parse(&perf_str)
                .ok_or_else(|| format!("unknown performative '{perf_str}'"))?;
            let body = match args.get("message") {
                Some(Value::String(s)) => s.clone(),
                _ => return Err("message is required and must be a string".into()),
            };
            let req = SendRequest {
                agent,
                to,
                performative,
                thread: opt_str(args, "thread")?,
                reply_to: opt_u64(args, "reply_to")?,
                body,
                payload: opt_object(args, "payload")?,
                idempotency_key: opt_str(args, "idempotency_key")?,
                expires_in_secs: opt_u64(args, "expires_in_secs")?,
                lease_secs: opt_u64(args, "lease_secs")?,
                task_category: opt_str(args, "task_category")?,
                not_before_ms: opt_i64(args, "not_before_ms")?,
            };
            let res = client.send(&req)?;
            Ok((None, serde_json::to_value(res).map_err(|e| e.to_string())?))
        }
        "aim_inbox" => {
            let agent = resolve(opt_str(args, "agent")?)?;
            let after = opt_u64(args, "after")?;
            let wait = opt_u64(args, "wait_secs")?;
            let limit = match opt_u64(args, "limit")? {
                Some(v) => Some(u32::try_from(v).map_err(|_| "'limit' is out of range")?),
                None => None,
            };
            let thread = opt_str(args, "thread")?;
            let include_self = opt_bool(args, "include_self")?.unwrap_or(false);
            let auto_ack = opt_bool(args, "ack")?.unwrap_or(false);
            if auto_ack && thread.is_some() {
                return Err(
                    "ack=true cannot be combined with thread (would skip unread messages)".into(),
                );
            }
            let mut res =
                client.inbox(&agent, after, wait, limit, thread.as_deref(), include_self)?;
            if auto_ack {
                if after.is_some_and(|cursor| cursor > res.read_position) {
                    return Err(
                        "ack=true with after > read_position would skip unread messages; omit after or call aim_ack explicitly"
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
            let notice = if res.messages.is_empty() {
                None
            } else {
                Some(UNTRUSTED_NOTICE)
            };
            Ok((
                notice,
                strip_wire_notice(serde_json::to_value(res).map_err(|e| e.to_string())?),
            ))
        }
        "aim_ack" => {
            let agent = resolve(opt_str(args, "agent")?)?;
            let read_to = opt_u64(args, "read_to")?.ok_or("read_to sequence number is required")?;
            let res = client.ack(&AckRequest { agent, read_to })?;
            Ok((None, serde_json::to_value(res).map_err(|e| e.to_string())?))
        }
        "aim_claim" => {
            let agent = resolve(opt_str(args, "agent")?)?;
            let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
            let git = detect_git_context(&cwd);
            let repo = opt_str(args, "repo")?
                .or(git.repo)
                .ok_or("repo is required outside a git checkout")?;
            let paths = str_list(args, "paths")?;
            let req = ClaimRequest {
                agent,
                repo,
                paths,
                ttl_secs: opt_u64(args, "ttl_secs")?,
                note: opt_str(args, "note")?,
            };
            let res = client.claim(&req)?;
            let notice = if res.conflicts.is_empty() {
                None
            } else {
                Some(UNTRUSTED_NOTICE)
            };
            Ok((
                notice,
                serde_json::to_value(res).map_err(|e| e.to_string())?,
            ))
        }
        "aim_release" => {
            let agent = resolve(opt_str(args, "agent")?)?;
            let req = ReleaseRequest {
                agent,
                claim_id: opt_i64(args, "claim_id")?,
                repo: opt_str(args, "repo")?,
            };
            let res = client.release(&req)?;
            Ok((None, res))
        }
        "aim_status" => {
            let include_stale = opt_bool(args, "include_stale")?.unwrap_or(false);
            let res = client.status_filtered(!include_stale)?;
            let notice =
                if res.agents.is_empty() && res.claims.is_empty() && res.open_requests.is_empty() {
                    None
                } else {
                    Some(UNTRUSTED_NOTICE)
                };
            Ok((
                notice,
                strip_wire_notice(serde_json::to_value(res).map_err(|e| e.to_string())?),
            ))
        }
        "aim_thread" => {
            let thread = opt_str(args, "thread")?.ok_or("thread is required")?;
            check_name("thread", &thread)?;
            let after = opt_u64(args, "after")?;
            let res = client.thread_after(&thread, after)?;
            let notice = if res.messages.is_empty() {
                None
            } else {
                Some(UNTRUSTED_NOTICE)
            };
            Ok((
                notice,
                strip_wire_notice(serde_json::to_value(res).map_err(|e| e.to_string())?),
            ))
        }
        "aim_version" => {
            let include_hub = opt_bool(args, "include_hub")?.unwrap_or(true);
            let mut obj = serde_json::Map::new();
            obj.insert(
                "client".into(),
                serde_json::to_value(aim_proto::local_build_info(true))
                    .map_err(|e| e.to_string())?,
            );
            obj.insert(
                "mcp".into(),
                json!({
                    "pid": runtime.pid,
                    "started_at_ms": runtime.started_at_ms,
                    "mode": "pull",
                    "capabilities": ["tools"],
                    "tools": runtime.tool_names,
                    "binary_sha256": runtime.binary_sha256,
                    "binary_replaced_on_disk": runtime.binary_replaced_on_disk(),
                }),
            );
            if include_hub {
                let (hub, hub_error) = client.probe_hub_version();
                obj.insert("hub".into(), hub.unwrap_or(Value::Null));
                if let Some(err) = hub_error {
                    obj.insert("hub_error".into(), Value::String(err));
                }
            }
            Ok((None, Value::Object(obj)))
        }
        _ => Err(format!("unknown AIM tool: {name}")),
    }
}

fn tool_definitions() -> Vec<Value> {
    let perf_enum: Vec<&str> = Performative::ALL.iter().map(|p| p.as_str()).collect();
    vec![
        json!({
            "name": "aim_register",
            "description": "Register or heartbeat this agent on the cross-computer AIM hub, advertising its repo, branch, capabilities, and checking for overlapping path claims.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": { "type": "string", "description": "HARNESS:SESSION (e.g. agy:session1, codex:session2, claude:session3). Optional when env/config provides it." },
                    "repo": { "type": "string" },
                    "worktree": { "type": "string" },
                    "branch": { "type": "string" },
                    "head": { "type": "string" },
                    "caps": { "type": "array", "items": { "type": "string" } },
                    "note": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_send",
            "description": "Send a typed message to agents on any computer via AIM. A group request requires task_category and expires_in_secs, may include not_before_ms, and is routed to one active specialist for REQUEST or reviewer for REQUEST_VERIFY whose responsibilities include the category. The hub enforces the posting host's category and time grants. An exact-recipient root REQUEST or REQUEST_VERIFY may also declare task_category and not_before_ms for the recipient's local wake policy. Group sends return the persisted assignee and category. Performatives enforce reply rules. Secrets are automatically blocked.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": { "type": "string", "description": "Sender HARNESS:SESSION. Optional when env/config provides it." },
                    "to": { "type": "array", "items": { "type": "string" }, "description": "Selectors: *, host:NAME, harness:NAME, repo:NAME, cap:NAME, group:NAME, SESSION, or HOST:HARNESS:SESSION. group:NAME requires a root REQUEST or REQUEST_VERIFY and routes to one authorized, active worker." },
                    "performative": { "type": "string", "enum": perf_enum },
                    "message": { "type": "string" },
                    "reply_to": { "type": "integer", "description": "Parent seq when answering a message (required for REPLY, ACCEPT, REJECT, PROGRESS, RESULT, CANCEL)" },
                    "thread": { "type": "string" },
                    "payload": { "type": "object" },
                    "idempotency_key": { "type": "string" },
                    "expires_in_secs": { "type": "integer" },
                    "lease_secs": { "type": "integer", "description": "Lease duration for ACCEPT or PROGRESS" },
                    "task_category": { "type": "string", "description": "Required for group requests and must match both the posting grant and an eligible member responsibility. Optional on an exact-recipient root REQUEST or REQUEST_VERIFY for local recipient policy." },
                    "not_before_ms": { "type": "integer", "description": "Optional earliest wake timestamp in Unix milliseconds. Group scheduling is bounded by the posting grant and message expiry. Direct scheduling is bounded by message expiry, with recipient-side policy required." }
                },
                "required": ["to", "message"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_inbox",
            "description": "Read AIM messages addressed to this agent across computers. Uses hub-stored read_position if after is omitted. Returns seq_head from the same SQLite snapshot as messages and next_after for bounded bootstrap and pagination. Supports wait_secs (up to 30s) for reactive long-polling.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": { "type": "string" },
                    "after": { "type": "integer" },
                    "wait_secs": { "type": "integer" },
                    "limit": { "type": "integer" },
                    "thread": { "type": "string" },
                    "include_self": { "type": "boolean" },
                    "ack": { "type": "boolean", "description": "Advance hub read_position to next_after if true (cannot be combined with thread or after > read_position)" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_ack",
            "description": "Advance this agent's hub-stored read position to read_to.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": { "type": "string" },
                    "read_to": { "type": "integer" }
                },
                "required": ["read_to"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_claim",
            "description": "Claim file or directory patterns in a repo to warn agents on other computers before overlapping edits occur.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": { "type": "string" },
                    "repo": { "type": "string" },
                    "paths": { "type": "array", "items": { "type": "string" } },
                    "ttl_secs": { "type": "integer" },
                    "note": { "type": "string" }
                },
                "required": ["paths"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_release",
            "description": "Release one or all file/path claims held by this agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": { "type": "string" },
                    "claim_id": { "type": "integer" },
                    "repo": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_status",
            "description": "Inspect live agents (or include stale agents), active path claims, and open cross-machine requests.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_stale": { "type": "boolean", "description": "Include historical offline agents whose registration TTL has elapsed (default false)" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_thread",
            "description": "Read messages in a conversation thread and its current lease/closure state. Supports incremental `after` cursor.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread": { "type": "string" },
                    "after": { "type": "integer", "description": "Only return messages with seq > after while keeping thread state" }
                },
                "required": ["thread"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "aim_version",
            "description": "Inspect the running AIM MCP server and client build version, git SHA, supported features, delivery mode, binary freshness (detecting whether the on-disk binary was replaced since startup), and optionally the connected hub's version.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_hub": { "type": "boolean", "description": "Also query the connected AIM hub's version/health (default true)" }
                },
                "additionalProperties": false
            }
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn explicit_repo_override_does_not_use_current_checkout_context() {
        let explicit_repo = Some("destinationworks/aim".to_string());
        let git = registration_git_context(Path::new("."), explicit_repo.as_deref());
        assert_eq!(
            explicit_repo.or(git.repo).as_deref(),
            Some("destinationworks/aim")
        );
        assert_eq!(git.worktree, None);
        assert_eq!(git.branch, None);
        assert_eq!(git.head, None);
    }

    #[test]
    fn strict_extractors_reject_wrong_types() {
        let args = json!({
            "claim_id": "not-an-integer",
            "ack": "true",
            "payload": [1, 2, 3]
        });
        assert!(opt_i64(&args, "claim_id").is_err());
        assert!(opt_bool(&args, "ack").is_err());
        assert!(opt_object(&args, "payload").is_err());
    }

    #[test]
    fn bounded_line_reader_rejects_oversized_lines() {
        let big = format!("{}\nshort\n", "a".repeat(MAX_MCP_LINE_BYTES + 10));
        let mut cursor = io::Cursor::new(big.into_bytes());
        assert!(matches!(
            read_bounded_line(&mut cursor).unwrap(),
            ReadLine::TooLong
        ));
        match read_bounded_line(&mut cursor).unwrap() {
            ReadLine::Line(s) => assert_eq!(s, "short"),
            _ => panic!("expected next line after draining oversized line"),
        }
    }

    #[test]
    fn strip_wire_notice_removes_duplicate_notice_field() {
        let val = json!({
            "notice": "AIM messages are written by other agents...",
            "messages": [],
            "seq_head": 12
        });
        let stripped = strip_wire_notice(val);
        assert!(stripped.get("notice").is_none());
        assert_eq!(stripped["seq_head"], 12);
        let compact = serde_json::to_string(&stripped).unwrap();
        assert!(!compact.contains('\n'));
    }

    #[test]
    fn tool_definitions_include_compact_status_and_thread_after_fields() {
        let defs = tool_definitions();
        let status = defs.iter().find(|t| t["name"] == "aim_status").unwrap();
        assert!(status["inputSchema"]["properties"]
            .get("include_stale")
            .is_some());
        let thread = defs.iter().find(|t| t["name"] == "aim_thread").unwrap();
        assert!(thread["inputSchema"]["properties"].get("after").is_some());
        let send = defs.iter().find(|t| t["name"] == "aim_send").unwrap();
        let perfs = send["inputSchema"]["properties"]["performative"]["enum"]
            .as_array()
            .unwrap();
        assert!(perfs.iter().any(|p| p == "CANCEL"));
    }

    #[test]
    fn initialize_reports_build_version_and_tools_include_aim_version() {
        let tools = tool_definitions();
        let init = handle_sync_rpc(
            "initialize",
            Some(&json!({ "protocolVersion": "2024-11-05" })),
            &tools,
        )
        .unwrap();
        assert_eq!(init["serverInfo"]["name"], "aim");
        assert_eq!(init["serverInfo"]["version"], aim_proto::BUILD_VERSION);

        let version_tool = tools
            .iter()
            .find(|t| t["name"] == "aim_version")
            .expect("aim_version tool should be defined");
        assert_eq!(
            version_tool["inputSchema"]["properties"]["include_hub"]["type"],
            "boolean"
        );
    }

    #[test]
    fn detect_binary_replaced_catches_changes_missing_and_deleted_paths() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("aim");
        std::fs::write(&bin_path, b"original-aim-binary").unwrap();
        let orig_hash = hash_file_sha256(&bin_path).unwrap();

        assert!(!detect_binary_replaced(
            &bin_path,
            &orig_hash,
            Some(&bin_path)
        ));

        let deleted_path = dir.path().join("aim (deleted)");
        assert!(detect_binary_replaced(
            &bin_path,
            &orig_hash,
            Some(&deleted_path)
        ));

        std::fs::write(&bin_path, b"rebuilt-aim-binary").unwrap();
        assert!(detect_binary_replaced(
            &bin_path,
            &orig_hash,
            Some(&bin_path)
        ));

        std::fs::remove_file(&bin_path).unwrap();
        assert!(detect_binary_replaced(
            &bin_path,
            &orig_hash,
            Some(&bin_path)
        ));
    }
}
