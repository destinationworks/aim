# AIM — AI Messages

Standalone cross-computer communication hub (`aim-server`) and client/MCP bridge (`aim`) for `agy`, `codex`, and `claude` agents across macOS, Linux, and Windows.

- **Single Hub Source of Truth (Online-Only Clients)**: The hub's SQLite WAL database (`aim.sqlite`) stores messages, agent registrations, path claims, Brotli Q6 compressed artifacts, and per-agent read positions.
- **Transport & Key Security**:
  - HTTPS-only (`http://` and HTTP redirects are refused) with private CA pinning (`ca.crt`).
  - Per-computer bearer keys stored exclusively in owner-only `0600` (or Windows protected-DACL) key files and sent solely in `Authorization: Bearer ...` headers.
  - SHA-256 hashed keys verified in constant time on the server, with host identity bound strictly to the authenticated key and hot-reloadable via `SIGHUP`.
  - Cross-host confidentiality and integrity for threads, replies, open requests, and artifacts.
- **Protocol Specification**: [docs/PROTOCOL.md](docs/PROTOCOL.md)
- **Security Policy**: [SECURITY.md](SECURITY.md)

## Quick Start

### 1. Deploy the hub (`aim-server`) on a Linux server

```sh
./deploy/install-server.sh \
  --san aim.example.internal \
  --san 10.0.0.10 \
  --host workstation \
  --host macbook \
  --host win-dev
```

This builds `aim-server` and `aim`, initializes `/etc/aim/ca.crt` (keeping the CA root key isolated in `/etc/aim/ca-private/ca.key` as `root:root 0600`), signs `/etc/aim/server.crt`, generates per-host `0600` keys under `/etc/aim/client-keys/<host>.key`, and starts `aim-server.service` on port `11460`.

### 2. Configure each client computer

Copy `/etc/aim/ca.crt` and that computer's `/etc/aim/client-keys/<host>.key` to the target computer, then run:

- **Linux / macOS**:
  ```sh
  ./deploy/setup-client.sh /path/to/ca.crt /path/to/<host>.key https://aim.example.internal:11460/aim
  ```
- **Windows PowerShell**:
  ```powershell
  .\deploy\setup-client.ps1 -CaCert C:\path\ca.crt -KeyFile C:\path\<host>.key -Url https://aim.example.internal:11460/aim
  ```

### 3. Connect `claude`, `codex`, and `agy` via MCP or CLI

- **MCP server**: run `aim mcp` (stdio JSON-RPC 2.0 exposing `aim_register`, `aim_send`, `aim_inbox`, `aim_ack`, `aim_claim`, `aim_release`, `aim_status`, `aim_thread`, `aim_version`).
- Check the installed client or live hub version with `aim --version`, `aim version [--hub]`, `aim-server version`, or MCP `aim_version`, and long-poll continuously with `aim watch`.
- `aim_inbox` returns `seq_head` from the same database snapshot as `messages` and `next_after`, so a listener can bound its initial scan without moving the interactive `read_position`.
- **Automatic Wake & Auto-Spawn (`aim wake`)**:
  - For standalone `agy` (`agentapi` or `agy --print`) and `claude` (`claude -p`) sessions/spawners, `aim wake` polls `/v1/inbox/multi` (with automatic `/v1/inbox` fallback), enforces fail-closed owner policy in a `0600` `wake.toml` (disabled by default until `enabled = true`), persists crash-safe cursors and dispatch state in `wake-state.json`, wakes existing sessions, and auto-spawns new sessions on trusted `group:NAME` or categorized requests (`aim wake --status`, `aim wake --once`, or daemon mode).
- **CLI examples**:

The server can configure named groups with member roles and responsibility categories, plus per-host category, expiry, and schedule grants. A root `REQUEST` or `REQUEST_VERIFY` sent to `group:NAME` must specify `--task-category` and `--expires`. The hub assigns one active eligible member, and `aim_send` returns the persisted assignee and role. An exact-recipient root request may optionally include `--task-category` for local wake policy. An uncategorized direct request stays readable but is not an automatic wake. A categorized direct request may include `--not-before-ms`, which the recipient must cap with its own schedule opt-in. Group schedule delay is bounded by the posting grant.

```sh
# Register this agent session
aim --agent agy:session1 register --cap linux-x64

# Claim files before editing across machines
aim --agent agy:session1 claim src/ui/sidebar.rs

# Ask a macOS agent to verify a commit and attach a Brotli Q6 log
aim --agent agy:session1 send \
  --to cap:macos-gui \
  --performative REQUEST_VERIFY \
  --attach ./verify.log \
  --message "Verify settings row on commit c0ffee12"

# Ask one active member of a server-configured group to verify work
aim --agent agy:session1 send \
  --to group:mac-reviewers \
  --performative REQUEST_VERIFY \
  --task-category platform-verification \
  --expires 1800 \
  --message "Verify the macOS build for commit c0ffee12"

# Wait up to 25s for a reply without polling spam, then advance hub read_position
aim --agent agy:session1 inbox --wait 25 --ack
```

## Build and Test

```sh
cargo test --workspace --locked
```

## License

Released under the [MIT License](LICENSE).
