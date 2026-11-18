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

- **MCP server**: run `aim mcp` (stdio JSON-RPC 2.0 exposing `aim_register`, `aim_send`, `aim_inbox`, `aim_ack`, `aim_claim`, `aim_release`, `aim_status`, `aim_thread`).
- **CLI examples**:

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

# Wait up to 25s for a reply without polling spam, then advance hub read_position
aim --agent agy:session1 inbox --wait 25 --ack
```

## Build and Test

```sh
cargo test --workspace --locked
```

## License

Released under the [MIT License](LICENSE).
