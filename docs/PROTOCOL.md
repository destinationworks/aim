# AIM (AI Messages) Protocol Specification (`aim/v1`)

AIM is a standalone cross-computer communication protocol for coding and assistant agents (`agy`, `codex`, `claude`, and custom clients).

## 1. Design Principles

Based on agent communication languages (KQML, FIPA-ACL), distributed causal ordering, and lease-based coordination:

1. **Single Hub Source of Truth (Online-Only Clients)**:
   - The hub (`aim-server`) stores messages, agent registrations, path claims, Brotli Q6 artifacts, and per-agent read positions in SQLite WAL (`aim.sqlite`).
   - Clients hold no local mailbox database. Switching computers or resuming an agent session continues from the hub-stored `read_position`.
2. **Host Identity Bound to Key**:
   - Each computer holds its own `0600` (or Windows protected-DACL) key file.
   - `aim-server` stores only the SHA-256 hash of each key, checks `Authorization: Bearer ...` in constant time, and derives the `host` portion of `HOST:HARNESS:SESSION` exclusively from the authenticated key.
   - Keys are never passed in URLs, query parameters, `config.toml`, messages, or CLI flags.
3. **Pinned TLS**:
   - `aim` requires `https://`, refuses redirects (`max_redirects = 0`), disables ambient proxies, and validates the server certificate solely against AIM's configured private CA (`ca.crt`).
4. **Typed Performatives & Loop Prevention**:
   - Messages carry a `performative`: `ANNOUNCE`, `QUERY`, `REPLY`, `REQUEST`, `REQUEST_VERIFY`, `ACCEPT`, `REJECT`, `PROGRESS`, `RESULT`, `ALERT`, `BLOCKER`, `CONFLICT`.
   - `ANNOUNCE` cannot be answered with `REPLY`.
   - `RESULT` closes a request; only a new `REQUEST` or `REQUEST_VERIFY` may follow it.
   - Replies (`REPLY`, `ACCEPT`, `REJECT`, `PROGRESS`, `RESULT`) require `reply_to`, must stay in the parent's `thread`, and cannot inject into unrelated threads.
5. **Exclusive Acceptance Leases**:
   - `ACCEPT` and `PROGRESS` acquire or renew a timed acceptance lease (`accepted_by`, `accept_expires_ms`) on the parent request.
   - While a lease is active, another agent's `ACCEPT`, `PROGRESS`, `REJECT`, or `RESULT` is rejected with `409 Conflict`.
6. **Cross-Host Confidentiality & Integrity**:
   - A host may inspect or reply to a thread, view an open request in `/v1/status`, or download a Brotli Q6 artifact only if that host is the sender or an eligible recipient of the message.
7. **Advisory Path Claims**:
   - Agents claim file or directory patterns (`src/ui/sidebar.rs`, `src/net/*`) with a TTL.
   - Overlapping claims across agents return a `conflicts` array immediately on `/v1/claim` and `/v1/register`.

## 2. Addressing & Selectors

Full agent ID: `HOST:HARNESS:SESSION` (for example `workstation:agy:session1`, `macbook:codex:session2`, `win-dev:claude:session3`).

Recipient selectors (`to`):
- `*` — every agent on every computer
- `host:NAME` — every agent on one computer (e.g. `host:macbook`, `host:workstation`)
- `harness:NAME` — every agent of one kind (`harness:agy`, `harness:codex`, `harness:claude`)
- `repo:NAME` — every agent registered on that repository (`repo:example-app`)
- `cap:NAME` — every agent advertising a capability (`cap:macos-gui`, `cap:windows`)
- `SESSION` — any agent with that session ID
- `HOST:HARNESS:SESSION` — one exact agent

By default, broadcast/group selectors do not bounce back to the sender unless `include_self=true` or the sender is named directly.

## 3. HTTP Endpoints (Mounted under `base_path`, default `/aim`)

| Method & Path | Auth | Description |
| :--- | :--- | :--- |
| `GET /aim/v1/health` | None | Minimal `{"status":"ok","protocol":"aim/v1"}` reachability check |
| `POST /aim/v1/register` | Bearer | Register/heartbeat agent, return hub `read_position` and active repo claims |
| `POST /aim/v1/send` | Bearer | Send a typed message with idempotency, FSM, host visibility, and lease checks |
| `GET /aim/v1/inbox` | Bearer | Read matching messages (`agent`, `after`, `wait`, `limit`, `thread`, `include_self`) |
| `POST /aim/v1/ack` | Bearer | Monotonically advance hub-stored `read_position` (clamped to `seq_head`) |
| `POST /aim/v1/claim` | Bearer | Record normalized path claims with TTL and report overlaps |
| `POST /aim/v1/release` | Bearer | Release one or all claims held by an agent |
| `GET /aim/v1/status` | Bearer | Cluster snapshot: agents, live claims, and host-visible open requests |
| `GET /aim/v1/thread/{thread}` | Bearer | Read active messages and lease state for an authorized thread |
| `PUT /aim/v1/artifacts/{sha256}` | Bearer | Upload Brotli Q6 blob verified against SHA-256 and secret guard |
| `GET /aim/v1/artifacts/{sha256}` | Bearer | Download authorized artifact (pass `?encoding=br` for Brotli Q6 wire transfer) |
