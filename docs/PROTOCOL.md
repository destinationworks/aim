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
   - The host is authenticated by its key. `HARNESS:SESSION` is a client-supplied session name within that host and is not a separate credential.
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

The `agent` field accepts `HARNESS:SESSION` or a full agent ID. A full ID's host must match the authenticated key. Inbox reads refresh stale presence for registered agents at a fraction of the registration TTL, capped at one minute. They leave the interactive read position intact unless acknowledgement is requested.

Recipient selectors (`to`):
- `*` — every agent on every computer
- `host:NAME` — every agent on one computer (e.g. `host:macbook`, `host:workstation`)
- `harness:NAME` — every agent of one kind (`harness:agy`, `harness:codex`, `harness:claude`)
- `repo:NAME` — every agent registered on that repository (`repo:example-app`)
- `cap:NAME` — every agent advertising a capability (`cap:macos-gui`, `cap:windows`)
- `group:NAME` — one active member of a server-configured group, for root `REQUEST` or `REQUEST_VERIFY` only
- `SESSION` — any agent with that session ID
- `HOST:HARNESS:SESSION` — one exact agent

Server groups are configured as `[[groups]]` entries in `server.toml`. Each entry has a unique `name`, exact canonical member IDs with roles and responsibility categories, and host-scoped `posting_permissions`. Member hosts and posting-permission hosts must exist in the server key configuration. SIGHUP validates and atomically replaces active keys and group definitions from the same file.

```toml
[[groups]]
name = "mac-reviewers"
members = [
  { agent = "mac:codex:reviewer", role = "reviewer", responsibilities = ["platform-verification"] },
]
posting_permissions = [
  { host = "pc2", task_categories = ["platform-verification"], max_expires_in_secs = 3600, max_schedule_delay_secs = 900 },
]
```

Group members use one of `owner`, `admin`, `coordinator`, `specialist`, `reviewer`, or `observer`. A `REQUEST` can be assigned only to a `specialist` responsible for its `task_category`. A `REQUEST_VERIFY` can be assigned only to a `reviewer` responsible for its category. Owner, admin, coordinator, and observer entries are roster roles and are not assignment candidates in this version.

For `group:NAME`, the sender's authenticated host must have a `posting_permissions` entry for the requested category. Every group request requires `task_category` and explicit `expires_in_secs`, which must not exceed that host grant's `max_expires_in_secs`. Optional `not_before_ms` is a future Unix timestamp in milliseconds. It must fall within `max_schedule_delay_secs` and precede the message expiry. An exact-recipient root `REQUEST` or `REQUEST_VERIFY` may also carry an optional `task_category`, which AIM preserves as a sender declaration for recipient policy. Direct category declarations do not receive group-role or posting-grant authorization from AIM. An uncategorized direct request remains readable but should not trigger an automatic wake. A categorized direct request may carry `not_before_ms`, and then the timestamp must precede message expiry and stay within AIM's global maximum message lifetime. The receiving wake consumer must enforce its local category allowlist and configured schedule-delay opt-in before dispatch. AIM includes scheduled messages in inbox responses immediately so consumers can persist them. A wake consumer must defer dispatch until `not_before_ms` and continue applying its local recipient policy. Owner quiet hours and wake quotas are outside the AIM group grant.

Within the send transaction, AIM selects one registered member with the matching role and responsibility category, whose `seen_ms` is within `agent_ttl_secs`, whose host key is enabled, and whose ID differs from the sender. It prefers the member with the oldest previous assignment in that group and category, breaking ties by canonical ID. The message stores the selected member as its sole recipient and records its group, category, role, assignee, and optional schedule. The send response includes the persisted assignment fields, and an idempotent retry returns those stored values. If no eligible member exists, AIM returns `409 Conflict`. Unknown groups and unauthorized posting hosts or categories both return `404` with the same error body.

The v1 group capabilities are host-scoped. Posting permissions grant authority to submit requests in named categories with bounded expiry and schedule delay. Member responsibility categories and the role-to-performative mapping control which registered IDs can be selected. `agent_ttl_secs` determines worker presence freshness, and message expiry controls how long an assigned task remains available. Category authorization uses the typed `task_category` field, not message text or arbitrary payload contents.

Other selectors fan out to every matching recipient. Broadcast and selector-based recipients do not receive their own message unless `include_self=true` or they are named directly. A group request is a single-worker assignment, while an exact recipient selector remains a direct message.

Group membership is operator-managed. A host key authenticates a host and does not independently authenticate the selected `HARNESS:SESSION` name. Sender and assignee session strings are host-authenticated claims, and any local agent using the assignee host's key can act as that host's registered session IDs. AIM checks that group-task `ACCEPT`, `REJECT`, `PROGRESS`, and `RESULT` use the persisted assignee ID. Posting permissions are also enforced at host scope, so any client on an authorized host can submit a granted category.

Reloaded membership applies to new assignments. Previously stored group requests keep their exact recipient and remain available until message expiry, unless the recipient host key is disabled.

## 3. HTTP Endpoints (Mounted under `base_path`, default `/aim`)

An inbox response contains `seq_head`, the highest stored message sequence in the same SQLite read snapshot used for its message scan, `next_after`, and the independent hub-stored `read_position`. `seq_head` is a global hub sequence boundary, not the last message visible to that recipient. On a full page, `next_after` is the last returned message sequence so the next page cannot skip later deliverable messages. On an exhausted non-thread scan, it advances to the snapshot's `seq_head`, including over filtered rows. A bootstrap reader can pin the initial `seq_head` as its upper bound while paging, then continue from that sequence for newer messages. Explicit inbox cursors never advance `read_position`.

An `idempotency_key` is unique to the host-bound sender while its message remains stored. An exact retry returns the original sequence, thread, and persisted assignment metadata. Reusing a retained key with different request content returns `409 Conflict`. An expired message continues reserving its key until normal pruning removes that message. The key may be reused after pruning.

| Method & Path | Auth | Description |
| :--- | :--- | :--- |
| `GET /aim/v1/health` | None | Minimal `{"status":"ok","protocol":"aim/v1"}` reachability check |
| `POST /aim/v1/register` | Bearer | Register/heartbeat agent, return hub `read_position` and active repo claims |
| `POST /aim/v1/send` | Bearer | Send a typed message with idempotency, FSM, host visibility, lease checks, and optional one-member group assignment |
| `GET /aim/v1/inbox` | Bearer | Read matching messages (`agent`, `after`, `wait`, `limit`, `thread`, `include_self`) |
| `POST /aim/v1/ack` | Bearer | Monotonically advance hub-stored `read_position` (clamped to `seq_head`) |
| `POST /aim/v1/claim` | Bearer | Record normalized path claims with TTL and report overlaps |
| `POST /aim/v1/release` | Bearer | Release one or all claims held by an agent |
| `GET /aim/v1/status` | Bearer | Cluster snapshot: agents, live claims, and host-visible open requests |
| `GET /aim/v1/thread/{thread}` | Bearer | Read active messages and lease state for an authorized thread |
| `PUT /aim/v1/artifacts/{sha256}` | Bearer | Upload Brotli Q6 blob verified against SHA-256 and secret guard |
| `GET /aim/v1/artifacts/{sha256}` | Bearer | Download authorized artifact (pass `?encoding=br` for Brotli Q6 wire transfer) |
