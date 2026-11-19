use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{GroupConfig, GroupRole};
use aim_proto::address::{deliverable, AgentId, Recipient, Selector};
use aim_proto::artifact::decompress_verified;
use aim_proto::guard::find_secret_bytes;
use aim_proto::names::check_name;
use aim_proto::wire::{
    check_artifact_name, check_sha256, paths_overlap, AckRequest, AckResponse, AgentInfo,
    ArtifactInfo, ClaimInfo, ClaimRequest, ClaimResponse, InboxResponse, Message, OpenRequest,
    RegisterRequest, RegisterResponse, ReleaseRequest, SendRequest, SendResponse, StatusResponse,
    ThreadResponse, MAX_EXPIRY_SECS,
};
use aim_proto::{Performative, MAX_ARTIFACT_BR_BYTES, MAX_INBOX_LIMIT, UNTRUSTED_NOTICE};
use rand::RngCore;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub enum StoreError {
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    QuotaExceeded(String),
    StorageFull(String),
    Internal(String),
}

impl StoreError {
    fn from_db(err: rusqlite::Error) -> Self {
        Self::Internal(format!("database error: {err}"))
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::from_db(err)
    }
}

#[derive(Clone, Debug)]
pub struct StoreConfig {
    pub agent_ttl_ms: i64,
    pub default_message_ttl_ms: i64,
    pub default_claim_ttl_ms: i64,
    pub default_accept_lease_ms: i64,
    pub max_messages: usize,
    pub max_agents: usize,
    pub max_claims_per_host: usize,
    pub max_artifacts_total_bytes: u64,
    pub agent_retention_ms: i64,
    pub groups: Vec<GroupConfig>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            agent_ttl_ms: 300_000,
            default_message_ttl_ms: 7 * 24 * 3600 * 1000,
            default_claim_ttl_ms: 3600 * 1000,
            default_accept_lease_ms: 900 * 1000,
            max_messages: 50_000,
            max_agents: 2_000,
            max_claims_per_host: 256,
            max_artifacts_total_bytes: 512 * 1024 * 1024,
            agent_retention_ms: 30 * 24 * 3600 * 1000,
            groups: Vec::new(),
        }
    }
}

struct ReadPool {
    db_path: PathBuf,
    conns: Mutex<Vec<Connection>>,
    max_size: usize,
}

impl ReadPool {
    fn new(db_path: PathBuf, max_size: usize) -> Self {
        Self {
            db_path,
            conns: Mutex::new(Vec::new()),
            max_size,
        }
    }

    fn acquire(&self) -> Result<PooledConn<'_>, StoreError> {
        let mut list = self
            .conns
            .lock()
            .map_err(|_| StoreError::Internal("read pool lock poisoned".into()))?;
        if let Some(conn) = list.pop() {
            return Ok(PooledConn {
                conn: Some(conn),
                pool: self,
            });
        }
        drop(list);

        let conn = Connection::open_with_flags(
            &self.db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| StoreError::Internal(format!("sqlite read open failed: {e}")))?;
        let _ = conn.busy_timeout(Duration::from_secs(5));
        let _ = conn.execute_batch("PRAGMA query_only=ON;");
        Ok(PooledConn {
            conn: Some(conn),
            pool: self,
        })
    }
}

struct PooledConn<'a> {
    conn: Option<Connection>,
    pool: &'a ReadPool,
}

impl<'a> std::ops::Deref for PooledConn<'a> {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().unwrap()
    }
}

impl<'a> Drop for PooledConn<'a> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if let Ok(mut list) = self.pool.conns.lock() {
                if list.len() < self.pool.max_size {
                    list.push(conn);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    read_pool: Arc<ReadPool>,
    artifacts_dir: PathBuf,
    artifact_io_lock: Arc<Mutex<()>>,
    cfg: StoreConfig,
    keyring: Option<crate::auth::KeyRing>,
}

struct ExistingSendRequest {
    seq: i64,
    msg_id: String,
    thread: String,
    expires_ms: i64,
    assigned_group: Option<String>,
    assigned_to: Option<String>,
    task_category: Option<String>,
    assigned_role: Option<String>,
    not_before_ms: Option<i64>,
    idempotency_fingerprint: Option<String>,
    created_ms: i64,
    to_json: String,
    performative: String,
    reply_to: Option<i64>,
    body: String,
    payload_json: Option<String>,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn new_msg_id(now: i64) -> String {
    let mut r = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut r);
    let rand_u64 = u64::from_be_bytes(r);
    format!("msg-{now:012x}-{rand_u64:016x}")
}

fn new_thread_id(now: i64) -> String {
    let mut r = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut r);
    let rand_u64 = u64::from_be_bytes(r);
    format!("thr-{now:012x}-{rand_u64:016x}")
}

fn normalize_path(path: &str) -> String {
    aim_proto::wire::normalize_claim_path(path)
}

fn ensure_assignment_columns(conn: &Connection) -> Result<(), String> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(messages)")
        .map_err(|e| format!("cannot inspect message schema: {e}"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("cannot inspect message schema: {e}"))?
        .collect::<Result<std::collections::HashSet<_>, _>>()
        .map_err(|e| format!("cannot read message schema: {e}"))?;
    drop(stmt);

    if !columns.contains("assigned_group") {
        conn.execute("ALTER TABLE messages ADD COLUMN assigned_group TEXT", [])
            .map_err(|e| format!("cannot add group assignment provenance: {e}"))?;
    }
    if !columns.contains("assigned_to") {
        conn.execute("ALTER TABLE messages ADD COLUMN assigned_to TEXT", [])
            .map_err(|e| format!("cannot add group assignment target: {e}"))?;
    }
    if !columns.contains("task_category") {
        conn.execute("ALTER TABLE messages ADD COLUMN task_category TEXT", [])
            .map_err(|e| format!("cannot add task category: {e}"))?;
    }
    if !columns.contains("assigned_role") {
        conn.execute("ALTER TABLE messages ADD COLUMN assigned_role TEXT", [])
            .map_err(|e| format!("cannot add assignment role: {e}"))?;
    }
    if !columns.contains("not_before_ms") {
        conn.execute("ALTER TABLE messages ADD COLUMN not_before_ms INTEGER", [])
            .map_err(|e| format!("cannot add scheduled delivery time: {e}"))?;
    }
    if !columns.contains("idempotency_fingerprint") {
        conn.execute(
            "ALTER TABLE messages ADD COLUMN idempotency_fingerprint TEXT",
            [],
        )
        .map_err(|e| format!("cannot add idempotency request fingerprint: {e}"))?;
    }
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_messages_assignment;
         CREATE INDEX IF NOT EXISTS idx_messages_assignment_category
         ON messages(assigned_group, task_category, assigned_to, seq);",
    )
    .map_err(|e| format!("cannot index group assignments: {e}"))?;
    Ok(())
}

fn send_request_fingerprint(request: &SendRequest) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(request).map_err(|error| {
        StoreError::Internal(format!("cannot encode request fingerprint: {error}"))
    })?;
    let digest = Sha256::digest(encoded);
    let hex = b"0123456789abcdef";
    let mut fingerprint = String::with_capacity(digest.len() * 2);
    for byte in digest {
        fingerprint.push(hex[(byte >> 4) as usize] as char);
        fingerprint.push(hex[(byte & 0x0f) as usize] as char);
    }
    Ok(fingerprint)
}

fn touch_sender(
    tx: &rusqlite::Transaction<'_>,
    sender_id: &AgentId,
    sender: &str,
    now: i64,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO agents(id, host, harness, session, caps_json, seen_ms, read_position)
         VALUES(?1, ?2, ?3, ?4, '[]', ?5, 0)
         ON CONFLICT(id) DO UPDATE SET seen_ms=excluded.seen_ms",
        params![
            sender,
            sender_id.host,
            sender_id.harness,
            sender_id.session,
            now
        ],
    )?;
    Ok(())
}

impl Store {
    pub fn open(data_dir: &Path, cfg: StoreConfig) -> Result<Self, String> {
        Self::open_inner(data_dir, cfg, None)
    }

    pub fn open_with_keyring(
        data_dir: &Path,
        cfg: StoreConfig,
        keyring: crate::auth::KeyRing,
    ) -> Result<Self, String> {
        Self::open_inner(data_dir, cfg, Some(keyring))
    }

    fn open_inner(
        data_dir: &Path,
        cfg: StoreConfig,
        keyring: Option<crate::auth::KeyRing>,
    ) -> Result<Self, String> {
        aim_fs::ensure_private_dir(data_dir)
            .map_err(|e| format!("cannot prepare data_dir {}: {e}", data_dir.display()))?;
        let artifacts_dir = data_dir.join("artifacts");
        aim_fs::ensure_private_dir(&artifacts_dir).map_err(|e| {
            format!(
                "cannot prepare artifacts dir {}: {e}",
                artifacts_dir.display()
            )
        })?;

        let db_path = data_dir.join("aim.sqlite");
        let file = aim_fs::open_private_rw(&db_path)
            .map_err(|e| format!("cannot open database {}: {e}", db_path.display()))?;
        aim_fs::verify_private_file(&file)
            .map_err(|e| format!("database {} is not private: {e}", db_path.display()))?;
        if !aim_fs::same_file(&file, &db_path).map_err(|e| e.to_string())? {
            return Err("database changed during open".into());
        }
        drop(file);

        let conn = Connection::open(&db_path)
            .map_err(|e| format!("sqlite open failed for {}: {e}", db_path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                harness TEXT NOT NULL,
                session TEXT NOT NULL,
                repo TEXT,
                worktree TEXT,
                branch TEXT,
                head TEXT,
                caps_json TEXT NOT NULL,
                note TEXT,
                seen_ms INTEGER NOT NULL,
                read_position INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_agents_host_seen ON agents(host, seen_ms);

            CREATE TABLE IF NOT EXISTS messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT NOT NULL UNIQUE,
                created_ms INTEGER NOT NULL,
                expires_ms INTEGER NOT NULL,
                sender TEXT NOT NULL,
                to_json TEXT NOT NULL,
                performative TEXT NOT NULL,
                thread TEXT NOT NULL,
                reply_to INTEGER,
                body TEXT NOT NULL,
                payload_json TEXT,
                idempotency_key TEXT,
                idempotency_fingerprint TEXT,
                assigned_group TEXT,
                assigned_to TEXT,
                task_category TEXT,
                assigned_role TEXT,
                not_before_ms INTEGER,
                accepted_by TEXT,
                accept_expires_ms INTEGER,
                closed INTEGER NOT NULL DEFAULT 0
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_idem
                ON messages(sender, idempotency_key)
                WHERE idempotency_key IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_messages_thread
                ON messages(thread, seq);
            CREATE INDEX IF NOT EXISTS idx_messages_expires
                ON messages(expires_ms);

            CREATE TABLE IF NOT EXISTS claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent TEXT NOT NULL,
                repo TEXT NOT NULL,
                path TEXT NOT NULL,
                note TEXT,
                created_ms INTEGER NOT NULL,
                expires_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_claims_repo
                ON claims(repo, expires_ms);
            CREATE INDEX IF NOT EXISTS idx_claims_agent
                ON claims(agent, expires_ms);

            CREATE TABLE IF NOT EXISTS artifacts (
                sha256 TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                sender TEXT NOT NULL,
                host TEXT NOT NULL,
                raw_bytes INTEGER NOT NULL,
                br_bytes INTEGER NOT NULL,
                created_ms INTEGER NOT NULL,
                expires_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifacts_host
                ON artifacts(host, expires_ms);

            CREATE TABLE IF NOT EXISTS artifact_owners (
                sha256 TEXT NOT NULL,
                host TEXT NOT NULL,
                expires_ms INTEGER NOT NULL,
                PRIMARY KEY (sha256, host)
            );
            INSERT OR IGNORE INTO artifact_owners(sha256, host, expires_ms)
                SELECT sha256, host, expires_ms FROM artifacts;
            ",
        )
        .map_err(|e| format!("failed initializing schema: {e}"))?;
        ensure_assignment_columns(&conn)?;

        let read_pool = Arc::new(ReadPool::new(db_path, 4));
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            read_pool,
            artifacts_dir,
            artifact_io_lock: Arc::new(Mutex::new(())),
            cfg,
            keyring,
        })
    }

    pub fn checkpoint_truncate(&self) -> Result<(), StoreError> {
        let db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Ok(())
    }

    pub fn register(
        &self,
        host: &str,
        req: RegisterRequest,
    ) -> Result<RegisterResponse, StoreError> {
        req.validate().map_err(StoreError::BadRequest)?;
        let agent_id = AgentId::from_local(host, &req.agent).map_err(StoreError::BadRequest)?;
        let agent_str = agent_id.to_string();
        let caps_json =
            serde_json::to_string(&req.caps).map_err(|e| StoreError::Internal(e.to_string()))?;
        let now = now_ms();

        let mut db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM claims WHERE expires_ms <= ?1", [now])?;

        let cutoff = now.saturating_sub(self.cfg.agent_ttl_ms);
        let live_agents: i64 = tx.query_row(
            "SELECT COUNT(*) FROM agents WHERE seen_ms >= ?1",
            [cutoff],
            |r| r.get(0),
        )?;
        if live_agents as usize >= self.cfg.max_agents {
            let already_exists: bool = tx
                .query_row("SELECT 1 FROM agents WHERE id = ?1", [&agent_str], |_| {
                    Ok(true)
                })
                .optional()?
                .unwrap_or(false);
            if !already_exists {
                return Err(StoreError::QuotaExceeded(format!(
                    "maximum registered agents ({}) reached",
                    self.cfg.max_agents
                )));
            }
        }

        tx.execute(
            "INSERT INTO agents(id, host, harness, session, repo, worktree, branch, head, caps_json, note, seen_ms, read_position)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0)
             ON CONFLICT(id) DO UPDATE SET
               host=excluded.host,
               harness=excluded.harness,
               session=excluded.session,
               repo=excluded.repo,
               worktree=excluded.worktree,
               branch=excluded.branch,
               head=excluded.head,
               caps_json=excluded.caps_json,
               note=excluded.note,
               seen_ms=excluded.seen_ms",
            params![
                agent_str,
                agent_id.host,
                agent_id.harness,
                agent_id.session,
                req.repo,
                req.worktree,
                req.branch,
                req.head,
                caps_json,
                req.note,
                now,
            ],
        )?;

        let read_position: i64 = tx.query_row(
            "SELECT read_position FROM agents WHERE id=?1",
            [&agent_str],
            |r| r.get(0),
        )?;
        let seq_head: i64 =
            tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM messages", [], |r| {
                r.get(0)
            })?;
        let live_agents: i64 = tx.query_row(
            "SELECT COUNT(*) FROM agents WHERE seen_ms >= ?1",
            [cutoff],
            |r| r.get(0),
        )?;

        let mut conflicts = Vec::new();
        if let Some(ref repo) = req.repo {
            let mut stmt = tx.prepare(
                "SELECT id, agent, repo, path, note, expires_ms FROM claims
                 WHERE repo=?1 AND agent != ?2 AND expires_ms > ?3 ORDER BY id",
            )?;
            let mut rows = stmt.query(params![repo, &agent_str, now])?;
            while let Some(row) = rows.next()? {
                conflicts.push(ClaimInfo {
                    id: row.get(0)?,
                    agent: row.get(1)?,
                    repo: row.get(2)?,
                    path: row.get(3)?,
                    note: row.get(4)?,
                    expires_ms: row.get(5)?,
                });
            }
        }

        tx.commit()?;
        Ok(RegisterResponse {
            agent: agent_str,
            host: host.to_string(),
            seq_head: seq_head.max(0) as u64,
            read_position: read_position.max(0) as u64,
            live_agents: live_agents.max(0) as usize,
            conflicts,
        })
    }

    pub fn send(
        &self,
        host: &str,
        mut req: SendRequest,
    ) -> Result<(SendResponse, Option<u64>), StoreError> {
        let selectors = req.validate().map_err(StoreError::BadRequest)?;
        let request_fingerprint = req
            .idempotency_key
            .as_ref()
            .map(|_| send_request_fingerprint(&req))
            .transpose()?;
        let sender_id = AgentId::from_local(host, &req.agent).map_err(StoreError::BadRequest)?;
        let sender_str = sender_id.to_string();
        let now = now_ms();
        let requested_group = selectors.iter().find_map(|selector| match selector {
            Selector::Group(name) => Some(name.as_str()),
            _ => None,
        });
        let mut db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        if let Some(ref idem) = req.idempotency_key {
            let existing: Option<ExistingSendRequest> = tx
                .query_row(
                    "SELECT seq, msg_id, thread, expires_ms, assigned_group, assigned_to,
                            task_category, assigned_role, not_before_ms,
                            idempotency_fingerprint, created_ms, to_json, performative,
                            reply_to, body, payload_json
                     FROM messages WHERE sender=?1 AND idempotency_key=?2",
                    params![&sender_str, idem],
                    |r| {
                        Ok(ExistingSendRequest {
                            seq: r.get(0)?,
                            msg_id: r.get(1)?,
                            thread: r.get(2)?,
                            expires_ms: r.get(3)?,
                            assigned_group: r.get(4)?,
                            assigned_to: r.get(5)?,
                            task_category: r.get(6)?,
                            assigned_role: r.get(7)?,
                            not_before_ms: r.get(8)?,
                            idempotency_fingerprint: r.get(9)?,
                            created_ms: r.get(10)?,
                            to_json: r.get(11)?,
                            performative: r.get(12)?,
                            reply_to: r.get(13)?,
                            body: r.get(14)?,
                            payload_json: r.get(15)?,
                        })
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                let ExistingSendRequest {
                    seq,
                    msg_id,
                    thread,
                    expires_ms,
                    assigned_group: stored_group,
                    assigned_to: stored_assignee,
                    task_category: stored_category,
                    assigned_role: stored_role,
                    not_before_ms: stored_not_before_ms,
                    idempotency_fingerprint: stored_fingerprint,
                    created_ms,
                    to_json: stored_to_json,
                    performative: stored_performative,
                    reply_to: stored_reply_to,
                    body: stored_body,
                    payload_json: stored_payload_json,
                } = existing;
                if expires_ms <= now {
                    return Err(StoreError::Conflict(
                        "idempotency key belongs to an expired retained message".into(),
                    ));
                }
                let legacy_request_matches = || -> Result<bool, StoreError> {
                    let request_to_json = serde_json::to_string(&req.to)
                        .map_err(|error| StoreError::Internal(error.to_string()))?;
                    let request_payload_json = req
                        .payload
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| StoreError::Internal(error.to_string()))?;
                    let requested_ttl_ms = req
                        .expires_in_secs
                        .map(|secs| (secs as i64).saturating_mul(1000))
                        .unwrap_or(self.cfg.default_message_ttl_ms);
                    let expiry_matches = expires_ms.saturating_sub(created_ms) == requested_ttl_ms;
                    let recipient_matches = if let Some(group) = stored_group.as_deref() {
                        let group_selector = vec![format!("group:{group}")];
                        let assigned_recipient = stored_assignee
                            .as_ref()
                            .map(|assignee| vec![assignee.clone()])
                            .map(|recipient| serde_json::to_string(&recipient))
                            .transpose()
                            .map_err(|error| StoreError::Internal(error.to_string()))?;
                        requested_group == Some(group)
                            && req.to == group_selector
                            && assigned_recipient.as_deref() == Some(stored_to_json.as_str())
                            && stored_assignee.is_some()
                            && stored_role.is_some()
                            && req.task_category == stored_category
                            && req.not_before_ms == stored_not_before_ms
                    } else {
                        requested_group.is_none()
                            && stored_assignee.is_none()
                            && stored_role.is_none()
                            && req.task_category == stored_category
                            && req.not_before_ms == stored_not_before_ms
                            && request_to_json == stored_to_json
                    };
                    Ok(stored_fingerprint.is_none()
                        && req.lease_secs.is_none()
                        && recipient_matches
                        && req.performative.as_str() == stored_performative
                        && req.reply_to.map(|seq| seq as i64) == stored_reply_to
                        && req.thread.as_ref().is_none_or(|value| value == &thread)
                        && req.body == stored_body
                        && request_payload_json == stored_payload_json
                        && expiry_matches)
                };
                if stored_fingerprint
                    .as_deref()
                    .is_some_and(|stored| request_fingerprint.as_deref() == Some(stored))
                    || (stored_fingerprint.is_none() && legacy_request_matches()?)
                {
                    touch_sender(&tx, &sender_id, &sender_str, now)?;
                    tx.commit()?;
                    return Ok((
                        SendResponse {
                            seq: seq as u64,
                            msg_id,
                            thread,
                            duplicate: true,
                            assigned_to: stored_assignee,
                            assigned_group: stored_group,
                            task_category: stored_category,
                            assigned_role: stored_role,
                            not_before_ms: stored_not_before_ms,
                        },
                        None,
                    ));
                }
                return Err(StoreError::Conflict(
                    "idempotency key was already used with different request content".into(),
                ));
            }
        }

        let requested_category = req.task_category.as_deref();
        let group_config = requested_group
            .map(|group_name| {
                let (group, enabled_hosts) = match &self.keyring {
                    Some(keyring) => keyring
                        .group_policy(group_name)
                        .map(|(group, hosts)| (Some(group), Some(hosts)))
                        .unwrap_or((None, None)),
                    None => (
                        self.cfg
                            .groups
                            .iter()
                            .find(|group| group.name == group_name)
                            .cloned(),
                        None,
                    ),
                };
                let group = group.ok_or_else(|| StoreError::NotFound("group not found".into()))?;
                let category =
                    requested_category.expect("group request validation requires task_category");
                let permission = group.posting_permissions.iter().find(|permission| {
                    permission.host == host
                        && permission
                            .task_categories
                            .iter()
                            .any(|allowed| allowed == category)
                });
                let Some(permission) = permission else {
                    return Err(StoreError::NotFound("group not found".into()));
                };
                let max_schedule_delay_secs = permission.max_schedule_delay_secs;
                let expires_in_secs = req
                    .expires_in_secs
                    .expect("group request validation requires expires_in_secs");
                if expires_in_secs > permission.max_expires_in_secs {
                    return Err(StoreError::BadRequest(
                        "expires_in_secs exceeds the group posting grant".into(),
                    ));
                }
                Ok((group, enabled_hosts, max_schedule_delay_secs))
            })
            .transpose()?;

        // Keep sender's last-seen fresh without overwriting registered metadata.
        touch_sender(&tx, &sender_id, &sender_str, now)?;

        if let Some(not_before_ms) = req.not_before_ms {
            let max_schedule_delay_secs = group_config
                .as_ref()
                .map(|(_, _, max_delay)| *max_delay)
                .unwrap_or(MAX_EXPIRY_SECS);
            let ttl_ms = req
                .expires_in_secs
                .map(|secs| (secs as i64).saturating_mul(1000))
                .unwrap_or(self.cfg.default_message_ttl_ms);
            let expires_ms = now.saturating_add(ttl_ms);
            let latest_not_before_ms =
                now.saturating_add((max_schedule_delay_secs as i64).saturating_mul(1000));
            if not_before_ms <= now
                || not_before_ms > latest_not_before_ms
                || not_before_ms >= expires_ms
            {
                return Err(StoreError::BadRequest(
                    "not_before_ms is outside the allowed schedule horizon or message lifetime"
                        .into(),
                ));
            }
        }

        // Existing idempotent messages remain retryable when the storage quota
        // has since filled.
        let msg_count: i64 = tx.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
        if msg_count as usize >= self.cfg.max_messages {
            return Err(StoreError::StorageFull(format!(
                "message storage full (max {} messages)",
                self.cfg.max_messages
            )));
        }

        let (assigned_to, assigned_role) = if let Some((group, enabled_hosts, _)) = group_config {
            let cutoff_ms = now.saturating_sub(self.cfg.agent_ttl_ms);
            let category = requested_category.expect("group request validation requires category");
            let candidates: Vec<String> = group
                .members
                .iter()
                .filter(|member| {
                    let permitted_role = match req.performative {
                        Performative::Request => member.role == GroupRole::Specialist,
                        Performative::RequestVerify => member.role == GroupRole::Reviewer,
                        _ => false,
                    };
                    permitted_role
                        && member
                            .responsibilities
                            .iter()
                            .any(|responsibility| responsibility == category)
                        && enabled_hosts.as_ref().is_none_or(|hosts| {
                            AgentId::parse_full(&member.agent)
                                .is_ok_and(|agent| hosts.contains(&agent.host))
                        })
                })
                .map(|member| member.agent.clone())
                .collect();
            let assignee = crate::assignment::choose(
                &tx,
                &group.name,
                category,
                &candidates,
                cutoff_ms,
                &sender_str,
            )?;
            let selected_member = group
                .members
                .iter()
                .find(|member| member.agent == assignee)
                .ok_or_else(|| StoreError::Internal("selected group member disappeared".into()))?;
            req.to = vec![assignee.clone()];
            (
                Some(assignee),
                Some(selected_member.role.as_str().to_string()),
            )
        } else {
            (None, None)
        };
        let assigned_group = requested_group.map(str::to_string);
        let task_category = req.task_category.clone();
        let not_before_ms = req.not_before_ms;

        let msg_id = new_msg_id(now);
        let thread = if let Some(parent_seq_u64) = req.reply_to {
            let parent_seq = i64::try_from(parent_seq_u64)
                .map_err(|_| StoreError::BadRequest("reply_to out of range".into()))?;
            struct ParentRow {
                sender: String,
                to_json: String,
                perf_str: String,
                thread: String,
                accepted_by: Option<String>,
                accept_expires_ms: Option<i64>,
                closed: i64,
                expires_ms: i64,
                assigned_group: Option<String>,
                assigned_to: Option<String>,
            }
            let parent_row: Option<ParentRow> = tx
                .query_row(
                    "SELECT sender, to_json, performative, thread, accepted_by, accept_expires_ms, closed, expires_ms,
                            assigned_group, assigned_to
                     FROM messages WHERE seq=?1",
                    [parent_seq],
                    |r| {
                        Ok(ParentRow {
                            sender: r.get(0)?,
                            to_json: r.get(1)?,
                            perf_str: r.get(2)?,
                            thread: r.get(3)?,
                            accepted_by: r.get(4)?,
                            accept_expires_ms: r.get(5)?,
                            closed: r.get(6)?,
                            expires_ms: r.get(7)?,
                            assigned_group: r.get(8)?,
                            assigned_to: r.get(9)?,
                        })
                    },
                )
                .optional()?;
            let Some(ParentRow {
                sender: parent_sender,
                to_json: parent_to_json,
                perf_str: parent_perf_str,
                thread: parent_thread,
                accepted_by,
                accept_expires_ms,
                closed,
                expires_ms: parent_expires,
                assigned_group: parent_assigned_group,
                assigned_to: parent_assigned_to,
            }) = parent_row
            else {
                return Err(StoreError::NotFound(format!(
                    "parent message seq {parent_seq_u64} not found"
                )));
            };

            // Host isolation: can caller host view this parent message?
            if !host_can_view_message(&tx, host, &parent_sender, &parent_to_json)? {
                return Err(StoreError::NotFound(format!(
                    "parent message seq {parent_seq_u64} not found"
                )));
            }

            if parent_expires <= now {
                return Err(StoreError::BadRequest(format!(
                    "parent message seq {parent_seq_u64} has expired"
                )));
            }
            let parent_perf = Performative::parse(&parent_perf_str)
                .ok_or_else(|| StoreError::Internal("corrupt parent performative".into()))?;
            if !req.performative.may_reply_to(parent_perf) {
                return Err(StoreError::BadRequest(format!(
                    "{} cannot reply to {}",
                    req.performative.as_str(),
                    parent_perf.as_str()
                )));
            }
            if let Some(ref req_thread) = req.thread {
                if req_thread != &parent_thread {
                    return Err(StoreError::BadRequest(format!(
                        "reply thread '{req_thread}' must match parent thread '{parent_thread}'"
                    )));
                }
            }

            if parent_perf.is_request() {
                if parent_assigned_group.is_some()
                    && matches!(
                        req.performative,
                        Performative::Accept
                            | Performative::Reject
                            | Performative::Progress
                            | Performative::Result
                    )
                    && parent_assigned_to.as_deref() != Some(sender_str.as_str())
                {
                    return Err(StoreError::Conflict(
                        "group task controls are limited to the persisted assignee".into(),
                    ));
                }
                if closed != 0 {
                    return Err(StoreError::Conflict(format!(
                        "request seq {parent_seq_u64} is already closed"
                    )));
                }
                let lease_ms = req
                    .lease_secs
                    .map(|s| (s as i64).saturating_mul(1000))
                    .unwrap_or(self.cfg.default_accept_lease_ms);
                let active_holder = accepted_by
                    .as_deref()
                    .filter(|holder| *holder != sender_str && accept_expires_ms.unwrap_or(0) > now);

                match req.performative {
                    Performative::Accept => {
                        if let Some(holder) = active_holder {
                            return Err(StoreError::Conflict(format!(
                                "request seq {parent_seq_u64} is already accepted by {holder}"
                            )));
                        }
                        tx.execute(
                            "UPDATE messages SET accepted_by=?1, accept_expires_ms=?2 WHERE seq=?3",
                            params![&sender_str, now.saturating_add(lease_ms), parent_seq],
                        )?;
                    }
                    Performative::Progress => {
                        if let Some(holder) = active_holder {
                            return Err(StoreError::Conflict(format!(
                                "request seq {parent_seq_u64} is accepted by {holder}"
                            )));
                        }
                        tx.execute(
                            "UPDATE messages SET accepted_by=?1, accept_expires_ms=?2 WHERE seq=?3",
                            params![&sender_str, now.saturating_add(lease_ms), parent_seq],
                        )?;
                    }
                    Performative::Reject => {
                        if let Some(holder) = active_holder {
                            return Err(StoreError::Conflict(format!(
                                "request seq {parent_seq_u64} is accepted by {holder}"
                            )));
                        }
                        if accepted_by.as_deref() == Some(sender_str.as_str()) {
                            tx.execute(
                                "UPDATE messages SET accepted_by=NULL, accept_expires_ms=NULL WHERE seq=?1",
                                [parent_seq],
                            )?;
                        }
                    }
                    Performative::Result => {
                        if let Some(holder) = active_holder {
                            return Err(StoreError::Conflict(format!(
                                "request seq {parent_seq_u64} is leased by {holder}"
                            )));
                        }
                        // RESULT closes the request; accept_expires_ms is cleared to NULL
                        tx.execute(
                            "UPDATE messages SET closed=1, accepted_by=COALESCE(accepted_by, ?1), accept_expires_ms=NULL WHERE seq=?2",
                            params![&sender_str, parent_seq],
                        )?;
                    }
                    _ => {}
                }
            }
            parent_thread
        } else {
            // New root message: block injecting into an existing thread
            if let Some(ref req_thread) = req.thread {
                let thread_exists: bool = tx
                    .query_row(
                        "SELECT 1 FROM messages WHERE thread=?1 LIMIT 1",
                        [req_thread],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if thread_exists {
                    return Err(StoreError::Conflict(format!(
                        "thread '{req_thread}' already exists; use reply_to to participate"
                    )));
                }
                req_thread.clone()
            } else {
                new_thread_id(now)
            }
        };

        let ttl_ms = req
            .expires_in_secs
            .map(|s| (s as i64).saturating_mul(1000))
            .unwrap_or(self.cfg.default_message_ttl_ms);
        let expires_ms = now.saturating_add(ttl_ms);
        let to_json =
            serde_json::to_string(&req.to).map_err(|e| StoreError::Internal(e.to_string()))?;
        let payload_json = req
            .payload
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        let reply_to_i64 = match req.reply_to {
            Some(v) => Some(
                i64::try_from(v)
                    .map_err(|_| StoreError::BadRequest("reply_to out of range".into()))?,
            ),
            None => None,
        };

        tx.execute(
            "INSERT INTO messages(msg_id, created_ms, expires_ms, sender, to_json, performative, thread,
             reply_to, body, payload_json, idempotency_key, idempotency_fingerprint,
             assigned_group, assigned_to, task_category, assigned_role, not_before_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                msg_id,
                now,
                expires_ms,
                sender_str,
                to_json,
                req.performative.as_str(),
                thread,
                reply_to_i64,
                req.body,
                payload_json,
                req.idempotency_key,
                request_fingerprint.as_deref(),
                assigned_group,
                assigned_to,
                task_category,
                assigned_role,
                not_before_ms,
            ],
        )?;
        let seq = tx.last_insert_rowid() as u64;
        tx.commit()?;

        Ok((
            SendResponse {
                seq,
                msg_id,
                thread,
                duplicate: false,
                assigned_to,
                assigned_group,
                task_category,
                assigned_role,
                not_before_ms,
            },
            Some(seq),
        ))
    }

    pub fn inbox(
        &self,
        host: &str,
        agent: &str,
        after: Option<u64>,
        limit: Option<u32>,
        thread: Option<&str>,
        include_self: bool,
    ) -> Result<InboxResponse, StoreError> {
        let agent_id = AgentId::from_local(host, agent).map_err(StoreError::BadRequest)?;
        if let Some(t) = thread {
            check_name("thread", t).map_err(StoreError::BadRequest)?;
        }
        let after_i64 = match after {
            Some(v) => Some(
                i64::try_from(v)
                    .map_err(|_| StoreError::BadRequest("after out of range".into()))?,
            ),
            None => None,
        };
        let max_rows = limit.unwrap_or(100).clamp(1, MAX_INBOX_LIMIT) as usize;
        let now = now_ms();

        let db = self.read_pool.acquire()?;
        let tx = db.unchecked_transaction()?;

        let agent_str = agent_id.to_string();
        let agent_meta: Option<(Option<String>, String, i64, i64)> = tx
            .query_row(
                "SELECT repo, caps_json, read_position, seen_ms FROM agents WHERE id=?1",
                [&agent_str],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (repo, caps, read_position, seen_ms) = match agent_meta {
            Some((repo, caps_json, rp, seen_ms)) => {
                let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
                (repo, caps, rp.max(0) as u64, Some(seen_ms))
            }
            None => (None, Vec::new(), 0, None),
        };
        let recipient = Recipient {
            id: &agent_id,
            repo: repo.as_deref(),
            caps: &caps,
        };

        let effective_after = after_i64.unwrap_or(read_position as i64);
        // Read the boundary and recipient-visible messages from the same
        // SQLite snapshot. A send committed after this snapshot is established
        // is deferred to the next request and cannot be skipped by a persisted
        // `next_after` cursor.
        let seq_head: i64 =
            tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM messages", [], |r| {
                r.get(0)
            })?;
        let seq_head = seq_head.max(0) as u64;

        let mut messages = Vec::new();
        let mut hit_limit = false;

        let sql = if thread.is_some() {
            "SELECT seq, msg_id, created_ms, expires_ms, sender, to_json, performative, thread, reply_to, body, payload_json,
                    assigned_group, task_category, assigned_role, not_before_ms
             FROM messages WHERE seq > ?1 AND expires_ms > ?2 AND thread = ?3 ORDER BY seq ASC"
        } else {
            "SELECT seq, msg_id, created_ms, expires_ms, sender, to_json, performative, thread, reply_to, body, payload_json,
                    assigned_group, task_category, assigned_role, not_before_ms
             FROM messages WHERE seq > ?1 AND expires_ms > ?2 ORDER BY seq ASC"
        };

        let mut stmt = tx.prepare(sql)?;
        let mut rows = if let Some(t) = thread {
            stmt.query(params![effective_after, now, t])?
        } else {
            stmt.query(params![effective_after, now])?
        };

        while let Some(row) = rows.next()? {
            let sender: String = row.get(4)?;
            let Ok(sender_id) = AgentId::parse_full(&sender) else {
                continue;
            };
            let to_json: String = row.get(5)?;
            let to_strings: Vec<String> = serde_json::from_str(&to_json).unwrap_or_default();
            let selectors: Vec<Selector> = to_strings
                .iter()
                .filter_map(|s| Selector::parse(s).ok())
                .collect();
            if deliverable(&selectors, &sender_id, &recipient, include_self) {
                if messages.len() >= max_rows {
                    hit_limit = true;
                    break;
                }
                let msg = decode_message_row(row)?;
                messages.push(msg);
            }
        }
        drop(rows);
        drop(stmt);

        let last_seq = messages
            .last()
            .map_or(effective_after.max(0) as u64, |message| message.seq);
        let next_after = if !hit_limit && thread.is_none() {
            seq_head.max(last_seq).max(effective_after.max(0) as u64)
        } else {
            last_seq
        };

        tx.commit()?;

        // Refresh presence after the read snapshot is closed. This endpoint is
        // the listener heartbeat, throttled to a fraction of the agent TTL.
        let heartbeat_cutoff = now.saturating_sub((self.cfg.agent_ttl_ms / 3).clamp(1, 60_000));
        if seen_ms.is_some_and(|seen| seen <= heartbeat_cutoff) {
            self.conn
                .lock()
                .map_err(|_| StoreError::Internal("db lock poisoned".into()))?
                .execute(
                    "UPDATE agents SET seen_ms=?2 WHERE id=?1 AND seen_ms<=?3",
                    params![agent_str, now, heartbeat_cutoff],
                )?;
        }
        Ok(InboxResponse {
            notice: UNTRUSTED_NOTICE.to_string(),
            messages,
            seq_head,
            next_after,
            read_position,
        })
    }

    pub fn ack(&self, host: &str, req: AckRequest) -> Result<AckResponse, StoreError> {
        req.validate().map_err(StoreError::BadRequest)?;
        let agent_id = AgentId::from_local(host, &req.agent).map_err(StoreError::BadRequest)?;
        let agent_str = agent_id.to_string();
        let now = now_ms();
        let read_to_i64 = i64::try_from(req.read_to)
            .map_err(|_| StoreError::BadRequest("read_to out of range".into()))?;

        let mut db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let seq_head: i64 =
            tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM messages", [], |r| {
                r.get(0)
            })?;
        let clamped_read_to = read_to_i64.min(seq_head);

        tx.execute(
            "INSERT INTO agents(id, host, harness, session, caps_json, seen_ms, read_position)
             VALUES(?1, ?2, ?3, ?4, '[]', ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
               seen_ms=excluded.seen_ms,
               read_position=MAX(agents.read_position, excluded.read_position)",
            params![
                agent_str,
                agent_id.host,
                agent_id.harness,
                agent_id.session,
                now,
                clamped_read_to,
            ],
        )?;
        let read_position: i64 = tx.query_row(
            "SELECT read_position FROM agents WHERE id=?1",
            [&agent_str],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(AckResponse {
            agent: agent_str,
            read_position: read_position.max(0) as u64,
        })
    }

    pub fn claim(&self, host: &str, mut req: ClaimRequest) -> Result<ClaimResponse, StoreError> {
        req.validate().map_err(StoreError::BadRequest)?;
        let agent_id = AgentId::from_local(host, &req.agent).map_err(StoreError::BadRequest)?;
        let agent_str = agent_id.to_string();
        let now = now_ms();
        let ttl_ms = req
            .ttl_secs
            .map(|s| (s as i64).saturating_mul(1000))
            .unwrap_or(self.cfg.default_claim_ttl_ms);
        let expires_ms = now.saturating_add(ttl_ms);

        // Normalize and deduplicate paths
        let mut unique_paths = Vec::with_capacity(req.paths.len());
        for p in req.paths {
            let norm = normalize_path(&p);
            if !unique_paths.contains(&norm) {
                unique_paths.push(norm);
            }
        }
        req.paths = unique_paths;

        let mut db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM claims WHERE expires_ms <= ?1", [now])?;

        // Enforce max_claims_per_host quota (exact prefix match without SQL LIKE '_' wildcard)
        let host_prefix = format!("{host}:");
        let current_claims: i64 = tx.query_row(
            "SELECT COUNT(*) FROM claims WHERE SUBSTR(agent, 1, ?1) = ?2 AND expires_ms > ?3",
            params![host_prefix.len() as i64, host_prefix, now],
            |r| r.get(0),
        )?;
        if (current_claims as usize).saturating_add(req.paths.len()) > self.cfg.max_claims_per_host
        {
            return Err(StoreError::QuotaExceeded(format!(
                "claim quota exceeded for host '{host}' (max {})",
                self.cfg.max_claims_per_host
            )));
        }

        // Keep agent last-seen fresh
        tx.execute(
            "INSERT INTO agents(id, host, harness, session, caps_json, seen_ms, read_position)
             VALUES(?1, ?2, ?3, ?4, '[]', ?5, 0)
             ON CONFLICT(id) DO UPDATE SET seen_ms=excluded.seen_ms",
            params![
                agent_str,
                agent_id.host,
                agent_id.harness,
                agent_id.session,
                now
            ],
        )?;

        // Gather existing live claims in this repo by OTHER agents to compute conflicts.
        let mut other_claims = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT id, agent, repo, path, note, expires_ms FROM claims
                 WHERE repo=?1 AND agent != ?2 AND expires_ms > ?3 ORDER BY id",
            )?;
            let mut rows = stmt.query(params![&req.repo, &agent_str, now])?;
            while let Some(row) = rows.next()? {
                other_claims.push(ClaimInfo {
                    id: row.get(0)?,
                    agent: row.get(1)?,
                    repo: row.get(2)?,
                    path: row.get(3)?,
                    note: row.get(4)?,
                    expires_ms: row.get(5)?,
                });
            }
        }

        let mut conflicts = Vec::new();
        for existing in &other_claims {
            if req.paths.iter().any(|p| paths_overlap(&existing.path, p)) {
                conflicts.push(existing.clone());
            }
        }

        let mut claims = Vec::new();
        for path in &req.paths {
            let existing_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM claims WHERE agent=?1 AND repo=?2 AND path=?3",
                    params![&agent_str, &req.repo, path],
                    |r| r.get(0),
                )
                .optional()?;
            let id = if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE claims SET note=?1, created_ms=?2, expires_ms=?3 WHERE id=?4",
                    params![&req.note, now, expires_ms, id],
                )?;
                id
            } else {
                tx.execute(
                    "INSERT INTO claims(agent, repo, path, note, created_ms, expires_ms)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![&agent_str, &req.repo, path, &req.note, now, expires_ms],
                )?;
                tx.last_insert_rowid()
            };
            claims.push(ClaimInfo {
                id,
                agent: agent_str.clone(),
                repo: req.repo.clone(),
                path: path.clone(),
                note: req.note.clone(),
                expires_ms,
            });
        }
        tx.commit()?;
        Ok(ClaimResponse { claims, conflicts })
    }

    pub fn release(&self, host: &str, req: ReleaseRequest) -> Result<usize, StoreError> {
        req.validate().map_err(StoreError::BadRequest)?;
        let agent_id = AgentId::from_local(host, &req.agent).map_err(StoreError::BadRequest)?;
        let agent_str = agent_id.to_string();

        let mut db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let removed = match (req.claim_id, &req.repo) {
            (Some(cid), Some(repo)) => tx.execute(
                "DELETE FROM claims WHERE agent=?1 AND id=?2 AND repo=?3",
                params![&agent_str, cid, repo],
            )?,
            (Some(cid), None) => tx.execute(
                "DELETE FROM claims WHERE agent=?1 AND id=?2",
                params![&agent_str, cid],
            )?,
            (None, Some(repo)) => tx.execute(
                "DELETE FROM claims WHERE agent=?1 AND repo=?2",
                params![&agent_str, repo],
            )?,
            (None, None) => tx.execute("DELETE FROM claims WHERE agent=?1", [&agent_str])?,
        };
        tx.commit()?;
        Ok(removed)
    }

    pub fn status(&self, caller_host: &str) -> Result<StatusResponse, StoreError> {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.cfg.agent_ttl_ms);
        let db = self.read_pool.acquire()?;

        let seq_head: i64 =
            db.query_row("SELECT COALESCE(MAX(seq), 0) FROM messages", [], |r| {
                r.get(0)
            })?;

        let mut agents = Vec::new();
        {
            let mut stmt = db.prepare(
                "SELECT id, host, harness, session, repo, worktree, branch, head, caps_json, note, seen_ms
                 FROM agents ORDER BY seen_ms DESC LIMIT 200",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let caps_json: String = row.get(8)?;
                let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
                let seen_ms: i64 = row.get(10)?;
                agents.push(AgentInfo {
                    id: row.get(0)?,
                    host: row.get(1)?,
                    harness: row.get(2)?,
                    session: row.get(3)?,
                    repo: row.get(4)?,
                    worktree: row.get(5)?,
                    branch: row.get(6)?,
                    head: row.get(7)?,
                    caps,
                    note: row.get(9)?,
                    seen_ms,
                    live: seen_ms >= cutoff,
                });
            }
        }

        let mut claims = Vec::new();
        {
            let mut stmt = db.prepare(
                "SELECT id, agent, repo, path, note, expires_ms FROM claims
                 WHERE expires_ms > ?1 ORDER BY id ASC LIMIT 200",
            )?;
            let mut rows = stmt.query([now])?;
            while let Some(row) = rows.next()? {
                claims.push(ClaimInfo {
                    id: row.get(0)?,
                    agent: row.get(1)?,
                    repo: row.get(2)?,
                    path: row.get(3)?,
                    note: row.get(4)?,
                    expires_ms: row.get(5)?,
                });
            }
        }

        let mut open_requests = Vec::new();
        {
            let mut stmt = db.prepare(
                "SELECT seq, thread, sender, to_json, performative, body, accepted_by, accept_expires_ms, created_ms
                 FROM messages
                 WHERE performative IN ('REQUEST', 'REQUEST_VERIFY') AND closed = 0 AND expires_ms > ?1
                 ORDER BY seq ASC LIMIT 200",
            )?;
            let mut rows = stmt.query([now])?;
            while let Some(row) = rows.next()? {
                let sender: String = row.get(2)?;
                let to_json: String = row.get(3)?;
                if !host_can_view_message(&db, caller_host, &sender, &to_json)? {
                    continue;
                }
                let to: Vec<String> = serde_json::from_str(&to_json).unwrap_or_default();
                let perf_str: String = row.get(4)?;
                let Some(performative) = Performative::parse(&perf_str) else {
                    continue;
                };
                let body: String = row.get(5)?;
                let summary: String = body
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(160)
                    .collect();
                let accepted_by: Option<String> = row.get(6)?;
                let accept_expires_ms: Option<i64> = row.get(7)?;
                let active_acceptor = accepted_by.filter(|_| accept_expires_ms.unwrap_or(0) > now);
                let active_exp = active_acceptor.as_ref().and(accept_expires_ms);
                open_requests.push(OpenRequest {
                    seq: row.get::<_, i64>(0)? as u64,
                    thread: row.get(1)?,
                    sender,
                    to,
                    performative,
                    summary,
                    accepted_by: active_acceptor,
                    accept_expires_ms: active_exp,
                    created_ms: row.get(8)?,
                });
            }
        }

        Ok(StatusResponse {
            notice: UNTRUSTED_NOTICE.to_string(),
            host: caller_host.to_string(),
            seq_head: seq_head.max(0) as u64,
            agents,
            claims,
            open_requests,
        })
    }

    pub fn thread(&self, caller_host: &str, thread: &str) -> Result<ThreadResponse, StoreError> {
        check_name("thread", thread).map_err(StoreError::BadRequest)?;
        let now = now_ms();
        let db = self.read_pool.acquire()?;

        let mut messages = Vec::new();
        let mut accepted_by = None;
        let mut accept_expires_ms = None;
        let mut closed = false;
        let mut caller_is_authorized = false;

        // Query up to 201 messages to detect truncation
        let mut stmt = db.prepare(
            "SELECT seq, msg_id, created_ms, expires_ms, sender, to_json, performative, thread, reply_to, body, payload_json,
                    assigned_group, task_category, assigned_role, not_before_ms,
                    accepted_by, accept_expires_ms, closed
             FROM messages WHERE thread=?1 AND expires_ms > ?2 ORDER BY seq ASC LIMIT 201",
        )?;
        let mut rows = stmt.query(params![thread, now])?;
        while let Some(row) = rows.next()? {
            let sender: String = row.get(4)?;
            let to_json: String = row.get(5)?;
            if !host_can_view_message(&db, caller_host, &sender, &to_json)? {
                continue;
            }
            caller_is_authorized = true;
            let msg = decode_message_row(row)?;
            if msg.performative.is_request() {
                let ab: Option<String> = row.get(15)?;
                let ae: Option<i64> = row.get(16)?;
                closed = row.get::<_, i64>(17)? != 0;
                accepted_by = ab.filter(|_| ae.unwrap_or(0) > now || closed);
                accept_expires_ms = if closed {
                    None
                } else {
                    accepted_by.as_ref().and(ae)
                };
            }
            messages.push(msg);
        }
        drop(rows);
        drop(stmt);

        if messages.is_empty() || !caller_is_authorized {
            return Err(StoreError::NotFound(format!("thread '{thread}' not found")));
        }

        let truncated = messages.len() > 200;
        if truncated {
            messages.truncate(200);
        }

        Ok(ThreadResponse {
            notice: UNTRUSTED_NOTICE.to_string(),
            thread: thread.to_string(),
            messages,
            accepted_by,
            accept_expires_ms,
            closed,
            truncated,
        })
    }

    pub fn put_artifact(
        &self,
        host: &str,
        agent: &str,
        sha256: &str,
        name: &str,
        compressed_br: &[u8],
    ) -> Result<ArtifactInfo, StoreError> {
        let agent_id = AgentId::from_local(host, agent).map_err(StoreError::BadRequest)?;
        check_sha256(sha256).map_err(StoreError::BadRequest)?;
        check_artifact_name(name).map_err(StoreError::BadRequest)?;

        if compressed_br.len() > MAX_ARTIFACT_BR_BYTES {
            return Err(StoreError::BadRequest(format!(
                "artifact exceeds maximum size of {MAX_ARTIFACT_BR_BYTES} bytes"
            )));
        }

        let raw = decompress_verified(compressed_br, sha256).map_err(StoreError::BadRequest)?;
        if let Some(rule) = find_secret_bytes(&raw) {
            return Err(StoreError::BadRequest(format!(
                "artifact rejected: contains {rule}"
            )));
        }

        // Lock file IO before DB connection to enforce consistent lock order with prune_expired
        let _io_guard = self
            .artifact_io_lock
            .lock()
            .map_err(|_| StoreError::Internal("artifact lock poisoned".into()))?;

        let db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let now = now_ms();

        let existing_exp: Option<i64> = db
            .query_row(
                "SELECT expires_ms FROM artifacts WHERE sha256 = ?1",
                [sha256],
                |r| r.get(0),
            )
            .optional()?;
        let already_unexpired = existing_exp.is_some_and(|exp| exp > now);

        // Check storage quota
        let current_bytes: i64 = db.query_row(
            "SELECT COALESCE(SUM(br_bytes), 0) FROM artifacts WHERE expires_ms > ?1",
            [now],
            |r| r.get(0),
        )?;
        let additional = if already_unexpired {
            0
        } else {
            compressed_br.len() as u64
        };
        if (current_bytes as u64).saturating_add(additional) > self.cfg.max_artifacts_total_bytes {
            return Err(StoreError::StorageFull(format!(
                "artifact storage quota exceeded (max {} bytes)",
                self.cfg.max_artifacts_total_bytes
            )));
        }

        let blob_path = self.artifacts_dir.join(format!("{sha256}.br"));
        aim_fs::write_private_atomic(&blob_path, compressed_br, true)
            .map_err(StoreError::Internal)?;

        let expires_ms = now.saturating_add(self.cfg.default_message_ttl_ms);
        let info = ArtifactInfo {
            sha256: sha256.to_string(),
            name: name.to_string(),
            raw_bytes: raw.len() as u64,
            br_bytes: compressed_br.len() as u64,
            sender: agent_id.to_string(),
            created_ms: now,
            expires_ms,
        };

        db.execute(
            "INSERT INTO artifacts(sha256, name, sender, host, raw_bytes, br_bytes, created_ms, expires_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(sha256) DO UPDATE SET
               name = CASE WHEN artifacts.expires_ms <= excluded.created_ms THEN excluded.name ELSE artifacts.name END,
               sender = CASE WHEN artifacts.expires_ms <= excluded.created_ms THEN excluded.sender ELSE artifacts.sender END,
               host = CASE WHEN artifacts.expires_ms <= excluded.created_ms THEN excluded.host ELSE artifacts.host END,
               raw_bytes = CASE WHEN artifacts.expires_ms <= excluded.created_ms THEN excluded.raw_bytes ELSE artifacts.raw_bytes END,
               br_bytes = CASE WHEN artifacts.expires_ms <= excluded.created_ms THEN excluded.br_bytes ELSE artifacts.br_bytes END,
               created_ms = CASE WHEN artifacts.expires_ms <= excluded.created_ms THEN excluded.created_ms ELSE artifacts.created_ms END,
               expires_ms = MAX(artifacts.expires_ms, excluded.expires_ms)",
            params![
                &info.sha256,
                &info.name,
                &info.sender,
                host,
                info.raw_bytes as i64,
                info.br_bytes as i64,
                info.created_ms,
                info.expires_ms,
            ],
        )?;
        db.execute(
            "INSERT INTO artifact_owners(sha256, host, expires_ms)
             VALUES(?1, ?2, ?3)
             ON CONFLICT(sha256, host) DO UPDATE SET
               expires_ms = MAX(artifact_owners.expires_ms, excluded.expires_ms)",
            params![&info.sha256, host, info.expires_ms],
        )?;

        Ok(info)
    }

    pub fn get_artifact(
        &self,
        caller_host: &str,
        sha256: &str,
        as_br: bool,
    ) -> Result<(String, Vec<u8>), StoreError> {
        check_sha256(sha256).map_err(StoreError::BadRequest)?;
        let now = now_ms();
        let db = self.read_pool.acquire()?;

        let row: Option<(String, String)> = db
            .query_row(
                "SELECT name, host FROM artifacts WHERE sha256=?1 AND expires_ms > ?2",
                params![sha256, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let Some((name, owner_host)) = row else {
            return Err(StoreError::NotFound(format!("artifact {sha256} not found")));
        };

        let caller_is_owner: bool = caller_host == owner_host
            || db
                .query_row(
                    "SELECT 1 FROM artifact_owners WHERE sha256=?1 AND host=?2 AND expires_ms > ?3",
                    params![sha256, caller_host, now],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);

        // Host authorization check:
        // Caller can access artifact if caller is an owner host OR if an owner host
        // shared the artifact in a message that caller is authorized to view.
        if !caller_is_owner {
            let mut is_authorized = false;
            let mut stmt = db.prepare(
                "SELECT sender, to_json FROM messages
                 WHERE (payload_json LIKE ?1 OR body LIKE ?1) AND expires_ms > ?2",
            )?;
            let pattern = format!("%{sha256}%");
            let mut rows = stmt.query(params![pattern, now])?;
            while let Some(r) = rows.next()? {
                let sender: String = r.get(0)?;
                let Some((sender_host, _)) = sender.split_once(':') else {
                    continue;
                };
                let sender_is_owner = sender_host == owner_host
                    || db
                        .query_row(
                            "SELECT 1 FROM artifact_owners WHERE sha256=?1 AND host=?2 AND expires_ms > ?3",
                            params![sha256, sender_host, now],
                            |_| Ok(true),
                        )
                        .optional()?
                        .unwrap_or(false);
                if !sender_is_owner {
                    continue;
                }
                let to_json: String = r.get(1)?;
                if host_can_view_message(&db, caller_host, &sender, &to_json)? {
                    is_authorized = true;
                    break;
                }
            }
            if !is_authorized {
                return Err(StoreError::NotFound(format!("artifact {sha256} not found")));
            }
        }

        let blob_path = self.artifacts_dir.join(format!("{sha256}.br"));
        let br_bytes = aim_fs::read_private_bytes(&blob_path, MAX_ARTIFACT_BR_BYTES)
            .map_err(|e| StoreError::Internal(format!("missing artifact blob: {e}")))?;
        if as_br {
            Ok((name, br_bytes))
        } else {
            let raw = decompress_verified(&br_bytes, sha256).map_err(StoreError::Internal)?;
            Ok((name, raw))
        }
    }

    pub fn prune_expired(&self) -> Result<(usize, usize, usize), StoreError> {
        let now = now_ms();
        let _io_guard = self
            .artifact_io_lock
            .lock()
            .map_err(|_| StoreError::Internal("artifact lock poisoned".into()))?;
        let mut db = self
            .conn
            .lock()
            .map_err(|_| StoreError::Internal("db lock poisoned".into()))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // Prune stale agents
        let agent_cutoff = now.saturating_sub(self.cfg.agent_retention_ms);
        let _ = tx.execute("DELETE FROM agents WHERE seen_ms <= ?1", [agent_cutoff])?;

        let msgs = tx.execute("DELETE FROM messages WHERE expires_ms <= ?1", [now])?;
        let claims = tx.execute("DELETE FROM claims WHERE expires_ms <= ?1", [now])?;

        let mut expired_shas = Vec::new();
        {
            let mut stmt = tx.prepare("SELECT sha256 FROM artifacts WHERE expires_ms <= ?1")?;
            let mut rows = stmt.query([now])?;
            while let Some(row) = rows.next()? {
                expired_shas.push(row.get::<_, String>(0)?);
            }
        }
        let arts = tx.execute("DELETE FROM artifacts WHERE expires_ms <= ?1", [now])?;
        let _ = tx.execute("DELETE FROM artifact_owners WHERE expires_ms <= ?1", [now])?;
        tx.commit()?;

        // Clean up artifact files
        for sha in &expired_shas {
            let _ = std::fs::remove_file(self.artifacts_dir.join(format!("{sha}.br")));
        }

        // Clean up orphan artifact files
        if let Ok(entries) = std::fs::read_dir(&self.artifacts_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("br") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        let exists: bool = db
                            .query_row("SELECT 1 FROM artifacts WHERE sha256=?1", [stem], |_| {
                                Ok(true)
                            })
                            .optional()
                            .unwrap_or(None)
                            .unwrap_or(false);
                        if !exists {
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
            }
        }

        let _ = db.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
        Ok((msgs, claims, arts))
    }
}

pub fn host_can_view_message(
    conn: &Connection,
    caller_host: &str,
    sender_str: &str,
    to_json: &str,
) -> Result<bool, rusqlite::Error> {
    // 1. Sender on caller host can view
    if let Some((sender_host, _)) = sender_str.split_once(':') {
        if sender_host == caller_host {
            return Ok(true);
        }
    }

    // 2. Parse recipients
    let to_strings: Vec<String> = serde_json::from_str(to_json).unwrap_or_default();
    for to_str in &to_strings {
        let Ok(selector) = Selector::parse(to_str) else {
            continue;
        };
        match selector {
            Selector::All => return Ok(true),
            Selector::Host(ref h) => {
                if h == caller_host {
                    return Ok(true);
                }
            }
            Selector::Agent(ref id) => {
                if id.host == caller_host {
                    return Ok(true);
                }
            }
            Selector::Session(ref s) => {
                let found: bool = conn
                    .query_row(
                        "SELECT 1 FROM agents WHERE host=?1 AND session=?2 LIMIT 1",
                        params![caller_host, s],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if found {
                    return Ok(true);
                }
            }
            Selector::Repo(ref r) => {
                let found: bool = conn
                    .query_row(
                        "SELECT 1 FROM agents WHERE host=?1 AND repo=?2 LIMIT 1",
                        params![caller_host, r],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if found {
                    return Ok(true);
                }
            }
            Selector::Cap(ref c) => {
                let mut stmt = conn.prepare("SELECT caps_json FROM agents WHERE host=?1")?;
                let mut rows = stmt.query([caller_host])?;
                while let Some(r) = rows.next()? {
                    let caps_json: String = r.get(0)?;
                    let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
                    if caps.contains(c) {
                        return Ok(true);
                    }
                }
            }
            Selector::Group(_) => {}
            Selector::Harness(ref h) => {
                let found: bool = conn
                    .query_row(
                        "SELECT 1 FROM agents WHERE host=?1 AND harness=?2 LIMIT 1",
                        params![caller_host, h],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if found {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn decode_message_row(row: &rusqlite::Row<'_>) -> Result<Message, rusqlite::Error> {
    let seq: i64 = row.get(0)?;
    let to_json: String = row.get(5)?;
    let to: Vec<String> = serde_json::from_str(&to_json).unwrap_or_default();
    let perf_str: String = row.get(6)?;
    let performative = Performative::parse(&perf_str).unwrap_or(Performative::Announce);
    let reply_to: Option<i64> = row.get(8)?;
    let payload_json: Option<String> = row.get(10)?;
    let payload: Option<Value> = payload_json.and_then(|s| serde_json::from_str(&s).ok());
    Ok(Message {
        seq: seq as u64,
        msg_id: row.get(1)?,
        created_ms: row.get(2)?,
        expires_ms: row.get(3)?,
        sender: row.get(4)?,
        to,
        assigned_group: row.get(11)?,
        task_category: row.get(12)?,
        assigned_role: row.get(13)?,
        not_before_ms: row.get(14)?,
        performative,
        thread: row.get(7)?,
        reply_to: reply_to.map(|v| v as u64),
        body: row.get(9)?,
        payload,
    })
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use crate::config::{
        GroupConfig, GroupMemberConfig, GroupPostingPermission, GroupRole, KeyEntry,
    };

    #[test]
    fn inbox_refreshes_stale_registered_presence_and_throttles_recent_presence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("data"), StoreConfig::default()).unwrap();
        let request = RegisterRequest {
            agent: "codex:worker".into(),
            ..RegisterRequest::default()
        };
        store.register("host", request).unwrap();
        let id = "host:codex:worker";
        let stale = now_ms().saturating_sub(360_000);
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE agents SET seen_ms=?2 WHERE id=?1",
                params![id, stale],
            )
            .unwrap();

        let poll_started = now_ms();
        store
            .inbox("host", "codex:worker", Some(0), Some(10), None, false)
            .unwrap();
        let refreshed: i64 = store
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT seen_ms FROM agents WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(refreshed >= poll_started);

        let recent = now_ms().saturating_sub(30_000);
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE agents SET seen_ms=?2 WHERE id=?1",
                params![id, recent],
            )
            .unwrap();
        store
            .inbox("host", "codex:worker", Some(0), Some(10), None, false)
            .unwrap();
        let throttled: i64 = store
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT seen_ms FROM agents WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(throttled, recent);

        store
            .inbox("host", "codex:unknown", None, None, None, false)
            .unwrap();
        let unknown_registered: bool = store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE id='host:codex:unknown')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!unknown_registered);
    }

    #[test]
    fn adds_group_assignment_columns_to_existing_message_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT NOT NULL,
                to_json TEXT NOT NULL
            );",
        )
        .unwrap();

        ensure_assignment_columns(&conn).unwrap();
        ensure_assignment_columns(&conn).unwrap();

        let mut stmt = conn.prepare("PRAGMA table_info(messages)").unwrap();
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<std::collections::HashSet<_>, _>>()
            .unwrap();
        assert!(columns.contains("assigned_group"));
        assert!(columns.contains("assigned_to"));
        assert!(columns.contains("task_category"));
        assert!(columns.contains("assigned_role"));
        assert!(columns.contains("not_before_ms"));
        assert!(columns.contains("idempotency_fingerprint"));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_messages_assignment_category'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn replaces_the_old_assignment_index_with_category_scope() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                assigned_group TEXT,
                assigned_to TEXT
            );
            CREATE INDEX idx_messages_assignment
                ON messages(assigned_group, assigned_to, seq);",
        )
        .unwrap();

        ensure_assignment_columns(&conn).unwrap();

        let old_index_count = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_messages_assignment'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        let new_index_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_messages_assignment_category'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_index_count, 0);
        assert!(new_index_sql.contains("task_category"));
    }

    #[test]
    fn group_assignment_skips_a_still_registered_but_revoked_host() {
        let dir = tempfile::tempdir().unwrap();
        let group = GroupConfig {
            name: "reviewers".into(),
            members: vec![
                GroupMemberConfig {
                    agent: "mac:codex:reviewer".into(),
                    role: GroupRole::Specialist,
                    responsibilities: vec!["build-verification".into()],
                },
                GroupMemberConfig {
                    agent: "win:claude:reviewer".into(),
                    role: GroupRole::Specialist,
                    responsibilities: vec!["build-verification".into()],
                },
            ],
            posting_permissions: vec![GroupPostingPermission {
                host: "workstation".into(),
                task_categories: vec!["build-verification".into()],
                max_expires_in_secs: 3600,
                max_schedule_delay_secs: 900,
            }],
        };
        let keyring = crate::auth::KeyRing::from_config(
            &[
                KeyEntry {
                    host: "mac".into(),
                    sha256: "ab".repeat(32),
                    enabled: true,
                },
                KeyEntry {
                    host: "win".into(),
                    sha256: "ef".repeat(32),
                    enabled: true,
                },
                KeyEntry {
                    host: "workstation".into(),
                    sha256: "cd".repeat(32),
                    enabled: true,
                },
            ],
            std::slice::from_ref(&group),
        )
        .unwrap();
        let store_cfg = StoreConfig {
            groups: vec![group.clone()],
            ..StoreConfig::default()
        };
        let store =
            Store::open_with_keyring(&dir.path().join("data"), store_cfg, keyring.clone()).unwrap();

        store
            .register(
                "mac",
                RegisterRequest {
                    agent: "codex:reviewer".into(),
                    ..RegisterRequest::default()
                },
            )
            .unwrap();
        store
            .register(
                "win",
                RegisterRequest {
                    agent: "claude:reviewer".into(),
                    ..RegisterRequest::default()
                },
            )
            .unwrap();

        keyring
            .reload_config(
                &[
                    KeyEntry {
                        host: "mac".into(),
                        sha256: "ab".repeat(32),
                        enabled: true,
                    },
                    KeyEntry {
                        host: "win".into(),
                        sha256: "ef".repeat(32),
                        enabled: false,
                    },
                    KeyEntry {
                        host: "workstation".into(),
                        sha256: "cd".repeat(32),
                        enabled: true,
                    },
                ],
                std::slice::from_ref(&group),
            )
            .unwrap();

        let request = SendRequest {
            agent: "agy:sender".into(),
            to: vec!["group:reviewers".into()],
            performative: Performative::Request,
            thread: None,
            reply_to: None,
            body: "Verify the build".into(),
            payload: None,
            idempotency_key: Some("stable-assignment".into()),
            expires_in_secs: Some(1800),
            lease_secs: None,
            task_category: Some("build-verification".into()),
            not_before_ms: Some(now_ms() + 60_000),
        };
        let (sent, _) = store.send("workstation", request.clone()).unwrap();

        assert_eq!(sent.assigned_to.as_deref(), Some("mac:codex:reviewer"));
        assert_eq!(sent.assigned_group.as_deref(), Some("reviewers"));
        assert_eq!(sent.task_category.as_deref(), Some("build-verification"));
        assert_eq!(sent.assigned_role.as_deref(), Some("specialist"));
        assert_eq!(sent.not_before_ms, request.not_before_ms);

        let expired_schedule = now_ms() - 1;
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE messages SET not_before_ms=?1 WHERE seq=?2",
                params![expired_schedule, sent.seq],
            )
            .unwrap();
        let retry = store.send("workstation", request).unwrap().0;
        assert!(retry.duplicate);
        assert_eq!(retry.assigned_to, sent.assigned_to);
        assert_eq!(retry.not_before_ms, Some(expired_schedule));

        let mac_inbox = store
            .inbox("mac", "codex:reviewer", Some(0), None, None, false)
            .unwrap();
        let win_inbox = store
            .inbox("win", "claude:reviewer", Some(0), None, None, false)
            .unwrap();
        assert_eq!(mac_inbox.messages.len(), 1);
        assert_eq!(
            mac_inbox.messages[0].assigned_group.as_deref(),
            Some("reviewers")
        );
        assert_eq!(
            mac_inbox.messages[0].task_category.as_deref(),
            Some("build-verification")
        );
        assert_eq!(
            mac_inbox.messages[0].assigned_role.as_deref(),
            Some("specialist")
        );
        assert!(win_inbox.messages.is_empty());
    }

    #[test]
    fn expired_retained_message_reserves_its_idempotency_key_until_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("data"), StoreConfig::default()).unwrap();
        let request = SendRequest {
            agent: "agy:sender".into(),
            to: vec!["mac:codex:reviewer".into()],
            performative: Performative::Request,
            thread: None,
            reply_to: None,
            body: "Check one commit".into(),
            payload: None,
            idempotency_key: Some("expiring-request".into()),
            expires_in_secs: None,
            lease_secs: None,
            task_category: None,
            not_before_ms: None,
        };
        let (sent, _) = store.send("workstation", request.clone()).unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE messages SET expires_ms=?1 WHERE seq=?2",
                params![now_ms() - 1, sent.seq],
            )
            .unwrap();

        assert!(matches!(
            store.send("workstation", request.clone()),
            Err(StoreError::Conflict(message)) if message.contains("expired retained message")
        ));

        store.prune_expired().unwrap();
        let mut reused = request;
        reused.body = "Check a different commit".into();
        let (new_message, created_seq) = store.send("workstation", reused).unwrap();
        assert!(!new_message.duplicate);
        assert!(created_seq.is_some());
    }

    #[test]
    fn migrated_legacy_idempotency_rows_allow_semantic_exact_retries() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("data"), StoreConfig::default()).unwrap();
        let request = SendRequest {
            agent: "agy:sender".into(),
            to: vec!["mac:codex:reviewer".into()],
            performative: Performative::Request,
            thread: None,
            reply_to: None,
            body: "Check this commit".into(),
            payload: Some(serde_json::json!({"commit": "abc123"})),
            idempotency_key: Some("legacy-replay".into()),
            expires_in_secs: None,
            lease_secs: None,
            task_category: Some("build-verification".into()),
            not_before_ms: Some(now_ms() + 60_000),
        };
        let (sent, _) = store.send("workstation", request.clone()).unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE messages SET idempotency_fingerprint=NULL WHERE seq=?1",
                [sent.seq],
            )
            .unwrap();

        let (retry, _) = store.send("workstation", request.clone()).unwrap();
        assert!(retry.duplicate);
        assert_eq!(retry.seq, sent.seq);
        assert_eq!(retry.thread, sent.thread);

        let mut explicit_default = request.clone();
        explicit_default.expires_in_secs = Some(7 * 24 * 3600);
        let (retry_with_explicit_default, _) = store.send("workstation", explicit_default).unwrap();
        assert!(retry_with_explicit_default.duplicate);
        assert_eq!(retry_with_explicit_default.seq, sent.seq);

        let mut changed = request;
        changed.body = "Changed request".into();
        assert!(matches!(
            store.send("workstation", changed),
            Err(StoreError::Conflict(message)) if message.contains("different request content")
        ));
    }
}
