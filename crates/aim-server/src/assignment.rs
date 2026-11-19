use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Transaction};

use crate::store::StoreError;

/// Choose one currently registered group member, preferring the member with
/// the oldest prior direct request assignment. The exact recipient is stored
/// on the message so later retries and replies keep the same assignment.
pub(crate) fn choose(
    tx: &Transaction<'_>,
    candidates: &[String],
    cutoff_ms: i64,
) -> Result<String, StoreError> {
    let mut eligible = BTreeMap::<Option<i64>, String>::new();

    for candidate in candidates.iter().collect::<BTreeSet<_>>() {
        let agent = aim_proto::AgentId::parse_full(candidate).map_err(StoreError::BadRequest)?;
        if agent.to_string() != *candidate {
            return Err(StoreError::BadRequest(format!(
                "group member '{candidate}' is not a canonical agent ID"
            )));
        }
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE id=?1 AND seen_ms>=?2)",
            params![candidate, cutoff_ms],
            |row| row.get(0),
        )?;
        if active {
            let exact_recipient = serde_json::to_string(&[candidate])
                .map_err(|error| StoreError::Internal(error.to_string()))?;
            let assigned_at: Option<i64> = tx.query_row(
                "SELECT MAX(created_ms) FROM messages
                 WHERE to_json=?1 AND performative IN ('REQUEST', 'REQUEST_VERIFY')",
                [&exact_recipient],
                |row| row.get(0),
            )?;
            eligible
                .entry(assigned_at)
                .or_insert_with(|| candidate.clone());
        }
    }

    eligible
        .into_values()
        .next()
        .ok_or_else(|| StoreError::Conflict("no active eligible group member".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup() -> (Connection, Vec<String>) {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE agents (id TEXT PRIMARY KEY, seen_ms INTEGER NOT NULL);
             CREATE TABLE messages (
                 to_json TEXT NOT NULL,
                 performative TEXT NOT NULL,
                 created_ms INTEGER NOT NULL
             );",
        )
        .unwrap();
        let candidates = vec![
            "mac:codex:one".to_string(),
            "mac:codex:two".to_string(),
            "mac:codex:three".to_string(),
        ];
        (db, candidates)
    }

    #[test]
    fn selects_active_member_with_oldest_assignment_and_stable_tie_break() {
        let (mut db, candidates) = setup();
        db.execute(
            "INSERT INTO agents (id, seen_ms) VALUES (?1, 100), (?2, 100), (?3, 100)",
            params![candidates[0], candidates[1], candidates[2]],
        )
        .unwrap();
        let first_recipient = serde_json::to_string(&[&candidates[0]]).unwrap();
        let second_recipient = serde_json::to_string(&[&candidates[1]]).unwrap();
        db.execute(
            "INSERT INTO messages (to_json, performative, created_ms)
             VALUES (?1, 'REQUEST', 20), (?2, 'REQUEST_VERIFY', 20)",
            params![first_recipient, second_recipient],
        )
        .unwrap();

        let tx = db.transaction().unwrap();
        assert_eq!(choose(&tx, &candidates, 50).unwrap(), candidates[2]);
        tx.rollback().unwrap();
    }

    #[test]
    fn assignment_ties_follow_agent_id_order_not_group_config_order() {
        let (mut db, mut candidates) = setup();
        candidates.reverse();
        db.execute(
            "INSERT INTO agents (id, seen_ms) VALUES (?1, 100), (?2, 100), (?3, 100)",
            params![candidates[0], candidates[1], candidates[2]],
        )
        .unwrap();

        let tx = db.transaction().unwrap();
        assert_eq!(choose(&tx, &candidates, 50).unwrap(), "mac:codex:one");
        tx.rollback().unwrap();
    }

    #[test]
    fn ignores_inactive_and_finds_one_active_candidate() {
        let (mut db, candidates) = setup();
        db.execute(
            "INSERT INTO agents (id, seen_ms) VALUES (?1, 49), (?2, 100)",
            params![candidates[0], candidates[1]],
        )
        .unwrap();

        let tx = db.transaction().unwrap();
        assert_eq!(choose(&tx, &candidates, 50).unwrap(), candidates[1]);
        tx.rollback().unwrap();
    }

    #[test]
    fn refuses_empty_or_stale_group_without_assignment() {
        let (mut db, candidates) = setup();
        let tx = db.transaction().unwrap();
        assert!(matches!(
            choose(&tx, &candidates, 50),
            Err(StoreError::Conflict(message)) if message.contains("no active")
        ));
        tx.rollback().unwrap();
    }
}
