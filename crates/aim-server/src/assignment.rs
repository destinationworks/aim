use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Transaction};

use crate::store::StoreError;

/// Choose one currently registered group member, preferring the member with
/// the oldest prior assignment for this group and task category. The exact
/// recipient is stored on the message so later retries keep the assignment.
pub(crate) fn choose(
    tx: &Transaction<'_>,
    group: &str,
    task_category: &str,
    candidates: &[String],
    cutoff_ms: i64,
    sender: &str,
) -> Result<String, StoreError> {
    let mut eligible = BTreeMap::<Option<i64>, String>::new();

    for candidate in candidates.iter().collect::<BTreeSet<_>>() {
        let agent = aim_proto::AgentId::parse_full(candidate).map_err(StoreError::BadRequest)?;
        if agent.to_string() != *candidate {
            return Err(StoreError::BadRequest(format!(
                "group member '{candidate}' is not a canonical agent ID"
            )));
        }
        if candidate == sender {
            continue;
        }
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE id=?1 AND seen_ms>=?2)",
            params![candidate, cutoff_ms],
            |row| row.get(0),
        )?;
        if active {
            let assigned_at: Option<i64> = tx.query_row(
                "SELECT MAX(seq) FROM messages
                 WHERE assigned_group=?1 AND task_category=?2 AND assigned_to=?3",
                params![group, task_category, candidate],
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
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 assigned_group TEXT,
                 task_category TEXT,
                 assigned_to TEXT
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
        db.execute(
            "INSERT INTO messages (assigned_group, task_category, assigned_to)
             VALUES ('reviewers', 'platform-verification', ?1),
                    ('reviewers', 'platform-verification', ?2)",
            params![candidates[0], candidates[1]],
        )
        .unwrap();

        let tx = db.transaction().unwrap();
        assert_eq!(
            choose(
                &tx,
                "reviewers",
                "platform-verification",
                &candidates,
                50,
                "mac:agy:sender"
            )
            .unwrap(),
            candidates[2]
        );
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
        assert_eq!(
            choose(
                &tx,
                "reviewers",
                "platform-verification",
                &candidates,
                50,
                "mac:agy:sender"
            )
            .unwrap(),
            "mac:codex:one"
        );
        tx.rollback().unwrap();
    }

    #[test]
    fn assignment_history_is_scoped_to_the_task_category() {
        let (mut db, candidates) = setup();
        db.execute(
            "INSERT INTO agents (id, seen_ms) VALUES (?1, 100), (?2, 100), (?3, 100)",
            params![candidates[0], candidates[1], candidates[2]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO messages (assigned_group, task_category, assigned_to)
             VALUES ('reviewers', 'security-review', ?1),
                    ('reviewers', 'build-verification', ?2)",
            params![candidates[0], candidates[1]],
        )
        .unwrap();

        let tx = db.transaction().unwrap();
        assert_eq!(
            choose(
                &tx,
                "reviewers",
                "security-review",
                &candidates,
                50,
                "mac:agy:sender"
            )
            .unwrap(),
            candidates[2]
        );
        assert_eq!(
            choose(
                &tx,
                "reviewers",
                "build-verification",
                &candidates,
                50,
                "mac:agy:sender"
            )
            .unwrap(),
            candidates[0]
        );
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
        assert_eq!(
            choose(
                &tx,
                "reviewers",
                "platform-verification",
                &candidates,
                50,
                "mac:agy:sender"
            )
            .unwrap(),
            candidates[1]
        );
        tx.rollback().unwrap();
    }

    #[test]
    fn refuses_empty_or_stale_group_without_assignment() {
        let (mut db, candidates) = setup();
        let tx = db.transaction().unwrap();
        assert!(matches!(
            choose(
                &tx,
                "reviewers",
                "platform-verification",
                &candidates,
                50,
                "mac:agy:sender"
            ),
            Err(StoreError::Conflict(message)) if message.contains("no active")
        ));
        tx.rollback().unwrap();
    }

    #[test]
    fn never_assigns_a_request_back_to_its_sender() {
        let (mut db, candidates) = setup();
        db.execute(
            "INSERT INTO agents (id, seen_ms) VALUES (?1, 100)",
            [&candidates[0]],
        )
        .unwrap();

        let tx = db.transaction().unwrap();
        assert!(matches!(
            choose(
                &tx,
                "reviewers",
                "platform-verification",
                &[candidates[0].clone()],
                50,
                &candidates[0]
            ),
            Err(StoreError::Conflict(message)) if message.contains("no active")
        ));
        tx.rollback().unwrap();
    }
}
