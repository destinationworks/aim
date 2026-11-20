use std::collections::BTreeMap;
use std::path::Path;

use aim_proto::wire::Message;
use serde::{Deserialize, Serialize};

const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDED_DISPATCHES_PER_AGENT: usize = 512;
const MAX_DEFERRED_PER_AGENT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchStatus {
    InFlight,
    Delivered,
    Uncertain,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchRecord {
    pub seq: u64,
    pub msg_id: String,
    pub status: DispatchStatus,
    pub updated_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeferredWake {
    pub deliver_at_ms: i64,
    pub message: Message,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AgentWakeState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_seq_head: Option<u64>,
    #[serde(default)]
    pub records: BTreeMap<u64, DispatchRecord>,
    #[serde(default)]
    pub deferred: Vec<DeferredWake>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WakeState {
    pub version: u32,
    #[serde(default)]
    pub agents: BTreeMap<String, AgentWakeState>,
}

impl Default for WakeState {
    fn default() -> Self {
        Self {
            version: 1,
            agents: BTreeMap::new(),
        }
    }
}

impl WakeState {
    pub fn load_for_run(path: &Path, now_ms: i64) -> Result<(Self, bool), String> {
        let mut state = Self::load_readonly(path)?;
        let mut recovered_uncertain = false;
        for agent_state in state.agents.values_mut() {
            for record in agent_state.records.values_mut() {
                if record.status == DispatchStatus::InFlight {
                    record.status = DispatchStatus::Uncertain;
                    record.updated_ms = now_ms;
                    record.detail = Some(
                        "previous wake process exited before dispatch completed; refusing automatic retry"
                            .into(),
                    );
                    recovered_uncertain = true;
                }
            }
        }
        Ok((state, recovered_uncertain))
    }

    pub fn load_readonly(path: &Path) -> Result<Self, String> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!("refusing symlink state file {}", path.display()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(format!("cannot inspect {}: {e}", path.display())),
        }
        let raw = aim_fs::read_private_string(path, MAX_STATE_BYTES)?;
        let state: WakeState =
            serde_json::from_str(&raw).map_err(|e| format!("invalid wake state JSON: {e}"))?;
        if state.version != 1 {
            return Err(format!("unsupported wake state version {}", state.version));
        }
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("cannot serialize wake state: {e}"))?;
        aim_fs::write_private_atomic(path, &json, true)
    }

    pub fn agent_mut(&mut self, agent_id: &str) -> &mut AgentWakeState {
        self.agents.entry(agent_id.to_string()).or_default()
    }

    pub fn earliest_due_ms(&self) -> Option<i64> {
        self.agents
            .values()
            .flat_map(|a| a.deferred.iter().map(|d| d.deliver_at_ms))
            .min()
    }
}

impl AgentWakeState {
    pub fn has_seq(&self, seq: u64) -> bool {
        self.records.contains_key(&seq) || self.deferred.iter().any(|d| d.message.seq == seq)
    }

    pub fn mark_in_flight(&mut self, seq: u64, msg_id: &str, now_ms: i64) {
        self.records.insert(
            seq,
            DispatchRecord {
                seq,
                msg_id: msg_id.to_string(),
                status: DispatchStatus::InFlight,
                updated_ms: now_ms,
                detail: None,
            },
        );
        self.prune_records();
    }

    pub fn finish_record(
        &mut self,
        seq: u64,
        msg_id: &str,
        status: DispatchStatus,
        now_ms: i64,
        detail: Option<String>,
    ) {
        self.records.insert(
            seq,
            DispatchRecord {
                seq,
                msg_id: msg_id.to_string(),
                status,
                updated_ms: now_ms,
                detail,
            },
        );
        self.prune_records();
    }

    pub fn defer_message(&mut self, deliver_at_ms: i64, msg: Message) {
        if self.has_seq(msg.seq) {
            return;
        }
        if self.deferred.len() >= MAX_DEFERRED_PER_AGENT {
            // Keep earliest scheduled items when bounded capacity is reached.
            self.deferred.sort_by_key(|d| d.deliver_at_ms);
            if self
                .deferred
                .last()
                .is_some_and(|last| last.deliver_at_ms <= deliver_at_ms)
            {
                return;
            }
            self.deferred.pop();
        }
        self.deferred.push(DeferredWake {
            deliver_at_ms,
            message: msg,
        });
        self.deferred.sort_by_key(|d| d.deliver_at_ms);
    }

    pub fn take_due(&mut self, now_ms: i64) -> Vec<Message> {
        let mut due = Vec::new();
        let mut keep = Vec::with_capacity(self.deferred.len());
        for item in self.deferred.drain(..) {
            if item.deliver_at_ms <= now_ms {
                due.push(item.message);
            } else {
                keep.push(item);
            }
        }
        self.deferred = keep;
        due
    }

    fn prune_records(&mut self) {
        if self.records.len() <= MAX_RECORDED_DISPATCHES_PER_AGENT {
            return;
        }
        let excess = self.records.len() - MAX_RECORDED_DISPATCHES_PER_AGENT;
        let to_remove: Vec<u64> = self
            .records
            .iter()
            .filter(|(seq, rec)| {
                self.cursor.is_some_and(|c| **seq <= c)
                    && rec.status != DispatchStatus::InFlight
                    && rec.status != DispatchStatus::Uncertain
            })
            .take(excess)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in to_remove {
            self.records.remove(&seq);
        }
    }
}
