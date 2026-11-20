pub mod config;
pub mod dispatch;
pub mod state;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aim_proto::names::sanitize_display;
use aim_proto::wire::{
    AckRequest, Message, MultiInboxAgentQuery, MultiInboxEntry, MultiInboxRequest, RegisterRequest,
};
use aim_proto::MAX_WAIT_SECS;
use clap::Args;
use serde::Serialize;

use crate::client::AimClient;
use crate::config::{default_os_caps, registration_git_context};

use self::config::{
    default_policy_path, default_state_path, evaluate_message, load_policy_file, FilterDecision,
    SessionPolicy, SpawnerPolicy, WakePolicyFile,
};
use self::dispatch::{
    build_session_command, build_spawner_command, execute_prepared, resolve_executable,
    DispatchJob, DispatchOutcome, PreparedCommand,
};
use self::state::{DispatchStatus, WakeState};

const MAX_FAILURE_LOG_BACKOFF_SECS: u64 = 16;

#[derive(Args, Clone, Debug)]
pub struct WakeArgs {
    /// Path to wake.toml policy (defaults next to config.toml or AIM_WAKE_CONFIG)
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Path to durable wake state JSON (defaults to OS local state dir)
    #[arg(long)]
    pub state: Option<PathBuf>,

    /// Run one registration, due-schedule sweep, and inbox poll cycle then exit
    #[arg(long)]
    pub once: bool,

    /// Show validated wake policy summary and durable cursor/dispatch counts without polling
    #[arg(long)]
    pub status: bool,

    /// Evaluate policy and advance cursors without executing external agent CLIs
    #[arg(long)]
    pub dry_run: bool,

    /// Override long-poll wait seconds per cycle (0-30)
    #[arg(long)]
    pub wait: Option<u64>,

    /// Maximum daemon poll cycles before exiting cleanly (omit to run until stopped)
    #[arg(long)]
    pub max_cycles: Option<u64>,
}

#[derive(Clone)]
enum TargetEntry<'a> {
    Session {
        id: &'a str,
        agent_id: String,
        policy: &'a SessionPolicy,
    },
    Spawner {
        id: &'a str,
        agent_id: String,
        policy: &'a SpawnerPolicy,
    },
}

impl<'a> TargetEntry<'a> {
    fn agent_id(&self) -> &str {
        match self {
            Self::Session { agent_id, .. } | Self::Spawner { agent_id, .. } => agent_id,
        }
    }

    fn is_spawner(&self) -> bool {
        matches!(self, Self::Spawner { .. })
    }

    fn cwd(&self) -> Option<&Path> {
        match self {
            Self::Session { policy, .. } => policy.cwd.as_deref(),
            Self::Spawner { policy, .. } => Some(policy.cwd.as_path()),
        }
    }

    fn rule(&self) -> config::MessageRule<'a> {
        match self {
            Self::Session { policy, .. } => policy.as_rule(),
            Self::Spawner { policy, .. } => policy.as_rule(),
        }
    }

    fn ack_on_dispatch(&self) -> bool {
        match self {
            Self::Session { policy, .. } => policy.ack_on_dispatch,
            Self::Spawner { policy, .. } => policy.ack_on_dispatch,
        }
    }

    fn build_command(
        &self,
        file: &WakePolicyFile,
        msg: &Message,
    ) -> Result<PreparedCommand, String> {
        match self {
            Self::Session { id, policy, .. } => build_session_command(file, id, policy, msg),
            Self::Spawner { id, policy, .. } => build_spawner_command(file, id, policy, msg),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct WakeRunSummary {
    pub enabled: bool,
    pub dry_run: bool,
    pub cycles: u64,
    pub registered: usize,
    pub multi_inbox_supported: bool,
    pub recovered_uncertain: bool,
    pub deferred: usize,
    pub skipped: usize,
    pub dispatched: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

#[derive(Serialize)]
struct TargetStatusView {
    agent: String,
    kind: &'static str,
    harness: String,
    backend: String,
    enabled: bool,
    cursor: Option<u64>,
    deferred: usize,
    delivered: usize,
    uncertain: usize,
    failed: usize,
    in_flight: usize,
}

#[derive(Serialize)]
struct WakeStatusView {
    policy_path: String,
    policy_exists: bool,
    state_path: String,
    enabled: bool,
    policy_error: Option<String>,
    targets: Vec<TargetStatusView>,
}

struct CompletionEvent {
    agent_id: String,
    seq: u64,
    msg_id: String,
    ack_on_dispatch: bool,
    spawner_key: Option<String>,
    outcome: DispatchOutcome,
}

pub fn run_status(args: &WakeArgs, pretty: bool) -> Result<i32, String> {
    let policy_path = default_policy_path(args.policy.as_deref())?;
    let state_path = default_state_path(args.state.as_deref())?;
    let policy_exists = policy_path.exists();
    let (policy, policy_error) = match load_policy_file(&policy_path) {
        Ok(p) => (p, None),
        Err(e) => (WakePolicyFile::default(), Some(e)),
    };
    let state = WakeState::load_readonly(&state_path).unwrap_or_default();

    let mut targets = Vec::new();
    for (id, sess) in &policy.sessions {
        let agent = format!("{}:{id}", sess.harness);
        let backend = sess
            .resolve_backend()
            .map_or_else(|_| "invalid".to_string(), |b| b.as_str().to_string());
        targets.push(build_status_view(
            agent,
            "session",
            sess.harness.clone(),
            backend,
            sess.enabled,
            state.agents.get(&format!("{}:{id}", sess.harness)),
        ));
    }
    for (id, spawner) in &policy.spawners {
        let agent = format!("{}:{id}", spawner.harness);
        let backend = spawner
            .resolve_backend()
            .map_or_else(|_| "invalid".to_string(), |b| b.as_str().to_string());
        targets.push(build_status_view(
            agent,
            "spawner",
            spawner.harness.clone(),
            backend,
            spawner.enabled,
            state.agents.get(&format!("{}:{id}", spawner.harness)),
        ));
    }

    let view = WakeStatusView {
        policy_path: policy_path.display().to_string(),
        policy_exists,
        state_path: state_path.display().to_string(),
        enabled: policy.enabled && policy_error.is_none(),
        policy_error,
        targets,
    };
    print_json(&view, pretty)?;
    Ok(0)
}

fn build_status_view(
    agent: String,
    kind: &'static str,
    harness: String,
    backend: String,
    enabled: bool,
    st: Option<&state::AgentWakeState>,
) -> TargetStatusView {
    let mut delivered = 0usize;
    let mut uncertain = 0usize;
    let mut failed = 0usize;
    let mut in_flight = 0usize;
    if let Some(st) = st {
        for rec in st.records.values() {
            match rec.status {
                DispatchStatus::Delivered => delivered += 1,
                DispatchStatus::Uncertain => uncertain += 1,
                DispatchStatus::Failed => failed += 1,
                DispatchStatus::InFlight => in_flight += 1,
            }
        }
    }
    TargetStatusView {
        agent,
        kind,
        harness,
        backend,
        enabled,
        cursor: st.and_then(|s| s.cursor),
        deferred: st.map_or(0, |s| s.deferred.len()),
        delivered,
        uncertain,
        failed,
        in_flight,
    }
}

pub fn run(client: &AimClient, args: &WakeArgs, pretty: bool) -> Result<i32, String> {
    let policy_path = default_policy_path(args.policy.as_deref())?;
    let state_path = default_state_path(args.state.as_deref())?;
    let policy = load_policy_file(&policy_path)?;
    if !policy.enabled {
        return Err(format!(
            "aim wake is disabled by default; set `enabled = true` and enable at least one session or spawner in {}",
            policy_path.display()
        ));
    }

    let targets = collect_enabled_targets(&policy)?;
    if targets.is_empty() {
        return Err(format!(
            "aim wake has no enabled sessions or spawners in {}",
            policy_path.display()
        ));
    }
    if !args.dry_run {
        verify_target_binaries(&policy, &targets)?;
    }

    if let Some(parent) = state_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            aim_fs::ensure_private_dir(parent).map_err(|e| {
                format!(
                    "cannot create wake state directory {}: {e}",
                    parent.display()
                )
            })?;
        } else {
            aim_fs::verify_dir_not_writable_by_others(parent).map_err(|e| {
                format!(
                    "wake state directory {} is not safely protected ({e})",
                    parent.display()
                )
            })?;
        }
    }
    let lock_path = lock_path_for_state(&state_path);
    let _lock_guard = aim_fs::lock_file_exclusive(&lock_path).map_err(|e| {
        format!(
            "another `aim wake` instance holds {}: {e}",
            lock_path.display()
        )
    })?;

    let (mut state, recovered_uncertain) = WakeState::load_for_run(&state_path, now_ms())?;
    if recovered_uncertain {
        state.save(&state_path)?;
    }

    let summary = run_loop_with_state(
        client,
        &policy,
        &targets,
        &state_path,
        &mut state,
        args,
        recovered_uncertain,
    )?;
    print_json(&summary, pretty)?;
    Ok(0)
}

fn collect_enabled_targets(policy: &WakePolicyFile) -> Result<Vec<TargetEntry<'_>>, String> {
    let mut out = Vec::new();
    for (id, sess) in &policy.sessions {
        if sess.enabled {
            out.push(TargetEntry::Session {
                id,
                agent_id: format!("{}:{id}", sess.harness),
                policy: sess,
            });
        }
    }
    for (id, spawner) in &policy.spawners {
        if spawner.enabled {
            out.push(TargetEntry::Spawner {
                id,
                agent_id: format!("{}:{id}", spawner.harness),
                policy: spawner,
            });
        }
    }
    Ok(out)
}

fn verify_target_binaries(
    policy: &WakePolicyFile,
    targets: &[TargetEntry<'_>],
) -> Result<(), String> {
    let mut needed = BTreeSet::new();
    for target in targets {
        let backend = match target {
            TargetEntry::Session { policy: p, .. } => p.resolve_backend()?,
            TargetEntry::Spawner { policy: p, .. } => p.resolve_backend()?,
        };
        let (prog, explicit) = match backend {
            config::BackendKind::Agentapi => ("agentapi", policy.agentapi_bin.as_deref()),
            config::BackendKind::AgyCli => ("agy", policy.agy_bin.as_deref()),
            config::BackendKind::ClaudeCli => ("claude", policy.claude_bin.as_deref()),
        };
        if needed.insert((prog, explicit.map(Path::to_path_buf))) {
            let _ = resolve_executable(explicit, prog)?;
        }
    }
    Ok(())
}

fn run_loop_with_state(
    client: &AimClient,
    policy: &WakePolicyFile,
    targets: &[TargetEntry<'_>],
    state_path: &Path,
    state: &mut WakeState,
    args: &WakeArgs,
    recovered_uncertain: bool,
) -> Result<WakeRunSummary, String> {
    let mut summary = WakeRunSummary {
        enabled: true,
        dry_run: args.dry_run,
        multi_inbox_supported: true,
        recovered_uncertain,
        ..WakeRunSummary::default()
    };

    let target_map: BTreeMap<String, &TargetEntry<'_>> = targets
        .iter()
        .map(|t| (t.agent_id().to_string(), t))
        .collect();

    let (tx, rx) = mpsc::channel::<CompletionEvent>();
    let mut active_sessions = BTreeSet::<String>::new();
    let mut active_spawns = BTreeMap::<String, u32>::new();
    let mut in_flight_count = 0usize;
    let mut last_heartbeat: Option<Instant> = None;
    let mut backoff_secs = 1u64;

    let max_cycles = if args.once { Some(1) } else { args.max_cycles };
    let configured_wait = args.wait.unwrap_or(policy.wait_secs).min(MAX_WAIT_SECS);
    let heartbeat_interval = Duration::from_secs(policy.heartbeat_secs);

    loop {
        if let Some(limit) = max_cycles {
            if summary.cycles >= limit {
                break;
            }
        }
        summary.cycles += 1;

        drain_completions(
            client,
            state,
            state_path,
            &rx,
            &mut active_sessions,
            &mut active_spawns,
            &mut in_flight_count,
            &mut summary,
        );

        let now = Instant::now();
        if last_heartbeat.is_none_or(|prev| now.duration_since(prev) >= heartbeat_interval) {
            for target in targets {
                match register_target(client, target) {
                    Ok(()) => summary.registered += 1,
                    Err(e) => push_bounded_error(&mut summary.errors, e),
                }
            }
            last_heartbeat = Some(Instant::now());
        }

        let current_ms = now_ms();
        let mut backpressured = false;

        // 1. Dispatch due scheduled wakes before fetching fresh messages.
        for target in targets {
            let agent_id = target.agent_id().to_string();
            let due = state.agent_mut(&agent_id).take_due(current_ms);
            for msg in due {
                match try_dispatch_message(
                    client,
                    policy,
                    state,
                    state_path,
                    target,
                    msg,
                    args.dry_run,
                    &tx,
                    &mut active_sessions,
                    &mut active_spawns,
                    &mut in_flight_count,
                    &mut summary,
                ) {
                    DispatchAttempt::Accepted => {}
                    DispatchAttempt::DeferredLater => {}
                    DispatchAttempt::Busy(deferred_msg) => {
                        state
                            .agent_mut(&agent_id)
                            .defer_message(current_ms, *deferred_msg);
                        let _ = state.save(state_path);
                        backpressured = true;
                    }
                    DispatchAttempt::Skipped => {}
                }
            }
        }

        // 2. Poll hub inboxes (batched when /v1/inbox/multi is supported).
        let queries = build_queries(targets, state);
        let cycle_wait = if max_cycles.is_some_and(|l| summary.cycles >= l) || args.once {
            Some(0)
        } else {
            effective_wait_secs(
                configured_wait,
                state.earliest_due_ms(),
                current_ms,
                in_flight_count > 0 || backpressured,
            )
        };

        let mut polled_entries = None;
        if summary.multi_inbox_supported {
            let multi_req = MultiInboxRequest {
                agents: queries.clone(),
                limit: Some(100),
                wait_secs: cycle_wait,
            };
            match client.inbox_multi_if_supported(&multi_req) {
                Ok(Some(res)) => {
                    polled_entries = Some(res.inboxes);
                    backoff_secs = 1;
                }
                Ok(None) => {
                    summary.multi_inbox_supported = false;
                }
                Err(err) => {
                    push_bounded_error(&mut summary.errors, err);
                }
            }
        }

        if polled_entries.is_none() && !summary.multi_inbox_supported {
            let mut entries = Vec::with_capacity(queries.len());
            let mut any_ok = false;
            for (idx, q) in queries.iter().enumerate() {
                let per_wait = if idx + 1 == queries.len() {
                    cycle_wait
                } else {
                    Some(0)
                };
                match client.inbox(
                    &q.agent,
                    q.after,
                    per_wait,
                    Some(100),
                    q.thread.as_deref(),
                    q.include_self,
                ) {
                    Ok(resp) => {
                        any_ok = true;
                        entries.push(MultiInboxEntry {
                            agent: q.agent.clone(),
                            thread: q.thread.clone(),
                            messages: resp.messages,
                            seq_head: resp.seq_head,
                            next_after: resp.next_after,
                            read_position: resp.read_position,
                        });
                    }
                    Err(err) => push_bounded_error(&mut summary.errors, err),
                }
            }
            if any_ok {
                polled_entries = Some(entries);
                backoff_secs = 1;
            }
        }

        if let Some(entries) = polled_entries {
            let poll_ms = now_ms();
            let mut dirty_state = false;
            for entry in entries {
                let Some(target) = target_map
                    .get(&entry.agent)
                    .copied()
                    .or_else(|| resolve_target_by_canonical(&target_map, &entry.agent))
                else {
                    continue;
                };
                let key = target.agent_id().to_string();
                if state.agent_mut(&key).cursor.is_none() {
                    let initial_hwm = if entry.seq_head > 0 || entry.messages.is_empty() {
                        entry.seq_head
                    } else {
                        entry.next_after
                    };
                    let agent_state = state.agent_mut(&key);
                    agent_state.cursor = Some(initial_hwm);
                    agent_state.bootstrap_seq_head = Some(initial_hwm);
                    dirty_state = true;
                    continue;
                }

                let mut next_cursor = state.agent_mut(&key).cursor.unwrap_or(0);
                for msg in entry.messages {
                    let seq = msg.seq;
                    if seq <= next_cursor || state.agent_mut(&key).has_seq(seq) {
                        next_cursor = next_cursor.max(seq);
                        continue;
                    }
                    match try_dispatch_message(
                        client,
                        policy,
                        state,
                        state_path,
                        target,
                        msg,
                        args.dry_run,
                        &tx,
                        &mut active_sessions,
                        &mut active_spawns,
                        &mut in_flight_count,
                        &mut summary,
                    ) {
                        DispatchAttempt::Accepted
                        | DispatchAttempt::DeferredLater
                        | DispatchAttempt::Skipped => {
                            next_cursor = next_cursor.max(seq);
                            dirty_state = true;
                        }
                        DispatchAttempt::Busy(_) => {
                            // Stop advancing cursor here so the next cycle re-reads this seq.
                            backpressured = true;
                            break;
                        }
                    }
                }
                if !backpressured {
                    next_cursor = next_cursor.max(entry.next_after);
                }
                let agent_state = state.agent_mut(&key);
                if agent_state.cursor != Some(next_cursor) {
                    agent_state.cursor = Some(next_cursor);
                    dirty_state = true;
                }
                let _ = poll_ms;
            }
            if dirty_state {
                state.save(state_path)?;
            }
        } else if !max_cycles.is_some_and(|l| summary.cycles >= l) {
            std::thread::sleep(Duration::from_secs(backoff_secs));
            backoff_secs = (backoff_secs * 2).min(MAX_FAILURE_LOG_BACKOFF_SECS);
        }

        if let Some(limit) = max_cycles {
            if summary.cycles >= limit {
                break;
            }
        }

        // Wait briefly for in-flight jobs if backpressured or approaching a scheduled wake.
        if in_flight_count > 0 && backpressured {
            if let Ok(done) = rx.recv_timeout(Duration::from_secs(1)) {
                apply_completion(
                    client,
                    state,
                    done,
                    &mut active_sessions,
                    &mut active_spawns,
                    &mut in_flight_count,
                    &mut summary,
                );
                let _ = state.save(state_path);
            }
        }
    }

    // Drain all remaining background dispatches started during our run before returning.
    while in_flight_count > 0 {
        match rx.recv() {
            Ok(done) => {
                apply_completion(
                    client,
                    state,
                    done,
                    &mut active_sessions,
                    &mut active_spawns,
                    &mut in_flight_count,
                    &mut summary,
                );
                let _ = state.save(state_path);
            }
            Err(_) => break,
        }
    }

    Ok(summary)
}

enum DispatchAttempt {
    Accepted,
    DeferredLater,
    Busy(Box<Message>),
    Skipped,
}

#[allow(clippy::too_many_arguments)]
fn try_dispatch_message(
    client: &AimClient,
    policy: &WakePolicyFile,
    state: &mut WakeState,
    state_path: &Path,
    target: &TargetEntry<'_>,
    msg: Message,
    dry_run: bool,
    tx: &mpsc::Sender<CompletionEvent>,
    active_sessions: &mut BTreeSet<String>,
    active_spawns: &mut BTreeMap<String, u32>,
    in_flight_count: &mut usize,
    summary: &mut WakeRunSummary,
) -> DispatchAttempt {
    let key = target.agent_id().to_string();
    let seq = msg.seq;
    let msg_id = msg.msg_id.clone();
    let current_ms = now_ms();

    match evaluate_message(&target.rule(), &msg, current_ms) {
        FilterDecision::Skip(_) => {
            summary.skipped += 1;
            return DispatchAttempt::Skipped;
        }
        FilterDecision::DeferUntil(deliver_at) => {
            state.agent_mut(&key).defer_message(deliver_at, msg);
            summary.deferred += 1;
            return DispatchAttempt::DeferredLater;
        }
        FilterDecision::DeliverNow => {}
    }

    if target.is_spawner() {
        let cap = match target {
            TargetEntry::Spawner { policy: sp, .. } => sp.max_concurrent,
            TargetEntry::Session { .. } => 1,
        };
        let active = active_spawns.get(&key).copied().unwrap_or(0);
        if active >= cap {
            return DispatchAttempt::Busy(Box::new(msg));
        }
    } else if active_sessions.contains(&key) {
        return DispatchAttempt::Busy(Box::new(msg));
    }

    if dry_run {
        state.agent_mut(&key).finish_record(
            seq,
            &msg_id,
            DispatchStatus::Delivered,
            current_ms,
            Some("dry-run".into()),
        );
        summary.dispatched += 1;
        summary.succeeded += 1;
        return DispatchAttempt::Accepted;
    }

    let prepared = match target.build_command(policy, &msg) {
        Ok(cmd) => cmd,
        Err(err) => {
            state.agent_mut(&key).finish_record(
                seq,
                &msg_id,
                DispatchStatus::Failed,
                current_ms,
                Some(sanitize_display(&err, 220)),
            );
            summary.dispatched += 1;
            summary.failed += 1;
            push_bounded_error(&mut summary.errors, err);
            return DispatchAttempt::Accepted;
        }
    };

    // Persist InFlight BEFORE spawning child process so a crash cannot double-spawn on restart.
    state
        .agent_mut(&key)
        .mark_in_flight(seq, &msg_id, current_ms);
    if let Err(err) = state.save(state_path) {
        push_bounded_error(&mut summary.errors, err);
        return DispatchAttempt::Busy(Box::new(msg));
    }

    if target.is_spawner() {
        *active_spawns.entry(key.clone()).or_insert(0) += 1;
    } else {
        active_sessions.insert(key.clone());
    }
    *in_flight_count += 1;
    summary.dispatched += 1;

    let spawner_key = target.is_spawner().then(|| key.clone());
    let ack_on_dispatch = target.ack_on_dispatch();
    let job = DispatchJob {
        agent_id: key,
        target_name: target.agent_id().to_string(),
        message: msg,
        ack_on_dispatch,
        spawner_key,
        command: prepared,
    };

    let sender = tx.clone();
    std::thread::spawn(move || {
        let outcome = execute_prepared(&job.command);
        let _ = sender.send(CompletionEvent {
            agent_id: job.agent_id,
            seq: job.message.seq,
            msg_id: job.message.msg_id,
            ack_on_dispatch: job.ack_on_dispatch,
            spawner_key: job.spawner_key,
            outcome,
        });
    });

    let _ = client;
    DispatchAttempt::Accepted
}

#[allow(clippy::too_many_arguments)]
fn drain_completions(
    client: &AimClient,
    state: &mut WakeState,
    state_path: &Path,
    rx: &mpsc::Receiver<CompletionEvent>,
    active_sessions: &mut BTreeSet<String>,
    active_spawns: &mut BTreeMap<String, u32>,
    in_flight_count: &mut usize,
    summary: &mut WakeRunSummary,
) {
    let mut changed = false;
    while let Ok(done) = rx.try_recv() {
        apply_completion(
            client,
            state,
            done,
            active_sessions,
            active_spawns,
            in_flight_count,
            summary,
        );
        changed = true;
    }
    if changed {
        if let Err(err) = state.save(state_path) {
            push_bounded_error(&mut summary.errors, err);
        }
    }
}

fn apply_completion(
    client: &AimClient,
    state: &mut WakeState,
    done: CompletionEvent,
    active_sessions: &mut BTreeSet<String>,
    active_spawns: &mut BTreeMap<String, u32>,
    in_flight_count: &mut usize,
    summary: &mut WakeRunSummary,
) {
    *in_flight_count = in_flight_count.saturating_sub(1);
    if let Some(sp_key) = done.spawner_key {
        if let Some(cnt) = active_spawns.get_mut(&sp_key) {
            *cnt = cnt.saturating_sub(1);
        }
    } else {
        active_sessions.remove(&done.agent_id);
    }

    let current_ms = now_ms();
    match done.outcome {
        DispatchOutcome::Delivered { detail } => {
            summary.succeeded += 1;
            state.agent_mut(&done.agent_id).finish_record(
                done.seq,
                &done.msg_id,
                DispatchStatus::Delivered,
                current_ms,
                detail,
            );
            if done.ack_on_dispatch {
                let _ = client.ack(&AckRequest {
                    agent: done.agent_id,
                    read_to: done.seq,
                });
            }
        }
        DispatchOutcome::Failed { spawned: _, detail } => {
            summary.failed += 1;
            push_bounded_error(
                &mut summary.errors,
                format!("{} seq {}: {}", done.agent_id, done.seq, detail),
            );
            state.agent_mut(&done.agent_id).finish_record(
                done.seq,
                &done.msg_id,
                DispatchStatus::Failed,
                current_ms,
                Some(detail),
            );
        }
    }
}

fn register_target(client: &AimClient, target: &TargetEntry<'_>) -> Result<(), String> {
    let cwd = target.cwd().unwrap_or_else(|| Path::new("."));
    let git = registration_git_context(cwd, None);
    let mut caps = default_os_caps();
    caps.push("wake".to_string());
    if target.is_spawner() {
        caps.push("auto_spawn".to_string());
    }
    let note = match target {
        TargetEntry::Session { policy, .. } => {
            let backend = policy.resolve_backend().map_or("unknown", |b| b.as_str());
            Some(format!("aim-wake session ({backend})"))
        }
        TargetEntry::Spawner { policy, .. } => {
            let backend = policy.resolve_backend().map_or("unknown", |b| b.as_str());
            let groups = policy.allowed_groups.join(",");
            Some(sanitize_display(
                &format!("aim-wake spawner ({backend}) groups=[{groups}]"),
                240,
            ))
        }
    };
    client
        .register(&RegisterRequest {
            agent: target.agent_id().to_string(),
            repo: git.repo,
            worktree: git.worktree,
            branch: git.branch,
            head: git.head,
            caps,
            note,
        })
        .map(|_| ())
}

fn build_queries(targets: &[TargetEntry<'_>], state: &WakeState) -> Vec<MultiInboxAgentQuery> {
    targets
        .iter()
        .map(|t| {
            let id = t.agent_id();
            let cursor = state.agents.get(id).and_then(|s| s.cursor);
            // First poll queries past i64::MAX so the server returns seq_head atomically with zero old rows.
            let after = cursor.or(Some(i64::MAX as u64));
            MultiInboxAgentQuery {
                agent: id.to_string(),
                after,
                thread: None,
                include_self: false,
            }
        })
        .collect()
}

fn resolve_target_by_canonical<'a>(
    map: &BTreeMap<String, &'a TargetEntry<'a>>,
    returned_agent: &str,
) -> Option<&'a TargetEntry<'a>> {
    if let Some(exact) = map.get(returned_agent).copied() {
        return Some(exact);
    }
    if let Ok(full) = aim_proto::AgentId::parse_full(returned_agent) {
        let local = format!("{}:{}", full.harness, full.session);
        return map.get(&local).copied();
    }
    None
}

fn effective_wait_secs(
    configured_wait: u64,
    earliest_due_ms: Option<i64>,
    now_ms: i64,
    has_active_work: bool,
) -> Option<u64> {
    if has_active_work {
        return Some(configured_wait.min(2));
    }
    if let Some(due) = earliest_due_ms {
        let delta_ms = due.saturating_sub(now_ms).max(0) as u64;
        let secs = delta_ms / 1000;
        return Some(configured_wait.min(secs));
    }
    Some(configured_wait)
}

fn lock_path_for_state(state_path: &Path) -> PathBuf {
    let stem = state_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wake-state");
    state_path.with_file_name(format!("{stem}.lock"))
}

fn push_bounded_error(errors: &mut Vec<String>, err: String) {
    if errors.len() < 32 {
        errors.push(sanitize_display(&err, 240));
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn print_json<T: Serialize>(value: &T, pretty: bool) -> Result<(), String> {
    let text = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
    .map_err(|e| format!("failed to format JSON: {e}"))?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::config::{
        evaluate_message, parse_policy_toml, validate_policy, AllowedPerformative, BackendKind,
        FilterDecision, WakePolicyFile,
    };
    use super::dispatch::{build_session_command, build_spawner_command};
    use super::state::{DispatchStatus, WakeState};
    use aim_proto::wire::Message;
    use aim_proto::Performative;
    use tempfile::TempDir;

    fn sample_msg(performative: Performative, sender: &str, not_before_ms: Option<i64>) -> Message {
        Message {
            seq: 42,
            msg_id: "m-42".into(),
            created_ms: 1_000_000,
            expires_ms: 9_999_999_999_999,
            sender: sender.into(),
            to: vec!["lubuntu:agy:spawner-review".into()],
            assigned_group: Some("reviewers".into()),
            task_category: Some("code-review".into()),
            assigned_role: Some("reviewer".into()),
            not_before_ms,
            performative,
            thread: "t-42".into(),
            reply_to: None,
            body: "Review PR #207\x1b[31m carefully".into(),
            payload: None,
        }
    }

    #[test]
    fn policy_defaults_disabled_and_rejects_secrets() {
        let disabled: WakePolicyFile = parse_policy_toml("").unwrap();
        assert!(!disabled.enabled);

        let err = parse_policy_toml("key = \"secret\"\n").unwrap_err();
        assert!(err.contains("key_file"));

        let err = parse_policy_toml(
            r#"
enabled = true
[spawners.review]
enabled = true
cwd = "/tmp"
trusted_sender_hosts = ["macbook"]
allowed_performatives = ["ANNOUNCE"]
allowed_groups = ["reviewers"]
"#,
        )
        .unwrap_err();
        assert!(err.contains("ANNOUNCE"));
    }

    #[test]
    fn valid_policy_enforces_hosts_groups_categories_and_schedule() {
        let dir = TempDir::new().unwrap();
        let toml = format!(
            r#"
enabled = true
[spawners.review]
enabled = true
harness = "agy"
backend = "agentapi"
cwd = {:?}
model = "pro"
trusted_sender_hosts = ["macbook"]
allowed_performatives = ["REQUEST", "REQUEST_VERIFY"]
allowed_groups = ["reviewers"]
allowed_task_categories = ["code-review"]
max_schedule_delay_secs = 60
max_concurrent = 2
"#,
            dir.path().to_string_lossy()
        );
        let policy = parse_policy_toml(&toml).unwrap();
        assert!(validate_policy(&policy).is_ok());

        let spawner = &policy.spawners["review"];
        assert_eq!(spawner.resolve_backend().unwrap(), BackendKind::Agentapi);
        assert!(spawner
            .allowed_performatives
            .contains(&AllowedPerformative::RequestVerify));

        let rule = spawner.as_rule();
        let ok_msg = sample_msg(Performative::RequestVerify, "macbook:codex:s1", None);
        assert_eq!(
            evaluate_message(&rule, &ok_msg, 1_500_000),
            FilterDecision::DeliverNow
        );

        let untrusted = sample_msg(Performative::RequestVerify, "rogue:codex:s1", None);
        assert!(matches!(
            evaluate_message(&rule, &untrusted, 1_500_000),
            FilterDecision::Skip(_)
        ));

        let mut wrong_group = ok_msg.clone();
        wrong_group.assigned_group = Some("other".into());
        assert!(matches!(
            evaluate_message(&rule, &wrong_group, 1_500_000),
            FilterDecision::Skip(_)
        ));

        let scheduled = sample_msg(Performative::Request, "macbook:codex:s1", Some(1_530_000));
        assert_eq!(
            evaluate_message(&rule, &scheduled, 1_500_000),
            FilterDecision::DeferUntil(1_530_000)
        );

        let too_far = sample_msg(Performative::Request, "macbook:codex:s1", Some(1_600_000));
        assert!(matches!(
            evaluate_message(&rule, &too_far, 1_500_000),
            FilterDecision::Skip(_)
        ));
    }

    #[test]
    fn command_builders_use_argv_only_and_strip_ansi_escapes() {
        let dir = TempDir::new().unwrap();
        let fake_bin = dir.path().join("mock-bin");
        std::fs::write(&fake_bin, "").unwrap();

        let toml = format!(
            r#"
enabled = true
agentapi_bin = {bin:?}
claude_bin = {bin:?}
[sessions.main_agy]
enabled = true
harness = "agy"
backend = "agentapi"
target_id = "00381b16-2659-4624-8191-56990711bdaf"
cwd = {cwd:?}
trusted_sender_hosts = ["macbook"]
allowed_performatives = ["QUERY", "REQUEST"]

[spawners.claude_worker]
enabled = true
harness = "claude"
backend = "claude_cli"
cwd = {cwd:?}
model = "claude-sonnet-4-5"
trusted_sender_hosts = ["macbook"]
allowed_performatives = ["REQUEST"]
allowed_groups = ["workers"]
"#,
            bin = fake_bin.to_string_lossy(),
            cwd = dir.path().to_string_lossy()
        );
        let policy = parse_policy_toml(&toml).unwrap();
        let msg = sample_msg(Performative::Request, "macbook:codex:lead", None);

        let sess_cmd =
            build_session_command(&policy, "main_agy", &policy.sessions["main_agy"], &msg).unwrap();
        assert_eq!(sess_cmd.args[0], "send-message");
        assert!(sess_cmd.args[1].starts_with("--title="));
        assert_eq!(sess_cmd.args[2], "00381b16-2659-4624-8191-56990711bdaf");
        assert!(!sess_cmd.args[3].contains('\x1b'));
        assert!(sess_cmd.args[3].contains("Untrusted sender data follows"));

        let spawn_cmd = build_spawner_command(
            &policy,
            "claude_worker",
            &policy.spawners["claude_worker"],
            &msg,
        )
        .unwrap();
        assert_eq!(spawn_cmd.args[0], "-p");
        assert_eq!(spawn_cmd.args[1], "--model");
        assert_eq!(spawn_cmd.args[2], "claude-sonnet-4-5");
        assert!(spawn_cmd.args[3].contains("[AIM WAKE mode=auto-spawn"));
    }

    #[test]
    fn state_recovers_in_flight_to_uncertain_on_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wake-state.json");
        let mut st = WakeState::default();
        st.agent_mut("agy:main").cursor = Some(42);
        st.agent_mut("agy:main").mark_in_flight(42, "m-42", 1_000);
        st.save(&path).unwrap();

        let (reloaded, recovered) = WakeState::load_for_run(&path, 2_000).unwrap();
        assert!(recovered);
        let rec = &reloaded.agents["agy:main"].records[&42];
        assert_eq!(rec.status, DispatchStatus::Uncertain);
        assert!(reloaded.agents["agy:main"].has_seq(42));
    }
}
