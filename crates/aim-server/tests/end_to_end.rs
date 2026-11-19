use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aim::client::AimClient;
use aim::config::ResolvedConfig;
use aim_proto::wire::{AckRequest, ClaimRequest, RegisterRequest, ReleaseRequest, SendRequest};
use aim_proto::{Performative, PROTOCOL};
use aim_server::auth::{generate_token, hash_token_hex};
use aim_server::certs::{init_ca, init_server_cert};
use aim_server::config::{
    GroupConfig, GroupMemberConfig, GroupPostingPermission, GroupRole, KeyEntry, ServerConfig,
};
use aim_server::serve_with_handle;
use axum_server::Handle;
use tempfile::TempDir;
use url::Url;

struct Harness {
    _dir: TempDir,
    base_url: Url,
    ca_cert: PathBuf,
    mac_key: PathBuf,
    wks_key: PathBuf,
    win_key: PathBuf,
    wrong_ca: PathBuf,
    disabled_key: PathBuf,
    handle: Handle,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

impl Harness {
    fn client_for(&self, key_file: &Path) -> AimClient {
        let cfg = ResolvedConfig {
            url: self.base_url.clone(),
            ca_cert: self.ca_cert.clone(),
            key_file: key_file.to_path_buf(),
            default_agent: None,
            caps: vec!["test".into()],
            timeout_secs: 10,
        };
        AimClient::from_config(&cfg).unwrap()
    }
}

async fn start_harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let ca_cert = root.join("ca.crt");
    let ca_key = root.join("ca.key");
    let srv_cert = root.join("server.crt");
    let srv_key = root.join("server.key");
    let wrong_ca = root.join("wrong-ca.crt");
    let wrong_ca_key = root.join("wrong-ca.key");

    init_ca(&ca_cert, &ca_key, "AIM Test CA", 365, false).unwrap();
    init_ca(&wrong_ca, &wrong_ca_key, "Wrong CA", 365, false).unwrap();
    init_server_cert(
        &ca_cert,
        &ca_key,
        &srv_cert,
        &srv_key,
        &["127.0.0.1".into(), "localhost".into()],
        365,
        false,
    )
    .unwrap();

    let mac_tok = generate_token();
    let wks_tok = generate_token();
    let win_tok = generate_token();
    let dis_tok = generate_token();

    let mac_key = root.join("macbook.key");
    let wks_key = root.join("workstation.key");
    let win_key = root.join("win-dev.key");
    let disabled_key = root.join("disabled.key");
    aim_fs::write_private_atomic(&mac_key, mac_tok.as_bytes(), false).unwrap();
    aim_fs::write_private_atomic(&wks_key, wks_tok.as_bytes(), false).unwrap();
    aim_fs::write_private_atomic(&win_key, win_tok.as_bytes(), false).unwrap();
    aim_fs::write_private_atomic(&disabled_key, dis_tok.as_bytes(), false).unwrap();

    let mut cfg = ServerConfig::defaults_for(root.join("data"), srv_cert, srv_key);
    cfg.listen = "127.0.0.1:0".into();
    cfg.base_path = "/aim".into();
    cfg.keys = vec![
        KeyEntry {
            host: "macbook".into(),
            sha256: hash_token_hex(&mac_tok),
            enabled: true,
        },
        KeyEntry {
            host: "workstation".into(),
            sha256: hash_token_hex(&wks_tok),
            enabled: true,
        },
        KeyEntry {
            host: "win-dev".into(),
            sha256: hash_token_hex(&win_tok),
            enabled: true,
        },
        KeyEntry {
            host: "revoked".into(),
            sha256: hash_token_hex(&dis_tok),
            enabled: false,
        },
    ];
    cfg.groups = vec![GroupConfig {
        name: "reviewers".into(),
        members: vec![
            GroupMemberConfig {
                agent: "macbook:codex:reviewer".into(),
                role: GroupRole::Reviewer,
                responsibilities: vec!["platform-verification".into()],
            },
            GroupMemberConfig {
                agent: "win-dev:claude:specialist".into(),
                role: GroupRole::Specialist,
                responsibilities: vec!["platform-verification".into()],
            },
        ],
        posting_permissions: vec![GroupPostingPermission {
            host: "workstation".into(),
            task_categories: vec!["platform-verification".into()],
            max_expires_in_secs: 7200,
            max_schedule_delay_secs: 3600,
        }],
    }];

    let handle = Handle::new();
    let srv_handle = handle.clone();
    let addr: SocketAddr = cfg.listen_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_with_handle(cfg, addr, srv_handle, None).await;
    });

    let bound = handle.listening().await.expect("server bound");
    let base_url = Url::parse(&format!("https://127.0.0.1:{}/aim", bound.port())).unwrap();

    Harness {
        _dir: dir,
        base_url,
        ca_cert,
        mac_key,
        wks_key,
        win_key,
        wrong_ca,
        disabled_key,
        handle,
    }
}

#[tokio::test]
async fn group_request_is_assigned_to_one_active_member_and_retry_keeps_assignment() {
    let h = start_harness().await;
    let mac = h.client_for(&h.mac_key);
    let wks = h.client_for(&h.wks_key);
    let win = h.client_for(&h.win_key);

    for (client, agent) in [
        (mac.clone(), "codex:reviewer"),
        (win.clone(), "claude:specialist"),
    ] {
        tokio::task::spawn_blocking(move || {
            client.register(&RegisterRequest {
                agent: agent.into(),
                ..RegisterRequest::default()
            })
        })
        .await
        .unwrap()
        .unwrap();
    }

    let req = SendRequest {
        agent: "agy:sender".into(),
        to: vec!["group:reviewers".into()],
        performative: Performative::RequestVerify,
        thread: None,
        reply_to: None,
        body: "Verify the cross-platform build".into(),
        payload: None,
        idempotency_key: Some("group-request-1".into()),
        expires_in_secs: Some(1800),
        lease_secs: None,
        task_category: Some("platform-verification".into()),
        not_before_ms: Some(aim_server::store::now_ms() + 30_000),
    };
    let sent = tokio::task::spawn_blocking({
        let client = wks.clone();
        let req = req.clone();
        move || client.send(&req)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(sent.assigned_to.as_deref(), Some("macbook:codex:reviewer"));
    assert_eq!(sent.assigned_group.as_deref(), Some("reviewers"));
    assert_eq!(sent.task_category.as_deref(), Some("platform-verification"));
    assert_eq!(sent.assigned_role.as_deref(), Some("reviewer"));
    assert_eq!(sent.not_before_ms, req.not_before_ms);

    let mut changed_category = req.clone();
    changed_category.task_category = Some("security-review".into());
    let conflict = tokio::task::spawn_blocking({
        let wks = wks.clone();
        move || wks.send(&changed_category)
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(conflict.contains("409"));

    let retry = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || client.send(&req)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(retry.duplicate);
    assert_eq!(retry.seq, sent.seq);
    assert_eq!(retry.assigned_to, sent.assigned_to);
    assert_eq!(retry.task_category, sent.task_category);
    assert_eq!(retry.not_before_ms, sent.not_before_ms);

    let mac_inbox = tokio::task::spawn_blocking({
        let client = mac.clone();
        move || client.inbox("codex:reviewer", Some(0), Some(0), None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    let win_inbox = tokio::task::spawn_blocking({
        let client = win.clone();
        move || client.inbox("claude:specialist", Some(0), Some(0), None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(mac_inbox.messages.len(), 1);
    assert_eq!(mac_inbox.messages[0].seq, sent.seq);
    assert_eq!(mac_inbox.messages[0].not_before_ms, sent.not_before_ms);
    assert_eq!(
        mac_inbox.messages[0].task_category.as_deref(),
        Some("platform-verification")
    );
    assert!(win_inbox.messages.is_empty());

    let lease_request = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["group:reviewers".into()],
                performative: Performative::RequestVerify,
                thread: None,
                reply_to: None,
                body: "Verify the release candidate".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(1800),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    let lease_seq = lease_request.seq;

    let requester_accept = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["macbook:codex:reviewer".into()],
                performative: Performative::Accept,
                thread: None,
                reply_to: Some(lease_seq),
                body: "The requester cannot accept this assignment".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: Some(300),
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(requester_accept.contains("409"));

    let assigned_accept = tokio::task::spawn_blocking({
        let client = mac.clone();
        move || {
            client.send(&SendRequest {
                agent: "codex:reviewer".into(),
                to: vec!["workstation:agy:sender".into()],
                performative: Performative::Accept,
                thread: None,
                reply_to: Some(lease_seq),
                body: "The assigned reviewer accepts".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: Some(300),
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert!(!assigned_accept.duplicate);

    let work_request = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["group:reviewers".into()],
                performative: Performative::Request,
                thread: None,
                reply_to: None,
                body: "Run the platform verification".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(1800),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        work_request.assigned_to.as_deref(),
        Some("win-dev:claude:specialist")
    );
    assert_eq!(work_request.assigned_role.as_deref(), Some("specialist"));
    let specialist_inbox = tokio::task::spawn_blocking({
        let client = win.clone();
        move || client.inbox("claude:specialist", Some(0), Some(0), None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(specialist_inbox.messages.len(), 1);
    assert_eq!(specialist_inbox.messages[0].seq, work_request.seq);
    assert_eq!(
        specialist_inbox.messages[0].assigned_role.as_deref(),
        Some("specialist")
    );

    let forbidden = SendRequest {
        agent: "agy:sender".into(),
        to: vec!["group:reviewers".into()],
        performative: Performative::Alert,
        thread: None,
        reply_to: None,
        body: "An alert to a group".into(),
        payload: None,
        idempotency_key: None,
        expires_in_secs: Some(1800),
        lease_secs: None,
        task_category: Some("platform-verification".into()),
        not_before_ms: None,
    };
    assert!(forbidden
        .validate()
        .unwrap_err()
        .contains("group recipient"));

    let unauthorized = tokio::task::spawn_blocking({
        let client = mac.clone();
        move || {
            client.send(&SendRequest {
                agent: "codex:sender".into(),
                to: vec!["group:reviewers".into()],
                performative: Performative::Request,
                thread: None,
                reply_to: None,
                body: "Unauthorized group post".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(1800),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap();
    let unauthorized_error = unauthorized.unwrap_err();
    assert!(unauthorized_error.contains("404"));

    let unknown_group = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["group:missing".into()],
                performative: Performative::Request,
                thread: None,
                reply_to: None,
                body: "Unknown group post".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(1800),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(unknown_group, unauthorized_error);

    let unauthorized_category = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["group:reviewers".into()],
                performative: Performative::RequestVerify,
                thread: None,
                reply_to: None,
                body: "Request outside the host grant".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(1800),
                lease_secs: None,
                task_category: Some("incident-response".into()),
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(unauthorized_category, unknown_group);

    let excessive_expiry = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["group:reviewers".into()],
                performative: Performative::RequestVerify,
                thread: None,
                reply_to: None,
                body: "Request exceeds its expiry grant".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(7201),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(excessive_expiry.contains("400"));

    let outside_schedule_grant = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["group:reviewers".into()],
                performative: Performative::RequestVerify,
                thread: None,
                reply_to: None,
                body: "Request exceeds its schedule grant".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(7200),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: Some(aim_server::store::now_ms() + 3_601_000),
            })
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(outside_schedule_grant.contains("400"));

    let after_expiry = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["group:reviewers".into()],
                performative: Performative::RequestVerify,
                thread: None,
                reply_to: None,
                body: "Request is scheduled after expiry".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(1800),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: Some(aim_server::store::now_ms() + 1_801_000),
            })
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(after_expiry.contains("400"));
}

#[tokio::test]
async fn categorized_direct_request_preserves_optional_schedule_for_recipient_policy() {
    let h = start_harness().await;
    let mac = h.client_for(&h.mac_key);
    let wks = h.client_for(&h.wks_key);
    tokio::task::spawn_blocking({
        let mac = mac.clone();
        move || {
            mac.register(&RegisterRequest {
                agent: "codex:reviewer".into(),
                ..RegisterRequest::default()
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let request = SendRequest {
        agent: "agy:sender".into(),
        to: vec!["macbook:codex:reviewer".into()],
        performative: Performative::Request,
        thread: None,
        reply_to: None,
        body: "Verify the macOS build".into(),
        payload: None,
        idempotency_key: Some("direct-categorized-request-1".into()),
        expires_in_secs: Some(1800),
        lease_secs: None,
        task_category: Some("platform-verification".into()),
        not_before_ms: Some(aim_server::store::now_ms() + 30_000),
    };
    let sent = tokio::task::spawn_blocking({
        let wks = wks.clone();
        let request = request.clone();
        move || wks.send(&request)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(sent.assigned_group, None);
    assert_eq!(sent.task_category.as_deref(), Some("platform-verification"));
    assert_eq!(sent.not_before_ms, request.not_before_ms);

    let mut changed_requests = Vec::new();
    let mut changed = request.clone();
    changed.to = vec!["win-dev:claude:specialist".into()];
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.performative = Performative::RequestVerify;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.thread = Some("different-thread".into());
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.reply_to = Some(1);
    changed.task_category = None;
    changed.not_before_ms = None;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.body = "Changed body".into();
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.payload = Some(serde_json::json!({"changed": true}));
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.expires_in_secs = Some(1801);
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.task_category = Some("security-review".into());
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.not_before_ms = Some(aim_server::store::now_ms() + 45_000);
    changed_requests.push(changed);

    for changed in changed_requests {
        let conflict = tokio::task::spawn_blocking({
            let wks = wks.clone();
            move || wks.send(&changed)
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(conflict.contains("409"), "{conflict}");
    }

    let retry = tokio::task::spawn_blocking({
        let wks = wks.clone();
        let request = request.clone();
        move || wks.send(&request)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(retry.duplicate);
    assert_eq!(retry.task_category, sent.task_category);
    assert_eq!(retry.not_before_ms, sent.not_before_ms);

    let inbox = tokio::task::spawn_blocking({
        let mac = mac.clone();
        move || mac.inbox("codex:reviewer", Some(0), Some(0), None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(inbox.messages.len(), 1);
    assert!(inbox.seq_head >= sent.seq);
    assert_eq!(
        inbox.messages[0].task_category.as_deref(),
        Some("platform-verification")
    );
    assert_eq!(inbox.messages[0].not_before_ms, sent.not_before_ms);

    let after_expiry = tokio::task::spawn_blocking({
        let wks = wks.clone();
        move || {
            wks.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["macbook:codex:reviewer".into()],
                performative: Performative::Request,
                thread: None,
                reply_to: None,
                body: "Reject a schedule after expiry".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: Some(10),
                lease_secs: None,
                task_category: Some("platform-verification".into()),
                not_before_ms: Some(aim_server::store::now_ms() + 11_000),
            })
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(after_expiry.contains("400"));
}

#[tokio::test]
async fn cross_host_protocol_tls_auth_leases_claims_and_artifacts() {
    let h = start_harness().await;
    let mac = h.client_for(&h.mac_key);
    let wks = h.client_for(&h.wks_key);
    let win = h.client_for(&h.win_key);
    let revoked = h.client_for(&h.disabled_key);

    // 1. Health works with pinned CA and fails with wrong CA.
    let health = tokio::task::spawn_blocking({
        let url = h.base_url.clone();
        let ca = h.ca_cert.clone();
        move || AimClient::health_unauth(&url, &ca, 5)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(health.status, "ok");
    assert_eq!(health.protocol, PROTOCOL);

    let bad_ca = tokio::task::spawn_blocking({
        let url = h.base_url.clone();
        let wrong = h.wrong_ca.clone();
        move || AimClient::health_unauth(&url, &wrong, 5)
    })
    .await
    .unwrap();
    assert!(bad_ca.is_err());

    // 2. Disabled/revoked key fails with 401.
    let unauth = tokio::task::spawn_blocking({
        let c = revoked.clone();
        move || c.status()
    })
    .await
    .unwrap();
    assert!(unauth.unwrap_err().contains("401"));

    // 3. Register agents on different hosts, plus path claims & conflict warning.
    let r_wks = tokio::task::spawn_blocking({
        let c = wks.clone();
        move || {
            c.register(&RegisterRequest {
                agent: "agy:s1".into(),
                repo: Some("example-app".into()),
                branch: Some("main".into()),
                head: Some("c0ffee12".into()),
                caps: vec!["linux".into(), "x86_64".into()],
                note: Some("building Linux fix".into()),
                ..Default::default()
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r_wks.agent, "workstation:agy:s1");
    assert_eq!(r_wks.host, "workstation");

    let claim1 = tokio::task::spawn_blocking({
        let c = wks.clone();
        move || {
            c.claim(&ClaimRequest {
                agent: "agy:s1".into(),
                repo: "example-app".into(),
                paths: vec!["src/ui/sidebar.rs".into()],
                ttl_secs: Some(600),
                note: Some("sidebar alignment".into()),
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert!(claim1.conflicts.is_empty());

    let r_mac = tokio::task::spawn_blocking({
        let c = mac.clone();
        move || {
            c.register(&RegisterRequest {
                agent: "codex:m1".into(),
                repo: Some("example-app".into()),
                caps: vec!["macos".into(), "macos-gui".into()],
                ..Default::default()
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r_mac.agent, "macbook:codex:m1");
    // Registering on the same repo surfaces active claims from other computers.
    assert_eq!(r_mac.conflicts.len(), 1);
    assert_eq!(r_mac.conflicts[0].agent, "workstation:agy:s1");

    // Overlapping directory claim detects conflict!
    let claim2 = tokio::task::spawn_blocking({
        let c = mac.clone();
        move || {
            c.claim(&ClaimRequest {
                agent: "codex:m1".into(),
                repo: "example-app".into(),
                paths: vec!["src/ui".into()],
                ttl_secs: None,
                note: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claim2.conflicts.len(), 1);

    // 4. Upload Brotli Q6 artifact; before it is shared in a message to macbook,
    // macbook cannot download it (cross-host artifact isolation), while uploader can.
    let raw_log = b"=== verification receipt ===\npass: 42\n".repeat(40);
    let art_info = tokio::task::spawn_blocking({
        let c = wks.clone();
        let data = raw_log.clone();
        move || c.put_artifact("agy:s1", "verify-receipt.log", &data)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(art_info.br_bytes < art_info.raw_bytes);

    let premature_fetch = tokio::task::spawn_blocking({
        let c = mac.clone();
        let sha = art_info.sha256.clone();
        move || c.get_artifact(&sha)
    })
    .await
    .unwrap();
    assert!(premature_fetch.unwrap_err().contains("404"));

    // Secret guard rejects secrets in artifacts too.
    let bad_art = tokio::task::spawn_blocking({
        let c = wks.clone();
        move || {
            c.put_artifact(
                "agy:s1",
                "bad.txt",
                b"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            )
        }
    })
    .await
    .unwrap();
    assert!(bad_art.is_err());

    // 5. Cross-computer REQUEST_VERIFY + idempotency + exclusive ACCEPT + RESULT.
    let req_msg = SendRequest {
        agent: "agy:s1".into(),
        to: vec!["cap:macos-gui".into()],
        performative: Performative::RequestVerify,
        thread: None,
        reply_to: None,
        body: "Verify settings row on macOS for commit c0ffee12".into(),
        payload: Some(serde_json::json!({ "artifact": art_info.sha256 })),
        idempotency_key: Some("step-verify-1".into()),
        expires_in_secs: None,
        lease_secs: None,
        task_category: None,
        not_before_ms: None,
    };
    let sent1 = tokio::task::spawn_blocking({
        let c = wks.clone();
        let r = req_msg.clone();
        move || c.send(&r)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(!sent1.duplicate);

    // Now that sent1 references art_info.sha256 to cap:macos-gui, macbook CAN download it,
    // while unaddressed host win-dev still gets 404!
    let fetched = tokio::task::spawn_blocking({
        let c = mac.clone();
        let sha = art_info.sha256.clone();
        move || c.get_artifact(&sha)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fetched, raw_log);

    let win_art_fetch = tokio::task::spawn_blocking({
        let c = win.clone();
        let sha = art_info.sha256.clone();
        move || c.get_artifact(&sha)
    })
    .await
    .unwrap();
    assert!(win_art_fetch.unwrap_err().contains("404"));

    // Self-authorization attempt: win-dev sends a message to itself mentioning art_info.sha256,
    // and STILL cannot download workstation's artifact (must return 404).
    tokio::task::spawn_blocking({
        let c = win.clone();
        let sha = art_info.sha256.clone();
        move || {
            c.send(&SendRequest {
                agent: "claude:w1".into(),
                to: vec!["host:win-dev".into()],
                performative: Performative::Announce,
                thread: None,
                reply_to: None,
                body: format!("Trying to self-authorize artifact {sha}"),
                payload: Some(serde_json::json!({ "artifact": sha })),
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let win_self_auth_fetch = tokio::task::spawn_blocking({
        let c = win.clone();
        let sha = art_info.sha256.clone();
        move || c.get_artifact(&sha)
    })
    .await
    .unwrap();
    assert!(win_self_auth_fetch.unwrap_err().contains("404"));

    // win-dev also cannot view the workstation <-> macbook thread or reply to it!
    let win_thread = tokio::task::spawn_blocking({
        let c = win.clone();
        let t = sent1.thread.clone();
        move || c.thread(&t)
    })
    .await
    .unwrap();
    assert!(win_thread.unwrap_err().contains("404"));

    let win_reply = tokio::task::spawn_blocking({
        let c = win.clone();
        let seq = sent1.seq;
        move || {
            c.send(&SendRequest {
                agent: "claude:w1".into(),
                to: vec!["workstation:agy:s1".into()],
                performative: Performative::Accept,
                thread: None,
                reply_to: Some(seq),
                body: "Trying to hijack from another host".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap();
    assert!(win_reply.unwrap_err().contains("404"));

    // Thread injection check: root message (reply_to: None) into existing thread fails with 409.
    let thread_inject = tokio::task::spawn_blocking({
        let c = wks.clone();
        let t = sent1.thread.clone();
        move || {
            c.send(&SendRequest {
                agent: "agy:s1".into(),
                to: vec!["*".into()],
                performative: Performative::Announce,
                thread: Some(t),
                reply_to: None,
                body: "Injected root message".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap();
    assert!(thread_inject.unwrap_err().contains("409"));

    let sent_dup = tokio::task::spawn_blocking({
        let c = wks.clone();
        move || c.send(&req_msg)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(sent_dup.duplicate);
    assert_eq!(sent_dup.seq, sent1.seq);

    // Sender does not receive its own broadcast if it checks inbox, while cap:macos-gui receives it.
    let mac_inbox = tokio::task::spawn_blocking({
        let c = mac.clone();
        move || c.inbox("codex:m1", None, None, None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(mac_inbox.messages.len(), 1);
    assert_eq!(mac_inbox.messages[0].seq, sent1.seq);
    assert_eq!(mac_inbox.read_position, 0);
    assert!(mac_inbox.seq_head >= sent1.seq);
    assert_eq!(mac_inbox.next_after, mac_inbox.seq_head);

    // A separate listener can keep its own cursor without consuming the
    // interactive inbox. Only explicit ACK advances the hub read position.
    let wake_inbox = tokio::task::spawn_blocking({
        let c = mac.clone();
        move || c.inbox("codex:m1", Some(0), Some(0), None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(wake_inbox.messages.len(), 1);
    assert!(wake_inbox.next_after >= wake_inbox.messages[0].seq);
    assert_eq!(wake_inbox.next_after, mac_inbox.next_after);
    assert_eq!(wake_inbox.seq_head, mac_inbox.seq_head);
    assert_eq!(wake_inbox.read_position, 0);

    let still_unread = tokio::task::spawn_blocking({
        let c = mac.clone();
        move || c.inbox("codex:m1", None, Some(0), None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(still_unread.messages.len(), 1);
    assert_eq!(still_unread.read_position, 0);

    // Ack advances hub-stored read_position; next inbox without `after` returns empty.
    let acked = tokio::task::spawn_blocking({
        let c = mac.clone();
        let next = mac_inbox.next_after;
        move || {
            c.ack(&AckRequest {
                agent: "codex:m1".into(),
                read_to: next,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(acked.read_position, mac_inbox.next_after);

    let mac_inbox_2 = tokio::task::spawn_blocking({
        let c = mac.clone();
        move || c.inbox("codex:m1", None, None, None, None, false)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(mac_inbox_2.messages.is_empty());
    assert_eq!(mac_inbox_2.read_position, mac_inbox.next_after);

    // Exclusive ACCEPT: macbook:codex:m1 accepts; second agent macbook:claude:m2 gets 409 Conflict.
    let accept_ok = tokio::task::spawn_blocking({
        let c = mac.clone();
        let seq = sent1.seq;
        move || {
            c.send(&SendRequest {
                agent: "codex:m1".into(),
                to: vec!["workstation:agy:s1".into()],
                performative: Performative::Accept,
                thread: None,
                reply_to: Some(seq),
                body: "Starting isolated macOS QA".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: Some(300),
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert!(!accept_ok.duplicate);

    let accept_race = tokio::task::spawn_blocking({
        let c = mac.clone();
        let seq = sent1.seq;
        move || {
            c.send(&SendRequest {
                agent: "claude:m2".into(),
                to: vec!["workstation:agy:s1".into()],
                performative: Performative::Accept,
                thread: None,
                reply_to: Some(seq),
                body: "I want to take it too".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap();
    assert!(accept_race.unwrap_err().contains("409"));

    // 6. Long-poll wakeup test: workstation waits on inbox while macbook sends RESULT.
    let wks_wait_task = tokio::task::spawn_blocking({
        let c = wks.clone();
        let after = accept_ok.seq;
        move || {
            let t0 = Instant::now();
            let res = c
                .inbox("agy:s1", Some(after), Some(5), None, None, false)
                .unwrap();
            (t0.elapsed(), res)
        }
    });

    tokio::time::sleep(Duration::from_millis(80)).await;
    let res_sent = tokio::task::spawn_blocking({
        let c = mac.clone();
        let seq = sent1.seq;
        move || {
            c.send(&SendRequest {
                agent: "codex:m1".into(),
                to: vec!["workstation:agy:s1".into()],
                performative: Performative::Result,
                thread: None,
                reply_to: Some(seq),
                body: "macOS settings check PASS".into(),
                payload: Some(serde_json::json!({"ok": true})),
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let (elapsed, woken) = wks_wait_task.await.unwrap();
    assert!(
        elapsed < Duration::from_secs(2),
        "long-poll took too long: {elapsed:?}"
    );
    assert_eq!(woken.messages.len(), 1);
    assert_eq!(woken.messages[0].seq, res_sent.seq);
    assert_eq!(woken.messages[0].performative, Performative::Result);

    // Replying with REPLY to RESULT is rejected (anti-loop rule).
    let loop_reply = tokio::task::spawn_blocking({
        let c = wks.clone();
        let rseq = res_sent.seq;
        move || {
            c.send(&SendRequest {
                agent: "agy:s1".into(),
                to: vec!["macbook:codex:m1".into()],
                performative: Performative::Reply,
                thread: None,
                reply_to: Some(rseq),
                body: "Thanks!".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap();
    assert!(loop_reply.is_err());

    // Replying with QUERY to the now-closed request also fails with 409 Conflict.
    let closed_query = tokio::task::spawn_blocking({
        let c = mac.clone();
        let req_seq = sent1.seq;
        move || {
            c.send(&SendRequest {
                agent: "codex:m1".into(),
                to: vec!["workstation:agy:s1".into()],
                performative: Performative::Query,
                thread: None,
                reply_to: Some(req_seq),
                body: "Follow-up question on closed request".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap();
    assert!(closed_query.unwrap_err().contains("409"));

    // Thread inspection + release + status.
    let thr = tokio::task::spawn_blocking({
        let c = wks.clone();
        let t = sent1.thread.clone();
        move || c.thread(&t)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(thr.closed);
    assert!(thr.accept_expires_ms.is_none());
    assert!(!thr.notice.is_empty());
    assert_eq!(thr.messages.len(), 3);

    tokio::task::spawn_blocking({
        let c = wks.clone();
        move || {
            c.release(&ReleaseRequest {
                agent: "agy:s1".into(),
                claim_id: None,
                repo: Some("example-app".into()),
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let status = tokio::task::spawn_blocking({
        let c = mac.clone();
        move || c.status()
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(status.host, "macbook");
    assert!(!status.notice.is_empty());
    assert!(status.open_requests.is_empty());
    assert!(status
        .agents
        .iter()
        .any(|a| a.id == "workstation:agy:s1" && a.live));
    assert!(status
        .agents
        .iter()
        .any(|a| a.id == "macbook:codex:m1" && a.live));
}

fn aim_binary() -> PathBuf {
    static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let srv_bin = PathBuf::from(env!("CARGO_BIN_EXE_aim-server"));
        let aim_bin = srv_bin.with_file_name(if cfg!(windows) { "aim.exe" } else { "aim" });
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "aim", "--bin", "aim", "--locked"])
            .status()
            .expect("failed invoking cargo build --bin aim");
        assert!(status.success(), "cargo build --bin aim failed");
        assert!(
            aim_bin.exists(),
            "expected built aim binary at {}",
            aim_bin.display()
        );
        aim_bin
    })
    .clone()
}

#[tokio::test]
async fn mcp_stdio_roundtrip_against_live_tls_hub() {
    let h = start_harness().await;
    let aim_bin = aim_binary();

    let res = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(&aim_bin)
            .arg("mcp")
            .env("AIM_URL", h.base_url.as_str())
            .env("AIM_CA_CERT", &h.ca_cert)
            .env("AIM_KEY_FILE", &h.mac_key)
            .env("AIM_AGENT", "macbook:claude:mcp-1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        {
            let stdin = child.stdin.as_mut().unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05"}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"aim_register","arguments":{{"note":"via mcp"}}}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"aim_status","arguments":{{}}}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"aim_register","arguments":{{"agent":"workstation:claude:mcp-1"}}}}}}"#).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    })
    .await
    .unwrap();

    let mut lines: Vec<serde_json::Value> = res
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 5);
    lines.sort_by_key(|v| v["id"].as_i64().unwrap_or(0));
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "aim");
    assert_eq!(lines[1]["id"], 2);
    assert!(lines[1]["result"]["tools"].as_array().unwrap().len() >= 8);
    assert_eq!(lines[2]["id"], 3);
    assert_eq!(lines[2]["result"]["isError"], false);
    assert!(lines[2]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("macbook:claude:mcp-1"));
    assert_eq!(lines[3]["id"], 4);
    assert_eq!(lines[3]["result"]["isError"], false);
    assert_eq!(lines[4]["id"], 5);
    assert_eq!(lines[4]["result"]["isError"], true);
    assert!(lines[4]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("agent host does not match authenticated host"));
}

#[tokio::test]
async fn cli_binaries_init_ca_cert_keygen_revoke_and_send_attach() {
    let h = start_harness().await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let srv_bin = PathBuf::from(env!("CARGO_BIN_EXE_aim-server"));
    let aim_bin = aim_binary();

    let base_url = h.base_url.to_string();
    let test_ca_cert = h.ca_cert.clone();
    let test_wks_key = h.wks_key.clone();

    tokio::task::spawn_blocking(move || {
        // Exercise aim-server CLI commands: init-ca, init-cert, init-config, keygen, list-keys, revoke.
        let ca_crt = root.join("ca.crt");
        let ca_key = root.join("ca.key");
        let srv_crt = root.join("srv.crt");
        let srv_key = root.join("srv.key");
        let srv_cfg = root.join("server.toml");
        let host_key = root.join("workstation.key");

        let run_srv = |args: &[String]| {
            let out = Command::new(&srv_bin).args(args).output().unwrap();
            assert!(
                out.status.success(),
                "aim-server {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };

        run_srv(&[
            "init-ca".into(),
            "--ca-cert".into(),
            ca_crt.display().to_string(),
            "--ca-key".into(),
            ca_key.display().to_string(),
        ]);
        run_srv(&[
            "init-cert".into(),
            "--ca-cert".into(),
            ca_crt.display().to_string(),
            "--ca-key".into(),
            ca_key.display().to_string(),
            "--cert".into(),
            srv_crt.display().to_string(),
            "--key".into(),
            srv_key.display().to_string(),
            "--san".into(),
            "aim.example.internal".into(),
            "--san".into(),
            "10.0.0.10".into(),
        ]);
        run_srv(&[
            "init-config".into(),
            "--config".into(),
            srv_cfg.display().to_string(),
            "--data-dir".into(),
            root.join("data").display().to_string(),
            "--tls-cert".into(),
            srv_crt.display().to_string(),
            "--tls-key".into(),
            srv_key.display().to_string(),
        ]);
        run_srv(&[
            "keygen".into(),
            "--config".into(),
            srv_cfg.display().to_string(),
            "--host".into(),
            "workstation".into(),
            "--out-key".into(),
            host_key.display().to_string(),
        ]);
        let listed = run_srv(&[
            "list-keys".into(),
            "--config".into(),
            srv_cfg.display().to_string(),
        ]);
        assert!(listed.contains("workstation"));
        let revoked = run_srv(&[
            "revoke".into(),
            "--config".into(),
            srv_cfg.display().to_string(),
            "--host".into(),
            "workstation".into(),
        ]);
        assert!(revoked.contains("\"revoked\":1"));

        // Exercise `aim init` + `aim health` + `aim register` + `aim send --attach` + `aim thread` + `aim artifact get`.
        let client_cfg = root.join("client.toml");
        let evidence_file = root.join("evidence.log");
        std::fs::write(&evidence_file, b"check passed\n".repeat(30)).unwrap();

        let run_aim = |args: &[String]| {
            let out = Command::new(&aim_bin)
                .env("AIM_CONFIG", &client_cfg)
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "aim {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };

        run_aim(&[
            "init".into(),
            "--url".into(),
            base_url,
            "--ca-cert".into(),
            test_ca_cert.display().to_string(),
            "--key-file".into(),
            test_wks_key.display().to_string(),
        ]);
        let health_out = run_aim(&["health".into()]);
        assert!(health_out.contains("\"aim/v1\""));

        run_aim(&[
            "--agent".into(),
            "agy:cli1".into(),
            "register".into(),
            "--repo".into(),
            "aim".into(),
        ]);
        let sent_out = run_aim(&[
            "--agent".into(),
            "agy:cli1".into(),
            "send".into(),
            "--to".into(),
            "host:macbook".into(),
            "--performative".into(),
            "ANNOUNCE".into(),
            "--attach".into(),
            evidence_file.display().to_string(),
            "--message".into(),
            "CLI test complete".into(),
        ]);
        let sent_json: serde_json::Value = serde_json::from_str(&sent_out).unwrap();
        let thr = sent_json["thread"].as_str().unwrap().to_string();

        let thr_out = run_aim(&["thread".into(), thr]);
        let thr_json: serde_json::Value = serde_json::from_str(&thr_out).unwrap();
        let art_sha = thr_json["messages"][0]["payload"]["artifacts"][0]["sha256"]
            .as_str()
            .unwrap()
            .to_string();

        let restored = root.join("restored.log");
        run_aim(&[
            "artifact".into(),
            "get".into(),
            art_sha,
            "--out".into(),
            restored.display().to_string(),
        ]);
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            std::fs::read(&evidence_file).unwrap()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn multi_inbox_serves_multiple_agents_and_wakes_immediately() {
    let h = start_harness().await;
    let mac = h.client_for(&h.mac_key);
    let wks = h.client_for(&h.wks_key);

    for agent in ["codex:w1", "codex:w2"] {
        let client = mac.clone();
        tokio::task::spawn_blocking(move || {
            client.register(&RegisterRequest {
                agent: agent.into(),
                ..RegisterRequest::default()
            })
        })
        .await
        .unwrap()
        .unwrap();
    }

    let waiter = tokio::task::spawn_blocking({
        let client = mac.clone();
        move || {
            client.inbox_multi(&aim_proto::wire::MultiInboxRequest {
                agents: vec![
                    aim_proto::wire::MultiInboxAgentQuery {
                        agent: "codex:w1".into(),
                        after: Some(0),
                        thread: None,
                        include_self: false,
                    },
                    aim_proto::wire::MultiInboxAgentQuery {
                        agent: "codex:w2".into(),
                        after: Some(0),
                        thread: None,
                        include_self: false,
                    },
                ],
                limit: Some(50),
                wait_secs: Some(15),
            })
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    tokio::task::spawn_blocking(move || {
        wks.send(&SendRequest {
            agent: "agy:coordinator".into(),
            to: vec!["macbook:codex:w2".into()],
            performative: Performative::Announce,
            thread: None,
            reply_to: None,
            body: "Wake second worker via multiplexed inbox".into(),
            payload: None,
            idempotency_key: None,
            expires_in_secs: None,
            lease_secs: None,
            task_category: None,
            not_before_ms: None,
        })
    })
    .await
    .unwrap()
    .unwrap();

    let resp = waiter.await.unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(resp.inboxes.len(), 2);
    assert!(resp.inboxes[0].messages.is_empty());
    assert_eq!(resp.inboxes[1].messages.len(), 1);
    assert_eq!(
        resp.inboxes[1].messages[0].body,
        "Wake second worker via multiplexed inbox"
    );
}

#[tokio::test]
async fn status_live_only_and_thread_after_filter_over_https() {
    let h = start_harness().await;
    let mac = h.client_for(&h.mac_key);
    let wks = h.client_for(&h.wks_key);

    tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.register(&RegisterRequest {
                agent: "agy:live".into(),
                ..RegisterRequest::default()
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let q1 = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:live".into(),
                to: vec!["macbook:codex:r1".into()],
                performative: Performative::Query,
                thread: None,
                reply_to: None,
                body: "First question".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let q2 = tokio::task::spawn_blocking({
        let client = wks.clone();
        let thread = q1.thread.clone();
        move || {
            client.send(&SendRequest {
                agent: "agy:live".into(),
                to: vec!["macbook:codex:r1".into()],
                performative: Performative::Query,
                thread: Some(thread),
                reply_to: Some(q1.seq),
                body: "Follow-up question".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let partial = tokio::task::spawn_blocking({
        let client = mac.clone();
        let thread = q1.thread.clone();
        move || client.thread_after(&thread, Some(q1.seq))
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(partial.messages.len(), 1);
    assert_eq!(partial.messages[0].seq, q2.seq);

    let caught_up = tokio::task::spawn_blocking({
        let client = mac.clone();
        let thread = q1.thread.clone();
        move || client.thread_after(&thread, Some(q2.seq))
    })
    .await
    .unwrap()
    .unwrap();
    assert!(caught_up.messages.is_empty());

    let live_status = tokio::task::spawn_blocking({
        let client = wks.clone();
        move || client.status_filtered(true)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(live_status.agents.iter().all(|a| a.live));
    assert!(live_status
        .agents
        .iter()
        .any(|a| a.id == "workstation:agy:live"));
}

#[tokio::test]
async fn mcp_compact_json_single_notice_and_cli_watch_over_tls() {
    let h = start_harness().await;
    let aim_bin = aim_binary();
    let wks = h.client_for(&h.wks_key);

    let mcp_url = h.base_url.to_string();
    let mcp_ca = h.ca_cert.clone();
    let mcp_key = h.mac_key.clone();
    let res = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(&aim_bin)
            .arg("mcp")
            .env("AIM_URL", &mcp_url)
            .env("AIM_CA_CERT", &mcp_ca)
            .env("AIM_KEY_FILE", &mcp_key)
            .env("AIM_AGENT", "claude:compact-1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        {
            let stdin = child.stdin.as_mut().unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05"}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"aim_inbox","arguments":{{}}}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"aim_inbox","arguments":{{"after":5,"ack":true}}}}}}"#).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    })
    .await
    .unwrap();

    let mut lines: Vec<serde_json::Value> = res
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    lines.sort_by_key(|v| v["id"].as_i64().unwrap_or(0));
    let empty_content = lines[1]["result"]["content"].as_array().unwrap();
    assert_eq!(empty_content.len(), 1);
    let empty_text = empty_content[0]["text"].as_str().unwrap();
    assert!(!empty_text.contains('\n'));
    let empty_payload: serde_json::Value = serde_json::from_str(empty_text).unwrap();
    assert!(empty_payload.get("notice").is_none());
    assert_eq!(lines[2]["result"]["isError"], true);

    tokio::task::spawn_blocking({
        let wks = wks.clone();
        move || {
            wks.send(&SendRequest {
                agent: "agy:sender".into(),
                to: vec!["macbook:claude:compact-1".into()],
                performative: Performative::Announce,
                thread: None,
                reply_to: None,
                body: "Non-empty MCP message".into(),
                payload: None,
                idempotency_key: None,
                expires_in_secs: None,
                lease_secs: None,
                task_category: None,
                not_before_ms: None,
            })
        }
    })
    .await
    .unwrap()
    .unwrap();

    let aim_bin_msg = aim_binary();
    let mcp_url2 = h.base_url.to_string();
    let mcp_ca2 = h.ca_cert.clone();
    let mcp_key2 = h.mac_key.clone();
    let res2 = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(&aim_bin_msg)
            .arg("mcp")
            .env("AIM_URL", &mcp_url2)
            .env("AIM_CA_CERT", &mcp_ca2)
            .env("AIM_KEY_FILE", &mcp_key2)
            .env("AIM_AGENT", "claude:compact-1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        {
            let stdin = child.stdin.as_mut().unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05"}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"aim_inbox","arguments":{{"ack":true}}}}}}"#).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    })
    .await
    .unwrap();

    let mut lines2: Vec<serde_json::Value> = res2
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    lines2.sort_by_key(|v| v["id"].as_i64().unwrap_or(0));
    let non_empty_content = lines2[1]["result"]["content"].as_array().unwrap();
    assert_eq!(non_empty_content.len(), 2);
    assert!(non_empty_content[0]["text"]
        .as_str()
        .unwrap()
        .contains("not verified"));
    let msg_json_text = non_empty_content[1]["text"].as_str().unwrap();
    assert!(!msg_json_text.contains('\n'));
    let msg_payload: serde_json::Value = serde_json::from_str(msg_json_text).unwrap();
    assert!(msg_payload.get("notice").is_none());
    assert_eq!(msg_payload["messages"][0]["body"], "Non-empty MCP message");
    assert_eq!(msg_payload["read_position"], msg_payload["next_after"]);

    let aim_bin2 = aim_binary();
    let watch_base = h.base_url.to_string();
    let watch_ca = h.ca_cert.clone();
    let watch_key = h.mac_key.clone();
    let watch_task = tokio::task::spawn_blocking(move || {
        Command::new(&aim_bin2)
            .env("AIM_URL", watch_base)
            .env("AIM_CA_CERT", watch_ca)
            .env("AIM_KEY_FILE", watch_key)
            .args([
                "--agent",
                "codex:watcher",
                "watch",
                "--timeout",
                "10",
                "--ack",
            ])
            .output()
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    tokio::task::spawn_blocking(move || {
        wks.send(&SendRequest {
            agent: "agy:sender".into(),
            to: vec!["macbook:codex:watcher".into()],
            performative: Performative::Announce,
            thread: None,
            reply_to: None,
            body: "Watch event arrived".into(),
            payload: None,
            idempotency_key: None,
            expires_in_secs: None,
            lease_secs: None,
            task_category: None,
            not_before_ms: None,
        })
    })
    .await
    .unwrap()
    .unwrap();

    let out = watch_task.await.unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let watched: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(watched["messages"].as_array().unwrap().len(), 1);
    assert_eq!(watched["messages"][0]["body"], "Watch event arrived");
    assert_eq!(watched["read_position"], watched["next_after"]);
}

#[tokio::test]
async fn version_cli_http_and_mcp_work_end_to_end() {
    let h = start_harness().await;
    let srv_bin = PathBuf::from(env!("CARGO_BIN_EXE_aim-server"));
    let aim_bin = aim_binary();

    // 1. Disabled/revoked key fails with 401 on authenticated /v1/version.
    let revoked = h.client_for(&h.disabled_key);
    let unauth = tokio::task::spawn_blocking(move || revoked.hub_version())
        .await
        .unwrap();
    assert!(unauth.unwrap_err().contains("401"));

    // 2. Authenticated hub_version() returns hub BuildInfo without target.
    let client = h.client_for(&h.mac_key);
    let hub_info = tokio::task::spawn_blocking(move || client.hub_version())
        .await
        .unwrap()
        .unwrap()
        .expect("current test hub should expose /v1/version");
    assert_eq!(hub_info.version, aim_proto::PKG_VERSION);
    assert_eq!(hub_info.build_version, aim_proto::BUILD_VERSION);
    assert_eq!(hub_info.git_sha, aim_proto::GIT_SHA);
    assert_eq!(hub_info.protocol, PROTOCOL);
    assert_eq!(hub_info.target, None);
    assert!(hub_info.features.iter().any(|f| f == "version_info"));

    // 3. CLI `--version`, offline `aim version`, `aim version --hub`, `aim-server version`, and MCP `aim_version`.
    let base_url = h.base_url.to_string();
    let ca_cert = h.ca_cert.clone();
    let wks_key = h.wks_key.clone();

    tokio::task::spawn_blocking(move || {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent_cfg = dir.path().join("missing.toml");

        let aim_ver_flag = Command::new(&aim_bin).arg("--version").output().unwrap();
        assert!(aim_ver_flag.status.success());
        assert!(String::from_utf8_lossy(&aim_ver_flag.stdout).contains(aim_proto::BUILD_VERSION));

        let srv_ver_flag = Command::new(&srv_bin).arg("--version").output().unwrap();
        assert!(srv_ver_flag.status.success());
        assert!(String::from_utf8_lossy(&srv_ver_flag.stdout).contains(aim_proto::BUILD_VERSION));

        let aim_ver_offline = Command::new(&aim_bin)
            .args([
                "--config",
                &nonexistent_cfg.display().to_string(),
                "version",
            ])
            .output()
            .unwrap();
        assert!(
            aim_ver_offline.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&aim_ver_offline.stderr)
        );
        let offline_json: serde_json::Value =
            serde_json::from_slice(&aim_ver_offline.stdout).unwrap();
        assert_eq!(offline_json["client"]["git_sha"], aim_proto::GIT_SHA);
        assert_eq!(offline_json["client"]["version"], aim_proto::PKG_VERSION);
        assert!(offline_json.get("hub").is_none());

        let aim_ver_hub = Command::new(&aim_bin)
            .env("AIM_CONFIG", &nonexistent_cfg)
            .env("AIM_URL", &base_url)
            .env("AIM_CA_CERT", &ca_cert)
            .env("AIM_KEY_FILE", &wks_key)
            .args(["version", "--hub"])
            .output()
            .unwrap();
        assert!(
            aim_ver_hub.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&aim_ver_hub.stderr)
        );
        let hub_json: serde_json::Value = serde_json::from_slice(&aim_ver_hub.stdout).unwrap();
        assert_eq!(hub_json["client"]["git_sha"], aim_proto::GIT_SHA);
        assert_eq!(hub_json["hub"]["git_sha"], aim_proto::GIT_SHA);
        assert_eq!(hub_json["hub"]["status"], "ok");
        assert_eq!(hub_json["hub"]["version_supported"], true);

        let srv_ver_cmd = Command::new(&srv_bin).arg("version").output().unwrap();
        assert!(srv_ver_cmd.status.success());
        let srv_json: serde_json::Value = serde_json::from_slice(&srv_ver_cmd.stdout).unwrap();
        assert_eq!(srv_json["git_sha"], aim_proto::GIT_SHA);
        assert_eq!(srv_json["version"], aim_proto::PKG_VERSION);
        assert!(srv_json["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "version_info"));

        let mut child = Command::new(&aim_bin)
            .arg("mcp")
            .env("AIM_CONFIG", &nonexistent_cfg)
            .env("AIM_URL", &base_url)
            .env("AIM_CA_CERT", &ca_cert)
            .env("AIM_KEY_FILE", &wks_key)
            .env("AIM_AGENT", "workstation:claude:ver-test")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        {
            let stdin = child.stdin.as_mut().unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05"}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"aim_version","arguments":{{}}}}}}"#).unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"aim_version","arguments":{{"include_hub":false}}}}}}"#).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout_text = String::from_utf8(out.stdout).unwrap();
        let mut lines: Vec<serde_json::Value> = stdout_text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 4);
        lines.sort_by_key(|v| v["id"].as_i64().unwrap_or(0));

        assert_eq!(lines[0]["result"]["serverInfo"]["version"], aim_proto::BUILD_VERSION);
        assert!(lines[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "aim_version"));

        assert_eq!(lines[2]["result"]["isError"], false);
        let ver_with_hub: serde_json::Value =
            serde_json::from_str(lines[2]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(ver_with_hub["client"]["git_sha"], aim_proto::GIT_SHA);
        assert_eq!(ver_with_hub["mcp"]["mode"], "pull");
        assert_eq!(ver_with_hub["mcp"]["binary_replaced_on_disk"], false);
        assert!(ver_with_hub["mcp"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "aim_version"));
        assert_eq!(ver_with_hub["hub"]["git_sha"], aim_proto::GIT_SHA);
        assert_eq!(ver_with_hub["hub"]["version_supported"], true);
        let features = ver_with_hub["client"]["features"].as_array().unwrap();
        for expected in ["version_info", "multi_inbox", "cancel", "watch", "compact_mcp"] {
            assert!(
                features.iter().any(|f| f == expected),
                "missing feature {expected}"
            );
        }

        assert_eq!(lines[3]["result"]["isError"], false);
        let ver_no_hub: serde_json::Value =
            serde_json::from_str(lines[3]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(ver_no_hub["client"]["git_sha"], aim_proto::GIT_SHA);
        assert!(ver_no_hub.get("hub").is_none());
    })
    .await
    .unwrap();
}
