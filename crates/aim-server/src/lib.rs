pub(crate) mod assignment;
pub mod auth;
pub mod certs;
pub mod config;
pub mod handlers;
pub mod store;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::watch;

use crate::auth::{AuthRateLimiter, AuthState, KeyRing};
use crate::config::ServerConfig;
use crate::handlers::{build_router, HubState, WaiterTracker};
use crate::store::{Store, StoreConfig};

pub fn build_hub_state(cfg: &ServerConfig) -> Result<HubState, String> {
    let store_cfg = StoreConfig {
        agent_ttl_ms: (cfg.agent_ttl_secs as i64) * 1000,
        default_message_ttl_ms: (cfg.default_message_ttl_secs as i64) * 1000,
        default_claim_ttl_ms: (cfg.default_claim_ttl_secs as i64) * 1000,
        default_accept_lease_ms: (cfg.default_accept_lease_secs as i64) * 1000,
        max_messages: cfg.max_messages,
        max_agents: cfg.max_agents,
        max_claims_per_host: cfg.max_claims_per_host,
        max_artifacts_total_bytes: cfg.max_artifacts_total_bytes,
        agent_retention_ms: (cfg.agent_retention_secs as i64) * 1000,
    };
    let store = Store::open(&cfg.data_dir, store_cfg)?;
    let keyring = KeyRing::from_entries(&cfg.keys)?;
    let limiter = AuthRateLimiter::new(cfg.auth_failures_per_minute);
    let auth = AuthState { keyring, limiter };
    let (seq_watch, _) = watch::channel(0u64);
    let waiter_tracker = Arc::new(WaiterTracker::new(
        cfg.max_concurrent_waiters,
        cfg.max_waiters_per_host,
    ));
    Ok(HubState {
        store,
        auth,
        seq_watch,
        waiter_tracker,
    })
}

pub async fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<RustlsConfig, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_bytes = aim_fs::read_trusted_config_bytes(cert_path, 1024 * 1024)?;
    let key_bytes = zeroize::Zeroizing::new(aim_fs::read_private_bytes(key_path, 1024 * 1024)?);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_bytes[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid TLS certificate PEM {}: {e}", cert_path.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "TLS certificate {} contains no certificates",
            cert_path.display()
        ));
    }
    let key = rustls_pemfile::private_key(&mut &key_bytes[..])
        .map_err(|e| format!("invalid TLS private key PEM {}: {e}", key_path.display()))?
        .ok_or_else(|| {
            format!(
                "TLS key file {} contains no private key",
                key_path.display()
            )
        })?;
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid TLS cert/key pair: {e}"))?;
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(tls_cfg)))
}

pub async fn serve(cfg: ServerConfig, addr: SocketAddr) -> Result<(), String> {
    let handle = axum_server::Handle::new();
    serve_with_handle(cfg, addr, handle, None).await
}

pub async fn serve_with_config_path(
    cfg: ServerConfig,
    addr: SocketAddr,
    config_path: PathBuf,
) -> Result<(), String> {
    let handle = axum_server::Handle::new();
    serve_with_handle(cfg, addr, handle, Some(config_path)).await
}

pub async fn serve_with_handle(
    cfg: ServerConfig,
    addr: SocketAddr,
    handle: axum_server::Handle,
    config_path: Option<PathBuf>,
) -> Result<(), String> {
    let tls = load_tls_config(&cfg.tls_cert, &cfg.tls_key).await?;
    let state = build_hub_state(&cfg)?;

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    // Background pruner (every 5 minutes)
    let cleanup_store = state.store.clone();
    let pruner_shutdown = shutdown_notify.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let s = cleanup_store.clone();
                    let _ = tokio::task::spawn_blocking(move || s.prune_expired()).await;
                }
                _ = pruner_shutdown.notified() => {
                    break;
                }
            }
        }
    });

    // Unix SIGHUP reload
    #[cfg(unix)]
    if let Some(cfg_path) = config_path {
        let keyring = state.auth.keyring.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut sighup) = signal(SignalKind::hangup()) {
                while sighup.recv().await.is_some() {
                    match ServerConfig::load(&cfg_path) {
                        Ok(new_cfg) => match keyring.reload(&new_cfg.keys) {
                            Ok(n) => eprintln!(
                                "aim-server: SIGHUP: reloaded {n} keys from {}",
                                cfg_path.display()
                            ),
                            Err(e) => eprintln!("aim-server: SIGHUP: failed reloading keys: {e}"),
                        },
                        Err(e) => eprintln!(
                            "aim-server: SIGHUP: failed reading config {}: {e}",
                            cfg_path.display()
                        ),
                    }
                }
            }
        });
    }

    // Graceful shutdown listener (SIGINT / SIGTERM)
    let shutdown_handle = handle.clone();
    let shutdown_alert = shutdown_notify.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            tokio::select! {
                _ = ctrl_c => {},
                _ = async {
                    if let Some(ref mut st) = sigterm {
                        st.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        eprintln!("aim-server: shutting down gracefully...");
        shutdown_alert.notify_waiters();
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });

    let app = build_router(&cfg.base_path, state.clone());
    eprintln!(
        "aim-server listening on https://{}{} (keys={})",
        addr,
        cfg.base_path,
        cfg.keys.iter().filter(|k| k.enabled).count()
    );

    #[cfg(not(unix))]
    let _ = &config_path;

    let mut server = axum_server::bind_rustls(addr, tls).handle(handle);
    server.http_builder().http1().max_buf_size(64 * 1024);

    let res = server
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| format!("server error: {e}"));

    let _ = state.store.checkpoint_truncate();
    res
}
