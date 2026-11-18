use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aim_proto::wire::{
    AckRequest, ClaimRequest, HealthResponse, RegisterRequest, ReleaseRequest, SendRequest,
};
use aim_proto::{MAX_ARTIFACT_BR_BYTES, MAX_WAIT_SECS, PROTOCOL};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::watch;
use tokio::time::{sleep_until, Instant};

use crate::auth::{require_bearer, AuthState, AuthenticatedHost};
use crate::store::{Store, StoreError};

pub struct WaiterTracker {
    max_concurrent: usize,
    max_per_host: usize,
    active_global: AtomicUsize,
    active_per_host: Mutex<HashMap<String, usize>>,
}

impl WaiterTracker {
    pub fn new(max_concurrent: usize, max_per_host: usize) -> Self {
        Self {
            max_concurrent,
            max_per_host,
            active_global: AtomicUsize::new(0),
            active_per_host: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_acquire(self: &Arc<Self>, host: &str) -> Result<WaiterGuard, String> {
        let current_global = self.active_global.load(Ordering::Relaxed);
        if current_global >= self.max_concurrent {
            return Err("too many concurrent long-poll connections".into());
        }

        let mut per_host = self
            .active_per_host
            .lock()
            .map_err(|_| "waiter tracker lock poisoned".to_string())?;
        let host_count = per_host.entry(host.to_string()).or_insert(0);
        if *host_count >= self.max_per_host {
            return Err(format!(
                "too many concurrent long-poll connections for host '{host}'"
            ));
        }

        *host_count += 1;
        self.active_global.fetch_add(1, Ordering::Relaxed);

        Ok(WaiterGuard {
            tracker: self.clone(),
            host: host.to_string(),
        })
    }
}

pub struct WaiterGuard {
    tracker: Arc<WaiterTracker>,
    host: String,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.tracker.active_global.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut per_host) = self.tracker.active_per_host.lock() {
            if let Some(count) = per_host.get_mut(&self.host) {
                if *count > 1 {
                    *count -= 1;
                } else {
                    per_host.remove(&self.host);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct HubState {
    pub store: Store,
    pub auth: AuthState,
    pub seq_watch: watch::Sender<u64>,
    pub waiter_tracker: Arc<WaiterTracker>,
}

async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    resp
}

pub fn build_router(base_path: &str, state: HubState) -> Router {
    let authed = Router::new()
        .route("/v1/register", post(register_handler))
        .route("/v1/send", post(send_handler))
        .route("/v1/inbox", get(inbox_handler))
        .route("/v1/ack", post(ack_handler))
        .route("/v1/claim", post(claim_handler))
        .route("/v1/release", post(release_handler))
        .route("/v1/status", get(status_handler))
        .route("/v1/thread/{thread}", get(thread_handler))
        .route(
            "/v1/artifacts/{sha256}",
            put(put_artifact_handler)
                .layer(DefaultBodyLimit::max(MAX_ARTIFACT_BR_BYTES + 16 * 1024))
                .get(get_artifact_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.auth.clone(),
            require_bearer,
        ));

    let v1 = Router::new()
        .route("/v1/health", get(health_handler))
        .merge(authed)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state);

    if base_path.is_empty() {
        v1
    } else {
        Router::new().nest(base_path, v1)
    }
}

pub struct ApiError(StoreError);

impl From<StoreError> for ApiError {
    fn from(value: StoreError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self.0 {
            StoreError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            StoreError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            StoreError::Conflict(m) => (StatusCode::CONFLICT, m),
            StoreError::QuotaExceeded(m) => (StatusCode::TOO_MANY_REQUESTS, m),
            StoreError::StorageFull(m) => (StatusCode::INSUFFICIENT_STORAGE, m),
            StoreError::Internal(m) => {
                eprintln!("aim-server: internal error: {m}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

async fn blocking<F, T>(f: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError(StoreError::Internal(format!("worker panicked: {e}"))))?
        .map_err(ApiError)
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        protocol: PROTOCOL.into(),
    })
}

async fn register_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<aim_proto::wire::RegisterResponse>, ApiError> {
    let store = state.store.clone();
    let res = blocking(move || store.register(&host, req)).await?;
    Ok(Json(res))
}

async fn send_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Json(req): Json<SendRequest>,
) -> Result<Json<aim_proto::wire::SendResponse>, ApiError> {
    let store = state.store.clone();
    let (res, new_seq) = blocking(move || store.send(&host, req)).await?;
    if let Some(seq) = new_seq {
        let _ = state.seq_watch.send(seq);
    }
    Ok(Json(res))
}

#[derive(Deserialize)]
pub struct InboxQuery {
    pub agent: String,
    pub after: Option<u64>,
    pub limit: Option<u32>,
    pub wait: Option<u64>,
    pub thread: Option<String>,
    pub include_self: Option<bool>,
}

async fn run_query(
    store: Store,
    host: String,
    agent: String,
    after: Option<u64>,
    limit: Option<u32>,
    thread: Option<String>,
    include_self: bool,
) -> Result<aim_proto::wire::InboxResponse, ApiError> {
    blocking(move || store.inbox(&host, &agent, after, limit, thread.as_deref(), include_self))
        .await
}

async fn inbox_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Query(q): Query<InboxQuery>,
) -> Result<Json<aim_proto::wire::InboxResponse>, ApiError> {
    let wait_secs = q.wait.unwrap_or(0).min(MAX_WAIT_SECS);
    let include_self = q.include_self.unwrap_or(false);
    let mut rx = state.seq_watch.subscribe();
    rx.borrow_and_update();

    let first = run_query(
        state.store.clone(),
        host.clone(),
        q.agent.clone(),
        q.after,
        q.limit,
        q.thread.clone(),
        include_self,
    )
    .await?;

    if !first.messages.is_empty() || wait_secs == 0 {
        return Ok(Json(first));
    }

    let _waiter_guard = state
        .waiter_tracker
        .try_acquire(&host)
        .map_err(|e| ApiError(StoreError::QuotaExceeded(e)))?;

    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    let mut latest = first;
    let mut scan_after = q.after;

    loop {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            _ = sleep_until(deadline) => {
                break;
            }
        }
        latest = run_query(
            state.store.clone(),
            host.clone(),
            q.agent.clone(),
            scan_after,
            q.limit,
            q.thread.clone(),
            include_self,
        )
        .await?;
        if !latest.messages.is_empty() {
            break;
        }
        if latest.next_after > 0 {
            scan_after = Some(latest.next_after);
        }
    }
    Ok(Json(latest))
}

async fn ack_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Json(req): Json<AckRequest>,
) -> Result<Json<aim_proto::wire::AckResponse>, ApiError> {
    let store = state.store.clone();
    let res = blocking(move || store.ack(&host, req)).await?;
    Ok(Json(res))
}

async fn claim_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Json(req): Json<ClaimRequest>,
) -> Result<Json<aim_proto::wire::ClaimResponse>, ApiError> {
    let store = state.store.clone();
    let res = blocking(move || store.claim(&host, req)).await?;
    Ok(Json(res))
}

async fn release_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Json(req): Json<ReleaseRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.clone();
    let released = blocking(move || store.release(&host, req)).await?;
    Ok(Json(json!({ "released": released })))
}

async fn status_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
) -> Result<Json<aim_proto::wire::StatusResponse>, ApiError> {
    let store = state.store.clone();
    let res = blocking(move || store.status(&host)).await?;
    Ok(Json(res))
}

async fn thread_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Path(thread): Path<String>,
) -> Result<Json<aim_proto::wire::ThreadResponse>, ApiError> {
    let store = state.store.clone();
    let res = blocking(move || store.thread(&host, &thread)).await?;
    Ok(Json(res))
}

async fn put_artifact_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<aim_proto::wire::ArtifactInfo>, ApiError> {
    let Some(agent) = headers
        .get("X-Aim-Agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return Err(ApiError(StoreError::BadRequest(
            "missing X-Aim-Agent header".into(),
        )));
    };
    let Some(name) = headers
        .get("X-Aim-Name")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return Err(ApiError(StoreError::BadRequest(
            "missing X-Aim-Name header".into(),
        )));
    };
    let encoding = headers
        .get("X-Aim-Encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("br-q6");
    if encoding != "br-q6" {
        return Err(ApiError(StoreError::BadRequest(
            "X-Aim-Encoding must be br-q6".into(),
        )));
    }
    let store = state.store.clone();
    let info = blocking(move || store.put_artifact(&host, &agent, &sha256, &name, &body)).await?;
    Ok(Json(info))
}

#[derive(Deserialize)]
pub struct ArtifactQuery {
    pub encoding: Option<String>,
}

async fn get_artifact_handler(
    State(state): State<HubState>,
    Extension(AuthenticatedHost(host)): Extension<AuthenticatedHost>,
    Path(sha256): Path<String>,
    Query(q): Query<ArtifactQuery>,
) -> Result<Response, ApiError> {
    let as_br = q.encoding.as_deref() == Some("br");
    let store = state.store.clone();
    let (name, data) = blocking(move || store.get_artifact(&host, &sha256, as_br)).await?;

    let mut resp = Response::new(axum::body::Body::from(data));
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if as_br {
        resp.headers_mut()
            .insert("X-Aim-Encoding", HeaderValue::from_static("br-q6"));
    }
    let mut safe_name: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if safe_name.is_empty() {
        safe_name = "artifact.bin".to_string();
    }
    if let Ok(val) = HeaderValue::from_str(&format!("attachment; filename=\"{safe_name}\"")) {
        resp.headers_mut().insert(CONTENT_DISPOSITION, val);
    }
    Ok(resp)
}
