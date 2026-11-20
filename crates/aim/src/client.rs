use std::path::Path;
use std::time::Duration;

use aim_proto::artifact::{compress_q6, decompress_verified};
use aim_proto::guard::find_secret_bytes;
use aim_proto::names::{check_name, sanitize_display};
use aim_proto::wire::{
    check_artifact_name, check_sha256, AckRequest, AckResponse, ArtifactInfo, BuildInfo,
    ClaimRequest, ClaimResponse, HealthResponse, InboxResponse, MultiInboxRequest,
    MultiInboxResponse, RegisterRequest, RegisterResponse, ReleaseRequest, SendRequest,
    SendResponse, StatusResponse, ThreadResponse,
};
use aim_proto::{MAX_ARTIFACT_BR_BYTES, MAX_WAIT_SECS};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use ureq::config::Config;
use ureq::http::Response;
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
use ureq::{Agent, Body};
use url::Url;

use crate::config::{ResolvedConfig, SecretKey};

const MAX_JSON_RESPONSE: u64 = 4 * 1024 * 1024;

fn validate_agent(agent: &str) -> Result<(), String> {
    aim_proto::AgentId::validate_identity(agent)
}

#[derive(Clone)]
pub struct AimClient {
    agent: Agent,
    base_url: Url,
    key: SecretKey,
    timeout: Duration,
}

impl AimClient {
    pub fn from_config(cfg: &ResolvedConfig) -> Result<Self, String> {
        let key = cfg.load_key()?;
        let agent = build_https_agent(&cfg.ca_cert, Duration::from_secs(cfg.timeout_secs))?;
        Ok(Self {
            agent,
            base_url: cfg.url.clone(),
            key,
            timeout: Duration::from_secs(cfg.timeout_secs),
        })
    }

    pub fn health_unauth(
        base_url: &Url,
        ca_cert: &Path,
        timeout_secs: u64,
    ) -> Result<HealthResponse, String> {
        let agent = build_https_agent(ca_cert, Duration::from_secs(timeout_secs))?;
        let url = endpoint_url(base_url, "/v1/health")?;
        let resp = agent
            .get(url.as_str())
            .call()
            .map_err(|e| format!("HTTPS request failed: {e}"))?;
        parse_json_response(resp)
    }

    pub fn health(&self) -> Result<HealthResponse, String> {
        let url = self.endpoint("/v1/health")?;
        let resp = self
            .agent
            .get(url.as_str())
            .call()
            .map_err(|e| format!("HTTPS request failed: {e}"))?;
        parse_json_response(resp)
    }

    /// Query authenticated `/v1/version`; returns `Ok(None)` on older hubs returning 404.
    pub fn hub_version(&self) -> Result<Option<BuildInfo>, String> {
        let url = self.endpoint("/v1/version")?;
        let auth = self.key.bearer_header();
        let resp = self
            .agent
            .get(url.as_str())
            .header("Authorization", auth.as_str())
            .call()
            .map_err(|e| format!("HTTPS version request failed: {e}"))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        parse_json_response(resp).map(Some)
    }

    /// Probe hub version metadata with `/v1/health` fallback for older hubs.
    pub fn probe_hub_version(&self) -> (Option<Value>, Option<String>) {
        match self.hub_version() {
            Ok(Some(info)) => match serde_json::to_value(info) {
                Ok(mut val) => {
                    if let Some(obj) = val.as_object_mut() {
                        obj.insert("status".into(), Value::String("ok".into()));
                        obj.insert("version_supported".into(), Value::Bool(true));
                    }
                    (Some(val), None)
                }
                Err(e) => (None, Some(e.to_string())),
            },
            Ok(None) => match self.health() {
                Ok(h) => (
                    Some(json!({
                        "status": h.status,
                        "protocol": h.protocol,
                        "version_supported": false,
                    })),
                    None,
                ),
                Err(e) => (None, Some(e)),
            },
            Err(e) => (None, Some(e)),
        }
    }

    pub fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, String> {
        req.validate()?;
        self.post_json("/v1/register", req)
    }

    pub fn send(&self, req: &SendRequest) -> Result<SendResponse, String> {
        req.validate()?;
        self.post_json("/v1/send", req)
    }

    pub fn inbox(
        &self,
        agent: &str,
        after: Option<u64>,
        wait_secs: Option<u64>,
        limit: Option<u32>,
        thread: Option<&str>,
        include_self: bool,
    ) -> Result<InboxResponse, String> {
        validate_agent(agent)?;
        if let Some(t) = thread {
            check_name("thread", t)?;
        }
        let mut url = self.endpoint("/v1/inbox")?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("agent", agent);
            if let Some(a) = after {
                qp.append_pair("after", &a.to_string());
            }
            if let Some(w) = wait_secs {
                let bounded = w.min(MAX_WAIT_SECS);
                qp.append_pair("wait", &bounded.to_string());
            }
            if let Some(l) = limit {
                qp.append_pair("limit", &l.to_string());
            }
            if let Some(t) = thread {
                qp.append_pair("thread", t);
            }
            if include_self {
                qp.append_pair("include_self", "true");
            }
        }
        let call_timeout = wait_secs
            .map(|w| Duration::from_secs(w.min(MAX_WAIT_SECS) + 10))
            .unwrap_or(self.timeout)
            .max(self.timeout);

        let auth = self.key.bearer_header();
        let resp = self
            .agent
            .get(url.as_str())
            .header("Authorization", auth.as_str())
            .config()
            .timeout_global(Some(call_timeout))
            .build()
            .call()
            .map_err(|e| format!("HTTPS inbox request failed: {e}"))?;
        parse_json_response(resp)
    }

    pub fn inbox_multi(&self, req: &MultiInboxRequest) -> Result<MultiInboxResponse, String> {
        match self.inbox_multi_if_supported(req)? {
            Some(res) => Ok(res),
            None => Err("AIM hub does not support /v1/inbox/multi".into()),
        }
    }

    /// Queries `POST /v1/inbox/multi`, returning `Ok(None)` when the hub reports
    /// `404`, `405`, or `501` so callers can fall back cleanly to `/v1/inbox`.
    pub fn inbox_multi_if_supported(
        &self,
        req: &MultiInboxRequest,
    ) -> Result<Option<MultiInboxResponse>, String> {
        req.validate()?;
        let url = self.endpoint("/v1/inbox/multi")?;
        let call_timeout = req
            .wait_secs
            .map(|w| Duration::from_secs(w.min(MAX_WAIT_SECS) + 10))
            .unwrap_or(self.timeout)
            .max(self.timeout);
        let auth = self.key.bearer_header();
        let resp = self
            .agent
            .post(url.as_str())
            .header("Authorization", auth.as_str())
            .config()
            .timeout_global(Some(call_timeout))
            .build()
            .send_json(req)
            .map_err(|e| format!("HTTPS multi-inbox request failed: {e}"))?;
        if matches!(resp.status().as_u16(), 404 | 405 | 501) {
            return Ok(None);
        }
        parse_json_response(resp).map(Some)
    }

    pub fn ack(&self, req: &AckRequest) -> Result<AckResponse, String> {
        req.validate()?;
        self.post_json("/v1/ack", req)
    }

    pub fn claim(&self, req: &ClaimRequest) -> Result<ClaimResponse, String> {
        req.validate()?;
        self.post_json("/v1/claim", req)
    }

    pub fn release(&self, req: &ReleaseRequest) -> Result<serde_json::Value, String> {
        req.validate()?;
        self.post_json("/v1/release", req)
    }

    pub fn status(&self) -> Result<StatusResponse, String> {
        self.status_filtered(false)
    }

    pub fn status_filtered(&self, live_only: bool) -> Result<StatusResponse, String> {
        let mut url = self.endpoint("/v1/status")?;
        if live_only {
            url.query_pairs_mut().append_pair("live_only", "true");
        }
        let auth = self.key.bearer_header();
        let resp = self
            .agent
            .get(url.as_str())
            .header("Authorization", auth.as_str())
            .call()
            .map_err(|e| format!("HTTPS status request failed: {e}"))?;
        parse_json_response(resp)
    }

    pub fn thread(&self, thread: &str) -> Result<ThreadResponse, String> {
        self.thread_after(thread, None)
    }

    pub fn thread_after(&self, thread: &str, after: Option<u64>) -> Result<ThreadResponse, String> {
        check_name("thread", thread)?;
        if let Some(a) = after {
            if i64::try_from(a).is_err() {
                return Err("after sequence number is out of range".into());
            }
        }
        let mut url = self.endpoint(&format!("/v1/thread/{thread}"))?;
        if let Some(a) = after {
            url.query_pairs_mut().append_pair("after", &a.to_string());
        }
        let auth = self.key.bearer_header();
        let resp = self
            .agent
            .get(url.as_str())
            .header("Authorization", auth.as_str())
            .call()
            .map_err(|e| format!("HTTPS thread request failed: {e}"))?;
        parse_json_response(resp)
    }

    pub fn put_artifact(
        &self,
        agent: &str,
        name: &str,
        raw: &[u8],
    ) -> Result<ArtifactInfo, String> {
        validate_agent(agent)?;
        check_artifact_name(name)?;
        if let Some(rule) = find_secret_bytes(raw) {
            return Err(format!(
                "artifact looks like it contains a credential ({rule}); AIM never carries secrets"
            ));
        }
        let (sha256, br) = compress_q6(raw)?;
        let url = self.endpoint(&format!("/v1/artifacts/{sha256}"))?;
        let auth = self.key.bearer_header();
        let resp = self
            .agent
            .put(url.as_str())
            .header("Authorization", auth.as_str())
            .header("Content-Type", "application/octet-stream")
            .header("X-Aim-Agent", agent)
            .header("X-Aim-Name", name)
            .header("X-Aim-Encoding", "br-q6")
            .send(&br[..])
            .map_err(|e| format!("HTTPS artifact upload failed: {e}"))?;
        parse_json_response(resp)
    }

    pub fn get_artifact(&self, sha256: &str) -> Result<Vec<u8>, String> {
        check_sha256(sha256)?;
        let mut url = self.endpoint(&format!("/v1/artifacts/{sha256}"))?;
        url.query_pairs_mut().append_pair("encoding", "br");
        let auth = self.key.bearer_header();
        let mut resp = self
            .agent
            .get(url.as_str())
            .header("Authorization", auth.as_str())
            .call()
            .map_err(|e| format!("HTTPS artifact download failed: {e}"))?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            return Err(format!(
                "server returned unexpected redirect ({status}); refusing"
            ));
        }
        if status >= 400 {
            return Err(extract_error_message(status, &mut resp));
        }
        let br = resp
            .body_mut()
            .with_config()
            .limit(MAX_ARTIFACT_BR_BYTES as u64)
            .read_to_vec()
            .map_err(|e| format!("failed reading artifact body: {e}"))?;
        decompress_verified(&br, sha256)
    }

    fn endpoint(&self, suffix: &str) -> Result<Url, String> {
        endpoint_url(&self.base_url, suffix)
    }

    fn post_json<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        suffix: &str,
        body: &Req,
    ) -> Result<Resp, String> {
        let url = self.endpoint(suffix)?;
        let auth = self.key.bearer_header();
        let resp = self
            .agent
            .post(url.as_str())
            .header("Authorization", auth.as_str())
            .send_json(body)
            .map_err(|e| format!("HTTPS request failed: {e}"))?;
        parse_json_response(resp)
    }
}

fn endpoint_url(base: &Url, suffix: &str) -> Result<Url, String> {
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    let next_path = format!("{base_path}{suffix}");
    url.set_path(&next_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn build_https_agent(ca_cert_path: &Path, timeout: Duration) -> Result<Agent, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pem = aim_fs::read_trusted_config_bytes(ca_cert_path, 1024 * 1024)?;
    let mut slice = &pem[..];
    let raw_certs = rustls_pemfile::certs(&mut slice)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid CA certificate PEM {}: {e}", ca_cert_path.display()))?;
    if raw_certs.is_empty() {
        return Err(format!(
            "CA certificate file {} contains no certificates",
            ca_cert_path.display()
        ));
    }

    let mut store = rustls::RootCertStore::empty();
    let mut certs: Vec<Certificate<'static>> = Vec::with_capacity(raw_certs.len());
    for der in raw_certs {
        store
            .add(der.clone())
            .map_err(|e| format!("invalid CA certificate in {}: {e}", ca_cert_path.display()))?;
        certs.push(Certificate::from_der(der.as_ref()).to_owned());
    }

    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::new_with_certs(&certs))
        .build();

    let cfg = Config::builder()
        .https_only(true)
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .tls_config(tls)
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_global(Some(timeout))
        .user_agent("aim/0.1")
        .build();

    Ok(Agent::new_with_config(cfg))
}

fn parse_json_response<T: DeserializeOwned>(mut resp: Response<Body>) -> Result<T, String> {
    let status = resp.status().as_u16();
    if (300..400).contains(&status) {
        return Err(format!(
            "server returned unexpected redirect ({status}); refusing to follow"
        ));
    }
    if status >= 400 {
        return Err(extract_error_message(status, &mut resp));
    }
    resp.body_mut()
        .with_config()
        .limit(MAX_JSON_RESPONSE)
        .read_json::<T>()
        .map_err(|e| format!("invalid JSON response from AIM server: {e}"))
}

fn extract_error_message(status: u16, resp: &mut Response<Body>) -> String {
    let raw = resp
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_string()
        .unwrap_or_default();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
        if let Some(msg) = val.get("error").and_then(|v| v.as_str()) {
            let safe = sanitize_display(msg, 240);
            return format!("AIM server error ({status}): {safe}");
        }
    }
    let snippet = sanitize_display(raw.trim(), 240);
    if snippet.is_empty() {
        format!("AIM server error ({status})")
    } else {
        format!("AIM server error ({status}): {snippet}")
    }
}
