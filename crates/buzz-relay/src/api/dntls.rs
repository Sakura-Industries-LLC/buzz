//! DNTLS verified-name admission HTTP API.
//!
//! The relay's own listener terminates DNTLS mutual TLS (`crate::dntls`) and
//! stamps the verified caller name on every request as `x-dntls-name` after
//! deleting any inbound copy. The relay binds `pubkey ↔ fqdn` at NIP-42 AUTH
//! or the first NIP-98-signed request when
//! [`crate::config::DntlsAdmission`] is not `Off`.
//!
//! HTTP routes (all NIP-98 signed, outside the Nostr event data plane):
//!
//! - `GET /api/dntls/pending` — list pending applications. Owner/admin only.
//! - `POST /api/dntls/approve` — admit a pending pubkey through the same
//!   membership path invite claims use, and retain the verified-name mapping.
//! - `POST /api/dntls/reject` — delete a pending application. Owner/admin only.
//! - `GET /api/dntls/names` — list approved pubkey→fqdn mappings. Any member.
//!
//! Feature-gated by `BUZZ_DNTLS_ADMISSION`. When `off` (default), every route
//! returns 404 before authentication.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::Deserialize;
use serde_json::Value;

use crate::config::DntlsAdmission;
use crate::connection::ConnectionState;
use crate::handlers::side_effects::{publish_nip43_member_added, publish_nip43_membership_list};
use crate::protocol::RelayMessage;
use crate::state::AppState;
use buzz_core::tenant::TenantContext;

const PENDING_PATH: &str = "/api/dntls/pending";
const APPROVE_PATH: &str = "/api/dntls/approve";
const REJECT_PATH: &str = "/api/dntls/reject";
const NAMES_PATH: &str = "/api/dntls/names";

/// NOTICE sent when a verified name is already bound to another pubkey.
pub(crate) const NAME_ALREADY_CLAIMED_NOTICE: &str = "dntls: name already claimed";

const DNTLS_NAME_HEADER: &str = crate::dntls::NAME_HEADER;
const MAX_FQDN_LEN: usize = 255;

/// Outcome of applying a gateway-verified name at AUTH or NIP-98.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionEffect {
    /// Mapping written or refreshed; AUTH should continue.
    Applied,
    /// The name is already bound to a different pubkey. AUTH continues as an
    /// ordinary (non-verified) member if membership allows.
    NameClaimed,
}

#[derive(Debug, Deserialize)]
struct PubkeyRequest {
    pubkey: String,
}

fn require_configured(state: &AppState) -> Result<(), (StatusCode, Json<Value>)> {
    match state.config.dntls_admission {
        DntlsAdmission::Off => Err(api_error(StatusCode::NOT_FOUND, "dntls_not_configured")),
        DntlsAdmission::Auto | DntlsAdmission::Approve => Ok(()),
    }
}

/// Read the stamped verified name from a WebSocket upgrade when admission is enabled.
pub(crate) fn verified_name_from_upgrade(state: &AppState, headers: &HeaderMap) -> Option<String> {
    if state.config.dntls_admission == DntlsAdmission::Off {
        return None;
    }
    verified_name_from_headers(headers)
}

/// Normalize the stamped verified-name header.
pub(crate) fn verified_name_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(DNTLS_NAME_HEADER)?.to_str().ok()?;
    let fqdn = raw.trim().to_ascii_lowercase();
    if fqdn.is_empty() || fqdn.len() > MAX_FQDN_LEN {
        return None;
    }
    Some(fqdn)
}

async fn authenticate(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    require_payload: bool,
) -> Result<(TenantContext, nostr::PublicKey), (StatusCode, Json<Value>)> {
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    let url = super::bridge::nip98_expected_url(&state.config.relay_url, &tenant, path);
    let (pubkey, event_id_bytes) = super::bridge::verify_bridge_auth_with_options(
        headers,
        method,
        &url,
        if body.is_empty() { None } else { Some(body) },
        true,
        require_payload,
    )?;
    super::bridge::check_nip98_replay(state, &tenant, event_id_bytes).await?;
    Ok((tenant, pubkey))
}

async fn require_owner_or_admin(
    state: &AppState,
    community: buzz_core::tenant::CommunityId,
    pubkey: &nostr::PublicKey,
) -> Result<(), (StatusCode, Json<Value>)> {
    let sender_hex = pubkey.to_hex();
    let member = state
        .db
        .get_relay_member(community, &sender_hex)
        .await
        .map_err(|e| super::internal_error(&format!("dntls role lookup: {e}")))?;
    let role = member.map(|m| m.role).unwrap_or_default();
    if role != "owner" && role != "admin" {
        return Err(super::api_error(
            StatusCode::FORBIDDEN,
            "only relay owners and admins can manage DNTLS applications",
        ));
    }
    Ok(())
}

fn validate_pubkey_hex(value: &str) -> Result<String, (StatusCode, Json<Value>)> {
    crate::handlers::community_provisioning::validate_pubkey_hex(value)
        .ok_or_else(|| super::api_error(StatusCode::BAD_REQUEST, "invalid_pubkey"))
}

async fn admit_as_member(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    pubkey_hex: &str,
    fqdn: &str,
) -> Result<(), String> {
    let was_inserted = state
        .db
        .claim_relay_membership(tenant.community(), pubkey_hex, "member", None)
        .await
        .map_err(|e| format!("dntls membership: {e}"))?;
    if was_inserted {
        tracing::info!(
            community = %tenant.community(),
            member = %pubkey_hex,
            fqdn,
            "relay member added via DNTLS admission"
        );
        if let Err(e) = publish_nip43_member_added(tenant, state, pubkey_hex).await {
            tracing::warn!("failed to publish NIP-43 member-added delta after DNTLS admit: {e}");
        }
        if let Err(e) = publish_nip43_membership_list(tenant, state).await {
            tracing::warn!("failed to publish NIP-43 membership list after DNTLS admit: {e}");
        }
    }
    Ok(())
}

/// Bind or queue a gateway-verified name after NIP-42 AUTH or NIP-98 succeeds.
pub(crate) async fn apply_connection_admission(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    pubkey_hex: &str,
    fqdn: &str,
) -> Result<AdmissionEffect, String> {
    let fqdn = fqdn.trim().to_ascii_lowercase();
    let fqdn = fqdn.as_str();
    match state.config.dntls_admission {
        DntlsAdmission::Off => Ok(AdmissionEffect::Applied),
        DntlsAdmission::Approve => {
            match state
                .db
                .upsert_dntls_pending_application(tenant.community(), pubkey_hex, fqdn)
                .await
                .map_err(|e| format!("dntls pending upsert: {e}"))?
            {
                buzz_db::dntls::UpsertJoinOutcome::Pending
                | buzz_db::dntls::UpsertJoinOutcome::Bound => Ok(AdmissionEffect::Applied),
                buzz_db::dntls::UpsertJoinOutcome::NameAlreadyClaimed => {
                    Ok(AdmissionEffect::NameClaimed)
                }
            }
        }
        DntlsAdmission::Auto => {
            match state
                .db
                .upsert_dntls_approved_application(tenant.community(), pubkey_hex, fqdn, pubkey_hex)
                .await
                .map_err(|e| format!("dntls approved upsert: {e}"))?
            {
                buzz_db::dntls::UpsertJoinOutcome::NameAlreadyClaimed => {
                    Ok(AdmissionEffect::NameClaimed)
                }
                buzz_db::dntls::UpsertJoinOutcome::Pending
                | buzz_db::dntls::UpsertJoinOutcome::Bound => {
                    admit_as_member(state, tenant, pubkey_hex, fqdn).await?;
                    Ok(AdmissionEffect::Applied)
                }
            }
        }
    }
}

/// Apply a stored verified name after NIP-42 crypto succeeds.
///
/// Returns `false` when AUTH must stop (internal error). A claimed name sends
/// a NOTICE and still returns `true` so ordinary membership can proceed.
pub(crate) async fn apply_auth_admission(
    state: &Arc<AppState>,
    conn: &ConnectionState,
    pubkey_hex: &str,
) -> bool {
    let Some(fqdn) = conn.dntls_name.as_deref() else {
        return true;
    };
    match apply_connection_admission(state, &conn.tenant, pubkey_hex, fqdn).await {
        Ok(AdmissionEffect::Applied) => true,
        Ok(AdmissionEffect::NameClaimed) => {
            conn.send(RelayMessage::notice(NAME_ALREADY_CLAIMED_NOTICE));
            true
        }
        Err(e) => {
            tracing::warn!(
                conn_id = %conn.conn_id,
                pubkey = %pubkey_hex,
                error = %e,
                "DNTLS admission failed"
            );
            false
        }
    }
}

/// Apply the stamped verified name after NIP-98 crypto succeeds.
///
/// No-op when admission is off or the header is absent. A claimed name cannot
/// send a NOTICE over HTTP; the caller proceeds to ordinary membership.
/// Safe to call once per request: binding is first-write-wins and idempotent.
pub(crate) async fn apply_http_admission(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    headers: &HeaderMap,
    pubkey_hex: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    if state.config.dntls_admission == DntlsAdmission::Off {
        return Ok(());
    }
    let Some(fqdn) = verified_name_from_headers(headers) else {
        return Ok(());
    };
    match apply_connection_admission(state, tenant, pubkey_hex, &fqdn).await {
        Ok(AdmissionEffect::Applied | AdmissionEffect::NameClaimed) => Ok(()),
        Err(e) => Err(super::internal_error(&format!(
            "DNTLS admission failed: {e}"
        ))),
    }
}

/// List pending applications — `GET /api/dntls/pending`.
pub async fn pending(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_configured(&state)?;
    let (tenant, pubkey) = authenticate(&state, &headers, "GET", PENDING_PATH, &[], false).await?;
    require_owner_or_admin(&state, tenant.community(), &pubkey).await?;

    let applications = state
        .db
        .list_dntls_applications(tenant.community(), "pending")
        .await
        .map_err(|e| super::internal_error(&format!("dntls pending list: {e}")))?;
    Ok(Json(serde_json::json!({
        "applications": applications.iter().map(|row| serde_json::json!({
            "pubkey": row.pubkey,
            "fqdn": row.fqdn,
            "created_at": row.created_at.timestamp(),
        })).collect::<Vec<_>>(),
    })))
}

/// Approve a pending application — `POST /api/dntls/approve`.
pub async fn approve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_configured(&state)?;
    let (tenant, pubkey) =
        authenticate(&state, &headers, "POST", APPROVE_PATH, &body, true).await?;
    require_owner_or_admin(&state, tenant.community(), &pubkey).await?;

    let request: PubkeyRequest = serde_json::from_slice(&body).map_err(|e| {
        super::api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid approve JSON: {e}"),
        )
    })?;
    let target = validate_pubkey_hex(&request.pubkey)?;

    let existing = state
        .db
        .get_dntls_application(tenant.community(), &target)
        .await
        .map_err(|e| super::internal_error(&format!("dntls approve lookup: {e}")))?;
    let Some(existing) = existing.filter(|row| row.status == "pending") else {
        return Err(super::api_error(
            StatusCode::NOT_FOUND,
            "application_not_found",
        ));
    };

    admit_as_member(&state, &tenant, &target, &existing.fqdn)
        .await
        .map_err(|e| super::internal_error(&e))?;

    let approved = state
        .db
        .approve_dntls_application(tenant.community(), &target, &pubkey.to_hex())
        .await
        .map_err(|e| super::internal_error(&format!("dntls approve persist: {e}")))?
        .ok_or_else(|| super::api_error(StatusCode::NOT_FOUND, "application_not_found"))?;

    Ok(Json(serde_json::json!({
        "status": "approved",
        "fqdn": approved.fqdn,
    })))
}

/// Reject a pending application — `POST /api/dntls/reject`.
pub async fn reject(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_configured(&state)?;
    let (tenant, pubkey) = authenticate(&state, &headers, "POST", REJECT_PATH, &body, true).await?;
    require_owner_or_admin(&state, tenant.community(), &pubkey).await?;

    let request: PubkeyRequest = serde_json::from_slice(&body).map_err(|e| {
        super::api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid reject JSON: {e}"),
        )
    })?;
    let target = validate_pubkey_hex(&request.pubkey)?;

    let deleted = state
        .db
        .reject_dntls_application(tenant.community(), &target)
        .await
        .map_err(|e| super::internal_error(&format!("dntls reject: {e}")))?;
    if !deleted {
        return Err(super::api_error(
            StatusCode::NOT_FOUND,
            "application_not_found",
        ));
    }
    Ok(Json(serde_json::json!({ "status": "rejected" })))
}

/// List approved verified-name mappings — `GET /api/dntls/names`.
pub async fn names(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_configured(&state)?;
    let (tenant, pubkey) = authenticate(&state, &headers, "GET", NAMES_PATH, &[], false).await?;
    super::relay_members::enforce_relay_membership(
        &state,
        tenant.community(),
        &pubkey.to_bytes(),
        headers
            .get("x-auth-tag")
            .and_then(|value| value.to_str().ok()),
    )
    .await?;

    let names = state
        .db
        .list_dntls_applications(tenant.community(), "approved")
        .await
        .map_err(|e| super::internal_error(&format!("dntls names list: {e}")))?;
    Ok(Json(serde_json::json!({
        "names": names.iter().map(name_entry_json).collect::<Vec<_>>(),
    })))
}

fn name_entry_json(row: &buzz_db::dntls::DntlsApplication) -> Value {
    serde_json::json!({
        "pubkey": row.pubkey,
        "fqdn": row.fqdn,
        "approved_at": row.approved_at.map(|ts| ts.timestamp()).unwrap_or(0),
    })
}

fn api_error(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    super::api_error(status, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU8;

    use axum::{
        body::{to_bytes, Body},
        extract::ws::Message as WsMessage,
        http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use base64::Engine;
    use nostr::{EventBuilder, Keys, Kind, RelayUrl, Tag};
    use sha2::{Digest, Sha256};
    use tokio::sync::{mpsc, Mutex, RwLock};
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::connection::AuthState;
    use crate::handlers::auth::handle_auth;
    use crate::router::build_router;

    struct AlwaysFreshReplayGuard;

    impl buzz_auth::Nip98ReplayGuard for AlwaysFreshReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(true) })
        }
    }

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1
    const TEST_REDIS_URL: &str = "redis://127.0.0.1:6379";

    fn nip98_auth_header(keys: &Keys, method: &str, url: &str, body: &[u8]) -> String {
        let hash: [u8; 32] = Sha256::digest(body).into();
        let mut tags = vec![
            Tag::parse(["u", url]).expect("u tag"),
            Tag::parse(["method", method]).expect("method tag"),
        ];
        if method != "GET" {
            tags.push(Tag::parse(["payload", hex::encode(hash).as_str()]).expect("payload tag"));
        }
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign NIP-98 event");
        let event_json = serde_json::to_string(&event).expect("serialize NIP-98 event");
        let encoded = base64::engine::general_purpose::STANDARD.encode(event_json.as_bytes());
        format!("Nostr {encoded}")
    }

    async fn unconfigured_test_state() -> Arc<AppState> {
        let mut config = crate::config::Config::from_env().expect("test config");
        config.dntls_admission = DntlsAdmission::Off;
        config.redis_url = "redis://127.0.0.1:1".to_string();

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://buzz:buzz_dev@127.0.0.1:1/buzz") // sadscan:disable np.postgres.1
            .expect("lazy test database pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy test Redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("test pubsub"),
        );
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage =
            buzz_media::MediaStorage::new(&config.media).expect("test media storage config");
        let (state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            None::<buzz_audit::AuditService>,
            pubsub,
            auth,
            search,
            workflow_engine,
            Keys::generate(),
            media_storage,
        );
        Arc::new(state)
    }

    async fn dntls_test_state(host: &str, admission: DntlsAdmission) -> Option<Arc<AppState>> {
        dntls_test_state_on(host, admission, "redis://127.0.0.1:1").await
    }

    async fn dntls_test_state_on(
        host: &str,
        admission: DntlsAdmission,
        redis_url: &str,
    ) -> Option<Arc<AppState>> {
        let mut config = crate::config::Config::from_env().ok()?;
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_string());
        config.database_url = database_url.clone();
        config.redis_url = redis_url.to_string();
        config.relay_url = format!("wss://{host}");
        config.require_relay_membership = true;
        config.dntls_admission = admission;

        let pool = sqlx::PgPool::connect(&database_url).await.ok()?;
        let db = buzz_db::Db::from_pool(pool.clone());
        db.ensure_configured_community(host).await.ok()?;

        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()?;
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .ok()?,
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).ok()?;
        let (mut state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        Some(Arc::new(state))
    }

    async fn send(
        state: Arc<AppState>,
        host: &str,
        method: Method,
        path: &str,
        keys: &Keys,
        body: String,
    ) -> axum::response::Response {
        send_with_dntls(state, host, method, path, keys, body, None).await
    }

    async fn send_with_dntls(
        state: Arc<AppState>,
        host: &str,
        method: Method,
        path: &str,
        keys: &Keys,
        body: String,
        dntls_name: Option<&str>,
    ) -> axum::response::Response {
        let scheme = if state.config.relay_url.trim_start().starts_with("wss://") {
            "https"
        } else {
            "http"
        };
        let url = format!("{scheme}://{host}{path}");
        let auth = nip98_auth_header(keys, method.as_str(), &url, body.as_bytes());
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, host)
            .header(header::AUTHORIZATION, auth);
        if let Some(name) = dntls_name {
            builder = builder.header(DNTLS_NAME_HEADER, name);
        }
        if !body.is_empty() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        build_router(state)
            .oneshot(builder.body(Body::from(body)).expect("request"))
            .await
            .expect("response")
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("response JSON")
    }

    fn ws_text(msg: &WsMessage) -> String {
        match msg {
            WsMessage::Text(text) => text.to_string(),
            other => panic!("expected text frame, got {other:?}"),
        }
    }

    async fn auth_connection(
        state: Arc<AppState>,
        host: &str,
        keys: &Keys,
        dntls_name: Option<&str>,
    ) -> (bool, Vec<String>) {
        let community = state
            .db
            .lookup_community_by_host(host)
            .await
            .expect("lookup")
            .expect("community exists");
        let tenant = TenantContext::resolved(community.id, host);
        let challenge = buzz_auth::generate_challenge();
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (ctrl_tx, _ctrl_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let subscriptions = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let conn_id = Uuid::new_v4();
        let conn = Arc::new(ConnectionState {
            conn_id,
            tenant,
            remote_addr: "127.0.0.1:1234".parse().expect("socket addr"),
            auth_state: RwLock::new(AuthState::Pending {
                challenge: challenge.clone(),
            }),
            subscriptions: Arc::clone(&subscriptions),
            send_tx: send_tx.clone(),
            ctrl_tx: ctrl_tx.clone(),
            cancel: cancel.clone(),
            backpressure_count: Arc::new(AtomicU8::new(0)),
            grace_limit: 3,
            dntls_name: dntls_name.map(str::to_string),
        });
        state.conn_manager.register(
            conn_id,
            send_tx,
            ctrl_tx,
            None,
            cancel,
            conn.tenant.community(),
            Arc::clone(&conn.backpressure_count),
            subscriptions,
            3,
        );

        let relay_url =
            crate::api::bridge::nip42_expected_relay_url(&state.config.relay_url, &conn.tenant);
        let event = EventBuilder::auth(&challenge, RelayUrl::parse(&relay_url).expect("relay url"))
            .sign_with_keys(keys)
            .expect("sign AUTH");
        handle_auth(event, Arc::clone(&conn), state).await;

        let mut messages = Vec::new();
        while let Ok(msg) = send_rx.try_recv() {
            messages.push(ws_text(&msg));
        }
        let authenticated = matches!(*conn.auth_state.read().await, AuthState::Authenticated(_));
        (authenticated, messages)
    }

    #[test]
    fn names_entry_includes_approved_at_unix_seconds() {
        let approved_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("unix seconds");
        let json = name_entry_json(&buzz_db::dntls::DntlsApplication {
            pubkey: "ab".repeat(32),
            fqdn: "alice.example".to_string(),
            status: "approved".to_string(),
            created_at: approved_at,
            approved_at: Some(approved_at),
            approved_by: Some("cd".repeat(32)),
        });
        assert_eq!(json["fqdn"], "alice.example");
        assert_eq!(json["approved_at"], 1_700_000_000);
        assert_eq!(json["pubkey"], "ab".repeat(32));
    }

    #[test]
    fn verified_name_from_headers_lowercases_and_ignores_empty() {
        let mut headers = HeaderMap::new();
        headers.insert(DNTLS_NAME_HEADER, HeaderValue::from_static("Alice.Example"));
        assert_eq!(
            verified_name_from_headers(&headers).as_deref(),
            Some("alice.example")
        );

        headers.insert(DNTLS_NAME_HEADER, HeaderValue::from_static("  "));
        assert_eq!(verified_name_from_headers(&headers), None);

        headers.clear();
        assert_eq!(verified_name_from_headers(&headers), None);
    }

    #[tokio::test]
    async fn dntls_routes_return_not_found_when_unconfigured() {
        let state = unconfigured_test_state().await;
        let router = Router::new()
            .route(PENDING_PATH, get(pending))
            .route(APPROVE_PATH, post(approve))
            .route(REJECT_PATH, post(reject))
            .route(NAMES_PATH, get(names))
            .with_state(state);

        for (method, path) in [
            (Method::GET, PENDING_PATH),
            (Method::POST, APPROVE_PATH),
            (Method::POST, REJECT_PATH),
            (Method::GET, NAMES_PATH),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            let json = read_json(response).await;
            assert_eq!(
                json.get("error").and_then(Value::as_str),
                Some("dntls_not_configured"),
                "{path}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_auto_header_auth_binds_and_admits() {
        let host = format!("dntls-auto-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Auto)
            .await
            .expect("requires reachable Postgres and relay test state");

        let (ok, messages) =
            auth_connection(state.clone(), &host, &joiner, Some("Alice.Example")).await;
        assert!(ok, "auto AUTH should succeed: {messages:?}");
        assert!(
            messages
                .iter()
                .all(|msg| !msg.contains(NAME_ALREADY_CLAIMED_NOTICE)),
            "{messages:?}"
        );

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let hex = joiner.public_key().to_hex();
        assert!(state
            .db
            .is_relay_member(community.id, &hex)
            .await
            .expect("membership"));
        let row = state
            .db
            .get_dntls_application(community.id, &hex)
            .await
            .expect("lookup")
            .expect("approved mapping");
        assert_eq!(row.fqdn, "alice.example");
        assert_eq!(row.status, "approved");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_header_auth_creates_pending() {
        let host = format!("dntls-pending-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Approve)
            .await
            .expect("requires reachable Postgres and relay test state");

        let (ok, _messages) =
            auth_connection(state.clone(), &host, &joiner, Some("alice.example")).await;
        assert!(!ok, "approve mode must not auto-admit");

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let hex = joiner.public_key().to_hex();
        assert!(!state
            .db
            .is_relay_member(community.id, &hex)
            .await
            .expect("membership"));
        let row = state
            .db
            .get_dntls_application(community.id, &hex)
            .await
            .expect("lookup")
            .expect("pending row");
        assert_eq!(row.fqdn, "alice.example");
        assert_eq!(row.status, "pending");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_off_ignores_header() {
        let host = format!("dntls-off-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Off)
            .await
            .expect("requires reachable Postgres and relay test state");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        state
            .db
            .add_relay_member(community.id, &joiner.public_key().to_hex(), "member", None)
            .await
            .expect("seed member");

        let (ok, messages) =
            auth_connection(state.clone(), &host, &joiner, Some("alice.example")).await;
        assert!(ok, "ordinary AUTH should succeed: {messages:?}");
        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup");
        assert!(row.is_none());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_first_bound_wins_sends_notice() {
        let host = format!("dntls-conflict-{}.example", Uuid::new_v4().simple());
        let first = Keys::generate();
        let second = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Auto)
            .await
            .expect("requires reachable Postgres and relay test state");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        state
            .db
            .add_relay_member(community.id, &second.public_key().to_hex(), "member", None)
            .await
            .expect("seed second member");

        let (ok, _) = auth_connection(state.clone(), &host, &first, Some("shared.example")).await;
        assert!(ok);

        let (ok, messages) =
            auth_connection(state.clone(), &host, &second, Some("shared.example")).await;
        assert!(
            ok,
            "AUTH still succeeds as an ordinary member: {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains(NAME_ALREADY_CLAIMED_NOTICE)),
            "{messages:?}"
        );

        let row = state
            .db
            .get_dntls_application(community.id, &first.public_key().to_hex())
            .await
            .expect("lookup")
            .expect("first mapping");
        assert_eq!(row.fqdn, "shared.example");
        let stolen = state
            .db
            .get_dntls_application(community.id, &second.public_key().to_hex())
            .await
            .expect("lookup");
        assert!(stolen.is_none());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_missing_header_is_ordinary_auth() {
        let host = format!("dntls-plain-{}.example", Uuid::new_v4().simple());
        let member = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Auto)
            .await
            .expect("requires reachable Postgres and relay test state");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        state
            .db
            .add_relay_member(community.id, &member.public_key().to_hex(), "member", None)
            .await
            .expect("seed member");

        let (ok, messages) = auth_connection(state.clone(), &host, &member, None).await;
        assert!(ok, "ordinary AUTH should succeed: {messages:?}");
        let row = state
            .db
            .get_dntls_application(community.id, &member.public_key().to_hex())
            .await
            .expect("lookup");
        assert!(row.is_none());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_adds_membership_and_retain_mapping() {
        let host = format!("dntls-approve-{}.example", Uuid::new_v4().simple());
        let owner = Keys::generate();
        let joiner = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Approve)
            .await
            .expect("requires reachable Postgres and relay test state");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        state
            .db
            .add_relay_member(community.id, &owner.public_key().to_hex(), "owner", None)
            .await
            .expect("seed owner");
        state
            .db
            .upsert_dntls_pending_application(
                community.id,
                &joiner.public_key().to_hex(),
                "alice.example",
            )
            .await
            .expect("seed pending");

        let approved = send(
            state.clone(),
            &host,
            Method::POST,
            APPROVE_PATH,
            &owner,
            serde_json::json!({ "pubkey": joiner.public_key().to_hex() }).to_string(),
        )
        .await;
        assert_eq!(approved.status(), StatusCode::OK);
        let json = read_json(approved).await;
        assert_eq!(json.get("status").and_then(Value::as_str), Some("approved"));
        assert_eq!(
            json.get("fqdn").and_then(Value::as_str),
            Some("alice.example")
        );

        assert!(state
            .db
            .is_relay_member(community.id, &joiner.public_key().to_hex())
            .await
            .expect("membership"));
        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup")
            .expect("retained mapping");
        assert_eq!(row.status, "approved");
        assert_eq!(row.fqdn, "alice.example");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_reject_deletes_pending_row() {
        let host = format!("dntls-reject-row-{}.example", Uuid::new_v4().simple());
        let owner = Keys::generate();
        let joiner = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Approve)
            .await
            .expect("requires reachable Postgres and relay test state");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        state
            .db
            .add_relay_member(community.id, &owner.public_key().to_hex(), "owner", None)
            .await
            .expect("seed owner");
        state
            .db
            .upsert_dntls_pending_application(
                community.id,
                &joiner.public_key().to_hex(),
                "alice.example",
            )
            .await
            .expect("seed pending");

        let rejected = send(
            state.clone(),
            &host,
            Method::POST,
            REJECT_PATH,
            &owner,
            serde_json::json!({ "pubkey": joiner.public_key().to_hex() }).to_string(),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::OK);

        let missing = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup");
        assert!(missing.is_none());

        let again = send(
            state,
            &host,
            Method::POST,
            REJECT_PATH,
            &owner,
            serde_json::json!({ "pubkey": joiner.public_key().to_hex() }).to_string(),
        )
        .await;
        assert_eq!(again.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_pending_and_names_authz() {
        let host = format!("dntls-authz-{}.example", Uuid::new_v4().simple());
        let owner = Keys::generate();
        let member = Keys::generate();
        let outsider = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Auto)
            .await
            .expect("requires reachable Postgres and relay test state");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        state
            .db
            .add_relay_member(community.id, &owner.public_key().to_hex(), "owner", None)
            .await
            .expect("seed owner");
        state
            .db
            .add_relay_member(community.id, &member.public_key().to_hex(), "member", None)
            .await
            .expect("seed member");

        let pending_forbidden = send(
            state.clone(),
            &host,
            Method::GET,
            PENDING_PATH,
            &member,
            String::new(),
        )
        .await;
        assert_eq!(pending_forbidden.status(), StatusCode::FORBIDDEN);

        let pending_ok = send(
            state.clone(),
            &host,
            Method::GET,
            PENDING_PATH,
            &owner,
            String::new(),
        )
        .await;
        assert_eq!(pending_ok.status(), StatusCode::OK);

        let names_ok = send(
            state.clone(),
            &host,
            Method::GET,
            NAMES_PATH,
            &member,
            String::new(),
        )
        .await;
        assert_eq!(names_ok.status(), StatusCode::OK);

        let names_gated = send(
            state,
            &host,
            Method::GET,
            NAMES_PATH,
            &outsider,
            String::new(),
        )
        .await;
        assert_eq!(names_gated.status(), StatusCode::FORBIDDEN);
        let json = read_json(names_gated).await;
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("relay_membership_required")
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_auto_header_nip98_binds_and_admits() {
        let host = format!("dntls-nip98-auto-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state_on(&host, DntlsAdmission::Auto, TEST_REDIS_URL)
            .await
            .expect("requires reachable Postgres, Redis, and relay test state");

        let response = send_with_dntls(
            state.clone(),
            &host,
            Method::POST,
            "/query",
            &joiner,
            "[]".to_string(),
            Some("Alice.Example"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let hex = joiner.public_key().to_hex();
        assert!(state
            .db
            .is_relay_member(community.id, &hex)
            .await
            .expect("membership"));
        let row = state
            .db
            .get_dntls_application(community.id, &hex)
            .await
            .expect("lookup")
            .expect("approved mapping");
        assert_eq!(row.fqdn, "alice.example");
        assert_eq!(row.status, "approved");

        let again = send_with_dntls(
            state,
            &host,
            Method::POST,
            "/query",
            &joiner,
            "[]".to_string(),
            Some("Alice.Example"),
        )
        .await;
        assert_eq!(again.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_header_nip98_creates_pending() {
        let host = format!("dntls-nip98-pending-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
            .await
            .expect("requires reachable Postgres, Redis, and relay test state");

        let response = send_with_dntls(
            state.clone(),
            &host,
            Method::POST,
            "/query",
            &joiner,
            "[]".to_string(),
            Some("alice.example"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let json = read_json(response).await;
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("relay_membership_required")
        );

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let hex = joiner.public_key().to_hex();
        assert!(!state
            .db
            .is_relay_member(community.id, &hex)
            .await
            .expect("membership"));
        let row = state
            .db
            .get_dntls_application(community.id, &hex)
            .await
            .expect("lookup")
            .expect("pending row");
        assert_eq!(row.fqdn, "alice.example");
        assert_eq!(row.status, "pending");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_missing_header_nip98_is_ordinary_403() {
        let host = format!("dntls-nip98-plain-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state_on(&host, DntlsAdmission::Auto, TEST_REDIS_URL)
            .await
            .expect("requires reachable Postgres, Redis, and relay test state");

        let response = send_with_dntls(
            state.clone(),
            &host,
            Method::POST,
            "/query",
            &joiner,
            "[]".to_string(),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let json = read_json(response).await;
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("relay_membership_required")
        );

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let hex = joiner.public_key().to_hex();
        assert!(!state
            .db
            .is_relay_member(community.id, &hex)
            .await
            .expect("membership"));
        let row = state
            .db
            .get_dntls_application(community.id, &hex)
            .await
            .expect("lookup");
        assert!(row.is_none());
    }
}
