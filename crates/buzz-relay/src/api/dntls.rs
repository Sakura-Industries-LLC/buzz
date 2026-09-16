//! DNTLS verified-name admission HTTP API.
//!
//! The relay's own listener terminates DNTLS mutual TLS (`crate::dntls`) and
//! stamps the verified caller name on every request as `x-dntls-name` after
//! deleting any inbound copy. The relay binds `pubkey ↔ fqdn` at NIP-42 AUTH
//! or the first NIP-98-signed request when
//! [`crate::config::DntlsAdmission`] is not `Off`.
//! Delegated callers skip name binding and use ordinary owner-delegation checks.
//!
//! In `auto` mode the latest verified caller can replace the name's previous
//! key. Listed `BUZZ_DNTLS_ADMINS` names also take this path in `approve` mode:
//! their admin role follows the binding, while displaced keys retain ordinary
//! membership and owners keep their role. Unlisted names retain their existing
//! roles on rebind. A key already approved for another name cannot take a second
//! mapping. Other `approve` connections replace pending bindings and inherit
//! approval of an approved name, removing the displaced key's membership unless
//! it is an owner. A newly verified key may replace a rejected mapping.
//! In `approve` mode, subnames inherit membership (not admin) from the nearest
//! approved DNTLS ancestor in this community, attributed to that ancestor's key.
//!
//! HTTP routes (all NIP-98 signed, outside the Nostr event data plane):
//!
//! - `GET /api/dntls/pending` — list pending applications. Owner/admin only.
//! - `POST /api/dntls/approve` — admit a pending or rejected pubkey through the
//!   same membership path invite claims use, and retain the verified-name mapping.
//! - `POST /api/dntls/reject` — mark a pending application rejected. Owner/admin
//!   only. The same pubkey cannot requeue while rejected. A different key proving
//!   the same name replaces the rejected row with a new pending application.
//!   Approve recovers a rejected row until it is replaced (no un-reject UI).
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
use crate::handlers::side_effects::{
    publish_nip43_member_added, publish_nip43_member_removed, publish_nip43_membership_list,
};
use crate::protocol::RelayMessage;
use crate::state::AppState;
use buzz_core::tenant::TenantContext;

const PENDING_PATH: &str = "/api/dntls/pending";
const APPROVE_PATH: &str = "/api/dntls/approve";
const REJECT_PATH: &str = "/api/dntls/reject";
const NAMES_PATH: &str = "/api/dntls/names";

/// NOTICE sent when an existing mapping prevents admission.
pub(crate) const NAME_ALREADY_CLAIMED_NOTICE: &str = "dntls: name already claimed";
/// NIP-42 OK reason when a matching `approve` application is still pending.
pub(crate) const AUTH_APPROVAL_PENDING: &str = "restricted: dntls approval pending";
/// HTTP 403 `error` when a matching `approve` application is still pending.
pub(crate) const HTTP_APPROVAL_PENDING: &str = "dntls_approval_pending";

const DNTLS_NAME_HEADER: &str = crate::dntls::NAME_HEADER;
const MAX_FQDN_LEN: usize = 255;

/// Outcome of applying a gateway-verified name at AUTH or NIP-98.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionEffect {
    /// Mapping written or refreshed; AUTH should continue.
    Applied,
    /// A name or key mapping conflicts with admission policy. AUTH continues
    /// as an ordinary member if membership allows.
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
    if !crate::handlers::auth::http_has_auth_tag(headers) {
        apply_http_admission(state, &tenant, headers, &pubkey.to_hex()).await?;
    }
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
    let is_admin = state.config.dntls_admins.iter().any(|name| name == fqdn);
    match state.config.dntls_admission {
        DntlsAdmission::Off => Ok(AdmissionEffect::Applied),
        DntlsAdmission::Approve if !is_admin => {
            match state
                .db
                .upsert_dntls_pending_application(tenant.community(), pubkey_hex, fqdn)
                .await
                .map_err(|e| format!("dntls pending upsert: {e}"))?
            {
                buzz_db::dntls::UpsertJoinOutcome::Pending
                | buzz_db::dntls::UpsertJoinOutcome::Rejected => Ok(AdmissionEffect::Applied),
                buzz_db::dntls::UpsertJoinOutcome::Bound {
                    displaced,
                    membership_changed,
                } => {
                    // Both memberships were committed with the binding; do not
                    // reinsert a key that a newer verified caller may displace.
                    if membership_changed {
                        if let Err(e) = publish_nip43_member_added(tenant, state, pubkey_hex).await
                        {
                            tracing::warn!("failed to publish NIP-43 member-added delta after DNTLS rebind: {e}");
                        }
                    }
                    if let Some(old) = displaced.as_deref() {
                        let retained = state
                            .db
                            .is_relay_member(tenant.community(), old)
                            .await
                            .map_err(|e| format!("dntls displaced membership: {e}"))?;
                        if !retained {
                            if let Err(e) = publish_nip43_member_removed(tenant, state, old).await {
                                tracing::warn!("failed to publish NIP-43 member-removed delta after DNTLS rebind: {e}");
                            }
                        }
                    }
                    if membership_changed || displaced.is_some() {
                        if let Err(e) = publish_nip43_membership_list(tenant, state).await {
                            tracing::warn!(
                                "failed to publish NIP-43 membership list after DNTLS rebind: {e}"
                            );
                        }
                    }
                    Ok(AdmissionEffect::Applied)
                }
                buzz_db::dntls::UpsertJoinOutcome::NameAlreadyClaimed => {
                    Ok(AdmissionEffect::NameClaimed)
                }
            }
        }
        DntlsAdmission::Auto | DntlsAdmission::Approve => {
            match state
                .db
                .upsert_dntls_approved_application(
                    tenant.community(),
                    pubkey_hex,
                    fqdn,
                    pubkey_hex,
                    is_admin,
                )
                .await
                .map_err(|e| format!("dntls approved upsert: {e}"))?
            {
                buzz_db::dntls::UpsertJoinOutcome::NameAlreadyClaimed => {
                    Ok(AdmissionEffect::NameClaimed)
                }
                buzz_db::dntls::UpsertJoinOutcome::Pending
                | buzz_db::dntls::UpsertJoinOutcome::Rejected => {
                    Err("dntls approved upsert returned a pending application".to_string())
                }
                buzz_db::dntls::UpsertJoinOutcome::Bound {
                    displaced,
                    membership_changed,
                } => {
                    if is_admin {
                        // Admin roles were committed with the binding. Granting them
                        // here could resurrect an admin displaced by a newer AUTH.
                        if membership_changed {
                            if let Err(e) =
                                publish_nip43_member_added(tenant, state, pubkey_hex).await
                            {
                                tracing::warn!("failed to publish NIP-43 member-added delta after DNTLS admit: {e}");
                            }
                        }
                        if membership_changed || displaced.is_some() {
                            // One snapshot announces both the new admin and displaced member.
                            if let Err(e) = publish_nip43_membership_list(tenant, state).await {
                                tracing::warn!("failed to publish NIP-43 membership list after DNTLS admit: {e}");
                            }
                        }
                    } else {
                        admit_as_member(state, tenant, pubkey_hex, fqdn).await?;
                    }
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
/// Repeating the same approved name/key pair leaves the mapping unchanged.
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

/// True when a membership denial should name a pending DNTLS application.
///
/// Only [`DntlsAdmission::Approve`] looks up: `auto`/`off` stay on the ordinary
/// membership path with no extra query. A pending row counts only when this
/// pubkey's application is `pending` for the same verified name.
pub(crate) async fn matching_pending_application(
    state: &AppState,
    community: buzz_core::tenant::CommunityId,
    pubkey_hex: &str,
    fqdn: Option<&str>,
) -> bool {
    if state.config.dntls_admission != DntlsAdmission::Approve {
        return false;
    }
    let Some(fqdn) = fqdn.map(str::trim).filter(|name| !name.is_empty()) else {
        return false;
    };
    let fqdn = fqdn.to_ascii_lowercase();
    match state.db.get_dntls_application(community, pubkey_hex).await {
        Ok(Some(row)) => row.status == "pending" && row.fqdn == fqdn,
        Ok(None) => false,
        Err(error) => {
            tracing::warn!(
                community = %community,
                pubkey = %pubkey_hex,
                error = %error,
                "DNTLS pending lookup failed; using generic membership denial"
            );
            false
        }
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
    let Some(existing) = existing.filter(|row| row.status == "pending" || row.status == "rejected")
    else {
        return Err(super::api_error(
            StatusCode::NOT_FOUND,
            "application_not_found",
        ));
    };

    let is_admin = state.config.dntls_admins.contains(&existing.fqdn);
    let (approved, membership_changed) = state
        .db
        .approve_dntls_application(
            tenant.community(),
            &target,
            &existing.fqdn,
            &pubkey.to_hex(),
            is_admin,
        )
        .await
        .map_err(|e| super::internal_error(&format!("dntls approve persist: {e}")))?
        .ok_or_else(|| super::api_error(StatusCode::NOT_FOUND, "application_not_found"))?;
    if membership_changed {
        if let Err(e) = publish_nip43_member_added(&tenant, &state, &target).await {
            tracing::warn!("failed to publish NIP-43 member-added delta after DNTLS approve: {e}");
        }
        if let Err(e) = publish_nip43_membership_list(&tenant, &state).await {
            tracing::warn!("failed to publish NIP-43 membership list after DNTLS approve: {e}");
        }
    }

    Ok(Json(serde_json::json!({
        "status": "approved",
        "fqdn": approved.fqdn,
    })))
}

/// Reject a pending application — `POST /api/dntls/reject`.
///
/// Sets status to `rejected`. The same pubkey's next AUTH is a generic
/// membership denial and does not recreate a pending row.
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
        verified_name_from_headers(&headers).as_deref(),
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
        "agent": row.admitted_via_parent.is_some(),
        "owner": row.admitted_via_parent,
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
            builder = builder.extension(axum::extract::ConnectInfo(crate::dntls::DntlsPeer {
                addr: "127.0.0.1:1234".parse().expect("socket address"),
                name: name.to_string(),
                community: Arc::from(host),
            }));
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
            admitted_via_parent: None,
        });
        assert_eq!(json["fqdn"], "alice.example");
        assert_eq!(json["approved_at"], 1_700_000_000);
        assert_eq!(json["pubkey"], "ab".repeat(32));
        assert_eq!(json["agent"], false);
        assert!(json["owner"].is_null());
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
    async fn dntls_listed_admin_bypasses_approval_but_other_names_do_not() {
        for mode in [DntlsAdmission::Approve, DntlsAdmission::Auto] {
            let host = format!("dntls-admin-{}.example", Uuid::new_v4().simple());
            let mut state = dntls_test_state_on(&host, mode, TEST_REDIS_URL)
                .await
                .expect("requires reachable Postgres, Redis, and relay test state");
            Arc::make_mut(&mut Arc::get_mut(&mut state).expect("unique state").config)
                .dntls_admins = vec!["josh.dntls".to_string()];
            let admin = Keys::generate();
            let newcomer = Keys::generate();
            let (ok, messages) =
                auth_connection(state.clone(), &host, &admin, Some(" Josh.DNTLS ")).await;
            assert!(ok, "listed admin AUTH: {messages:?}");
            let response = send(
                state.clone(),
                &host,
                Method::GET,
                PENDING_PATH,
                &admin,
                String::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                read_json(response).await["applications"],
                serde_json::json!([])
            );

            let (ok, _) =
                auth_connection(state.clone(), &host, &newcomer, Some("newcomer.dntls")).await;
            assert_eq!(ok, mode == DntlsAdmission::Auto);
            let community = state
                .db
                .lookup_community_by_host(&host)
                .await
                .expect("lookup")
                .expect("community");
            let members = state
                .db
                .list_relay_members(community.id)
                .await
                .expect("members");
            assert_eq!(
                members
                    .iter()
                    .find(|m| m.pubkey == admin.public_key().to_hex())
                    .expect("admin member")
                    .role,
                "admin"
            );
            let newcomer_member = members
                .iter()
                .find(|m| m.pubkey == newcomer.public_key().to_hex());
            if mode == DntlsAdmission::Auto {
                assert_eq!(newcomer_member.expect("ordinary member").role, "member");
            } else {
                assert!(newcomer_member.is_none());
                let response = send(
                    state.clone(),
                    &host,
                    Method::GET,
                    PENDING_PATH,
                    &admin,
                    String::new(),
                )
                .await;
                let json = read_json(response).await;
                assert_eq!(json["applications"][0]["fqdn"], "newcomer.dntls");
                assert_eq!(
                    json["applications"][0]["pubkey"],
                    newcomer.public_key().to_hex()
                );
            }

            // Exact names only: a subname does not inherit the configured role.
            let subname = Keys::generate();
            let (ok, _) =
                auth_connection(state.clone(), &host, &subname, Some("buzz.josh.dntls")).await;
            assert!(ok, "subnames inherit membership, not the configured role");
            let member = state
                .db
                .get_relay_member(community.id, &subname.public_key().to_hex())
                .await
                .expect("subname membership");
            assert_eq!(member.map(|m| m.role).as_deref(), Some("member"));
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_listed_admin_promotes_member_and_preserves_owner() {
        for initial_role in ["member", "owner"] {
            let host = format!("dntls-promote-{}.example", Uuid::new_v4().simple());
            let mut state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
                .await
                .expect("requires reachable Postgres, Redis, and relay test state");
            Arc::make_mut(&mut Arc::get_mut(&mut state).expect("unique state").config)
                .dntls_admins = vec!["josh.dntls".to_string()];
            let keys = Keys::generate();
            let hex = keys.public_key().to_hex();
            let community = state
                .db
                .lookup_community_by_host(&host)
                .await
                .expect("lookup")
                .expect("community");
            state
                .db
                .add_relay_member(community.id, &hex, initial_role, None)
                .await
                .expect("seed member");
            // Also cover a previously queued application when the allowlist changes.
            state
                .db
                .upsert_dntls_pending_application(community.id, &hex, "josh.dntls")
                .await
                .expect("seed pending");
            let response = send_with_dntls(
                state.clone(),
                &host,
                Method::GET,
                PENDING_PATH,
                &keys,
                String::new(),
                Some("josh.dntls"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "NIP-98 admission");
            assert_eq!(
                read_json(response).await["applications"],
                serde_json::json!([])
            );
            let expected_role = if initial_role == "owner" {
                "owner"
            } else {
                "admin"
            };
            assert_eq!(
                state
                    .db
                    .get_relay_member(community.id, &hex)
                    .await
                    .expect("lookup")
                    .expect("member")
                    .role,
                expected_role
            );

            // Removing configuration is not a revocation operation.
            let state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
                .await
                .expect("reopen community without configured admins");
            let (ok, messages) =
                auth_connection(state.clone(), &host, &keys, Some("josh.dntls")).await;
            assert!(ok, "existing member AUTH: {messages:?}");
            assert_eq!(
                state
                    .db
                    .get_relay_member(community.id, &hex)
                    .await
                    .expect("lookup")
                    .expect("member")
                    .role,
                expected_role
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_admin_rebinding_transfers_role_and_publishes_both_members() {
        for mode in [DntlsAdmission::Approve, DntlsAdmission::Auto] {
            let host = format!("dntls-admin-rebind-{}.example", Uuid::new_v4().simple());
            let mut state = dntls_test_state_on(&host, mode, TEST_REDIS_URL)
                .await
                .expect("requires reachable Postgres, Redis, and relay test state");
            Arc::make_mut(&mut Arc::get_mut(&mut state).expect("unique state").config)
                .dntls_admins = vec!["josh.dntls".to_string()];
            let first = Keys::generate();
            let second = Keys::generate();
            for keys in [&first, &second] {
                let (ok, messages) =
                    auth_connection(state.clone(), &host, keys, Some("josh.dntls")).await;
                assert!(ok, "admin AUTH: {messages:?}");
            }
            let community = state
                .db
                .lookup_community_by_host(&host)
                .await
                .expect("lookup")
                .expect("community");
            for (keys, role) in [(&first, "member"), (&second, "admin")] {
                assert_eq!(
                    state
                        .db
                        .get_relay_member(community.id, &keys.public_key().to_hex(),)
                        .await
                        .expect("lookup")
                        .expect("member")
                        .role,
                    role
                );
            }
            let response = send(
                state.clone(),
                &host,
                Method::GET,
                PENDING_PATH,
                &first,
                String::new(),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "old key loses admin API access"
            );
            let response = send(
                state.clone(),
                &host,
                Method::GET,
                NAMES_PATH,
                &second,
                String::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let json = read_json(response).await;
            assert_eq!(json["names"].as_array().expect("names").len(), 1);
            assert_eq!(json["names"][0]["pubkey"], second.public_key().to_hex());
            assert_eq!(json["names"][0]["fqdn"], "josh.dntls");

            let response = send(
                state.clone(),
                &host,
                Method::POST,
                "/query",
                &second,
                r#"[{"kinds":[13534]}]"#.to_string(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let events = read_json(response).await;
            let snapshot = events
                .as_array()
                .expect("events")
                .iter()
                .find(|event| event["kind"] == 13534)
                .expect("membership snapshot");
            for (keys, role) in [(&first, "member"), (&second, "admin")] {
                assert!(
                    snapshot["tags"]
                        .as_array()
                        .expect("tags")
                        .iter()
                        .any(|tag| {
                            tag[0] == "member"
                                && tag[1] == keys.public_key().to_hex()
                                && tag[2] == role
                        }),
                    "snapshot missing {role}: {snapshot}"
                );
            }
            // Owner bootstrap remains authoritative even when its name is displaced.
            state
                .db
                .bootstrap_owner(community.id, &second.public_key().to_hex())
                .await
                .expect("bootstrap owner");
            let third = Keys::generate();
            let (ok, messages) =
                auth_connection(state.clone(), &host, &third, Some("josh.dntls")).await;
            assert!(ok, "new key AUTH: {messages:?}");
            assert_eq!(
                state
                    .db
                    .get_relay_member(community.id, &second.public_key().to_hex(),)
                    .await
                    .expect("lookup")
                    .expect("owner")
                    .role,
                "owner"
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

        let (ok, messages) =
            auth_connection(state.clone(), &host, &joiner, Some("alice.example")).await;
        assert!(!ok, "approve mode must not auto-admit");
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains(AUTH_APPROVAL_PENDING)),
            "{messages:?}"
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
    async fn dntls_auto_rebinds_name_after_key_rotation() {
        let host = format!("dntls-rebind-{}.example", Uuid::new_v4().simple());
        let first = Keys::generate();
        let second = Keys::generate();
        let state = dntls_test_state_on(&host, DntlsAdmission::Auto, TEST_REDIS_URL)
            .await
            .expect("requires reachable Postgres, Redis, and relay test state");

        let (ok, messages) =
            auth_connection(state.clone(), &host, &first, Some("shared.example")).await;
        assert!(ok, "first AUTH: {messages:?}");
        let (ok, _) = auth_connection(state.clone(), &host, &second, None).await;
        assert!(
            !ok,
            "a new key without a verified name must not be admitted"
        );

        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/query")
                    .header(header::HOST, &host)
                    .header(
                        header::AUTHORIZATION,
                        nip98_auth_header(&second, "POST", &format!("https://{host}/query"), b"[]"),
                    )
                    .header(DNTLS_NAME_HEADER, "shared.example")
                    .body(Body::from("[]"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a forged identity header must not replace the binding"
        );

        let (ok, messages) =
            auth_connection(state.clone(), &host, &second, Some("shared.example")).await;
        assert!(ok, "rotated key AUTH must succeed: {messages:?}");
        assert!(
            messages
                .iter()
                .all(|msg| !msg.contains(NAME_ALREADY_CLAIMED_NOTICE)),
            "{messages:?}"
        );

        // Possessing the old Nostr key alone cannot reclaim the name. Its
        // ordinary membership is retained; rebinding is not account migration.
        let (ok, messages) = auth_connection(state.clone(), &host, &first, None).await;
        assert!(ok, "old key retains ordinary membership: {messages:?}");
        let response = send(
            state.clone(),
            &host,
            Method::GET,
            NAMES_PATH,
            &second,
            String::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = read_json(response).await;
        let names = json["names"].as_array().expect("names");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0]["pubkey"], second.public_key().to_hex());
        assert_eq!(names[0]["fqdn"], "shared.example");

        // Members discover the new key through the normal NIP-43 events.
        let response = send(
            state.clone(),
            &host,
            Method::POST,
            "/query",
            &second,
            r#"[{"kinds":[8000,13534]}]"#.to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let events = read_json(response).await;
        let events = events.as_array().expect("events");
        for (kind, tag_name) in [(8000, "p"), (13534, "member")] {
            assert!(
                events.iter().any(|event| {
                    event["kind"] == kind
                        && event["tags"]
                            .as_array()
                            .expect("tags")
                            .iter()
                            .any(|tag| tag[0] == tag_name && tag[1] == second.public_key().to_hex())
                }),
                "missing NIP-43 kind {kind} for the new key: {events:?}"
            );
        }

        // The HTTP admission path must also replace a binding, not only AUTH.
        let third = Keys::generate();
        let response = send_with_dntls(
            state.clone(),
            &host,
            Method::POST,
            "/query",
            &third,
            "[]".to_string(),
            Some("shared.example"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(state, &host, Method::GET, NAMES_PATH, &third, String::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = read_json(response).await;
        let names = json["names"].as_array().expect("names");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0]["pubkey"], third.public_key().to_hex());
        assert_eq!(names[0]["fqdn"], "shared.example");
    }

    #[tokio::test]
    #[ignore = "requires Postgres and Redis"]
    async fn dntls_http_delegation_never_claims_the_transport_name() {
        let host = format!("dntls-http-agent-{}.example", Uuid::new_v4().simple());
        let owner = Keys::generate();
        let agent = Keys::generate();
        let mut state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
            .await
            .expect("test services");
        let config = Arc::make_mut(&mut Arc::get_mut(&mut state).unwrap().config);
        config.dntls_admins = vec!["josh.dntls".to_string()];
        config.allow_nip_oa_auth = true;
        assert!(
            auth_connection(state.clone(), &host, &owner, Some("josh.dntls"))
                .await
                .0
        );
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .unwrap()
            .unwrap();
        let tag = buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "").unwrap();
        for path in ["/query", NAMES_PATH] {
            for auth_tag in [tag.as_str(), "invalid"] {
                let method = if path == "/query" {
                    Method::POST
                } else {
                    Method::GET
                };
                let body = if path == "/query" { "[]" } else { "" };
                let url = format!("https://{host}{path}");
                let auth = nip98_auth_header(&agent, method.as_str(), &url, body.as_bytes());
                let response = build_router(state.clone())
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .header(header::HOST, &host)
                            .header(header::AUTHORIZATION, auth)
                            .header(header::CONTENT_TYPE, "application/json")
                            .header("x-auth-tag", auth_tag)
                            .extension(axum::extract::ConnectInfo(crate::dntls::DntlsPeer {
                                addr: "127.0.0.1:1234".parse().unwrap(),
                                name: "josh.dntls".to_string(),
                                community: Arc::from(host.as_str()),
                            }))
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if auth_tag == "invalid" {
                    assert_eq!(
                        response.status(),
                        StatusCode::FORBIDDEN,
                        "{path}: invalid tag"
                    );
                } else {
                    assert_eq!(
                        response.status(),
                        StatusCode::OK,
                        "{path}: valid delegation"
                    );
                }
                assert!(
                    state
                        .db
                        .get_dntls_application(community.id, &agent.public_key().to_hex())
                        .await
                        .unwrap()
                        .is_none(),
                    "{path}: agent must not bind"
                );
                assert!(
                    state
                        .db
                        .get_relay_member(community.id, &agent.public_key().to_hex())
                        .await
                        .unwrap()
                        .is_none(),
                    "{path}: agent must not gain a role"
                );
                assert_eq!(
                    state
                        .db
                        .get_relay_member(community.id, &owner.public_key().to_hex())
                        .await
                        .unwrap()
                        .unwrap()
                        .role,
                    "admin"
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres and Redis"]
    async fn dntls_approve_rebinds_approved_name_without_another_approval() {
        let host = format!("dntls-approved-rebind-{}.example", Uuid::new_v4().simple());
        let owner = Keys::generate();
        let first = Keys::generate();
        let second = Keys::generate();
        let third = Keys::generate();
        let state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
            .await
            .expect("requires reachable Postgres, Redis, and relay test state");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .add_relay_member(community.id, &owner.public_key().to_hex(), "owner", None)
            .await
            .unwrap();
        let (ok, messages) =
            auth_connection(state.clone(), &host, &first, Some("shared.example")).await;
        assert!(!ok, "{messages:?}");
        assert!(messages
            .iter()
            .any(|msg| msg.contains(AUTH_APPROVAL_PENDING)));
        let response = send(
            state.clone(),
            &host,
            Method::POST,
            APPROVE_PATH,
            &owner,
            serde_json::json!({ "pubkey": first.public_key().to_hex() }).to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let (ok, messages) =
            auth_connection(state.clone(), &host, &second, Some("shared.example")).await;
        assert!(ok, "reinstalled caller is already approved: {messages:?}");
        assert!(messages
            .iter()
            .all(|msg| !msg.contains(NAME_ALREADY_CLAIMED_NOTICE)));
        let (ok, messages) = auth_connection(state.clone(), &host, &first, None).await;
        assert!(!ok, "the displaced key must lose admission");
        assert!(messages
            .iter()
            .any(|msg| msg.contains("restricted: not a relay member")));
        let response = send(
            state.clone(),
            &host,
            Method::GET,
            NAMES_PATH,
            &second,
            String::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let names = read_json(response).await;
        assert_eq!(names["names"].as_array().unwrap().len(), 1);
        assert_eq!(names["names"][0]["pubkey"], second.public_key().to_hex());
        assert_eq!(names["names"][0]["fqdn"], "shared.example");

        let response = send(
            state.clone(),
            &host,
            Method::POST,
            "/query",
            &second,
            r#"[{"kinds":[8000,8001,13534]}]"#.to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let events = read_json(response).await;
        let events = events.as_array().unwrap();
        for (kind, pubkey) in [
            (8000, second.public_key().to_hex()),
            (8001, first.public_key().to_hex()),
        ] {
            assert!(
                events.iter().any(|event| {
                    event["kind"] == kind
                        && event["tags"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|tag| tag[0] == "p" && tag[1] == pubkey)
                }),
                "missing delta kind {kind}: {events:?}"
            );
        }
        let snapshots: Vec<_> = events
            .iter()
            .filter(|event| event["kind"] == 13534)
            .collect();
        assert_eq!(snapshots.len(), 1, "one authoritative membership snapshot");
        let members: Vec<_> = snapshots[0]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|tag| tag[0] == "member")
            .map(|tag| tag[1].as_str().unwrap())
            .collect();
        assert!(members.contains(&second.public_key().to_hex().as_str()));
        assert!(members.contains(&owner.public_key().to_hex().as_str()));
        assert!(!members.contains(&first.public_key().to_hex().as_str()));

        // NIP-98 follows the same transition, without a preceding WebSocket AUTH.
        let response = send_with_dntls(
            state.clone(),
            &host,
            Method::POST,
            "/query",
            &third,
            "[]".to_string(),
            Some("shared.example"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(
            state.clone(),
            &host,
            Method::GET,
            NAMES_PATH,
            &third,
            String::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            read_json(response).await["names"][0]["pubkey"],
            third.public_key().to_hex()
        );
        let response = send(
            state,
            &host,
            Method::POST,
            "/query",
            &second,
            "[]".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
    async fn dntls_reject_persists_rejected_row() {
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

        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup")
            .expect("rejected row");
        assert_eq!(row.status, "rejected");
        assert_eq!(row.fqdn, "alice.example");
        assert!(state
            .db
            .list_dntls_applications(community.id, "pending")
            .await
            .expect("pending list")
            .is_empty());

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
            Some(HTTP_APPROVAL_PENDING)
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

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_auth_pending_requires_matching_name_and_key() {
        let host = format!("dntls-pending-match-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let other = Keys::generate();
        let state = dntls_test_state(&host, DntlsAdmission::Approve)
            .await
            .expect("requires reachable Postgres and relay test state");

        let (ok, messages) =
            auth_connection(state.clone(), &host, &joiner, Some("alice.example")).await;
        assert!(!ok, "{messages:?}");
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains(AUTH_APPROVAL_PENDING)),
            "{messages:?}"
        );

        let (ok, messages) = auth_connection(state.clone(), &host, &joiner, None).await;
        assert!(!ok, "{messages:?}");
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains("restricted: not a relay member")),
            "{messages:?}"
        );
        assert!(
            messages
                .iter()
                .all(|msg| !msg.contains(AUTH_APPROVAL_PENDING)),
            "{messages:?}"
        );

        let (ok, messages) =
            auth_connection(state.clone(), &host, &other, Some("alice.example")).await;
        assert!(!ok, "{messages:?}");
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains(AUTH_APPROVAL_PENDING)),
            "{messages:?}"
        );
        let (ok, messages) = auth_connection(state, &host, &joiner, None).await;
        assert!(!ok, "{messages:?}");
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains("restricted: not a relay member")),
            "the displaced key is no longer pending: {messages:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_non_approve_auth_keeps_generic_membership_denial() {
        for (admission, name) in [
            (DntlsAdmission::Off, Some("alice.example")),
            (DntlsAdmission::Auto, None),
        ] {
            let host = format!("dntls-generic-auth-{}.example", Uuid::new_v4().simple());
            let joiner = Keys::generate();
            let state = dntls_test_state(&host, admission)
                .await
                .expect("requires reachable Postgres and relay test state");
            let (ok, messages) = auth_connection(state, &host, &joiner, name).await;
            assert!(!ok, "{admission:?}: {messages:?}");
            assert!(
                messages
                    .iter()
                    .any(|msg| msg.contains("restricted: not a relay member")),
                "{admission:?}: {messages:?}"
            );
            assert!(
                messages
                    .iter()
                    .all(|msg| !msg.contains(AUTH_APPROVAL_PENDING)),
                "{admission:?}: {messages:?}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_http_pending_requires_matching_name_and_key() {
        let host = format!("dntls-nip98-match-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let other = Keys::generate();
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
        assert_eq!(
            read_json(response)
                .await
                .get("error")
                .and_then(Value::as_str),
            Some(HTTP_APPROVAL_PENDING)
        );

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
        assert_eq!(
            read_json(response)
                .await
                .get("error")
                .and_then(Value::as_str),
            Some("relay_membership_required")
        );

        let response = send_with_dntls(
            state,
            &host,
            Method::POST,
            "/query",
            &other,
            "[]".to_string(),
            Some("alice.example"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            read_json(response)
                .await
                .get("error")
                .and_then(Value::as_str),
            Some(HTTP_APPROVAL_PENDING)
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_non_approve_http_keeps_generic_membership_denial() {
        for (admission, name) in [
            (DntlsAdmission::Off, Some("alice.example")),
            (DntlsAdmission::Auto, None),
        ] {
            let host = format!("dntls-generic-http-{}.example", Uuid::new_v4().simple());
            let joiner = Keys::generate();
            let state = dntls_test_state_on(&host, admission, TEST_REDIS_URL)
                .await
                .expect("requires reachable Postgres, Redis, and relay test state");
            let response = send_with_dntls(
                state,
                &host,
                Method::POST,
                "/query",
                &joiner,
                "[]".to_string(),
                name,
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{admission:?}");
            assert_eq!(
                read_json(response)
                    .await
                    .get("error")
                    .and_then(Value::as_str),
                Some("relay_membership_required"),
                "{admission:?}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_reject_blocks_same_pubkey_and_frees_name() {
        let host = format!("dntls-reject-requeue-{}.example", Uuid::new_v4().simple());
        let owner = Keys::generate();
        let joiner = Keys::generate();
        let other = Keys::generate();
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

        let (ok, messages) =
            auth_connection(state.clone(), &host, &joiner, Some("alice.example")).await;
        assert!(!ok, "{messages:?}");

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

        let (ok, messages) =
            auth_connection(state.clone(), &host, &joiner, Some("alice.example")).await;
        assert!(!ok, "{messages:?}");
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains("restricted: not a relay member")),
            "{messages:?}"
        );
        assert!(
            messages
                .iter()
                .all(|msg| !msg.contains(AUTH_APPROVAL_PENDING)),
            "{messages:?}"
        );
        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup")
            .expect("rejected row");
        assert_eq!(row.status, "rejected");

        let (ok, messages) =
            auth_connection(state.clone(), &host, &other, Some("alice.example")).await;
        assert!(!ok, "{messages:?}");
        assert!(
            messages
                .iter()
                .any(|msg| msg.contains(AUTH_APPROVAL_PENDING)),
            "a different key may still apply for the freed name: {messages:?}"
        );
        assert!(state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("replaced rejected")
            .is_none());
        let steal = send(
            state,
            &host,
            Method::POST,
            APPROVE_PATH,
            &owner,
            serde_json::json!({ "pubkey": joiner.public_key().to_hex() }).to_string(),
        )
        .await;
        assert_eq!(steal.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_recovers_rejected_row() {
        let host = format!("dntls-reject-recover-{}.example", Uuid::new_v4().simple());
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

        let recovered = send(
            state.clone(),
            &host,
            Method::POST,
            APPROVE_PATH,
            &owner,
            serde_json::json!({ "pubkey": joiner.public_key().to_hex() }).to_string(),
        )
        .await;
        assert_eq!(recovered.status(), StatusCode::OK);
        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup")
            .expect("approved after misclick");
        assert_eq!(row.status, "approved");
        assert!(state
            .db
            .is_relay_member(community.id, &joiner.public_key().to_hex())
            .await
            .expect("membership"));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_subname_inherits_membership_and_parent_attribution() {
        let host = format!("dntls-subname-{}.example", Uuid::new_v4().simple());
        let state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
            .await
            .expect("requires Postgres and Redis");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .unwrap()
            .unwrap();
        let parent = Keys::generate();
        let child = Keys::generate();
        let parent_hex = parent.public_key().to_hex();
        let child_hex = child.public_key().to_hex();
        state
            .db
            .add_relay_member(community.id, &parent_hex, "owner", None)
            .await
            .unwrap();
        state
            .db
            .upsert_dntls_approved_application(
                community.id,
                &parent_hex,
                "josh.dntls",
                &parent_hex,
                false,
            )
            .await
            .unwrap();

        let (ok, messages) =
            auth_connection(state.clone(), &host, &child, Some("fizz.josh.dntls")).await;
        assert!(ok, "subname AUTH: {messages:?}");
        assert_eq!(
            state
                .db
                .get_relay_member(community.id, &child_hex)
                .await
                .unwrap()
                .unwrap()
                .role,
            "member"
        );
        let row = state
            .db
            .get_dntls_application(community.id, &child_hex)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "approved");
        assert_eq!(row.approved_by.as_deref(), Some(parent_hex.as_str()));
        assert_eq!(row.admitted_via_parent.as_deref(), Some("josh.dntls"));
        let events = state
            .db
            .query_events(&buzz_db::EventQuery {
                kinds: Some(vec![8000, 13534]),
                ..buzz_db::EventQuery::for_community(community.id)
            })
            .await
            .unwrap();
        let mut kinds: Vec<_> = events
            .iter()
            .map(|stored| stored.event.kind.as_u16())
            .collect();
        kinds.sort_unstable();
        assert_eq!(kinds, [8000, 13534], "NIP-43 admission announcements");
        for stored in &events {
            let expected = if stored.event.kind.as_u16() == 8000 {
                vec!["p", child_hex.as_str()]
            } else {
                vec!["member", child_hex.as_str(), "member"]
            };
            assert!(stored
                .event
                .tags
                .iter()
                .any(|tag| tag.as_slice() == expected));
        }
        let snapshot = events
            .iter()
            .find(|stored| stored.event.kind.as_u16() == 13534)
            .unwrap();
        assert!(snapshot
            .event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["dntls-agent", child_hex.as_str(), "josh.dntls"]));

        let response = send(
            state.clone(),
            &host,
            Method::GET,
            NAMES_PATH,
            &child,
            String::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let names = read_json(response).await;
        let mut fqdns: Vec<_> = names["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["fqdn"].as_str().unwrap())
            .collect();
        fqdns.sort_unstable();
        assert_eq!(fqdns, ["fizz.josh.dntls", "josh.dntls"]);
        let child_entry = names["names"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["pubkey"] == child_hex)
            .unwrap();
        assert_eq!(child_entry["agent"], true);
        assert_eq!(child_entry["owner"], "josh.dntls");
        let parent_entry = names["names"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["pubkey"] == parent_hex)
            .unwrap();
        assert_eq!(parent_entry["agent"], false);
        assert!(parent_entry["owner"].is_null());
        let response = send(
            state.clone(),
            &host,
            Method::GET,
            PENDING_PATH,
            &parent,
            String::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            read_json(response).await["applications"],
            serde_json::json!([])
        );

        // A verified replacement retains approval, but not the displaced membership.
        let replacement = Keys::generate();
        let response = send_with_dntls(
            state.clone(),
            &host,
            Method::GET,
            NAMES_PATH,
            &replacement,
            String::new(),
            Some("fizz.josh.dntls"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!state
            .db
            .is_relay_member(community.id, &child_hex)
            .await
            .unwrap());
        let rebound = state
            .db
            .get_dntls_application(community.id, &replacement.public_key().to_hex())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rebound.approved_by, row.approved_by);
        assert_eq!(rebound.approved_at, row.approved_at);
        assert_eq!(rebound.admitted_via_parent, row.admitted_via_parent);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_subname_requires_approved_ancestor_in_community() {
        for (parent_status, child_name) in [
            ("pending", "fizz.josh.dntls"),
            ("rejected", "fizz.josh.dntls"),
            ("unbound", "fizz.josh.dntls"),
            ("foreign", "fizz.josh.dntls"),
            ("approved", "fizz.other.dntls"),
            ("approved", "fizz.notjosh.dntls"),
        ] {
            let host = format!("dntls-subname-denied-{}.example", Uuid::new_v4().simple());
            let state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
                .await
                .expect("requires Postgres and Redis");
            let community = state
                .db
                .lookup_community_by_host(&host)
                .await
                .unwrap()
                .unwrap();
            let parent = Keys::generate().public_key().to_hex();
            state
                .db
                .add_relay_member(community.id, &parent, "member", None)
                .await
                .unwrap();
            match parent_status {
                "pending" | "rejected" => {
                    state
                        .db
                        .upsert_dntls_pending_application(community.id, &parent, "josh.dntls")
                        .await
                        .unwrap();
                    if parent_status == "rejected" {
                        state
                            .db
                            .reject_dntls_application(community.id, &parent)
                            .await
                            .unwrap();
                    }
                }
                "approved" | "foreign" => {
                    let target = if parent_status == "foreign" {
                        state
                            .db
                            .ensure_configured_community(&format!("other-{host}"))
                            .await
                            .unwrap()
                            .id
                    } else {
                        community.id
                    };
                    state
                        .db
                        .upsert_dntls_approved_application(
                            target,
                            &parent,
                            "josh.dntls",
                            &parent,
                            false,
                        )
                        .await
                        .unwrap();
                }
                _ => {}
            }
            let child = Keys::generate();
            let (ok, messages) =
                auth_connection(state.clone(), &host, &child, Some(child_name)).await;
            assert!(!ok, "{parent_status}/{child_name}: {messages:?}");
            assert!(
                messages
                    .iter()
                    .any(|message| message.contains(AUTH_APPROVAL_PENDING)),
                "{messages:?}"
            );
            let row = state
                .db
                .get_dntls_application(community.id, &child.public_key().to_hex())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.status, "pending");
            assert!(row.approved_by.is_none());
            assert!(!state
                .db
                .is_relay_member(community.id, &child.public_key().to_hex())
                .await
                .unwrap());
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_subname_uses_nearest_approved_ancestor() {
        let host = format!("dntls-subname-depth-{}.example", Uuid::new_v4().simple());
        let state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
            .await
            .expect("requires Postgres and Redis");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .unwrap()
            .unwrap();
        let root = Keys::generate().public_key().to_hex();
        let nearer_keys = Keys::generate();
        let nearer = nearer_keys.public_key().to_hex();
        state
            .db
            .upsert_dntls_pending_application(community.id, &nearer, "fizz.josh.dntls")
            .await
            .unwrap();
        state
            .db
            .upsert_dntls_approved_application(community.id, &root, "josh.dntls", &root, false)
            .await
            .unwrap();

        for (name, approver) in [
            ("bot.fizz.josh.dntls", root.as_str()),
            ("next.fizz.josh.dntls", nearer.as_str()),
        ] {
            let child = Keys::generate();
            let response = send_with_dntls(
                state.clone(),
                &host,
                Method::GET,
                NAMES_PATH,
                &child,
                String::new(),
                Some(name),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            let row = state
                .db
                .get_dntls_application(community.id, &child.public_key().to_hex())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.status, "approved");
            assert_eq!(row.approved_by.as_deref(), Some(approver));
            let (ok, messages) =
                auth_connection(state.clone(), &host, &nearer_keys, Some("fizz.josh.dntls")).await;
            assert!(ok, "pending ancestor inherits on retry: {messages:?}");
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_subname_preserves_rejection_and_single_name_binding() {
        let host = format!("dntls-subname-rejected-{}.example", Uuid::new_v4().simple());
        let state = dntls_test_state_on(&host, DntlsAdmission::Approve, TEST_REDIS_URL)
            .await
            .expect("requires Postgres and Redis");
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .unwrap()
            .unwrap();
        let parent = Keys::generate();
        let child = Keys::generate();
        let parent_hex = parent.public_key().to_hex();
        let child_hex = child.public_key().to_hex();
        state
            .db
            .upsert_dntls_pending_application(community.id, &child_hex, "fizz.josh.dntls")
            .await
            .unwrap();
        state
            .db
            .reject_dntls_application(community.id, &child_hex)
            .await
            .unwrap();
        state
            .db
            .upsert_dntls_approved_application(
                community.id,
                &parent_hex,
                "josh.dntls",
                &parent_hex,
                false,
            )
            .await
            .unwrap();
        let (ok, messages) =
            auth_connection(state.clone(), &host, &child, Some("fizz.josh.dntls")).await;
        assert!(!ok, "{messages:?}");
        let rejected = state
            .db
            .get_dntls_application(community.id, &child_hex)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rejected.status, "rejected");
        assert!(!state
            .db
            .is_relay_member(community.id, &child_hex)
            .await
            .unwrap());

        let replacement = Keys::generate();
        let (ok, messages) =
            auth_connection(state.clone(), &host, &replacement, Some("fizz.josh.dntls")).await;
        assert!(
            ok,
            "a different verified key replaces rejection: {messages:?}"
        );
        assert!(state
            .db
            .get_dntls_application(community.id, &child_hex)
            .await
            .unwrap()
            .is_none());

        let (_, messages) =
            auth_connection(state.clone(), &host, &replacement, Some("other.josh.dntls")).await;
        assert!(
            messages
                .iter()
                .any(|message| message.contains(NAME_ALREADY_CLAIMED_NOTICE)),
            "{messages:?}"
        );
        let row = state
            .db
            .get_dntls_application(community.id, &replacement.public_key().to_hex())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.fqdn, "fizz.josh.dntls");
    }
}
