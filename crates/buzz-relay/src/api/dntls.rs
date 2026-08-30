//! DNTLS join-proof admission HTTP API.
//!
//! Routes (all NIP-98 signed, outside the Nostr event data plane):
//!
//! - `POST /api/dntls/join/challenge` — mint a single-use challenge. Caller is
//!   the joining pubkey; **exempt from the relay-membership gate**.
//! - `POST /api/dntls/join` — consume the challenge and verify a join proof
//!   against the operator-configured introducer. Membership-exempt; rate-limited
//!   per (community, pubkey) like invite claims.
//! - `GET /api/dntls/pending` — list pending applications. Owner/admin only.
//! - `POST /api/dntls/approve` — admit a pending pubkey through the same
//!   membership path invite claims use, and retain the verified-name mapping.
//! - `POST /api/dntls/reject` — delete a pending application. Owner/admin only.
//! - `GET /api/dntls/names` — list approved pubkey→fqdn mappings. Any member.
//!
//! Feature-gated by `BUZZ_DNTLS_INTRODUCER_URL`. When unset, every route
//! returns 404 before authentication.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

use crate::handlers::side_effects::{publish_nip43_member_added, publish_nip43_membership_list};
use crate::state::AppState;

use super::{api_error, bridge, internal_error, relay_members};

/// Challenge lifetime advertised to clients and used as the moka TTL.
pub(crate) const CHALLENGE_TTL: Duration = Duration::from_secs(300);
/// Maximum distinct (community, pubkey) challenges retained process-locally.
pub(crate) const CHALLENGE_CACHE_CAPACITY: u64 = 10_000;
/// Max join attempts per pubkey per window — same bound as invite claims.
const JOIN_RATE_LIMIT: u32 = 10;

const CHALLENGE_PATH: &str = "/api/dntls/join/challenge";
const JOIN_PATH: &str = "/api/dntls/join";
const PENDING_PATH: &str = "/api/dntls/pending";
const APPROVE_PATH: &str = "/api/dntls/approve";
const REJECT_PATH: &str = "/api/dntls/reject";
const NAMES_PATH: &str = "/api/dntls/names";

/// Outcome of asking the DNTLS introducer to verify a join proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntroducerOutcome {
    /// HTTP 200 with a verified proof.
    Verified,
    /// Authoritative refusal (`403 join_proof_rejected`).
    Rejected,
    /// Backend unavailable, transport error, or any non-200/403/503.
    Unavailable,
}

/// Client used to verify join proofs against a DNTLS introducer.
///
/// Production binds [`HttpIntroducer`]. Tests inject a stub so the join
/// handler can be exercised without a live sidecar.
#[async_trait::async_trait]
pub trait IntroducerClient: Send + Sync {
    /// Verify a join proof at `{introducer_url}/v1/verify-join`.
    async fn verify_join(
        &self,
        introducer_url: &str,
        fqdn: &str,
        nostr_public_key: &str,
        challenge: &str,
        service_signature: &str,
    ) -> IntroducerOutcome;
}

/// HTTP client for `POST {introducer_url}/v1/verify-join`.
pub struct HttpIntroducer {
    client: reqwest::Client,
}

impl HttpIntroducer {
    /// Build the shared introducer client.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("static DNTLS introducer HTTP client configuration"),
        }
    }
}

impl Default for HttpIntroducer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl IntroducerClient for HttpIntroducer {
    async fn verify_join(
        &self,
        introducer_url: &str,
        fqdn: &str,
        nostr_public_key: &str,
        challenge: &str,
        service_signature: &str,
    ) -> IntroducerOutcome {
        let url = format!("{introducer_url}/v1/verify-join");
        let response = match self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "fqdn": fqdn,
                "nostr_public_key": nostr_public_key,
                "challenge": challenge,
                "service_signature": service_signature,
            }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    timeout = error.is_timeout(),
                    "DNTLS introducer request failed"
                );
                return IntroducerOutcome::Unavailable;
            }
        };

        map_introducer_response(response.status().as_u16(), response.json().await.ok())
    }
}

/// Map an introducer HTTP status + optional JSON body onto the join contract.
pub(crate) fn map_introducer_response(status: u16, body: Option<Value>) -> IntroducerOutcome {
    match status {
        200 => {
            if body
                .as_ref()
                .and_then(|value| value.get("verified"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                IntroducerOutcome::Verified
            } else {
                IntroducerOutcome::Unavailable
            }
        }
        403 => IntroducerOutcome::Rejected,
        _ => IntroducerOutcome::Unavailable,
    }
}

#[derive(Debug, Deserialize)]
struct JoinRequest {
    fqdn: String,
    service_signature: String,
}

#[derive(Debug, Deserialize)]
struct PubkeyRequest {
    pubkey: String,
}

fn require_configured(state: &AppState) -> Result<&str, (StatusCode, Json<Value>)> {
    state
        .config
        .dntls_introducer_url
        .as_deref()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "dntls_not_configured"))
}

async fn authenticate(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    require_payload: bool,
) -> Result<(buzz_core::TenantContext, nostr::PublicKey), (StatusCode, Json<Value>)> {
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

    let url = bridge::nip98_expected_url(&state.config.relay_url, &tenant, path);
    let (pubkey, event_id_bytes) = bridge::verify_bridge_auth_with_options(
        headers,
        method,
        &url,
        if body.is_empty() { None } else { Some(body) },
        true,
        require_payload,
    )?;
    bridge::check_nip98_replay(state, &tenant, event_id_bytes).await?;
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
        .map_err(|e| internal_error(&format!("dntls role lookup: {e}")))?;
    let role = member.map(|m| m.role).unwrap_or_default();
    if role != "owner" && role != "admin" {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "only relay owners and admins can manage DNTLS applications",
        ));
    }
    Ok(())
}

fn join_rate_limited(
    state: &AppState,
    community: buzz_core::tenant::CommunityId,
    pubkey: &nostr::PublicKey,
) -> bool {
    let key = (community, pubkey.to_bytes());
    let counter = state
        .dntls_join_rate_limiter
        .get_with(key, || Arc::new(std::sync::atomic::AtomicU32::new(0)));
    counter.fetch_add(1, Ordering::Relaxed) >= JOIN_RATE_LIMIT
}

fn mint_challenge_bytes(
    cache: &moka::sync::Cache<crate::state::ScopedPubkeyKey, [u8; 32]>,
    key: crate::state::ScopedPubkeyKey,
) -> [u8; 32] {
    let challenge: [u8; 32] = rand::random();
    cache.insert(key, challenge);
    challenge
}

fn consume_challenge(
    cache: &moka::sync::Cache<crate::state::ScopedPubkeyKey, [u8; 32]>,
    key: crate::state::ScopedPubkeyKey,
) -> Option<[u8; 32]> {
    let challenge = cache.get(&key)?;
    cache.invalidate(&key);
    Some(challenge)
}

fn validate_fqdn(raw: &str) -> Result<&str, (StatusCode, Json<Value>)> {
    let fqdn = raw.trim();
    if fqdn.is_empty() || fqdn.len() > 255 {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid_fqdn"));
    }
    Ok(fqdn)
}

fn validate_pubkey_hex(value: &str) -> Result<String, (StatusCode, Json<Value>)> {
    crate::handlers::community_provisioning::validate_pubkey_hex(value)
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "invalid_pubkey"))
}

/// Mint a single-use join challenge — `POST /api/dntls/join/challenge`.
pub async fn join_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_configured(&state)?;
    let (tenant, pubkey) =
        authenticate(&state, &headers, "POST", CHALLENGE_PATH, &body, true).await?;
    let challenge = mint_challenge_bytes(
        &state.dntls_join_challenges,
        (tenant.community(), pubkey.to_bytes()),
    );
    Ok(Json(serde_json::json!({
        "challenge": base64::engine::general_purpose::STANDARD.encode(challenge),
        "expires_in_secs": CHALLENGE_TTL.as_secs(),
    })))
}

/// Verify a join proof and upsert a pending application — `POST /api/dntls/join`.
pub async fn join(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let introducer_url = require_configured(&state)?;
    let (tenant, pubkey) = authenticate(&state, &headers, "POST", JOIN_PATH, &body, true).await?;

    if join_rate_limited(&state, tenant.community(), &pubkey) {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many join attempts, slow down",
        ));
    }

    let request: JoinRequest = serde_json::from_slice(&body)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid join JSON: {e}")))?;
    let fqdn = validate_fqdn(&request.fqdn)?;
    let claimer_hex = pubkey.to_hex();

    let Some(challenge) = consume_challenge(
        &state.dntls_join_challenges,
        (tenant.community(), pubkey.to_bytes()),
    ) else {
        return Err(api_error(StatusCode::BAD_REQUEST, "challenge_required"));
    };

    let challenge_b64 = base64::engine::general_purpose::STANDARD.encode(challenge);
    match state
        .dntls_introducer
        .verify_join(
            introducer_url,
            fqdn,
            &claimer_hex,
            &challenge_b64,
            &request.service_signature,
        )
        .await
    {
        IntroducerOutcome::Verified => {}
        IntroducerOutcome::Rejected => {
            return Err(api_error(StatusCode::FORBIDDEN, "join_proof_rejected"));
        }
        IntroducerOutcome::Unavailable => {
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "introducer_unavailable",
            ));
        }
    }

    match state
        .db
        .upsert_dntls_pending_application(tenant.community(), &claimer_hex, fqdn)
        .await
        .map_err(|e| internal_error(&format!("dntls join upsert: {e}")))?
    {
        buzz_db::dntls::UpsertJoinOutcome::Pending => Ok(Json(serde_json::json!({
            "status": "pending",
        }))),
        buzz_db::dntls::UpsertJoinOutcome::NameAlreadyClaimed => {
            Err(api_error(StatusCode::CONFLICT, "name_already_claimed"))
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
        .map_err(|e| internal_error(&format!("dntls pending list: {e}")))?;
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
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid approve JSON: {e}"),
        )
    })?;
    let target = validate_pubkey_hex(&request.pubkey)?;

    let existing = state
        .db
        .get_dntls_application(tenant.community(), &target)
        .await
        .map_err(|e| internal_error(&format!("dntls approve lookup: {e}")))?;
    let Some(existing) = existing.filter(|row| row.status == "pending") else {
        return Err(api_error(StatusCode::NOT_FOUND, "application_not_found"));
    };

    let was_inserted = state
        .db
        .claim_relay_membership(tenant.community(), &target, "member", None)
        .await
        .map_err(|e| internal_error(&format!("dntls approve membership: {e}")))?;

    let approved = state
        .db
        .approve_dntls_application(tenant.community(), &target, &pubkey.to_hex())
        .await
        .map_err(|e| internal_error(&format!("dntls approve persist: {e}")))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "application_not_found"))?;

    if was_inserted {
        tracing::info!(
            community = %tenant.community(),
            member = %target,
            fqdn = %approved.fqdn,
            "relay member added via DNTLS join"
        );
        if let Err(e) = publish_nip43_member_added(&tenant, &state, &target).await {
            tracing::warn!("failed to publish NIP-43 member-added delta after DNTLS approve: {e}");
        }
        if let Err(e) = publish_nip43_membership_list(&tenant, &state).await {
            tracing::warn!("failed to publish NIP-43 membership list after DNTLS approve: {e}");
        }
    }

    Ok(Json(serde_json::json!({
        "status": "approved",
        "fqdn": existing.fqdn,
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
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid reject JSON: {e}"),
        )
    })?;
    let target = validate_pubkey_hex(&request.pubkey)?;

    let deleted = state
        .db
        .reject_dntls_application(tenant.community(), &target)
        .await
        .map_err(|e| internal_error(&format!("dntls reject: {e}")))?;
    if !deleted {
        return Err(api_error(StatusCode::NOT_FOUND, "application_not_found"));
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
    relay_members::enforce_relay_membership(
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
        .map_err(|e| internal_error(&format!("dntls names list: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use axum::{
        body::{to_bytes, Body},
        http::{header, Method, Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use nostr::{EventBuilder, Keys, Kind, Tag};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

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

    struct StubIntroducer {
        outcome: IntroducerOutcome,
        calls: Mutex<Vec<(String, String, String, String)>>,
    }

    impl StubIntroducer {
        fn new(outcome: IntroducerOutcome) -> Self {
            Self {
                outcome,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl IntroducerClient for StubIntroducer {
        async fn verify_join(
            &self,
            _introducer_url: &str,
            fqdn: &str,
            nostr_public_key: &str,
            challenge: &str,
            service_signature: &str,
        ) -> IntroducerOutcome {
            self.calls.lock().expect("stub calls").push((
                fqdn.to_string(),
                nostr_public_key.to_string(),
                challenge.to_string(),
                service_signature.to_string(),
            ));
            self.outcome.clone()
        }
    }

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1

    fn challenge_cache(
        capacity: u64,
        ttl: Duration,
    ) -> moka::sync::Cache<crate::state::ScopedPubkeyKey, [u8; 32]> {
        moka::sync::Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl)
            .build()
    }

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
        config.dntls_introducer_url = None;
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

    async fn dntls_test_state(
        host: &str,
        introducer: Arc<dyn IntroducerClient>,
    ) -> Option<Arc<AppState>> {
        let mut config = crate::config::Config::from_env().ok()?;
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_string());
        config.database_url = database_url.clone();
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.relay_url = format!("wss://{host}");
        config.require_relay_membership = true;
        config.dntls_introducer_url = Some("http://127.0.0.1:9".to_string());

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
        state.dntls_introducer = introducer;
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

    #[test]
    fn names_entry_includes_approved_at_unix_seconds() {
        let approved_at =
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("unix seconds");
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
    fn map_introducer_response_distinguishes_verified_rejected_unavailable() {
        assert_eq!(
            map_introducer_response(200, Some(serde_json::json!({"verified": true}))),
            IntroducerOutcome::Verified
        );
        assert_eq!(
            map_introducer_response(
                403,
                Some(serde_json::json!({"error": "join_proof_rejected"}))
            ),
            IntroducerOutcome::Rejected
        );
        assert_eq!(
            map_introducer_response(503, None),
            IntroducerOutcome::Unavailable
        );
        assert_eq!(
            map_introducer_response(400, None),
            IntroducerOutcome::Unavailable
        );
        assert_eq!(
            map_introducer_response(200, Some(serde_json::json!({"verified": false}))),
            IntroducerOutcome::Unavailable
        );
        assert_eq!(
            map_introducer_response(500, None),
            IntroducerOutcome::Unavailable
        );
    }

    #[test]
    fn dntls_challenge_mint_replaces_and_consume_is_single_use() {
        let cache = challenge_cache(100, Duration::from_secs(60));
        let key = (buzz_core::CommunityId::from_uuid(Uuid::nil()), [7; 32]);

        let first = mint_challenge_bytes(&cache, key);
        let second = mint_challenge_bytes(&cache, key);
        assert_ne!(first, second, "newer mint replaces older");

        let consumed = consume_challenge(&cache, key).expect("cached challenge");
        assert_eq!(consumed, second);
        assert!(
            consume_challenge(&cache, key).is_none(),
            "second consume without re-mint is challenge_required"
        );
    }

    #[test]
    fn dntls_challenge_expires_entries() {
        let cache = challenge_cache(100, Duration::from_millis(10));
        let key = (buzz_core::CommunityId::from_uuid(Uuid::nil()), [8; 32]);
        mint_challenge_bytes(&cache, key);
        std::thread::sleep(Duration::from_millis(25));
        cache.run_pending_tasks();
        assert!(consume_challenge(&cache, key).is_none());
    }

    #[tokio::test]
    async fn dntls_routes_return_not_found_when_unconfigured() {
        let state = unconfigured_test_state().await;
        let router = Router::new()
            .route(CHALLENGE_PATH, post(join_challenge))
            .route(JOIN_PATH, post(join))
            .route(PENDING_PATH, get(pending))
            .route(APPROVE_PATH, post(approve))
            .route(REJECT_PATH, post(reject))
            .route(NAMES_PATH, get(names))
            .with_state(state);

        for (method, path) in [
            (Method::POST, CHALLENGE_PATH),
            (Method::POST, JOIN_PATH),
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
    async fn dntls_join_consumes_challenge_and_creates_pending_row() {
        let host = format!("dntls-join-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let stub = Arc::new(StubIntroducer::new(IntroducerOutcome::Verified));
        let state = dntls_test_state(&host, stub.clone())
            .await
            .expect("requires reachable Postgres and relay test state");

        let challenge = send(
            state.clone(),
            &host,
            Method::POST,
            CHALLENGE_PATH,
            &joiner,
            "{}".to_string(),
        )
        .await;
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge_json = read_json(challenge).await;
        assert_eq!(
            challenge_json
                .get("expires_in_secs")
                .and_then(Value::as_u64),
            Some(300)
        );

        let join_body = serde_json::json!({
            "fqdn": "alice.example",
            "service_signature": "c2ln",
        })
        .to_string();
        let joined = send(
            state.clone(),
            &host,
            Method::POST,
            JOIN_PATH,
            &joiner,
            join_body.clone(),
        )
        .await;
        assert_eq!(joined.status(), StatusCode::OK);
        let json = read_json(joined).await;
        assert_eq!(json.get("status").and_then(Value::as_str), Some("pending"));

        let replay = send(
            state.clone(),
            &host,
            Method::POST,
            JOIN_PATH,
            &joiner,
            join_body,
        )
        .await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let json = read_json(replay).await;
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("challenge_required")
        );

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup application")
            .expect("pending row");
        assert_eq!(row.fqdn, "alice.example");
        assert_eq!(row.status, "pending");
        assert_eq!(stub.calls.lock().expect("calls").len(), 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_join_rejected_proof_creates_no_row() {
        let host = format!("dntls-reject-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state(
            &host,
            Arc::new(StubIntroducer::new(IntroducerOutcome::Rejected)),
        )
        .await
        .expect("requires reachable Postgres and relay test state");

        let challenge = send(
            state.clone(),
            &host,
            Method::POST,
            CHALLENGE_PATH,
            &joiner,
            "{}".to_string(),
        )
        .await;
        assert_eq!(challenge.status(), StatusCode::OK);

        let joined = send(
            state.clone(),
            &host,
            Method::POST,
            JOIN_PATH,
            &joiner,
            serde_json::json!({
                "fqdn": "alice.example",
                "service_signature": "c2ln",
            })
            .to_string(),
        )
        .await;
        assert_eq!(joined.status(), StatusCode::FORBIDDEN);
        let json = read_json(joined).await;
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("join_proof_rejected")
        );

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup application");
        assert!(row.is_none());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_join_unavailable_introducer_creates_no_row() {
        let host = format!("dntls-unavail-{}.example", Uuid::new_v4().simple());
        let joiner = Keys::generate();
        let state = dntls_test_state(
            &host,
            Arc::new(StubIntroducer::new(IntroducerOutcome::Unavailable)),
        )
        .await
        .expect("requires reachable Postgres and relay test state");

        let challenge = send(
            state.clone(),
            &host,
            Method::POST,
            CHALLENGE_PATH,
            &joiner,
            "{}".to_string(),
        )
        .await;
        assert_eq!(challenge.status(), StatusCode::OK);

        let joined = send(
            state.clone(),
            &host,
            Method::POST,
            JOIN_PATH,
            &joiner,
            serde_json::json!({
                "fqdn": "alice.example",
                "service_signature": "c2ln",
            })
            .to_string(),
        )
        .await;
        assert_eq!(joined.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = read_json(joined).await;
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("introducer_unavailable")
        );

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community exists");
        let row = state
            .db
            .get_dntls_application(community.id, &joiner.public_key().to_hex())
            .await
            .expect("lookup application");
        assert!(row.is_none());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_first_bound_wins_name_conflict() {
        let host = format!("dntls-conflict-{}.example", Uuid::new_v4().simple());
        let first = Keys::generate();
        let second = Keys::generate();
        let state = dntls_test_state(
            &host,
            Arc::new(StubIntroducer::new(IntroducerOutcome::Verified)),
        )
        .await
        .expect("requires reachable Postgres and relay test state");

        for keys in [&first, &second] {
            let challenge = send(
                state.clone(),
                &host,
                Method::POST,
                CHALLENGE_PATH,
                keys,
                "{}".to_string(),
            )
            .await;
            assert_eq!(challenge.status(), StatusCode::OK);
        }

        let body = serde_json::json!({
            "fqdn": "shared.example",
            "service_signature": "c2ln",
        })
        .to_string();
        let ok = send(
            state.clone(),
            &host,
            Method::POST,
            JOIN_PATH,
            &first,
            body.clone(),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);

        let conflict = send(state, &host, Method::POST, JOIN_PATH, &second, body).await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let json = read_json(conflict).await;
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("name_already_claimed")
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_approve_adds_membership_and_retain_mapping() {
        let host = format!("dntls-approve-{}.example", Uuid::new_v4().simple());
        let owner = Keys::generate();
        let joiner = Keys::generate();
        let state = dntls_test_state(
            &host,
            Arc::new(StubIntroducer::new(IntroducerOutcome::Verified)),
        )
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

        let challenge = send(
            state.clone(),
            &host,
            Method::POST,
            CHALLENGE_PATH,
            &joiner,
            "{}".to_string(),
        )
        .await;
        assert_eq!(challenge.status(), StatusCode::OK);
        let joined = send(
            state.clone(),
            &host,
            Method::POST,
            JOIN_PATH,
            &joiner,
            serde_json::json!({
                "fqdn": "alice.example",
                "service_signature": "c2ln",
            })
            .to_string(),
        )
        .await;
        assert_eq!(joined.status(), StatusCode::OK);

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
        let state = dntls_test_state(
            &host,
            Arc::new(StubIntroducer::new(IntroducerOutcome::Verified)),
        )
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

        let challenge = send(
            state.clone(),
            &host,
            Method::POST,
            CHALLENGE_PATH,
            &joiner,
            "{}".to_string(),
        )
        .await;
        assert_eq!(challenge.status(), StatusCode::OK);
        let joined = send(
            state.clone(),
            &host,
            Method::POST,
            JOIN_PATH,
            &joiner,
            serde_json::json!({
                "fqdn": "alice.example",
                "service_signature": "c2ln",
            })
            .to_string(),
        )
        .await;
        assert_eq!(joined.status(), StatusCode::OK);

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
        let state = dntls_test_state(
            &host,
            Arc::new(StubIntroducer::new(IntroducerOutcome::Verified)),
        )
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
}
