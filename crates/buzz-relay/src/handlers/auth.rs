//! NIP-42 AUTH handler — verify challenge response, transition auth state.
//!
//! Relay membership enforcement uses the shared
//! [`crate::api::relay_members::enforce_relay_membership`] helper, which supports
//! NIP-OA owner-delegation fallback on closed relays. On open relays, the auth
//! handler calls [`crate::api::relay_members::extract_nip_oa_owner`] directly to
//! extract the owner pubkey for agent→owner backfill (observer frame auth).
//!
//! For WebSocket auth, the NIP-OA `auth` tag is extracted from the signed AUTH
//! event itself (the tag is integrity-protected by the event signature).
//!
//! Verified NIP-OA delegated AUTH never binds or rebinds a DNTLS name and never
//! grants admin or auto-membership through the DNTLS path. Agents are admitted
//! through the owner's delegation. Absent or invalid `auth` tags fail closed:
//! DNTLS admission still runs and ordinary membership checks are unchanged.

use std::sync::Arc;

use axum::extract::ws::Message as WsMessage;
use tracing::{debug, info, warn};

use crate::connection::{AuthState, ConnectionState};
use crate::protocol::RelayMessage;
use crate::state::AppState;

/// Extract a NIP-OA `auth` tag from a verified AUTH event and serialize it as
/// the JSON-array string that [`buzz_sdk::nip_oa::verify_auth_tag`] expects.
///
/// Returns `None` if no `auth` tag is present (direct-member auth path) or if
/// more than one `auth` tag exists (per NIP-OA spec: >1 auth tag ⇒ no valid tag).
pub fn extract_auth_tag_json(event: &nostr::Event) -> Option<String> {
    let mut iter = event
        .tags
        .iter()
        .filter(|t| t.as_slice().first().map(|s| s.as_str()) == Some("auth"));
    let first = iter.next()?;
    if iter.next().is_some() {
        return None; // NIP-OA spec: treat >1 auth tag as no valid auth tag
    }
    serde_json::to_string(first.as_slice()).ok()
}

/// Detect delegation intent before DNTLS admission, without granting access.
///
/// Even malformed or duplicate tags must skip name binding. The normal
/// membership gate verifies delegation; an invalid tag cannot mint membership
/// through DNTLS before that gate runs.
pub(crate) fn http_has_auth_tag(headers: &axum::http::HeaderMap) -> bool {
    if headers.contains_key("x-auth-tag") {
        return true;
    }
    let event = (|| {
        use base64::Engine;
        let encoded = headers
            .get(axum::http::header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Nostr ")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        serde_json::from_slice::<nostr::Event>(&bytes).ok()
    })();
    event.is_some_and(|event| event.tags.iter().any(|tag| tag.as_slice()[0] == "auth"))
}

/// Handle a NIP-42 AUTH message: verify the challenge response and transition
/// the connection to authenticated state.
///
/// Pure crypto verification — no API tokens, no JWT, no DB token lookups.
#[tracing::instrument(skip_all, fields(event_id, conn_id))]
pub async fn handle_auth(event: nostr::Event, conn: Arc<ConnectionState>, state: Arc<AppState>) {
    let event_id_hex = event.id.to_hex();
    let (challenge, conn_id) = {
        let auth = conn.auth_state.read().await;
        match &*auth {
            AuthState::Pending { challenge } => (challenge.clone(), conn.conn_id),
            AuthState::Authenticated(_) => {
                debug!(conn_id = %conn.conn_id, "AUTH received but already authenticated");
                conn.send(RelayMessage::ok(
                    &event_id_hex,
                    false,
                    "auth-required: already authenticated",
                ));
                return;
            }
            AuthState::Failed => {
                debug!(conn_id = %conn.conn_id, "AUTH received after failed auth");
                conn.send(RelayMessage::ok(
                    &event_id_hex,
                    false,
                    "auth-required: authentication already failed",
                ));
                return;
            }
        }
    };

    // Record the declared span fields now that we have the values.
    tracing::Span::current()
        .record("event_id", event_id_hex.as_str())
        .record("conn_id", conn_id.to_string().as_str());

    // Extract the NIP-OA auth tag before verification consumes the event.
    // The tag is integrity-protected by the event's Schnorr signature — if
    // tampered, NIP-42 verification will fail before we ever inspect it.
    let auth_tag_json = extract_auth_tag_json(&event);
    let has_auth_tag = event.tags.iter().any(|tag| tag.as_slice()[0] == "auth");

    let relay_url =
        crate::api::bridge::nip42_expected_relay_url(&state.config.relay_url, &conn.tenant);
    let auth_svc = Arc::clone(&state.auth);

    metrics::counter!("buzz_auth_attempts_total", "method" => "nip42").increment(1);

    // Pure NIP-42 verification — crypto only, no DB lookups.
    match auth_svc
        .verify_auth_event(event, &challenge, &relay_url)
        .await
    {
        Ok(mut auth_ctx) => {
            let pubkey = auth_ctx.pubkey;

            // Community ban gate (NIP-42 seam). Runs immediately after auth
            // verification succeeds and before the allowlist and relay-membership
            // gates, per COMMUNITY_MODERATION_PLAN.md §0 decision 4 and the
            // MOD-7/M20 invariant (a ban must block connection auth even for open
            // channels — enforcement is structural, not filtered later). A banned
            // principal gets the standard protocol denial and the connection is
            // dropped with zero further processing.
            //
            // NIP-OA cascade: a ban on the authenticated pubkey blocks it directly;
            // a ban on its cryptographically-proven owner cascades to the agent
            // (owner ban ⇒ agents banned; agent ban is agent-only). The owner is
            // extracted from the self-proving auth tag with no DB round-trip.
            {
                // Fail closed on a DB error, but distinguish it from a real ban:
                // a transient blip must deny (never let a banned principal
                // through) without telling an innocent user they are banned and
                // pinning `Failed` for the connection's life on a false premise.
                // `Banned` claims the ban; `DbError` denies with `error: internal`
                // (mirrors the ingest write-path gate).
                enum BanOutcome {
                    Clear,
                    Banned,
                    DbError,
                }

                let mut outcome = match state
                    .db
                    .moderation_restriction_state(conn.tenant.community(), pubkey.as_bytes())
                    .await
                {
                    Ok(state) if state.banned => BanOutcome::Banned,
                    Ok(_) => BanOutcome::Clear,
                    Err(e) => {
                        warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = %e,
                              "ban-state DB lookup failed, denying (fail-closed)");
                        BanOutcome::DbError
                    }
                };

                // Cascade: check the proven NIP-OA owner only if the agent itself
                // is clear (a DB error already denies; a direct ban already blocks
                // — both skip the needless second DB read).
                if matches!(outcome, BanOutcome::Clear) {
                    if let Some(owner) = crate::api::relay_members::extract_nip_oa_owner(
                        pubkey.as_bytes(),
                        auth_tag_json.as_deref(),
                    ) {
                        outcome = match state
                            .db
                            .moderation_restriction_state(conn.tenant.community(), owner.as_bytes())
                            .await
                        {
                            Ok(state) if state.banned => BanOutcome::Banned,
                            Ok(_) => BanOutcome::Clear,
                            Err(e) => {
                                warn!(conn_id = %conn_id, owner = %owner.to_hex(), error = %e,
                                      "owner ban-state DB lookup failed, denying (fail-closed)");
                                BanOutcome::DbError
                            }
                        };
                    }
                }

                let denial: Option<(&str, &str)> = match outcome {
                    BanOutcome::Clear => None,
                    BanOutcome::Banned => {
                        Some(("banned", "blocked: you are banned from this community"))
                    }
                    BanOutcome::DbError => Some((
                        "ban_check_error",
                        "error: internal error checking restriction state",
                    )),
                };

                if let Some((metric_reason, deny_reason)) = denial {
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), reason = deny_reason, "principal denied at ban seam");
                    metrics::counter!("buzz_auth_failures_total", "reason" => metric_reason)
                        .increment(1);
                    *conn.auth_state.write().await = AuthState::Failed;
                    // Decision 4: banned ⇒ OK false + immediate WebSocket close.
                    // Route the reason frame on the control channel (not `send`,
                    // which uses the data channel and would race the cancel), so
                    // the send loop drains it ahead of the Close it emits on
                    // cancel. Then cancel to close the socket immediately.
                    let _ = conn.ctrl_tx.try_send(WsMessage::Text(
                        RelayMessage::ok(&event_id_hex, false, deny_reason).into(),
                    ));
                    conn.cancel.cancel();
                    return;
                }
            }

            // Pubkey allowlist gate — only for pubkey-only auth.
            if state.config.pubkey_allowlist_enabled
                && auth_ctx.auth_method == buzz_auth::AuthMethod::Nip42
            {
                let allowed = match state
                    .db
                    .is_pubkey_allowed(conn.tenant.community(), pubkey.as_bytes())
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = %e,
                              "allowlist DB lookup failed, denying (fail-closed)");
                        false
                    }
                };
                if !allowed {
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), "pubkey not in allowlist");
                    metrics::counter!("buzz_auth_failures_total", "reason" => "allowlist_denied")
                        .increment(1);
                    *conn.auth_state.write().await = AuthState::Failed;
                    conn.send(RelayMessage::ok(
                        &event_id_hex,
                        false,
                        "auth-required: verification failed",
                    ));
                    return;
                }
            }

            // A caller presenting delegation must use the owner-membership
            // gate, even if its tag is malformed or ambiguous.
            if !has_auth_tag
                && !crate::api::dntls::apply_auth_admission(&state, &conn, &pubkey.to_hex()).await
            {
                metrics::counter!("buzz_auth_failures_total", "reason" => "dntls_admission")
                    .increment(1);
                *conn.auth_state.write().await = AuthState::Failed;
                conn.send(RelayMessage::ok(
                    &event_id_hex,
                    false,
                    "error: internal error applying DNTLS admission",
                ));
                return;
            }

            // Relay membership gate — uses the shared helper with NIP-OA fallback.
            let nip_oa_owner = match crate::api::relay_members::enforce_relay_membership(
                &state,
                conn.tenant.community(),
                pubkey.as_bytes(),
                auth_tag_json.as_deref(),
                conn.dntls_name.as_deref(),
            )
            .await
            {
                Ok(owner) => owner,
                Err(e) => {
                    // Matching pending was already classified on the HTTP error.
                    let pending = e.1.get("error").and_then(|value| value.as_str())
                        == Some(crate::api::dntls::HTTP_APPROVAL_PENDING);
                    let (metric_reason, deny_reason) = if pending {
                        (
                            "dntls_approval_pending",
                            crate::api::dntls::AUTH_APPROVAL_PENDING,
                        )
                    } else {
                        ("not_relay_member", "restricted: not a relay member")
                    };
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = ?e, "{deny_reason}");
                    metrics::counter!("buzz_auth_failures_total", "reason" => metric_reason)
                        .increment(1);
                    *conn.auth_state.write().await = AuthState::Failed;
                    conn.send(RelayMessage::ok(&event_id_hex, false, deny_reason));
                    return;
                }
            };

            // Open relay NIP-OA backfill: extract owner for agent→owner DB mapping
            // (needed for observer frame auth). Only runs on open relays — on closed
            // relays, enforce_relay_membership already handles NIP-OA delegation.
            // No feature flag needed: NIP-OA is cryptographically self-proving.
            let nip_oa_owner = nip_oa_owner.or_else(|| {
                if !state.config.require_relay_membership && auth_tag_json.is_some() {
                    crate::api::relay_members::extract_nip_oa_owner(
                        pubkey.as_bytes(),
                        auth_tag_json.as_deref(),
                    )
                } else {
                    None
                }
            });

            // Stash NIP-OA owner on the auth context only after the shared
            // backfill confirms the first-write-wins relationship.
            if let Some(owner) = nip_oa_owner {
                if crate::api::relay_members::materialize_nip_oa_owner(
                    &state,
                    &conn.tenant,
                    &pubkey,
                    &owner,
                )
                .await
                {
                    auth_ctx.agent_owner_pubkey = Some(owner);
                } else {
                    warn!(
                        conn_id = %conn_id,
                        agent = %pubkey.to_hex(),
                        nip_oa_owner = %owner.to_hex(),
                        "NIP-OA owner could not be materialized"
                    );
                }
            }

            info!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), "NIP-42 auth successful");
            *conn.auth_state.write().await = AuthState::Authenticated(auth_ctx);
            state
                .conn_manager
                .set_authenticated_pubkey(conn_id, pubkey.to_bytes().to_vec());
            conn.send(RelayMessage::ok(&event_id_hex, true, ""));
        }
        Err(e) => {
            warn!(conn_id = %conn_id, error = %e, "NIP-42 auth failed");
            metrics::counter!("buzz_auth_failures_total", "reason" => "nip42_invalid").increment(1);
            *conn.auth_state.write().await = AuthState::Failed;
            conn.send(RelayMessage::ok(
                &event_id_hex,
                false,
                "auth-required: verification failed",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_auth_tag_json, handle_auth};
    use std::sync::atomic::AtomicU8;
    use std::sync::Arc;

    use axum::extract::ws::Message as WsMessage;
    use nostr::{EventBuilder, Keys, Kind, RelayUrl, Tag};
    use tokio::sync::{mpsc, Mutex, RwLock};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::config::DntlsAdmission;
    use crate::connection::AuthState;
    use crate::state::AppState;
    use buzz_core::tenant::TenantContext;

    /// Build a signed NIP-98 (kind 27235) event carrying the given tags. The
    /// `auth` tag lives inside the signed event exactly as the git and
    /// WebSocket auth paths receive it.
    fn signed_event_with_tags(tags: Vec<Tag>) -> nostr::Event {
        EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(&Keys::generate())
            .expect("sign auth event")
    }

    /// A single `auth` tag is extracted verbatim as its JSON-array string —
    /// this is the exact value fed to `verify_auth_tag` on the git path.
    #[test]
    fn single_auth_tag_extracted_verbatim() {
        let owner = Keys::generate().public_key().to_hex();
        let sig = "00".repeat(64);
        let event = signed_event_with_tags(vec![
            Tag::parse(["u", "https://relay/git/x/y"]).unwrap(),
            Tag::parse(["auth", owner.as_str(), "", sig.as_str()]).unwrap(),
        ]);

        let extracted = extract_auth_tag_json(&event).expect("auth tag present");
        let expected = serde_json::to_string(&["auth", owner.as_str(), "", sig.as_str()]).unwrap();
        assert_eq!(extracted, expected);
    }

    /// No `auth` tag → `None` (the direct-member path, tag absent).
    #[test]
    fn no_auth_tag_returns_none() {
        let event =
            signed_event_with_tags(vec![Tag::parse(["u", "https://relay/git/x/y"]).unwrap()]);
        assert_eq!(extract_auth_tag_json(&event), None);
    }

    /// More than one `auth` tag → `None`. Per NIP-OA, an ambiguous set of
    /// attestations is treated as no valid attestation (fail-closed), so a
    /// second forged tag cannot smuggle an alternate delegation past the gate.
    #[test]
    fn duplicate_auth_tags_return_none() {
        let a = Keys::generate().public_key().to_hex();
        let b = Keys::generate().public_key().to_hex();
        let sig = "00".repeat(64);
        let event = signed_event_with_tags(vec![
            Tag::parse(["auth", a.as_str(), "", sig.as_str()]).unwrap(),
            Tag::parse(["auth", b.as_str(), "", sig.as_str()]).unwrap(),
        ]);
        assert_eq!(extract_auth_tag_json(&event), None);
    }

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1
    const TEST_REDIS_URL: &str = "redis://127.0.0.1:6379";

    async fn delegated_test_state(host: &str) -> Option<Arc<AppState>> {
        let mut config = crate::config::Config::from_env().ok()?;
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_string());
        config.database_url = database_url.clone();
        config.redis_url = TEST_REDIS_URL.to_string();
        config.relay_url = format!("wss://{host}");
        config.require_relay_membership = true;
        config.allow_nip_oa_auth = true;
        config.dntls_admission = DntlsAdmission::Approve;
        config.dntls_admins = vec!["josh.dntls".to_string()];

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
        let (state, _audit_shutdown) = AppState::new(
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
        Some(Arc::new(state))
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
        auth_tag: Option<Tag>,
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
        let conn = Arc::new(crate::connection::ConnectionState {
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
        let mut builder =
            EventBuilder::auth(&challenge, RelayUrl::parse(&relay_url).expect("relay url"));
        if let Some(tag) = auth_tag {
            builder = builder.tags([tag]);
        }
        let event = builder.sign_with_keys(keys).expect("sign AUTH");
        handle_auth(event, Arc::clone(&conn), state).await;

        let mut messages = Vec::new();
        while let Ok(msg) = send_rx.try_recv() {
            messages.push(ws_text(&msg));
        }
        let authenticated = matches!(*conn.auth_state.read().await, AuthState::Authenticated(_));
        (authenticated, messages)
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn delegated_auth_does_not_rebind_listed_admin_name() {
        let host = format!("dntls-delegated-auth-{}.example", Uuid::new_v4().simple());
        let state = delegated_test_state(&host)
            .await
            .expect("requires reachable Postgres, Redis, and relay test state");
        let owner = Keys::generate();
        let agent = Keys::generate();

        let (ok, messages) =
            auth_connection(state.clone(), &host, &owner, Some("josh.dntls"), None).await;
        assert!(ok, "owner AUTH: {messages:?}");

        let tag_json =
            buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "").expect("auth tag");
        let auth_tag = buzz_sdk::nip_oa::parse_auth_tag(&tag_json).expect("parse");
        let (ok, messages) = auth_connection(
            state.clone(),
            &host,
            &agent,
            Some("josh.dntls"),
            Some(auth_tag),
        )
        .await;
        assert!(ok, "delegated agent AUTH: {messages:?}");

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community");
        let owner_hex = owner.public_key().to_hex();
        let agent_hex = agent.public_key().to_hex();

        assert_eq!(
            state
                .db
                .get_relay_member(community.id, &owner_hex)
                .await
                .expect("owner member")
                .expect("owner present")
                .role,
            "admin"
        );
        assert!(
            state
                .db
                .get_relay_member(community.id, &agent_hex)
                .await
                .expect("agent member")
                .is_none(),
            "delegated agent must not gain DNTLS auto-membership"
        );

        let bound = state
            .db
            .get_dntls_application(community.id, &owner_hex)
            .await
            .expect("owner binding")
            .expect("name bound to owner");
        assert_eq!(bound.fqdn, "josh.dntls");
        assert_eq!(bound.status, "approved");
        assert!(
            state
                .db
                .get_dntls_application(community.id, &agent_hex)
                .await
                .expect("agent binding")
                .is_none(),
            "delegated agent must not bind or rebind the DNTLS name"
        );

        let impostor = Keys::generate();
        let (ok, messages) = auth_connection(
            state.clone(),
            &host,
            &impostor,
            Some("josh.dntls"),
            Some(Tag::parse(["auth", "invalid"]).unwrap()),
        )
        .await;
        assert!(
            !ok,
            "invalid delegation must not get DNTLS membership: {messages:?}"
        );
        assert!(state
            .db
            .get_dntls_application(community.id, &impostor.public_key().to_hex())
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            state
                .db
                .get_relay_member(community.id, &owner_hex)
                .await
                .unwrap()
                .unwrap()
                .role,
            "admin"
        );

        let snapshots = state
            .db
            .query_events(&buzz_db::EventQuery {
                kinds: Some(vec![buzz_core::kind::KIND_NIP43_MEMBERSHIP_LIST as i32]),
                pubkey: Some(state.relay_keypair.public_key().to_bytes().to_vec()),
                global_only: true,
                limit: Some(10),
                ..buzz_db::EventQuery::for_community(community.id)
            })
            .await
            .expect("snapshots");
        assert_eq!(
            snapshots.len(),
            1,
            "delegated AUTH must not publish extra membership snapshots: {snapshots:?}"
        );
    }
}
