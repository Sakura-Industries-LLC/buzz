//! DNTLS verified-name application persistence.
//!
//! The `dntls_applications` table is community-scoped: its primary key is
//! `(community_id, pubkey)` and a second unique key is `(community_id, fqdn)`.
//! Every read and write is bound to a single `community_id` so that admitting
//! a name in community A never claims it in community B. `pubkey` values are
//! 64-char lowercase hex strings.

use buzz_datastore_tracing::datastore_span;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row as _};

use crate::error::Result;
use crate::{CommunityId, Db};

/// Outcome of upserting a verified-name application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertJoinOutcome {
    /// Inserted or replaced this pubkey's own pending row.
    Pending,
    /// This pubkey was previously rejected; the row is left unchanged.
    Rejected,
    /// Approved binding inserted, promoted, reassigned, or unchanged.
    Bound {
        /// Previous holder of this name, if the binding moved to `pubkey`.
        ///
        /// Returned even when that key is not demoted (`owner`, ordinary
        /// `member`, or a pending row with no admin role).
        displaced: Option<String>,
        /// Whether this call inserted `admin` or promoted `member` → `admin`
        /// for `pubkey`. Ordinary member admission stays on
        /// [`crate::relay_members::claim_relay_membership`].
        membership_changed: bool,
    },
    /// Approval mode found the name held by another key, or this key already
    /// has an approved mapping for another name in the community.
    NameAlreadyClaimed,
}

/// A DNTLS application row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DntlsApplication {
    /// 64-char lowercase hex pubkey of the joining identity.
    pub pubkey: String,
    /// Verified name bound to the pubkey.
    pub fqdn: String,
    /// `pending`, `approved`, or `rejected`.
    pub status: String,
    /// When created, replaced while pending, or rebound to a different pubkey.
    pub created_at: DateTime<Utc>,
    /// When an owner/admin approved the application, if approved.
    pub approved_at: Option<DateTime<Utc>>,
    /// Hex pubkey of the approving owner/admin, if approved.
    pub approved_by: Option<String>,
}

fn map_application_row(row: &sqlx::postgres::PgRow) -> DntlsApplication {
    DntlsApplication {
        pubkey: row.get("pubkey"),
        fqdn: row.get("fqdn"),
        status: row.get("status"),
        created_at: row.get("created_at"),
        approved_at: row.get("approved_at"),
        approved_by: row.get("approved_by"),
    }
}

const DNTLS_BIND_LOCK_NAMESPACE: &str = "buzz_dntls_bind:";

/// Serialize binding mutations within a community, including missing rows.
///
/// Replacing a pending application can change both its source and destination
/// names. One community lock keeps displacement reads and role changes ordered
/// across both names without cross-name lock ordering or stale MVCC reads.
async fn lock_application_bindings(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    community: CommunityId,
) -> Result<()> {
    crate::observability::observe_advisory_lock(
        crate::observability::LockType::Membership,
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("{DNTLS_BIND_LOCK_NAMESPACE}{community}"))
            .execute(&mut **tx),
    )
    .await?;
    Ok(())
}

/// Insert or replace this pubkey's pending application after a verified name.
///
/// First-bound-wins: if a *different* pubkey already holds a pending or
/// approved application for `fqdn` in `community`, returns
/// [`UpsertJoinOutcome::NameAlreadyClaimed`] and writes nothing. Repeating a
/// verified application for the same pubkey replaces its own pending row.
/// A rejected pubkey is left rejected and cannot requeue; a rejected name
/// does not block a different key.
pub async fn upsert_pending_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
    fqdn: &str,
) -> Result<UpsertJoinOutcome> {
    let mut tx = pool.begin().await?;
    lock_application_bindings(&mut tx, community).await?;

    let existing_fqdn: Option<String> = sqlx::query_scalar(
        "SELECT pubkey FROM dntls_applications \
         WHERE community_id = $1 AND fqdn = $2 AND pubkey <> $3 \
           AND status IN ('pending', 'approved') \
         FOR UPDATE",
    )
    .bind(community.as_uuid())
    .bind(fqdn)
    .bind(pubkey)
    .fetch_optional(&mut *tx)
    .await?;
    if existing_fqdn.is_some() {
        tx.commit().await?;
        return Ok(UpsertJoinOutcome::NameAlreadyClaimed);
    }

    let existing_self: Option<String> = sqlx::query_scalar(
        "SELECT status FROM dntls_applications \
         WHERE community_id = $1 AND pubkey = $2 \
         FOR UPDATE",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .fetch_optional(&mut *tx)
    .await?;

    match existing_self.as_deref() {
        Some("approved") => {
            // An approved mapping is durable. A later verified join for the
            // same pubkey that still holds the same name is a no-op; a new
            // name is refused because (community, fqdn) uniqueness would
            // otherwise leave the old name mapping behind or collide.
            let current_fqdn: String = sqlx::query_scalar(
                "SELECT fqdn FROM dntls_applications \
                 WHERE community_id = $1 AND pubkey = $2",
            )
            .bind(community.as_uuid())
            .bind(pubkey)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            if current_fqdn == fqdn {
                return Ok(UpsertJoinOutcome::Pending);
            }
            return Ok(UpsertJoinOutcome::NameAlreadyClaimed);
        }
        Some("rejected") => {
            tx.commit().await?;
            return Ok(UpsertJoinOutcome::Rejected);
        }
        Some("pending") => {
            let update = sqlx::query(
                "UPDATE dntls_applications \
                 SET fqdn = $3, status = 'pending', created_at = now(), \
                     approved_at = NULL, approved_by = NULL \
                 WHERE community_id = $1 AND pubkey = $2 AND status = 'pending'",
            )
            .bind(community.as_uuid())
            .bind(pubkey)
            .bind(fqdn)
            .execute(&mut *tx)
            .await;
            match update {
                Ok(_) => {}
                Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
                    tx.commit().await?;
                    return Ok(UpsertJoinOutcome::NameAlreadyClaimed);
                }
                Err(err) => return Err(err.into()),
            }
        }
        Some(_) => {
            tx.commit().await?;
            return Ok(UpsertJoinOutcome::NameAlreadyClaimed);
        }
        None => {
            let insert = sqlx::query(
                "INSERT INTO dntls_applications (community_id, pubkey, fqdn, status) \
                 VALUES ($1, $2, $3, 'pending')",
            )
            .bind(community.as_uuid())
            .bind(pubkey)
            .bind(fqdn)
            .execute(&mut *tx)
            .await;
            match insert {
                Ok(_) => {}
                Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
                    tx.commit().await?;
                    return Ok(UpsertJoinOutcome::NameAlreadyClaimed);
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    tx.commit().await?;
    Ok(UpsertJoinOutcome::Pending)
}

/// Bind a currently verified name to this pubkey in auto-admission mode.
///
/// The caller must have proved `fqdn` and possession of `pubkey`. The name's
/// previous pending or approved mapping is replaced atomically, including
/// under concurrent claims. Repeating the same approved mapping is a no-op.
///
/// A pending application by this pubkey for another name is replaced. An
/// approved mapping for another name is preserved: the transaction rolls back
/// and returns [`UpsertJoinOutcome::NameAlreadyClaimed`].
///
/// When `is_admin` is false, ordinary membership is unchanged — the relay
/// still claims `member` via [`crate::relay_members::claim_relay_membership`].
/// When `is_admin` is true, binding replacement, displaced `admin`→`member`
/// demotion, and the new key's admin insert or `member`→`admin` promotion run
/// in one transaction. `owner` rows are never changed.
pub async fn upsert_approved_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
    fqdn: &str,
    approved_by: &str,
    is_admin: bool,
) -> Result<UpsertJoinOutcome> {
    let mut tx = pool.begin().await?;
    lock_application_bindings(&mut tx, community).await?;

    sqlx::query(
        "DELETE FROM dntls_applications \
         WHERE community_id = $1 AND pubkey = $2 \
           AND (status = 'rejected' OR (status = 'pending' AND fqdn <> $3))",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .bind(fqdn)
    .execute(&mut *tx)
    .await?;

    // PostgreSQL 17 cannot return OLD from ON CONFLICT. The community lock
    // protects this pre-read even if another claim moves a pending name.
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT pubkey FROM dntls_applications \
         WHERE community_id = $1 AND fqdn = $2 \
           AND status IN ('pending', 'approved')",
    )
    .bind(community.as_uuid())
    .bind(fqdn)
    .fetch_optional(&mut *tx)
    .await?;

    // The pubkey primary key still forbids a second approved name on this key.
    let binding = sqlx::query(
        "INSERT INTO dntls_applications \
         (community_id, pubkey, fqdn, status, approved_at, approved_by) \
         VALUES ($1, $2, $3, 'approved', now(), $4) \
         ON CONFLICT (community_id, fqdn) WHERE status IN ('pending', 'approved') DO UPDATE \
         SET pubkey = EXCLUDED.pubkey, status = 'approved', \
             created_at = CASE WHEN dntls_applications.pubkey = EXCLUDED.pubkey \
                 THEN dntls_applications.created_at ELSE EXCLUDED.created_at END, \
             approved_at = EXCLUDED.approved_at, approved_by = EXCLUDED.approved_by \
         WHERE dntls_applications.pubkey <> EXCLUDED.pubkey \
             OR dntls_applications.status = 'pending'",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .bind(fqdn)
    .bind(approved_by)
    .execute(&mut *tx)
    .await;
    match binding {
        Ok(_) => {
            let displaced = previous.filter(|held| held != pubkey);
            let membership_changed = if is_admin {
                if let Some(old) = displaced.as_deref() {
                    super::relay_members::demote_relay_admin_to_member_on(&mut tx, community, old)
                        .await?;
                }
                super::relay_members::grant_relay_admin_on(&mut tx, community, pubkey).await?
            } else {
                false
            };
            tx.commit().await?;
            Ok(UpsertJoinOutcome::Bound {
                displaced,
                membership_changed,
            })
        }
        Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
            tx.rollback().await?;
            Ok(UpsertJoinOutcome::NameAlreadyClaimed)
        }
        Err(err) => Err(err.into()),
    }
}

/// Returns the application for `pubkey` in `community`, or `None`.
pub async fn get_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
) -> Result<Option<DntlsApplication>> {
    let row = sqlx::query(
        "SELECT pubkey, fqdn, status, created_at, approved_at, approved_by \
         FROM dntls_applications WHERE community_id = $1 AND pubkey = $2",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(map_application_row))
}

/// Lists applications in `community` with `status`, ordered by `created_at`.
pub async fn list_applications(
    pool: &PgPool,
    community: CommunityId,
    status: &str,
) -> Result<Vec<DntlsApplication>> {
    let rows = sqlx::query(
        "SELECT pubkey, fqdn, status, created_at, approved_at, approved_by \
         FROM dntls_applications \
         WHERE community_id = $1 AND status = $2 \
         ORDER BY created_at ASC",
    )
    .bind(community.as_uuid())
    .bind(status)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(map_application_row).collect())
}

/// Approves a pending or rejected name and grants membership in one transaction.
///
/// Returns the approved row and whether membership was inserted or promoted.
/// A removed, rebound, or changed application returns `None` and grants
/// nothing. Listed administrators use the same binding lock as connection admission.
/// Approve also recovers a rejected row after a misclick; there is no un-reject UI.
pub async fn approve_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
    fqdn: &str,
    approved_by: &str,
    is_admin: bool,
) -> Result<Option<(DntlsApplication, bool)>> {
    let mut tx = pool.begin().await?;
    lock_application_bindings(&mut tx, community).await?;
    let row = match sqlx::query(
        "UPDATE dntls_applications \
         SET status = 'approved', approved_at = now(), approved_by = $3 \
         WHERE community_id = $1 AND pubkey = $2 \
           AND status IN ('pending', 'rejected') AND fqdn = $4 \
         RETURNING pubkey, fqdn, status, created_at, approved_at, approved_by",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .bind(approved_by)
    .bind(fqdn)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
            tx.commit().await?;
            return Ok(None);
        }
        Err(err) => return Err(err.into()),
    };
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let changed = if is_admin {
        super::relay_members::grant_relay_admin_on(&mut tx, community, pubkey).await?
    } else {
        super::relay_members::insert_relay_member_on(
            &mut tx,
            community,
            pubkey,
            "member",
            Some("invite"),
        )
        .await?
    };
    tx.commit().await?;
    Ok(Some((map_application_row(&row), changed)))
}

/// Marks a pending application rejected. Returns `true` if a pending row changed.
pub async fn reject_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE dntls_applications \
         SET status = 'rejected' \
         WHERE community_id = $1 AND pubkey = $2 AND status = 'pending'",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}


impl Db {
    /// Insert or replace this pubkey's pending DNTLS application.
    #[datastore_span(name = "upsert_dntls_pending_application", system = "postgresql")]
    pub async fn upsert_dntls_pending_application(
        &self,
        community: CommunityId,
        pubkey: &str,
        fqdn: &str,
    ) -> Result<UpsertJoinOutcome> {
        upsert_pending_application(&self.pool, community, pubkey, fqdn).await
    }

    /// Bind a verified DNTLS name, replacing its former key in auto mode.
    /// See [`upsert_approved_application`] for proof, conflict, and admin
    /// transfer requirements.
    #[datastore_span(name = "upsert_dntls_approved_application", system = "postgresql")]
    pub async fn upsert_dntls_approved_application(
        &self,
        community: CommunityId,
        pubkey: &str,
        fqdn: &str,
        approved_by: &str,
        is_admin: bool,
    ) -> Result<UpsertJoinOutcome> {
        upsert_approved_application(&self.pool, community, pubkey, fqdn, approved_by, is_admin)
            .await
    }

    /// Returns the DNTLS application for `pubkey` in `community`, or `None`.
    #[datastore_span(name = "get_dntls_application", system = "postgresql")]
    pub async fn get_dntls_application(
        &self,
        community: CommunityId,
        pubkey: &str,
    ) -> Result<Option<DntlsApplication>> {
        get_application(&self.pool, community, pubkey).await
    }

    /// Lists DNTLS applications in `community` with `status`.
    #[datastore_span(name = "list_dntls_applications", system = "postgresql")]
    pub async fn list_dntls_applications(
        &self,
        community: CommunityId,
        status: &str,
    ) -> Result<Vec<DntlsApplication>> {
        list_applications(&self.pool, community, status).await
    }

    /// Approves a pending or rejected name and atomically grants its membership.
    #[datastore_span(name = "approve_dntls_application", system = "postgresql")]
    pub async fn approve_dntls_application(
        &self,
        community: CommunityId,
        pubkey: &str,
        fqdn: &str,
        approved_by: &str,
        is_admin: bool,
    ) -> Result<Option<(DntlsApplication, bool)>> {
        approve_application(&self.pool, community, pubkey, fqdn, approved_by, is_admin).await
    }

    /// Marks a pending DNTLS application rejected.
    #[datastore_span(name = "reject_dntls_application", system = "postgresql")]
    pub async fn reject_dntls_application(
        &self,
        community: CommunityId,
        pubkey: &str,
    ) -> Result<bool> {
        reject_application(&self.pool, community, pubkey).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(displaced: Option<&str>, membership_changed: bool) -> UpsertJoinOutcome {
        UpsertJoinOutcome::Bound {
            displaced: displaced.map(str::to_string),
            membership_changed,
        }
    }

    async fn test_db() -> (Db, CommunityId) {
        let url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .expect("BUZZ_TEST_DATABASE_URL must point to a migrated test database");
        let db = Db::from_pool(PgPool::connect(&url).await.expect("connect test database"));
        let host = format!("dntls-store-{}.example", uuid::Uuid::new_v4().simple());
        db.ensure_configured_community(&host)
            .await
            .expect("community");
        let community = db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community")
            .id;
        (db, community)
    }

    async fn role_of(db: &Db, community: CommunityId, pubkey: &str) -> Option<String> {
        db.get_relay_member(community, pubkey)
            .await
            .expect("member lookup")
            .map(|member| member.role)
    }

    fn assert_non_admin_rebind(outcome: UpsertJoinOutcome) -> Option<String> {
        match outcome {
            UpsertJoinOutcome::Bound {
                displaced,
                membership_changed,
            } => {
                assert!(!membership_changed);
                displaced
            }
            other => panic!("expected Bound, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_concurrent_rebinding_is_scoped_and_idempotent() {
        let (db, community) = test_db().await;
        let (_, other) = test_db().await;
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let third = "cc".repeat(32);
        for scope in [community, other] {
            assert_eq!(
                db.upsert_dntls_approved_application(scope, &first, "alice.example", &first, false)
                    .await
                    .expect("seed"),
                bound(None, false)
            );
        }
        let (left, right) = tokio::join!(
            db.upsert_dntls_approved_application(
                community,
                &second,
                "alice.example",
                &second,
                false
            ),
            db.upsert_dntls_approved_application(community, &third, "alice.example", &third, false),
        );
        let left_displaced = assert_non_admin_rebind(left.expect("second binding"));
        let right_displaced = assert_non_admin_rebind(right.expect("third binding"));
        assert!(left_displaced.is_some());
        assert!(right_displaced.is_some());
        let rows = db
            .list_dntls_applications(community, "approved")
            .await
            .expect("list");
        assert_eq!(rows.len(), 1);
        let winner = &rows[0];
        assert!(winner.pubkey == second || winner.pubkey == third);
        assert_eq!(winner.fqdn, "alice.example");
        assert!(db
            .get_dntls_application(community, &first)
            .await
            .expect("old key")
            .is_none());
        assert_eq!(
            db.get_dntls_application(other, &first)
                .await
                .expect("other community")
                .expect("unchanged binding")
                .fqdn,
            "alice.example"
        );
        assert_eq!(role_of(&db, other, &first).await, None);

        assert_eq!(
            db.upsert_dntls_approved_application(
                community,
                &winner.pubkey,
                "alice.example",
                &winner.pubkey,
                false,
            )
            .await
            .expect("repeat"),
            bound(None, false)
        );
        assert_eq!(
            db.get_dntls_application(community, &winner.pubkey)
                .await
                .expect("lookup")
                .expect("mapping"),
            *winner
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_rebinding_preserves_another_approved_name() {
        let (db, community) = test_db().await;
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        assert_eq!(
            db.upsert_dntls_approved_application(community, &first, "alice.example", &first, true)
                .await
                .expect("first binding"),
            bound(None, true)
        );
        db.add_relay_member(community, &second, "member", None)
            .await
            .expect("seed member");
        assert_eq!(
            db.upsert_dntls_approved_application(community, &second, "bob.example", &second, false)
                .await
                .expect("second binding"),
            bound(None, false)
        );
        let before = db
            .list_dntls_applications(community, "approved")
            .await
            .expect("before");
        assert_eq!(
            db.upsert_dntls_approved_application(
                community,
                &second,
                "alice.example",
                &second,
                true
            )
            .await
            .expect("conflicting binding"),
            UpsertJoinOutcome::NameAlreadyClaimed
        );
        assert_eq!(
            db.list_dntls_applications(community, "approved")
                .await
                .expect("after"),
            before
        );
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("admin")
        );
        assert_eq!(
            role_of(&db, community, &second).await.as_deref(),
            Some("member")
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_auto_rebinding_replaces_pending_but_approve_does_not() {
        let (db, community) = test_db().await;
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        db.upsert_dntls_pending_application(community, &first, "alice.example")
            .await
            .expect("first pending");
        db.upsert_dntls_pending_application(community, &second, "bob.example")
            .await
            .expect("second pending");
        assert_eq!(
            db.upsert_dntls_pending_application(community, &second, "alice.example")
                .await
                .expect("approve conflict"),
            UpsertJoinOutcome::NameAlreadyClaimed
        );
        assert_eq!(
            db.upsert_dntls_approved_application(
                community,
                &second,
                "alice.example",
                &second,
                false
            )
            .await
            .expect("auto rebind"),
            bound(Some(first.as_str()), false)
        );
        assert!(db
            .list_dntls_applications(community, "pending")
            .await
            .expect("pending")
            .is_empty());
        let rows = db
            .list_dntls_applications(community, "approved")
            .await
            .expect("approved");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pubkey, second);
        assert_eq!(rows[0].fqdn, "alice.example");
        assert_eq!(role_of(&db, community, &first).await, None);
        assert_eq!(role_of(&db, community, &second).await, None);
        assert_eq!(
            db.upsert_dntls_pending_application(community, &first, "alice.example")
                .await
                .expect("approved conflict"),
            UpsertJoinOutcome::NameAlreadyClaimed
        );
        assert_eq!(
            db.list_dntls_applications(community, "approved")
                .await
                .expect("unchanged"),
            rows
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_admin_binding_transfers_roles_and_preserves_owner() {
        let (db, community) = test_db().await;
        let owner = "01".repeat(32);
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let third = "cc".repeat(32);
        db.bootstrap_owner(community, &owner).await.expect("owner");
        db.add_relay_member(community, &first, "member", None)
            .await
            .expect("seed member");

        assert_eq!(
            db.upsert_dntls_approved_application(community, &first, "alice.example", &first, true)
                .await
                .expect("promote member"),
            bound(None, true)
        );
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("admin")
        );
        assert_eq!(
            db.upsert_dntls_approved_application(community, &first, "alice.example", &first, true)
                .await
                .expect("repeat admin"),
            bound(None, false)
        );

        assert_eq!(
            db.upsert_dntls_approved_application(
                community,
                &second,
                "alice.example",
                &second,
                true
            )
            .await
            .expect("admin rebind"),
            bound(Some(first.as_str()), true)
        );
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("member")
        );
        assert_eq!(
            role_of(&db, community, &second).await.as_deref(),
            Some("admin")
        );

        assert_eq!(
            db.upsert_dntls_approved_application(community, &owner, "alice.example", &owner, true)
                .await
                .expect("owner bind"),
            bound(Some(second.as_str()), false)
        );
        assert_eq!(
            role_of(&db, community, &owner).await.as_deref(),
            Some("owner")
        );
        assert_eq!(
            role_of(&db, community, &second).await.as_deref(),
            Some("member")
        );

        assert_eq!(
            db.upsert_dntls_approved_application(community, &third, "alice.example", &third, true)
                .await
                .expect("displace owner"),
            bound(Some(owner.as_str()), true)
        );
        assert_eq!(
            role_of(&db, community, &owner).await.as_deref(),
            Some("owner")
        );
        assert_eq!(
            role_of(&db, community, &third).await.as_deref(),
            Some("admin")
        );

        assert_eq!(
            db.upsert_dntls_approved_application(community, &first, "alice.example", &first, false)
                .await
                .expect("non-admin rebind"),
            bound(Some(third.as_str()), false)
        );
        assert_eq!(
            role_of(&db, community, &third).await.as_deref(),
            Some("admin")
        );
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("member")
        );
        assert_eq!(
            db.get_dntls_application(community, &first)
                .await
                .expect("lookup")
                .expect("mapping")
                .fqdn,
            "alice.example"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_manual_approval_cannot_grant_admin_after_rebinding() {
        let (db, community) = test_db().await;
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        db.upsert_dntls_pending_application(community, &first, "admin.example")
            .await
            .expect("pending admin");
        db.add_relay_member(community, &first, "member", None)
            .await
            .expect("member");
        let (approved, changed) = db
            .approve_dntls_application(community, &first, "admin.example", &second, true)
            .await
            .expect("approve")
            .expect("pending row");
        assert_eq!(approved.status, "approved");
        assert!(changed);
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("admin")
        );
        db.upsert_dntls_approved_application(community, &second, "admin.example", &second, true)
            .await
            .expect("rebind");
        assert!(db
            .approve_dntls_application(community, &first, "admin.example", &second, true,)
            .await
            .expect("stale approval")
            .is_none());
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("member")
        );
        assert_eq!(
            role_of(&db, community, &second).await.as_deref(),
            Some("admin")
        );

        // A refreshed pending application cannot inherit an old name's privilege.
        db.upsert_dntls_pending_application(community, &first, "ordinary.example")
            .await
            .expect("changed pending name");
        assert!(db
            .approve_dntls_application(community, &first, "admin.example", &second, true,)
            .await
            .expect("stale name approval")
            .is_none());
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("member")
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_pending_name_move_cannot_demote_another_names_admin() {
        async fn wait_for_waiters(pool: &PgPool, blocker: i32, expected: i64) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let count: i64 = sqlx::query_scalar(
                        "WITH RECURSIVE waiting(pid) AS ( \
                         SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) \
                         UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w \
                         ON w.pid = ANY(pg_blocking_pids(a.pid))) \
                         SELECT count(*) FROM waiting",
                    )
                    .bind(blocker)
                    .fetch_one(pool)
                    .await
                    .expect("waiting queries");
                    if count >= expected {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("admission queries reached the held row");
        }

        let (db, community) = test_db().await;
        let moving = "aa".repeat(32);
        let replacing = "bb".repeat(32);
        db.upsert_dntls_pending_application(community, &moving, "old.example")
            .await
            .expect("pending name");
        let mut blocker = db.pool.begin().await.expect("blocker");
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .expect("blocker pid");
        sqlx::query("SELECT 1 FROM dntls_applications WHERE community_id = $1 FOR UPDATE")
            .bind(community.as_uuid())
            .execute(&mut *blocker)
            .await
            .expect("hold pending row");
        let moving_db = db.clone();
        let moving_key = moving.clone();
        let move_name = tokio::spawn(async move {
            moving_db
                .upsert_dntls_approved_application(
                    community,
                    &moving_key,
                    "new.example",
                    &moving_key,
                    true,
                )
                .await
        });
        wait_for_waiters(&db.pool, blocker_pid, 1).await;
        let replacing_db = db.clone();
        let replacing_key = replacing.clone();
        let replace_name = tokio::spawn(async move {
            replacing_db
                .upsert_dntls_approved_application(
                    community,
                    &replacing_key,
                    "old.example",
                    &replacing_key,
                    true,
                )
                .await
        });
        wait_for_waiters(&db.pool, blocker_pid, 2).await;
        blocker.rollback().await.expect("release pending row");
        assert_eq!(
            move_name.await.expect("move task").expect("move name"),
            bound(None, true)
        );
        assert_eq!(
            replace_name
                .await
                .expect("replace task")
                .expect("replace name"),
            bound(None, true)
        );
        for key in [&moving, &replacing] {
            assert_eq!(role_of(&db, community, key).await.as_deref(), Some("admin"));
        }
        assert_eq!(
            db.get_dntls_application(community, &moving)
                .await
                .expect("moving mapping")
                .expect("approved")
                .fqdn,
            "new.example"
        );
        assert_eq!(
            db.get_dntls_application(community, &replacing)
                .await
                .expect("replacing mapping")
                .expect("approved")
                .fqdn,
            "old.example"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_concurrent_admin_rebinding_serializes_roles() {
        let (db, community) = test_db().await;
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let third = "cc".repeat(32);

        let (left, right) = tokio::join!(
            db.upsert_dntls_approved_application(
                community,
                &second,
                "alice.example",
                &second,
                true
            ),
            db.upsert_dntls_approved_application(community, &third, "alice.example", &third, true),
        );
        let left = left.expect("second admin bind");
        let right = right.expect("third admin bind");
        let mut missing_row_displaced = 0;
        for outcome in [&left, &right] {
            match outcome {
                UpsertJoinOutcome::Bound {
                    displaced,
                    membership_changed,
                } => {
                    assert!(*membership_changed);
                    if displaced.is_none() {
                        missing_row_displaced += 1;
                    }
                }
                other => panic!("expected Bound, got {other:?}"),
            }
        }
        assert_eq!(missing_row_displaced, 1);
        let alice = db
            .list_dntls_applications(community, "approved")
            .await
            .expect("alice");
        assert_eq!(alice.len(), 1);
        let alice_winner = alice[0].pubkey.clone();
        let alice_loser = if alice_winner == second {
            &third
        } else {
            &second
        };
        assert_eq!(
            role_of(&db, community, &alice_winner).await.as_deref(),
            Some("admin")
        );
        assert_eq!(
            role_of(&db, community, alice_loser).await.as_deref(),
            Some("member")
        );

        let second = "dd".repeat(32);
        let third = "ee".repeat(32);
        assert_eq!(
            db.upsert_dntls_approved_application(community, &first, "bob.example", &first, true)
                .await
                .expect("seed bob"),
            bound(None, true)
        );
        let (left, right) = tokio::join!(
            db.upsert_dntls_approved_application(community, &second, "bob.example", &second, true),
            db.upsert_dntls_approved_application(community, &third, "bob.example", &third, true),
        );
        for outcome in [left.expect("second bob"), right.expect("third bob")] {
            match outcome {
                UpsertJoinOutcome::Bound {
                    displaced,
                    membership_changed,
                } => {
                    assert!(membership_changed);
                    assert!(displaced.is_some());
                }
                other => panic!("expected Bound, got {other:?}"),
            }
        }
        let bob = db
            .list_dntls_applications(community, "approved")
            .await
            .expect("bob list")
            .into_iter()
            .find(|row| row.fqdn == "bob.example")
            .expect("bob");
        assert!(bob.pubkey == second || bob.pubkey == third);
        assert_eq!(
            role_of(&db, community, &bob.pubkey).await.as_deref(),
            Some("admin")
        );
        assert_eq!(
            role_of(&db, community, &first).await.as_deref(),
            Some("member")
        );
        assert_eq!(
            role_of(&db, community, &alice_winner).await.as_deref(),
            Some("admin")
        );
        assert_eq!(
            db.get_dntls_application(community, &first)
                .await
                .expect("first lost bob"),
            None
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn dntls_reject_persists_and_does_not_burn_name() {
        let (db, community) = test_db().await;
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        db.upsert_dntls_pending_application(community, &first, "alice.example")
            .await
            .expect("pending");
        assert!(db
            .reject_dntls_application(community, &first)
            .await
            .expect("reject"));
        let row = db
            .get_dntls_application(community, &first)
            .await
            .expect("lookup")
            .expect("rejected");
        assert_eq!(row.status, "rejected");
        assert_eq!(row.fqdn, "alice.example");
        assert!(db
            .list_dntls_applications(community, "pending")
            .await
            .expect("pending")
            .is_empty());
        assert_eq!(
            db.upsert_dntls_pending_application(community, &first, "alice.example")
                .await
                .expect("same pubkey"),
            UpsertJoinOutcome::Rejected
        );
        assert_eq!(
            db.get_dntls_application(community, &first)
                .await
                .expect("unchanged")
                .expect("still rejected")
                .status,
            "rejected"
        );
        let (approved, changed) = db
            .approve_dntls_application(community, &first, "alice.example", &second, false)
            .await
            .expect("approve rejected")
            .expect("recovered");
        assert_eq!(approved.status, "approved");
        assert!(changed);

        let third = "cc".repeat(32);
        let fourth = "dd".repeat(32);
        db.upsert_dntls_pending_application(community, &third, "bob.example")
            .await
            .expect("bob pending");
        assert!(db
            .reject_dntls_application(community, &third)
            .await
            .expect("reject bob"));
        assert_eq!(
            db.upsert_dntls_pending_application(community, &fourth, "bob.example")
                .await
                .expect("other key"),
            UpsertJoinOutcome::Pending
        );
        let pending = db
            .list_dntls_applications(community, "pending")
            .await
            .expect("other pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].pubkey, fourth);
        assert_eq!(pending[0].fqdn, "bob.example");
    }
}
