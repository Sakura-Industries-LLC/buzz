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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertJoinOutcome {
    /// Inserted or replaced this pubkey's own pending row.
    Pending,
    /// Approved binding inserted, promoted, reassigned, or unchanged.
    Bound,
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
    /// `pending` or `approved`.
    pub status: String,
    /// When the application was first created (or last replaced while pending).
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

/// Insert or replace this pubkey's pending application after a verified name.
///
/// First-bound-wins: if a *different* pubkey already holds a pending or
/// approved application for `fqdn` in `community`, returns
/// [`UpsertJoinOutcome::NameAlreadyClaimed`] and writes nothing. Repeating a
/// verified application for the same pubkey replaces its own pending row.
pub async fn upsert_pending_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
    fqdn: &str,
) -> Result<UpsertJoinOutcome> {
    let mut tx = pool.begin().await?;

    let existing_fqdn: Option<String> = sqlx::query_scalar(
        "SELECT pubkey FROM dntls_applications \
         WHERE community_id = $1 AND fqdn = $2 AND pubkey <> $3 \
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
        Some(_) => {
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
/// under concurrent claims. Ordinary membership and roles are not transferred
/// or revoked. Repeating the same approved mapping is a no-op.
///
/// A pending application by this pubkey for another name is replaced. An
/// approved mapping for another name is preserved: the transaction rolls back
/// and returns [`UpsertJoinOutcome::NameAlreadyClaimed`].
pub async fn upsert_approved_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
    fqdn: &str,
    approved_by: &str,
) -> Result<UpsertJoinOutcome> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "DELETE FROM dntls_applications \
         WHERE community_id = $1 AND pubkey = $2 AND fqdn <> $3 AND status = 'pending'",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .bind(fqdn)
    .execute(&mut *tx)
    .await?;

    // The unique name key serializes competing bindings, including when no
    // row exists yet. The pubkey key still forbids taking a second approved name.
    let binding = sqlx::query(
        "INSERT INTO dntls_applications \
         (community_id, pubkey, fqdn, status, approved_at, approved_by) \
         VALUES ($1, $2, $3, 'approved', now(), $4) \
         ON CONFLICT (community_id, fqdn) DO UPDATE \
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
            tx.commit().await?;
            Ok(UpsertJoinOutcome::Bound)
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

/// Marks a pending application approved. Returns the row, or `None` if missing.
pub async fn approve_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
    approved_by: &str,
) -> Result<Option<DntlsApplication>> {
    let row = sqlx::query(
        "UPDATE dntls_applications \
         SET status = 'approved', approved_at = now(), approved_by = $3 \
         WHERE community_id = $1 AND pubkey = $2 AND status = 'pending' \
         RETURNING pubkey, fqdn, status, created_at, approved_at, approved_by",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .bind(approved_by)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(map_application_row))
}

/// Deletes a pending application. Returns `true` if a pending row was removed.
pub async fn reject_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM dntls_applications \
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
    /// See [`upsert_approved_application`] for proof and conflict requirements.
    #[datastore_span(name = "upsert_dntls_approved_application", system = "postgresql")]
    pub async fn upsert_dntls_approved_application(
        &self,
        community: CommunityId,
        pubkey: &str,
        fqdn: &str,
        approved_by: &str,
    ) -> Result<UpsertJoinOutcome> {
        upsert_approved_application(&self.pool, community, pubkey, fqdn, approved_by).await
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

    /// Marks a pending DNTLS application approved.
    #[datastore_span(name = "approve_dntls_application", system = "postgresql")]
    pub async fn approve_dntls_application(
        &self,
        community: CommunityId,
        pubkey: &str,
        approved_by: &str,
    ) -> Result<Option<DntlsApplication>> {
        approve_application(&self.pool, community, pubkey, approved_by).await
    }

    /// Deletes a pending DNTLS application.
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
                db.upsert_dntls_approved_application(scope, &first, "alice.example", &first)
                    .await
                    .expect("seed"),
                UpsertJoinOutcome::Bound
            );
        }
        let (left, right) = tokio::join!(
            db.upsert_dntls_approved_application(community, &second, "alice.example", &second),
            db.upsert_dntls_approved_application(community, &third, "alice.example", &third),
        );
        assert_eq!(left.expect("second binding"), UpsertJoinOutcome::Bound);
        assert_eq!(right.expect("third binding"), UpsertJoinOutcome::Bound);
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

        assert_eq!(
            db.upsert_dntls_approved_application(
                community,
                &winner.pubkey,
                "alice.example",
                &winner.pubkey,
            )
            .await
            .expect("repeat"),
            UpsertJoinOutcome::Bound
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
        db.upsert_dntls_approved_application(community, &first, "alice.example", &first)
            .await
            .expect("first binding");
        db.upsert_dntls_approved_application(community, &second, "bob.example", &second)
            .await
            .expect("second binding");
        let before = db
            .list_dntls_applications(community, "approved")
            .await
            .expect("before");
        assert_eq!(
            db.upsert_dntls_approved_application(community, &second, "alice.example", &second)
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
            db.upsert_dntls_approved_application(community, &second, "alice.example", &second)
                .await
                .expect("auto rebind"),
            UpsertJoinOutcome::Bound
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
}
