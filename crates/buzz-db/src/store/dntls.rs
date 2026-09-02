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
    /// Bound this pubkey to the name as approved (insert, promote, or no-op).
    Bound,
    /// A different pubkey already holds a pending or approved application for
    /// the same fqdn in this community.
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

/// Bind this pubkey to `fqdn` as an approved mapping.
///
/// First-bound-wins: if a *different* pubkey already holds the name, returns
/// [`UpsertJoinOutcome::NameAlreadyClaimed`]. Repeating the same pubkey and
/// name is a no-op. An already-approved row for this pubkey under a different
/// name is refused so the original mapping stays put.
pub async fn upsert_approved_application(
    pool: &PgPool,
    community: CommunityId,
    pubkey: &str,
    fqdn: &str,
    approved_by: &str,
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

    let existing_self: Option<(String, String)> = sqlx::query_as(
        "SELECT status, fqdn FROM dntls_applications \
         WHERE community_id = $1 AND pubkey = $2 \
         FOR UPDATE",
    )
    .bind(community.as_uuid())
    .bind(pubkey)
    .fetch_optional(&mut *tx)
    .await?;

    match existing_self
        .as_ref()
        .map(|(status, current_fqdn)| (status.as_str(), current_fqdn.as_str()))
    {
        Some(("approved", current_fqdn)) if current_fqdn == fqdn => {
            tx.commit().await?;
            return Ok(UpsertJoinOutcome::Bound);
        }
        Some(("approved", _)) => {
            tx.commit().await?;
            return Ok(UpsertJoinOutcome::NameAlreadyClaimed);
        }
        Some(_) => {
            let update = sqlx::query(
                "UPDATE dntls_applications \
                 SET fqdn = $3, status = 'approved', approved_at = now(), \
                     approved_by = $4 \
                 WHERE community_id = $1 AND pubkey = $2 AND status = 'pending'",
            )
            .bind(community.as_uuid())
            .bind(pubkey)
            .bind(fqdn)
            .bind(approved_by)
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
                "INSERT INTO dntls_applications \
                 (community_id, pubkey, fqdn, status, approved_at, approved_by) \
                 VALUES ($1, $2, $3, 'approved', now(), $4)",
            )
            .bind(community.as_uuid())
            .bind(pubkey)
            .bind(fqdn)
            .bind(approved_by)
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
    Ok(UpsertJoinOutcome::Bound)
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

    /// Bind this pubkey to a DNTLS name as an approved mapping.
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
