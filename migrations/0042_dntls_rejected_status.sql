-- Remember DNTLS join rejections without burning the verified name.
-- The same pubkey cannot requeue; another key may still apply for that fqdn.
SET LOCAL lock_timeout = '5s';

ALTER TABLE dntls_applications
    DROP CONSTRAINT dntls_applications_status_check,
    DROP CONSTRAINT dntls_applications_check;

ALTER TABLE dntls_applications
    ADD CONSTRAINT dntls_applications_status_check
        CHECK (status IN ('pending', 'approved', 'rejected')),
    ADD CONSTRAINT dntls_applications_status_fields_check
        CHECK (
            (status IN ('pending', 'rejected') AND approved_at IS NULL AND approved_by IS NULL)
            OR (status = 'approved' AND approved_at IS NOT NULL)
        );

ALTER TABLE dntls_applications
    DROP CONSTRAINT dntls_applications_community_id_fqdn_key;

CREATE UNIQUE INDEX dntls_applications_live_fqdn_idx
    ON dntls_applications (community_id, fqdn)
    WHERE status IN ('pending', 'approved');
