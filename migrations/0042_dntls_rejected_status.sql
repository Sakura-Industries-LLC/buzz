-- Remember DNTLS join rejections. UNIQUE (community_id, fqdn) stays so a
-- later applicant replaces a rejected row rather than sharing the name.
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
