-- DNTLS join-proof applications: community-scoped pending/approved
-- pubkey→fqdn mappings used by relay join admission.
--
-- Unique (community_id, pubkey) is one application per joining key.
-- Unique (community_id, fqdn) is first-bound-wins for a verified name.
-- Both keys lead with community_id so a mapping in tenant A never collides
-- with tenant B.
CREATE TABLE dntls_applications (
    community_id UUID        NOT NULL REFERENCES communities(id),
    pubkey       TEXT        NOT NULL,
    fqdn         TEXT        NOT NULL CHECK (length(btrim(fqdn)) > 0 AND length(fqdn) <= 255),
    status       TEXT        NOT NULL CHECK (status IN ('pending', 'approved')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at  TIMESTAMPTZ,
    approved_by  TEXT,
    PRIMARY KEY (community_id, pubkey),
    UNIQUE (community_id, fqdn),
    CHECK (
        (status = 'pending' AND approved_at IS NULL AND approved_by IS NULL)
        OR (status = 'approved' AND approved_at IS NOT NULL)
    )
);

CREATE INDEX dntls_applications_status_idx
    ON dntls_applications (community_id, status, created_at);

SELECT attach_community_write_fence('dntls_applications');
