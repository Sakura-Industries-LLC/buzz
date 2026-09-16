-- Preserve the admission decision, not a suffix inferred from today's roster.
-- Existing approvals have no unambiguous provenance: approved_by can also be
-- an administrator who manually approved a descendant. Leave those rows unset.
ALTER TABLE dntls_applications ADD COLUMN admitted_via_parent TEXT;
