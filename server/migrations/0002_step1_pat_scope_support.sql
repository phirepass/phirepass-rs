-- Step 1 PAT requirements for /api/nodes/claim:
-- 1) token must be valid and not expired
-- 2) token must include scope server:register
-- Existing pat_tokens schema already has scopes and expiry, so this migration
-- only adds supporting indexes for faster lookup paths used during claim.

CREATE INDEX IF NOT EXISTS pat_tokens_token_id_idx
    ON pat_tokens (token_id);

CREATE INDEX IF NOT EXISTS pat_tokens_expires_at_idx
    ON pat_tokens (expires_at);