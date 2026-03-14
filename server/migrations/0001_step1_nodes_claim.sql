-- Step 1: idempotent PAT bootstrap claim for nodes keyed by public_key
-- Existing PAT flow remains untouched; this extends the nodes table for key-based claims.

ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS public_key text,
    ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS last_seen timestamptz,
    ADD COLUMN IF NOT EXISTS revoked boolean NOT NULL DEFAULT false;

-- Step 1 decouples node registration from PAT token ownership.
ALTER TABLE nodes
    ALTER COLUMN token_id DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'nodes_public_key_key'
    ) THEN
        ALTER TABLE nodes
            ADD CONSTRAINT nodes_public_key_key UNIQUE (public_key);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS nodes_last_seen_idx
    ON nodes (last_seen);