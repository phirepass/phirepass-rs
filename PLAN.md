# Plan

## Objective
Move node authentication to a zero-trust model where:
- PAT is used only once for bootstrap claim.
- Node identity is persistent and cryptographic (Ed25519 key pair generated locally by agent).
- Runtime auth is challenge-response plus short-lived JWT.
- WebSocket node auth uses JWT, not PAT.
- Private keys never leave the agent host.

## What Has Been Done
- Added node claim endpoint: `POST /api/nodes/claim`.
- Added challenge-response endpoints:
  - `POST /api/nodes/auth/challenge`
  - `POST /api/nodes/auth/verify`
- Added JWT-protected heartbeat endpoint:
  - `POST /api/nodes/heartbeat`
- Switched node WebSocket first-frame auth to JWT.
- Added DB support for challenge storage and claim lookups.
- Added migrations:
  - `0001_step1_nodes_claim.sql`
  - `0002_step1_pat_scope_support.sql`
  - `0003_step2_auth_challenges.sql`
  - `0004_drop_legacy_nodes_columns.sql`
- Removed legacy node columns from `nodes` table (`token_id`, `name`) via migration.
- Updated server code paths to use current `nodes` schema (not legacy columns).
- Improved claim endpoint error semantics:
  - `400` for invalid request payload
  - `401` for credential/scope failures
  - `500` for internal/database claim failures
- Updated agent flow:
  - bootstrap claim with PAT
  - local keypair persistence
  - runtime challenge signing and JWT retrieval
  - JWT passed in websocket auth frame
- Added database-side challenge cleanup via Postgres `pg_cron` job.

## Current State
- Server and agent compile with the new flow.
- Claim/challenge/verify/websocket auth path is working in local testing.
- PAT scope required for claim: `server:register`.

## What Still Needs To Be Done
- Security hardening:
  - Add rate limiting / abuse controls for challenge endpoint.
  - Consider anti-enumeration behavior for auth challenge requests.
- Documentation updates beyond schema:
  - Update README sections that still describe legacy auth behavior.
  - Add explicit end-to-end testing docs for claim/challenge/verify/ws.
- Tests:
  - Add integration tests for claim idempotency and challenge replay prevention.
  - Add regression tests for websocket auth with JWT.
- Operational polish:
  - Add request IDs or structured error codes to claim/auth responses for easier debugging.

## Quick Resume Checklist
1. Ensure migrations up to `0004` are applied in Postgres.
2. Start server with `NODE_JWT_SECRET` set.
3. Run `phirepass-agent login` with PAT that has `server:register`.
4. Start agent and confirm websocket auth success.
5. Continue with hardening and tests listed above.
