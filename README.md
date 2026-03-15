# Phirepass

Rust workspace for the Phirepass remote-access relay. The system has three main pieces:

- `server`: accepts web clients and node agents over WebSocket, forwards traffic, and exposes basic HTTP status endpoints.
- `agent`: runs on a target host, dials the server via WebSocket, and opens SSH sessions on behalf of web clients.
- `channel`: WASM client helpers for browsers (frames, heartbeat, auth prompts).
- `common`: shared protocol, env, and stats code.

## How traffic flows

1. A browser (via the `channel` package or your own client) connects to `ws://<server-host>:8080/api/web/ws`.
2. A node agent connects to `ws://<server-host>:8080/api/nodes/ws`.
3. Web clients send `WebControlMessage::OpenTunnel` with protocol/target/credentials; the server forwards it to the matching node as `NodeControlMessage::OpenTunnel`.
4. The agent opens a local SSH session (`russh`), pipes stdin/stdout over WebSocket frames, and mirrors resize events. When the SSH channel closes it sends `TunnelClosed`.
5. Heartbeats and ping/pong frames keep both directions alive; stats are logged server-side.

## Protocol snapshot

- Frames: 1 byte protocol + 4 byte BE payload length + payload. `Protocol::Control = 0`, `Protocol::SSH = 1`.
- Control messages web→server: `Heartbeat`, `OpenTunnel`, `TunnelData` (payload for SSH), `Resize`, `TunnelClosed`, `Error`, `Ok`.
- First frame from agent→server on node websocket is `NodeFrameData::Auth { node_id, token=<node-jwt>, version }`.
- Control messages server→agent after auth: `Heartbeat { stats }`, `OpenTunnel`, `TunnelData`, `Resize`, `Ping/Pong`, `ConnectionDisconnect`, `Frame { frame, cid }`, `Error`, `Ok`.
- Errors back to web use `WebControlMessage::Error` with kinds `Generic`, `RequiresPassword`.

## HTTP endpoints (server)

- `GET /api/web/ws` and `GET /api/nodes/ws`: WebSocket upgrades for web clients and nodes.
- `POST /api/nodes/claim`: PAT bootstrap endpoint (requires `Authorization: Bearer pat_*` with scope `server:register`).
- `POST /api/nodes/auth/challenge`: returns a one-time challenge for `node_id`.
- `POST /api/nodes/auth/verify`: verifies Ed25519 signature and returns short-lived node JWT.
- `POST /api/nodes/heartbeat`: JWT-protected node heartbeat endpoint.
- `GET /api/nodes`: connected nodes with last heartbeat and stats.
- `GET /api/connections`: active web connections.
- `GET /stats`: server process stats plus counts of nodes/connections.
- `GET /version`: workspace version string.

## Configuration

Server env (defaults): `APP_MODE=development|production`, `IP_SOURCE=ConnectInfo|XForwardedFor|Forwarded`, `HOST=0.0.0.0`, `PORT=8080`, `FQDN=localhost`, `ACCESS_CONTROL_ALLOW_ORIGIN`, `DATABASE_URL`, `DATABASE_MAX_CONNECTIONS=5`, `REDIS_DATABASE_URL`, `JWT_SECRET`, `NODE_JWT_TTL_SECS=300`, `NODE_CHALLENGE_TTL_SECS=60`.

Agent env (defaults): `APP_MODE=development|production`, `HOST=0.0.0.0`, `PORT=8081`, `STATS_REFRESH_INTERVAL=30`, `PING_INTERVAL=30`, `SERVER_HOST=api.phirepass.com`, `SERVER_PORT=443`, `SSH_HOST=localhost`, `SSH_PORT=22`, `SSH_AUTH_METHOD=password`, `SSH_INACTIVITY_PERIOD=3600`.

## Agent login

The agent uses PAT only for bootstrap. During `login`, it:
- calls `/api/nodes/claim` with PAT,
- generates and stores a local Ed25519 keypair,
- stores `node_id` + key material locally.

At runtime, the agent uses challenge-sign-verify to obtain a short-lived JWT and authenticates websocket with that JWT.

PAT input modes for `login`:

- **Interactive prompt** (default): `phirepass-agent login` — prompts for the token interactively.
- **File input**: `phirepass-agent login --from-file /path/to/token` — reads the token from a file (recommended for Kubernetes/Docker secrets).
- **Stdin input**: `phirepass-agent login --from-stdin` — reads the token from stdin (recommended for Docker).

### Docker usage

To run the agent in Docker with token passed via stdin or environment variable:

```bash
# Via stdin
echo "$AGENT_TOKEN" | docker run -i phirepass-agent:latest login --from-stdin

# Via mounted secret file
docker run -v /run/secrets/agent_token:/token phirepass-agent:latest login --from-file /token

# Using Docker Compose with environment variable
services:
  agent:
    image: phirepass-agent:latest
    stdin_open: true
    environment:
      - AGENT_TOKEN=your-token-here
    command: sh -c 'echo $$AGENT_TOKEN | /app/agent login --from-stdin && /app/agent start'
```

By default, the container runs `login --from-stdin`, which reads the PAT and then starts the agent.

## Local development

- Build everything: `cargo build --all` (or `make build`); release: `make prod`.
- Run server: `make server` (binds `0.0.0.0:8080`, uses `RUST_LOG=info`).
- Run a node on the same box: `SSH_USER=$USER make agent` (connects back to the server, opens SSH to `SSH_HOST:SSH_PORT`).
- WASM client (optional): requires `wasm-pack`; `make wasm-dev` or `make wasm-prod` builds `channel/pkg`, `make web` serves the static demo with `http-server` on `:8083`.
- Formatting: `make format`.

## Current gaps and notes

- Node runtime authentication is challenge-response with short-lived JWT; websocket auth requires a valid node JWT.
- Node identity metadata/challenges are persisted in Postgres; connection presence is tracked in memory/Redis.
- Rate limiting for `/api/nodes/claim`, `/api/nodes/auth/challenge`, and `/api/nodes/auth/verify` is enforced at the load balancer layer.
- Open tasks live in `TASKS.md` (UI, OAuth device flow, PAT revocation, packaging).

## Directory map

- `server/`: axum HTTP and WebSocket bridge, connection/node registries, metrics.
- `agent/`: reconnecting WebSocket client, SSH tunnel management, optional HTTP `/version`.
- `common/`: protocol types, stats gathering, logging helpers, env mode.
- `channel/`: browser channel helper and demo assets (served via `make web`).
- `Makefile`: convenience targets for running, building, Docker images, and wasm artifacts.

## Database schema

```sql
-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.users (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  created_at timestamp with time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc'::text),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc'::text),
  provider text NOT NULL,
  email text NOT NULL UNIQUE,
  password text,
  username text NOT NULL,
  avatar_url text NOT NULL,
  roles text[] NOT NULL DEFAULT '{user}'::text[],
  CONSTRAINT users_pkey PRIMARY KEY (id)
);
CREATE TABLE public.pat_tokens (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  token_id text NOT NULL UNIQUE,
  token_hash text NOT NULL,
  user_id uuid NOT NULL,
  name text NOT NULL DEFAULT ''::text,
  scopes text[] NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc'::text),
  expires_at timestamp with time zone,
  CONSTRAINT pat_tokens_pkey PRIMARY KEY (id),
  CONSTRAINT pat_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);
CREATE TABLE public.nodes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  name text,
  public_key text NOT NULL UNIQUE,
  hostname text NOT NULL DEFAULT ''::text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT (now() AT TIME ZONE 'utc'::text),
  last_seen timestamp with time zone,
  revoked boolean NOT NULL DEFAULT false,
  CONSTRAINT nodes_pkey PRIMARY KEY (id),
  CONSTRAINT nodes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);
CREATE TABLE public.auth_challenges (
  node_id uuid NOT NULL,
  challenge text NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  CONSTRAINT auth_challenges_pkey PRIMARY KEY (node_id),
  CONSTRAINT auth_challenges_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE
);

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.schedule(
   'phirepass-auth-challenge-cleanup',
   '* * * * *', -- every minute
   $$DELETE FROM auth_challenges WHERE expires_at <= NOW();$$
);
```
