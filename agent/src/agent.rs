use crate::creds::{StoredState, TokenStore};
use crate::env::Env;
use crate::http::{AppState, get_version};
use crate::ws;
use anyhow::Context;
use axum::Router;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use log::{debug, info, warn};
use phirepass_common::stats::Stats;
use phirepass_common::token::mask_after_10;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::signal;
use tokio::sync::broadcast;
use uuid::Uuid;

pub(crate) async fn start(config: Env) -> anyhow::Result<()> {
    info!("running server on {} mode", config.mode);

    let stats_refresh_interval = config.stats_refresh_interval;
    let (shutdown_tx, _) = broadcast::channel(1);

    let state = AppState::new(Arc::new(config));
    let ws_task = start_ws_connection(&state, shutdown_tx.subscribe());
    let http_task = start_http_server(state, shutdown_tx.subscribe());
    let stats_task = spawn_stats_logger(stats_refresh_interval as u64, shutdown_tx.subscribe());

    let shutdown_signal = async {
        if let Err(err) = signal::ctrl_c().await {
            warn!("failed to listen for shutdown signal: {}", err);
        } else {
            info!("ctrl+c pressed, shutting down");
        }
    };

    tokio::select! {
        _ = ws_task => warn!("ws task ended"),
        _ = http_task => warn!("http task ended"),
        _ = stats_task => warn!("stats logger task ended"),
        _ = shutdown_signal => info!("shutdown signal received"),
    }

    let _ = shutdown_tx.send(());

    info!("waiting for tasks to shut down gracefully...");
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(())
}

pub(crate) async fn login(
    server_host: String,
    server_port: u16,
    file: Option<PathBuf>,
    from_stdin: bool,
) -> anyhow::Result<()> {
    let server_host = server_host
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_host.as_str());
    info!("logging in with {server_host}:{server_port}");

    let pat = if let Some(file_path) = file {
        info!("reading token from file: {}", file_path.display());
        if !file_path.exists() {
            return Err(anyhow::anyhow!("file does not exist"));
        }

        let token = fs::read_to_string(&file_path).await?;
        token.trim().to_string()
    } else if from_stdin {
        info!("reading token from stdin");
        let mut token = String::new();
        use std::io::Read;
        std::io::stdin().read_to_string(&mut token)?;
        token.trim().to_string()
    } else {
        rpassword::prompt_password("Enter authentication token: ")?
    };

    bootstrap_identity(server_host, server_port, pat.as_str()).await
}

pub(crate) async fn save_token(
    server_host: &str,
    server_port: u16,
    token: &str,
) -> anyhow::Result<()> {
    info!("saving token for {}:{}", server_host, server_port);

    let server_host = server_host
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_host);

    debug!("token to save: {}", mask_after_10(token));
    debug!("server host: {}, server port: {}", server_host, server_port);

    bootstrap_identity(server_host, server_port, token.trim()).await
}

pub(crate) fn load_creds_for_server(server_host: &str) -> Option<(String, StoredState)> {
    let ts = TokenStore::new("phirepass", "agent", server_host).ok()?;

    match ts.load() {
        Ok(state) => Some((server_host.to_string(), state)),
        Err(err) => {
            warn!("failed to load node identity: {}", err);
            None
        }
    }
}

pub(crate) async fn logout(server_host: String, server_port: u16) -> anyhow::Result<()> {
    let _ = server_port;

    let ts = TokenStore::new("phirepass", "agent", server_host.as_str())?;
    let _ = ts
        .load()
        .context("no active login found - please login first")?;

    ts.delete().context("failed to delete local identity")?;
    info!("local identity deleted");
    println!("Successfully logged out locally.");

    Ok(())
}

fn start_http_server(
    state: AppState,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let host = format!("{}:{}", state.env.host, state.env.port);

    tokio::spawn(async move {
        let app = Router::new()
            .route("/version", get(get_version))
            .with_state(state);

        let listener = match tokio::net::TcpListener::bind(host).await {
            Ok(l) => l,
            Err(err) => {
                warn!("failed to bind http listener: {err}");
                return;
            }
        };

        match listener.local_addr() {
            Ok(addr) => info!("listening on: {}", addr),
            Err(err) => warn!("could not read local address: {err}"),
        }

        if let Err(err) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        })
        .await
        {
            warn!("http server error: {err}");
        }
    })
}

fn start_ws_connection(
    state: &AppState,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let env = Arc::clone(&state.env);
    tokio::spawn(async move {
        let mut attempt: u32 = 0;

        let server_host = env.server_host.clone();
        let server_host = env
            .server_host
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(server_host.as_str());

        loop {
            let creds_result = load_creds_for_server(server_host);

            if let Some((_, identity)) = creds_result {
                match fetch_session_jwt(&env, &identity).await {
                    Ok(session_token) => {
                        let conn = ws::WebSocketConnection::new(identity.node_id, session_token);
                        tokio::select! {
                            res = conn.connect(Arc::clone(&env)) => {
                                match res {
                                    Ok(()) => warn!("ws connection ended, attempting reconnect"),
                                    Err(err) => warn!("ws client error: {err}, attempting reconnect"),
                                }
                            }
                            _ = shutdown.recv() => {
                                info!("ws connection shutting down");
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        warn!("failed to obtain node session token: {err}");
                    }
                }
            } else {
                warn!("node identity not found");
                info!("please login first");
            }

            attempt = attempt.saturating_add(1);
            let backoff_secs = 2u64.saturating_pow(attempt.min(4));
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {},
                _ = shutdown.recv() => {
                    info!("ws connection shutting down");
                    break;
                }
            }
        }
    })
}

#[derive(Debug, Deserialize)]
struct ClaimResponse {
    node_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    access_token: String,
}

#[derive(Debug)]
struct LocalIdentity {
    private_key: String,
    public_key: String,
}

fn generate_identity() -> LocalIdentity {
    let mut rng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut rng);

    let private_key = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

    LocalIdentity {
        private_key,
        public_key,
    }
}

fn local_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn generate_http_endpoint(server_host: &str, server_port: u16) -> String {
    let server_host = server_host
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_host);

    let scheme = match server_port {
        443 | 8443 => "https",
        _ => "http",
    };

    if matches!(server_port, 80 | 443 | 8443) {
        format!("{}://{}", scheme, server_host)
    } else {
        format!("{}://{}:{}", scheme, server_host, server_port)
    }
}

async fn bootstrap_identity(
    server_host: &str,
    server_port: u16,
    pat_token: &str,
) -> anyhow::Result<()> {
    info!("token found: {}", mask_after_10(pat_token));

    let username = whoami::username()?;
    let ts = TokenStore::new("phirepass", "agent", server_host)?;

    // Reuse existing identity for the same server so relogin does not create stale node rows.
    let identity = match ts.load() {
        Ok(stored) => {
            info!("reusing existing local node identity for {}", server_host);
            LocalIdentity {
                private_key: stored.private_key,
                public_key: stored.public_key,
            }
        }
        Err(err) => {
            info!("no reusable local identity found: {err}; generating a new one");
            generate_identity()
        }
    };
    let hostname = local_hostname();

    let client = reqwest::Client::new();
    let base_url = generate_http_endpoint(server_host, server_port);

    let claim: ClaimResponse = post_with_pat(
        &client,
        &format!("{}/api/nodes/claim", base_url),
        pat_token,
        &json!({
            "public_key": identity.public_key,
            "hostname": hostname,
            "metadata": {
                "agent_version": crate::env::version(),
                "user": username,
            }
        }),
    )
    .await
    .context("failed to claim node identity")?;

    ts.save_identity(claim.node_id, identity.private_key, identity.public_key)
        .context("failed to persist local node identity")?;

    info!(
        "node identity bootstrap complete; node_id={}",
        claim.node_id
    );
    Ok(())
}

async fn fetch_session_jwt(env: &Env, state: &StoredState) -> anyhow::Result<SecretString> {
    let base_url = generate_http_endpoint(&env.server_host, env.server_port);
    let client = reqwest::Client::new();

    let challenge: ChallengeResponse = post_json(
        &client,
        &format!("{}/api/nodes/auth/challenge", base_url),
        &json!({ "node_id": state.node_id }),
    )
    .await
    .context("failed to request auth challenge")?;

    let private_key_bytes = URL_SAFE_NO_PAD
        .decode(&state.private_key)
        .context("invalid private key encoding")?;

    let private_key_bytes: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must decode to 32 bytes"))?;

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let signature = signing_key.sign(challenge.challenge.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let verify: VerifyResponse = post_json(
        &client,
        &format!("{}/api/nodes/auth/verify", base_url),
        &json!({
            "node_id": state.node_id,
            "challenge": challenge.challenge,
            "signature": signature,
        }),
    )
    .await
    .context("failed to verify auth challenge")?;

    Ok(SecretString::from(verify.access_token))
}

async fn post_with_pat<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
    pat: &str,
    body: &serde_json::Value,
) -> anyhow::Result<T> {
    let response = client.post(url).bearer_auth(pat).json(body).send().await?;

    parse_json_response(response).await
}

async fn post_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
) -> anyhow::Result<T> {
    let response = client.post(url).json(body).send().await?;
    parse_json_response(response).await
}

async fn parse_json_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> anyhow::Result<T> {
    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();

    if !status.is_success() {
        let body = serde_json::from_str::<serde_json::Value>(&body_text)
            .unwrap_or_else(|_| json!({ "raw": body_text }));

        let error = body
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("request failed");

        anyhow::bail!("request failed ({}): {}", status, error);
    }

    let parsed = serde_json::from_str::<T>(&body_text)
        .map_err(|err| anyhow::anyhow!("failed to decode response json: {err}"))?;

    Ok(parsed)
}

fn spawn_stats_logger(
    stats_refresh_interval: u64,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(stats_refresh_interval));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Stats::refresh() calls blocking syscalls (sysinfo, netstat). Use
                    // block_in_place so the async runtime's worker threads are not stalled.
                    match tokio::task::block_in_place(Stats::refresh) {
                        Some(stats) => info!("agent stats\n{}", stats.log_line()),
                        None => warn!("stats: unable to read process metrics"),
                    }
                }
                _ = shutdown.recv() => {
                    info!("stats logger shutting down");
                    break;
                }
            }
        }
    })
}
