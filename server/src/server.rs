use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::db::postgres::Database;
use crate::db::redis::MemoryDB;
use crate::env::Env;
use crate::http::{AppState, READY, build_cors, healthz, list_connections, list_nodes, readiness};
use crate::node::{claim_node, ws_node_handler};
use crate::node_auth::{create_auth_challenge, heartbeat, require_node_jwt, verify_auth_challenge};
use crate::web::ws_web_handler;
use crate::{stun, tasks};
use anyhow::Context;
use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use dashmap::DashMap;
use log::{info, warn};
use phirepass_common::server::ServerIdentifier;
use tokio::signal;
use tokio::sync::broadcast;
use uuid::Uuid;

pub fn create_server_identifier(config: &Env, id: Uuid) -> anyhow::Result<ServerIdentifier> {
    let public_ip = stun::get_public_address().context("failed to get public address from stun")?;
    let private_ip = local_ip_address::local_ip()?.to_string();
    let fqdn = config.fqdn.clone();
    let port = config.port;
    Ok(ServerIdentifier {
        id,
        private_ip,
        public_ip,
        port,
        fqdn,
    })
}

pub async fn start(config: Env) -> anyhow::Result<()> {
    info!("running server on {} mode", config.mode);

    let id = Uuid::new_v4();
    info!("server id: {}", id);

    let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);
    info!("comms channel ready");

    let db = Database::create(&config).await?;
    info!("connected to postgres");

    let memory_db = MemoryDB::create(&config).await?;
    info!("connected to valkey");

    let server_identifier = create_server_identifier(&config, id)?;
    info!("server identifier: {:?}", server_identifier);

    let state = AppState {
        id: Arc::new(id),
        server: Arc::new(server_identifier),
        env: Arc::new(config),
        db: Arc::new(db),
        memory_db: Arc::new(memory_db),
        nodes: Arc::new(DashMap::new()),
        connections: Arc::new(DashMap::new()),
        tunnel_sessions: Arc::new(DashMap::new()),
    };

    info!("state ready");

    let server_task = spawn_server_update_task(&state, 30u64, shutdown_tx.subscribe());
    let conns_refresh_task = spawn_connections_refresh_task(&state, 30u64, shutdown_tx.subscribe());
    let stats_task = spawn_stats_log_task(&state, 60u64, shutdown_tx.subscribe());
    let http_task = start_http_server(state, shutdown_tx.subscribe());

    info!("server tasks started");

    let shutdown_signal = async {
        if let Err(err) = signal::ctrl_c().await {
            warn!("failed to listen for shutdown signal: {}", err);
        } else {
            info!("ctrl+c pressed, shutting down");
        }
    };

    info!("shutdown signal listener ready");

    READY.store(true, std::sync::atomic::Ordering::Release);

    info!("server is ready to accept connections");

    tokio::select! {
        _ = server_task => warn!("server task terminated"),
        _ = http_task => warn!("http task ended"),
        _ = stats_task => warn!("stats logger task ended"),
        _ = conns_refresh_task => warn!("connections refresh task ended"),
        _ = shutdown_signal => info!("shutdown signal received"),
    }

    info!("shutting down server");

    let _ = shutdown_tx.send(());

    Ok(())
}

fn start_http_server(
    state: AppState,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    info!("starting http server");

    let ip_source = state.env.ip_source.clone();
    let host = format!("{}:{}", state.env.host, state.env.port);

    tokio::spawn(async move {
        let cors = build_cors(&state);

        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readiness))
            .route("/api/web/ws", get(ws_web_handler))
            .route("/api/nodes/claim", post(claim_node))
            .route("/api/nodes/auth/challenge", post(create_auth_challenge))
            .route("/api/nodes/auth/verify", post(verify_auth_challenge))
            .route(
                "/api/nodes/heartbeat",
                post(heartbeat).route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_node_jwt,
                )),
            )
            .route("/api/nodes/ws", get(ws_node_handler))
            .route("/api/nodes", get(list_nodes))
            .route("/api/connections", get(list_connections))
            .layer(ip_source.into_extension())
            .layer(cors)
            .with_state(state);

        info!("listening on: {host}");

        let listener = match tokio::net::TcpListener::bind(host).await {
            Ok(listener) => listener,
            Err(err) => {
                warn!("error listening on host: {err}");
                return;
            }
        };

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        })
        .await
        .unwrap();
    })
}

fn spawn_server_update_task(
    state: &AppState,
    interval: u64,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    info!("spawning server update task");
    let state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tasks::keep_server_alive_task(&state).await;
                }
                _ = shutdown.recv() => {
                    info!("stats logger shutting down");
                    break;
                }
            }
        }
    })
}

fn spawn_stats_log_task(
    state: &AppState,
    interval: u64,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    info!("starting stats connections worker");
    let state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tasks::print_server_stats_task(&state);
                }
                _ = shutdown.recv() => {
                    info!("stats logger shutting down");
                    break;
                }
            }
        }
    })
}

fn spawn_connections_refresh_task(
    state: &AppState,
    interval: u64,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    info!("starting connections refresh worker");
    let state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tasks::refresh_connections_task(&state).await;
                }
                _ = shutdown.recv() => {
                    info!("stats logger shutting down");
                    break;
                }
            }
        }
    })
}
