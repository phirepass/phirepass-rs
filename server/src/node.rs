use crate::connection::NodeConnection;
use crate::db::common::TokenRecord;
use crate::db::postgres::Database;
use crate::env;
use crate::http::AppState;
use crate::node_auth::authenticate_node_jwt;
use argon2::{PasswordHash, PasswordVerifier};
use axum::Json;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_client_ip::ClientIp;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use log::{debug, info, warn};
use phirepass_common::ip::resolve_client_ip;
use phirepass_common::protocol::common::{Frame, FrameData};
use phirepass_common::protocol::node::{NodeFrameData, WebFrameId};
use phirepass_common::protocol::web::WebFrameData;
use phirepass_common::stats::Stats;
use phirepass_common::token::extract_creds;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use uuid::Uuid;

pub(crate) async fn ws_node_handler(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let ip = resolve_client_ip(&headers, client_ip);

    debug!("All websocket headers {:?}", headers);
    debug!("Client IP {:?}", ip);
    for (name, value) in headers.iter() {
        debug!("{}: {:?}", name, value);
    }

    ws.on_upgrade(move |socket| handle_node_socket(socket, state, ip))
}

async fn wait_for_auth(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &mpsc::Sender<NodeFrameData>,
    state: &AppState,
    _ip: IpAddr,
) -> anyhow::Result<Uuid> {
    // Wait for the first message which must be Auth
    let msg = ws_rx
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("connection closed before auth"))??;

    let data = match msg {
        Message::Binary(data) => data,
        Message::Close(reason) => {
            anyhow::bail!("connection closed before auth: {:?}", reason);
        }
        _ => {
            anyhow::bail!("expected binary message for auth, got: {:?}", msg);
        }
    };

    let frame = Frame::decode(&data)?;

    let node_frame = match frame.data {
        FrameData::Node(data) => data,
        FrameData::Web(_) => {
            anyhow::bail!("expected node frame for auth, got web frame");
        }
    };

    match node_frame {
        NodeFrameData::Auth {
            token,
            node_id,
            version: _,
        } => {
            info!("auth request received for node {node_id}");

            let mut response: Option<NodeFrameData> = None;
            let mut correct_node_id = Uuid::nil();
            let mut auth_ok = false;

            if let Ok(auth) = authenticate_node_jwt(state, token.as_str()).await {
                correct_node_id = auth.node_id;
                if auth.node_id.eq(&node_id) {
                    response = Some(NodeFrameData::AuthResponse {
                        node_id: correct_node_id,
                        success: true,
                        version: env::version().to_string(),
                    });
                    auth_ok = true;
                }
            }

            if response.is_none() {
                response = Some(NodeFrameData::AuthResponse {
                    node_id: correct_node_id,
                    success: false,
                    version: env::version().to_string(),
                });
            }

            let Some(response) = response else {
                anyhow::bail!("failed to generate auth response for node {node_id}");
            };

            tx.send(response)
                .await
                .map_err(|err| anyhow::anyhow!("failed to send auth response: {err}"))?;

            if !auth_ok {
                anyhow::bail!("authentication failed for node {node_id}")
            }

            Ok(node_id)
        }
        other => {
            anyhow::bail!("expected Auth as first message, got: {:?}", other);
        }
    }
}

async fn handle_node_socket(socket: WebSocket, state: AppState, ip: IpAddr) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Bounded channel to avoid unbounded memory growth if the node socket is back-pressured.
    let (tx, mut rx) = mpsc::channel::<NodeFrameData>(256);

    // Wait for authentication as the first message
    let node_id = match wait_for_auth(&mut ws_rx, &tx, &state, ip).await {
        Ok(node_id) => node_id,
        Err(err) => {
            warn!("authentication failed from {ip}: {err}");
            let _ = ws_tx.close().await;
            return;
        }
    };

    let node_record = match state.db.get_node_by_id(&node_id).await {
        Ok(node_record) => node_record,
        Err(err) => {
            warn!("failed to load node {node_id} after auth: {err}");
            let _ = ws_tx.close().await;
            return;
        }
    };

    if let Err(err) = state
        .memory_db
        .set_node_connected(&node_record, &state.server)
    {
        warn!("failed to update node {node_id} as connected in postgres: {err}");
    }

    {
        let server_id = state.id.as_ref().clone();
        state.nodes.insert(
            node_id,
            NodeConnection::new(server_id, ip, tx.clone(), node_record),
        );
        let total = state.nodes.len();
        info!("node {node_id} ({ip}) authenticated and registered (total: {total})");
    }

    let write_task = tokio::spawn(async move {
        while let Some(node_frame) = rx.recv().await {
            let frame: Frame = node_frame.into();
            let frame = match frame.to_bytes() {
                Ok(frame) => frame,
                Err(err) => {
                    warn!("web frame error: {err}");
                    break;
                }
            };

            if let Err(err) = ws_tx.send(Message::Binary(frame.into())).await {
                warn!("failed to send frame to web connection: {}", err);
                break;
            }
        }
    });

    // Handle messages in separate function to ensure cleanup always happens
    handle_node_messages(&mut ws_rx, &state, node_id, &tx).await;

    // Always abort write task regardless of how we exited message loop
    drop(tx); // Close sender first to wake write task
    write_task.abort();
    disconnect_node(&state, node_id).await;
}

/// Handles incoming WebSocket messages. Always returns to parent for cleanup.
async fn handle_node_messages(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &AppState,
    node_id: Uuid,
    tx: &mpsc::Sender<NodeFrameData>,
) {
    while let Some(msg) = ws_rx.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(err) => {
                warn!("node web socket error: {err}");
                disconnect_node(&state, node_id).await;
                return;
            }
        };

        match msg {
            Message::Close(reason) => {
                warn!("node connection close message: {:?}", reason);
                return; // Cleanup handled by caller
            }
            Message::Binary(data) => {
                let frame = match Frame::decode(&data) {
                    Ok(frame) => frame,
                    Err(err) => {
                        warn!("received malformed frame: {err:?}");
                        break;
                    }
                };

                debug!("received frame: {frame:?}");

                let node_frame = match frame.data {
                    FrameData::Node(data) => data,
                    FrameData::Web(_) => {
                        warn!("received web frame, but expected a node frame");
                        break;
                    }
                };

                match node_frame {
                    NodeFrameData::Heartbeat { stats } => {
                        update_node_heartbeat(&state, &node_id, Some(stats)).await;
                    }
                    NodeFrameData::Auth { .. } => {
                        warn!(
                            "received Auth message after initial authentication from node {node_id}"
                        );
                    }
                    // ping from agent
                    NodeFrameData::Ping { sent_at } => {
                        let now = now_millis();
                        let latency = now.saturating_sub(sent_at);
                        debug!("ping from node {node_id}; latency={}ms", latency);
                        let pong = NodeFrameData::Pong { sent_at: now };
                        if let Err(err) = tx.send(pong).await {
                            warn!("failed to queue pong for node {node_id}: {err}");
                        } else {
                            debug!("pong response to node {node_id} sent");
                        }
                    }
                    // agent notified server that a tunnel has been opened
                    NodeFrameData::TunnelOpened {
                        protocol,
                        cid,
                        sid,
                        msg_id,
                    } => {
                        handle_tunnel_opened(&state, protocol, cid, sid, &node_id, msg_id).await;
                    }
                    // agent notified server with data for web
                    NodeFrameData::WebFrame { .. } => {
                        handle_frame_response(&state, node_frame, node_id).await;
                    }
                    // agent notified server with data for web
                    NodeFrameData::TunnelClosed {
                        protocol,
                        cid,
                        sid,
                        msg_id,
                    } => {
                        handle_tunnel_closed(&state, protocol, cid, sid, &node_id, msg_id).await;
                    }
                    o => warn!("unhandled node frame: {o:?}"),
                }
            }
            _ => {
                info!("unknown message: {:?}", msg);
            }
        }
    }
}

async fn handle_frame_response(state: &AppState, node_frame: NodeFrameData, node_id: Uuid) {
    debug!("web frame response received");

    let NodeFrameData::WebFrame { frame, id } = node_frame else {
        warn!("node frame not of webframe type");
        return;
    };

    let cid = match id {
        WebFrameId::ConnectionId(cid) => cid,
        WebFrameId::SessionId(sid) => match state.get_connection_id_by_sid(sid, node_id).await {
            Ok(client_id) => client_id,
            Err(err) => {
                warn!("error getting client id: {err}");
                return;
            }
        },
    };

    match state.notify_client_by_cid(cid, frame).await {
        Ok(_) => debug!("forwarded tunnel data to node {node_id} for client {cid}"),
        Err(_) => {} // Error already logged in notify_client_by_cid
    }
}

async fn handle_tunnel_closed(
    state: &AppState,
    protocol: u8,
    cid: Uuid,
    sid: u32,
    node_id: &Uuid,
    msg_id: Option<u32>,
) {
    debug!("handling tunnel closed for connection {cid} with session {sid}");

    let key = crate::http::TunnelSessionKey::new(*node_id, sid);
    state.tunnel_sessions.remove(&key);

    match state
        .notify_client_by_cid(
            cid,
            WebFrameData::TunnelClosed {
                protocol,
                sid,
                msg_id,
            },
        )
        .await
    {
        Ok(..) => info!("tunnel closed notification sent to web client {cid}"),
        Err(_) => {} // Error already logged in notify_client_by_cid
    }
}

async fn handle_tunnel_opened(
    state: &AppState,
    protocol: u8,
    cid: Uuid,
    sid: u32,
    node_id: &Uuid,
    msg_id: Option<u32>,
) {
    debug!("handling tunnel opened for connection {cid} with session {sid}");

    let key = crate::http::TunnelSessionKey::new(*node_id, sid);
    state.tunnel_sessions.insert(key, (cid, *node_id));

    match state
        .notify_client_by_cid(
            cid,
            WebFrameData::TunnelOpened {
                protocol,
                sid,
                msg_id,
            },
        )
        .await
    {
        Ok(..) => info!("tunnel opened notification sent to web client {cid}"),
        Err(_) => {} // Error already logged in notify_client_by_cid
    }
}

async fn disconnect_node(state: &AppState, id: Uuid) {
    if let Some((_, info)) = state.nodes.remove(&id) {
        let alive = info.node.connected_at.elapsed();
        let mut total = state.nodes.len() as u32;
        info!(
            "node {id} ({}) removed after {:.1?} (total: {})",
            info.node.ip, alive, total
        );

        if let Err(err) = state.memory_db.set_node_disconnected(&info.node_record) {
            warn!("failed to update node {id} as disconnected in postgres: {err}");
        }

        total = notify_all_clients_for_closed_tunnel(state, id).await;
        info!("notified {total} client(s) for node {id} shutdown",)
    }
}

async fn notify_all_clients_for_closed_tunnel(state: &AppState, id: Uuid) -> u32 {
    let mut count = 0u32;

    let sessions_to_close: Vec<_> = state
        .tunnel_sessions
        .iter()
        .filter(|entry| entry.key().node_id == id)
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect();

    for (key, (cid, _)) in sessions_to_close {
        state.tunnel_sessions.remove(&key);

        if let Ok(_) = state
            .notify_client_by_cid(
                cid,
                WebFrameData::TunnelClosed {
                    protocol: 0,
                    sid: key.sid,
                    msg_id: None,
                },
            )
            .await
        {
            count += 1;
            info!("tunnel closed notification sent to web client {cid} due to node disconnect");
        }
    }

    count
}

async fn update_node_heartbeat(state: &AppState, node_id: &Uuid, stats: Option<Stats>) {
    let mut info = match state.nodes.get_mut(node_id) {
        Some(info) => info,
        None => {
            warn!("node {node_id} not found");
            return;
        }
    };

    let Some(stats) = stats else {
        warn!("node {node_id} stats not found");
        return;
    };

    let Ok(extended_stats) = info.get_extended_stats() else {
        warn!("failed to encode stats");
        return;
    };

    if let Err(err) =
        state
            .memory_db
            .update_node_stats(&info.node_record, &state.server, extended_stats)
    {
        warn!("failed to update node stats for node {node_id}: {err}");
        return;
    };

    info!("node {node_id} stats updated");

    let since_last = info.node.last_heartbeat.elapsed();

    let log_line = stats.log_line();
    info.node.last_stats = Some(stats);
    info.node.last_heartbeat = SystemTime::now();

    match since_last {
        Ok(_) => {
            info!(
                "heartbeat from node {node_id} ({}) after {:.1?}; \n{}",
                info.node.ip, since_last, log_line
            );
        }
        Err(_) => {
            info!(
                "heartbeat from node {node_id} ({}); \n{}",
                info.node.ip, log_line
            );
        }
    };
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimNodeRequest {
    pub public_key: String,
    pub hostname: String,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
}

fn default_metadata() -> Value {
    Value::Object(Default::default())
}

fn unauthorized(value: serde_json::Value) -> Response {
    (StatusCode::UNAUTHORIZED, Json(value)).into_response()
}

fn bad_request(value: serde_json::Value) -> Response {
    (StatusCode::BAD_REQUEST, Json(value)).into_response()
}

fn internal_error(value: serde_json::Value) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(value)).into_response()
}

fn success(value: serde_json::Value) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

fn extract_bearer_token(headers: &HeaderMap) -> anyhow::Result<String> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| anyhow::anyhow!("missing authorization header"))?;

    let header = header
        .to_str()
        .map_err(|_| anyhow::anyhow!("invalid authorization header"))?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| anyhow::anyhow!("expected Bearer token"))?
        .trim();

    if token.is_empty() {
        anyhow::bail!("bearer token is empty")
    }

    Ok(token.to_string())
}

enum CredentialValidationError {
    Unauthorized(String),
    Internal(String),
}

async fn validate_creds(
    db: Arc<Database>,
    token_id: String,
    token_secret: String,
) -> Result<TokenRecord, CredentialValidationError> {
    info!("validating credentials against postgres");

    let token_record = match db.get_token_by_id(token_id.as_str()).await {
        Ok(record) => record,
        Err(err) => {
            warn!("database error while validating token {token_id}: {err}");
            return Err(CredentialValidationError::Internal(
                "failed to validate token".to_string(),
            ));
        }
    };

    debug!("token record {} found", token_record.id);

    if let Some(expires_at) = token_record.expires_at {
        if expires_at < Utc::now() {
            warn!("token {} expired: {:?}", token_id, token_record.expires_at);
            return Err(CredentialValidationError::Unauthorized(
                "token has expired".to_string(),
            ));
        }
    }

    debug!("token is still valid");

    let parsed_hash = match PasswordHash::new(&token_record.token_hash) {
        Ok(hash) => hash,
        Err(err) => {
            warn!("failed to parse stored password hash: {}", err);
            return Err(CredentialValidationError::Internal(
                "failed to parse stored password hash".to_string(),
            ));
        }
    };

    debug!("token hash generated");

    if let Err(e) = db
        .hasher
        .verify_password(token_secret.as_bytes(), &parsed_hash)
    {
        warn!("invalid token secret for token_id={}: {}", token_id, e);
        return Err(CredentialValidationError::Unauthorized(
            "failed to verify token".to_string(),
        ));
    }

    debug!("password verified successfully");

    Ok(token_record)
}

pub async fn claim_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ClaimNodeRequest>,
) -> impl IntoResponse {
    if payload.public_key.trim().is_empty() {
        return bad_request(json!({
            "success": false,
            "code": "BAD_REQUEST_PUBLIC_KEY_REQUIRED",
            "error": "public_key is required",
        }));
    }

    if payload.hostname.trim().is_empty() {
        return bad_request(json!({
            "success": false,
            "code": "BAD_REQUEST_HOSTNAME_REQUIRED",
            "error": "hostname is required",
        }));
    }

    let bearer = match extract_bearer_token(&headers) {
        Ok(token) => token,
        Err(err) => {
            return unauthorized(json!({
                "success": false,
                "code": "AUTH_HEADER_INVALID",
                "error": err.to_string(),
            }));
        }
    };

    let (token_id, token_secret) = match extract_creds(bearer) {
        Ok(parts) => parts,
        Err(err) => {
            return unauthorized(json!({
                "success": false,
                "code": "AUTH_TOKEN_FORMAT_INVALID",
                "error": err.to_string(),
            }));
        }
    };

    let token = match validate_creds(state.db.clone(), token_id, token_secret).await {
        Ok(token) => token,
        Err(CredentialValidationError::Unauthorized(err)) => {
            return unauthorized(json!({
                "success": false,
                "code": "AUTH_TOKEN_UNAUTHORIZED",
                "error": err,
            }));
        }
        Err(CredentialValidationError::Internal(err)) => {
            return internal_error(json!({
                "success": false,
                "code": "AUTH_TOKEN_VALIDATION_FAILED",
                "error": err,
            }));
        }
    };

    if !token.scopes.iter().any(|scope| scope == "server:register") {
        return unauthorized(json!({
            "success": false,
            "code": "AUTH_SCOPE_MISSING",
            "error": "missing required scope: server:register",
        }));
    }

    if let Some(existing) = match state
        .db
        .get_node_by_public_key(payload.public_key.trim())
        .await
    {
        Ok(result) => result,
        Err(err) => {
            warn!("failed to query node by public key: {err}");
            return internal_error(json!({
                "success": false,
                "code": "CLAIM_LOOKUP_FAILED",
                "error": "failed to check node claim",
            }));
        }
    } {
        if existing.user_id != token.user_id {
            return unauthorized(json!({
                "success": false,
                "code": "CLAIM_PUBLIC_KEY_OWNERSHIP_CONFLICT",
                "error": "public key already claimed by another user",
            }));
        }
    }

    let node = match state
        .db
        .claim_node_by_public_key(
            token.user_id,
            payload.public_key.trim(),
            payload.hostname.trim(),
            &payload.metadata,
        )
        .await
    {
        Ok(node) => node,
        Err(err) => {
            warn!("failed to claim node: {err}");
            return internal_error(json!({
                "success": false,
                "code": "CLAIM_WRITE_FAILED",
                "error": "failed to claim node",
            }));
        }
    };

    success(json!({
        "success": true,
        "node_id": node.id,
    }))
}
