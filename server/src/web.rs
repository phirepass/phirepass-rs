use crate::connection::WebConnection;
use crate::http::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::http::header::SEC_WEBSOCKET_PROTOCOL;
use axum_client_ip::ClientIp;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use log::{debug, info, warn};
use phirepass_common::ip::resolve_client_ip;
use phirepass_common::protocol::common::{Frame, FrameData, FrameError};
use phirepass_common::protocol::node::NodeFrameData;
use phirepass_common::protocol::web::WebFrameData;
use serde::Deserialize;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct WebJwtClaims {
    sub: String,
    #[allow(dead_code)]
    exp: usize,
    #[allow(dead_code)]
    iat: Option<usize>,
    #[allow(dead_code)]
    provider: Option<String>,
}

pub(crate) async fn ws_web_handler(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    let ip = resolve_client_ip(&headers, client_ip);

    debug!("WEB websocket headers {:?}", headers);
    debug!("WEB Client IP {:?}", ip);
    for (name, value) in headers.iter() {
        debug!("WEB {}: {:?}", name, value);
    }

    let protocols: Vec<String> = headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let ws = if !protocols.is_empty() {
        ws.protocols(protocols)
    } else {
        ws
    };

    ws.on_upgrade(move |socket| handle_web_socket(socket, state, ip))
}

async fn wait_for_auth(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &Sender<WebFrameData>,
    state: &AppState,
) -> anyhow::Result<Uuid> {
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

    let web_frame = match frame.data {
        FrameData::Web(data) => data,
        FrameData::Node(_) => {
            anyhow::bail!("expected web frame for auth, got node frame");
        }
    };

    match web_frame {
        WebFrameData::Auth {
            token,
            node_id,
            msg_id,
            version,
        } => {
            let cid = Uuid::new_v4();
            info!("authenticating connection {cid} for node {node_id} for version {version}");

            // to enable local dev
            if !cfg!(debug_assertions) {
                let claims = validate_jwt(tx, state, &token, cid, msg_id).await?;
                validate_user_node(tx, state, claims, node_id, cid, msg_id).await?;
            } else {
                warn!("authentication bypass is active (debug build) — do not use in production");
            }

            successful_auth(tx, cid, version, msg_id).await?;

            Ok(cid)
        }
        other => {
            anyhow::bail!("expected Auth as first message, got: {:?}", other);
        }
    }
}

async fn successful_auth(
    tx: &Sender<WebFrameData>,
    cid: Uuid,
    version: String,
    msg_id: Option<u32>,
) -> anyhow::Result<()> {
    info!("notifying user {cid} for successful authentication");

    tx.send(WebFrameData::AuthSuccess {
        cid,
        version,
        msg_id,
    })
    .await
    .map_err(|err| anyhow::anyhow!("failed to send auth response: {err}"))?;

    Ok(())
}

async fn validate_jwt(
    tx: &Sender<WebFrameData>,
    state: &AppState,
    token: &str,
    cid: Uuid,
    msg_id: Option<u32>,
) -> anyhow::Result<WebJwtClaims> {
    match authenticate_web_jwt(state, token).await {
        Ok(claims) => {
            info!("websocket auth succeeded for client {cid}");
            Ok(claims)
        }
        Err(err) => {
            warn!("websocket auth failed for client {cid}: {err}");
            tx.send(WebFrameData::Error {
                kind: FrameError::Authentication,
                message: "failed to validate token".to_string(),
                msg_id,
            })
            .await
            .map_err(|send_err| {
                anyhow::anyhow!("failed to send auth response after auth failure: {send_err}")
            })?;
            anyhow::bail!("web jwt authentication failed: {err}");
        }
    }
}

async fn validate_user_node(
    tx: &Sender<WebFrameData>,
    state: &AppState,
    claims: WebJwtClaims,
    node_id: String,
    cid: Uuid,
    msg_id: Option<u32>,
) -> anyhow::Result<()> {
    let user_id = Uuid::parse_str(claims.sub.as_str())
        .map_err(|err| anyhow::anyhow!("invalid jwt sub claim: {err}"))?;

    let node_id = Uuid::parse_str(node_id.as_str())
        .map_err(|err| anyhow::anyhow!("invalid node id: {err}"))?;

    let node = match state.db.get_node_by_id(&node_id).await {
        Ok(node) => node,
        Err(err) => {
            warn!("failed to load node {node_id} for client {cid}: {err}");

            tx.send(WebFrameData::Error {
                kind: FrameError::Authentication,
                message: "failed to validate node ownership".to_string(),
                msg_id,
            })
            .await
            .map_err(|send_err| {
                anyhow::anyhow!("failed to send node ownership validation error: {send_err}")
            })?;

            anyhow::bail!("failed to validate node ownership: {err}");
        }
    };

    if node.user_id != user_id {
        warn!("websocket auth failed for client {cid}: user {user_id} does not own node {node_id}");

        tx.send(WebFrameData::Error {
            kind: FrameError::Authentication,
            message: "you do not own this node".to_string(),
            msg_id,
        })
        .await
        .map_err(|send_err| {
            anyhow::anyhow!("failed to send node ownership error to client: {send_err}")
        })?;

        anyhow::bail!("user {user_id} does not own node {node_id}");
    }

    info!("websocket node ownership validated for client {cid} on node {node_id}");

    Ok(())
}

async fn handle_web_socket(socket: WebSocket, state: AppState, ip: IpAddr) {
    info!("handling web socket connection for {ip}");

    let (mut ws_tx, mut ws_rx) = socket.split();

    let (tx, mut rx) = mpsc::channel::<WebFrameData>(256);

    let cid = match wait_for_auth(&mut ws_rx, &tx, &state).await {
        Ok(uuid) => uuid,
        Err(err) => {
            warn!("authentication failed from {ip}: {err}");
            let _ = ws_tx.close().await;
            return;
        }
    };

    {
        state
            .connections
            .insert(cid, WebConnection::new(ip, tx.clone()));
        let total = state.connections.len();

        info!("connection {cid} ({ip}) established (total: {total})");

        if let Err(err) = state
            .memory_db
            .set_connection_connected(&cid, ip, &state.server)
            .await
        {
            warn!("failed to add connection {cid} to redis: {err}");
        }
    }

    let write_task = tokio::spawn(async move {
        while let Some(web_frame) = rx.recv().await {
            let frame: Frame = web_frame.into();

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

    // Handle messages in a separate function to ensure cleanup always happens
    handle_web_messages(&mut ws_rx, &state, cid).await;

    // Always abort a write task regardless of how we exited the message loop
    drop(tx); // Close sender first to wake a write task
    write_task.abort();
    disconnect_web_client(&state, &cid).await;
}

/// Handles incoming WebSocket messages. Always returns to parent for cleanup.
async fn handle_web_messages(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &AppState,
    cid: Uuid,
) {
    //
    while let Some(msg) = ws_rx.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(_) => {
                break; // handle_web_socket calls disconnect_web_client after this returns
            }
        };

        match msg {
            Message::Binary(data) => {
                let frame = match Frame::decode(&data) {
                    Ok(frame) => frame,
                    Err(err) => {
                        warn!("received malformed frame: {err}");
                        break;
                    }
                };

                let web_frame = match frame.data {
                    FrameData::Web(data) => data,
                    FrameData::Node(_) => {
                        warn!("received node frame, but expected a web frame");
                        break;
                    }
                };

                match web_frame {
                    WebFrameData::Heartbeat => {
                        update_web_heartbeat(state, &cid).await;
                    }
                    WebFrameData::Auth { .. } => {
                        // auth already handled before.
                        // any attempt to reauthenticate will result in a connection shutdown
                        // might allow this in the future
                        warn!(
                            "received auth request which is invalid if sent by web client more than once"
                        );
                        break;
                    }
                    WebFrameData::AuthSuccess { .. } => {
                        warn!("received auth success which is invalid if sent by web client");
                        break;
                    }
                    WebFrameData::OpenTunnel {
                        protocol,
                        node_id: target,
                        msg_id,
                        username,
                        password,
                    } => {
                        handle_web_open_tunnel(
                            state, cid, protocol, target, msg_id, username, password,
                        )
                        .await;
                    }
                    WebFrameData::TunnelOpened { .. } => {
                        warn!("received tunnel opened frame which is invalid if sent by user");
                        break;
                    }
                    WebFrameData::TunnelData {
                        protocol,
                        sid,
                        node_id,
                        data,
                    } => {
                        handle_web_tunnel_data(state, cid, protocol, sid, node_id, data).await;
                    }
                    WebFrameData::TunnelClosed { .. } => {
                        warn!(
                            "received tunnel closed frame which is invalid if sent by web client"
                        );
                        break;
                    }
                    WebFrameData::SSHWindowResize {
                        node_id,
                        sid,
                        cols,
                        rows,
                        px_width,
                        px_height,
                    } => {
                        handle_web_resize(
                            state, cid, sid, node_id, cols, rows, px_width, px_height,
                        )
                        .await;
                    }
                    WebFrameData::SFTPList {
                        path,
                        sid,
                        node_id,
                        msg_id,
                    } => {
                        handle_sftp_list(state, cid, sid, node_id, path, msg_id).await;
                    }
                    WebFrameData::SFTPDownloadStart {
                        sid,
                        node_id,
                        msg_id,
                        download,
                    } => {
                        handle_sftp_download_start(state, cid, sid, node_id, msg_id, download)
                            .await;
                    }
                    WebFrameData::SFTPDownloadChunkRequest {
                        sid,
                        node_id,
                        msg_id,
                        download_id,
                        chunk_index,
                    } => {
                        handle_sftp_download_chunk_request(
                            state,
                            cid,
                            sid,
                            node_id,
                            msg_id,
                            download_id,
                            chunk_index,
                        )
                        .await;
                    }
                    WebFrameData::SFTPDownloadChunk { msg_id: _, .. } => {
                        // Download chunks are sent from agent to web client, not web client to agent
                        warn!(
                            "received sftp download chunk which is invalid if sent by web client"
                        );
                        break;
                    }
                    WebFrameData::SFTPUploadStart {
                        sid,
                        node_id,
                        msg_id,
                        upload,
                    } => {
                        handle_sftp_upload_start(state, cid, sid, node_id, msg_id, upload).await;
                    }
                    WebFrameData::SFTPUpload {
                        sid,
                        node_id,
                        msg_id,
                        chunk,
                    } => {
                        handle_sftp_upload(state, cid, sid, node_id, msg_id, chunk).await;
                    }
                    WebFrameData::SFTPDelete {
                        sid,
                        node_id,
                        msg_id,
                        data,
                    } => {
                        handle_sftp_delete(state, cid, sid, node_id, msg_id, data).await;
                    }
                    WebFrameData::SFTPListItems { .. } => {
                        warn!("received sftp list items which is invalid if sent by web client");
                        break;
                    }
                    WebFrameData::SFTPUploadChunkAck { .. } => {
                        warn!(
                            "received sftp upload chunk ack which is invalid if sent by web client"
                        );
                        break;
                    }
                    WebFrameData::SFTPUploadStartResponse { .. } => {
                        warn!(
                            "received sftp upload start response which is invalid if sent by web client"
                        );
                        break;
                    }
                    WebFrameData::SFTPDownloadStartResponse { .. } => {
                        warn!(
                            "received sftp download start response which is invalid if sent by web client"
                        );
                        break;
                    }
                    WebFrameData::Error { .. } => {
                        warn!("received error frame which is invalid if sent by web client");
                        break;
                    }
                }
            }
            Message::Close(err) => {
                match err {
                    None => warn!("web client {cid} disconnected"),
                    Some(err) => warn!("web client {cid} disconnected: {:?}", err),
                }
                return; // Cleanup handled by caller
            }
            _ => {
                info!("unknown message: {:?}", msg);
            }
        }
    }
}

async fn disconnect_web_client(state: &AppState, cid: &Uuid) {
    if let Some((_, info)) = state.connections.remove(cid) {
        let alive = info.connected_at.elapsed().unwrap_or_default();
        let total = state.connections.len();

        info!(
            "web client {cid} ({}) removed after {:.1?} (total: {})",
            info.ip, alive, total
        );

        if let Err(err) = state.memory_db.set_connection_disconnected(cid).await {
            warn!("failed to remove connection {cid} from redis: {err}");
        }
    }

    notify_nodes_client_disconnect(state, cid).await;
}

async fn update_web_heartbeat(state: &AppState, cid: &Uuid) {
    if let Some(mut info) = state.connections.get_mut(cid) {
        let since_last = info
            .last_heartbeat
            .elapsed()
            .unwrap_or(Duration::from_secs(0));
        info.last_heartbeat = SystemTime::now();
        debug!(
            "heartbeat from web {cid} ({}) after {:.1?}",
            info.ip, since_last
        );
    } else {
        warn!("received heartbeat for unknown web client {cid}");
    }
}

async fn handle_web_tunnel_data(
    state: &AppState,
    cid: Uuid,
    protocol: u8,
    sid: u32,
    node_id: String,
    data: Bytes,
) {
    debug!("tunnel data received: {} bytes", data.len());

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, node_id, sid).await {
        Ok(node_id) => node_id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    if tx
        .send(NodeFrameData::TunnelData {
            cid,
            protocol,
            sid,
            data,
        })
        .await
        .is_err()
    {
        warn!("failed to forward tunnel data to node {node_id}");
    } else {
        debug!("forwarded tunnel data to node {node_id}");
    }
}

async fn handle_sftp_list(
    state: &AppState,
    cid: Uuid,
    sid: u32,
    target: String,
    path: String,
    msg_id: Option<u32>,
) {
    debug!("handle sftp list request");

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, target, sid).await {
        Ok(id) => id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    match tx
        .send(NodeFrameData::SFTPList {
            cid,
            path,
            sid,
            msg_id,
        })
        .await
    {
        Ok(_) => info!("sent sftp list to {node_id}"),
        Err(err) => warn!("failed to forward sftp list to node {node_id}: {err}"),
    }
}

async fn handle_sftp_download_start(
    state: &AppState,
    cid: Uuid,
    sid: u32,
    target: String,
    msg_id: Option<u32>,
    download: phirepass_common::protocol::sftp::SFTPDownloadStart,
) {
    debug!("handle sftp download start request");

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, target, sid).await {
        Ok(id) => id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    match tx
        .send(NodeFrameData::SFTPDownloadStart {
            cid,
            sid,
            msg_id,
            download,
        })
        .await
    {
        Ok(_) => info!("sent sftp download start request to {node_id}"),
        Err(err) => warn!("failed to forward sftp download start to node {node_id}: {err}"),
    }
}

async fn handle_sftp_download_chunk_request(
    state: &AppState,
    cid: Uuid,
    sid: u32,
    target: String,
    msg_id: Option<u32>,
    download_id: u32,
    chunk_index: u32,
) {
    debug!("handle sftp download chunk request");

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, target, sid).await {
        Ok(id) => id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    match tx
        .send(NodeFrameData::SFTPDownloadChunkRequest {
            cid,
            sid,
            msg_id,
            download_id,
            chunk_index,
        })
        .await
    {
        Ok(_) => info!("sent sftp download chunk request to {node_id}"),
        Err(err) => {
            warn!("failed to forward sftp download chunk request to node {node_id}: {err}")
        }
    }
}

async fn handle_sftp_upload_start(
    state: &AppState,
    cid: Uuid,
    sid: u32,
    target: String,
    msg_id: Option<u32>,
    upload: phirepass_common::protocol::sftp::SFTPUploadStart,
) {
    debug!("handle sftp upload start request");

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, target, sid).await {
        Ok(id) => id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    match tx
        .send(NodeFrameData::SFTPUploadStart {
            cid,
            sid,
            msg_id,
            upload,
        })
        .await
    {
        Ok(_) => debug!("sent sftp upload start to {node_id}"),
        Err(err) => warn!("failed to forward sftp upload start to node {node_id}: {err}"),
    }
}

async fn handle_sftp_upload(
    state: &AppState,
    cid: Uuid,
    sid: u32,
    target: String,
    msg_id: Option<u32>,
    chunk: phirepass_common::protocol::sftp::SFTPUploadChunk,
) {
    debug!("handle sftp upload request");

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, target, sid).await {
        Ok(id) => id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    match tx
        .send(NodeFrameData::SFTPUpload {
            cid,
            sid,
            msg_id,
            chunk,
        })
        .await
    {
        Ok(_) => debug!("sent sftp upload chunk to {node_id}"),
        Err(err) => warn!("failed to forward sftp upload to node {node_id}: {err}"),
    }
}

async fn handle_sftp_delete(
    state: &AppState,
    cid: Uuid,
    sid: u32,
    target: String,
    msg_id: Option<u32>,
    data: phirepass_common::protocol::sftp::SFTPDelete,
) {
    debug!("handle sftp delete request");

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, target, sid).await {
        Ok(id) => id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    match tx
        .send(NodeFrameData::SFTPDelete {
            cid,
            sid,
            msg_id,
            data,
        })
        .await
    {
        Ok(_) => info!("sent sftp delete request to {node_id}"),
        Err(err) => warn!("failed to forward sftp delete to node {node_id}: {err}"),
    }
}

async fn handle_web_resize(
    state: &AppState,
    cid: Uuid,
    sid: u32,
    target: String,
    cols: u32,
    rows: u32,
    px_width: u32,
    px_height: u32,
) {
    debug!("tunnel ssh resize received");

    let node_id = match state.get_node_id_by_cid_and_sid(&cid, target, sid).await {
        Ok(id) => id,
        Err(err) => {
            warn!("error getting node id: {err}");
            return;
        }
    };

    let tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = tx else {
        warn!("tx for node not found {node_id}");
        return;
    };

    match tx
        .send(NodeFrameData::SSHWindowResize {
            cid,
            sid,
            cols,
            rows,
            px_width,
            px_height,
        })
        .await
    {
        Ok(_) => debug!("sent ssh window resize to {node_id}"),
        Err(err) => warn!("failed to forward resize to node {node_id}: {err}"),
    }
}

async fn handle_web_open_tunnel(
    state: &AppState,
    cid: Uuid,
    protocol: u8,
    target: String,
    msg_id: Option<u32>,
    username: Option<String>,
    password: Option<String>,
) {
    info!("received open tunnel message protocol={protocol} node_id={target}");

    let node_id = match Uuid::parse_str(&target) {
        Ok(id) => id,
        Err(err) => {
            warn!("invalid node id {target}: {err}");
            return;
        }
    };

    let node_tx = state.nodes.get(&node_id).map(|info| info.tx.clone());

    let Some(tx) = node_tx else {
        warn!("node not found {node_id}");

        if let Err(err) = state
            .notify_client_by_cid(
                cid,
                WebFrameData::Error {
                    kind: FrameError::Generic,
                    message: format!("Node[id={}] could not be found", node_id),
                    msg_id,
                },
            )
            .await
        {
            warn!("error notifying clients by cid on node {node_id}: {err}");
        }

        return;
    };

    info!("notifying agent to open tunnel {protocol}");

    if tx
        .send(NodeFrameData::OpenTunnel {
            protocol,
            cid,
            username,
            password,
            msg_id,
        })
        .await
        .is_err()
    {
        warn!("failed to forward open tunnel to node {node_id}");
    } else {
        debug!(
            "forwarded open tunnel to node {node_id} (protocol {})",
            protocol
        );
    }
}

async fn notify_nodes_client_disconnect(state: &AppState, cid: &Uuid) {
    for entry in state.nodes.iter() {
        let (node_id, conn) = entry.pair();
        match conn
            .tx
            .send(NodeFrameData::ConnectionDisconnect { cid: *cid })
            .await
        {
            Ok(..) => info!("notified node {node_id} about client {cid} disconnect"),
            Err(err) => {
                warn!("failed to notify node {node_id} about client {cid} disconnect: {err}")
            }
        }
    }
}

async fn authenticate_web_jwt(state: &AppState, token: &str) -> anyhow::Result<WebJwtClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = ["exp".to_string()].into();

    let claims = decode::<WebJwtClaims>(
        token,
        &DecodingKey::from_secret(state.env.jwt_secret.as_bytes()),
        &validation,
    )?
    .claims;

    let user_id = Uuid::parse_str(claims.sub.as_str())
        .map_err(|err| anyhow::anyhow!("invalid jwt sub claim: {err}"))?;

    if !state.db.user_exists(&user_id).await? {
        anyhow::bail!("user not found")
    }

    Ok(claims)
}
