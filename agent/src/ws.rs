use crate::common::{send_frame_data, send_requires_password_error, send_requires_username_error};
use crate::env::Env;
use crate::session::{SessionCommand, SessionHandle, TunnelSessions};
use crate::sftp::connection::{SFTPConfig, SFTPConfigAuth, SFTPConnection};
use crate::sftp::session::{SFTPCommand, SFTPSessionHandle};
use crate::sftp::{SFTPActiveDownloads, SFTPActiveUploads};
use crate::ssh::auth::SSHAuthMethod;
use crate::ssh::connection::{SSHConfig, SSHConfigAuth, SSHConnection};
use crate::ssh::session::{SSHCommand, SSHSessionHandle};
use anyhow::anyhow;
use bytes::Bytes;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use phirepass_common::env::Mode;
use phirepass_common::protocol::Protocol;
use phirepass_common::protocol::common::{Frame, FrameData, FrameError};
use phirepass_common::protocol::node::NodeFrameData;
use phirepass_common::protocol::web::WebFrameData;
use phirepass_common::stats::Stats;
use phirepass_common::time::now_millis;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::oneshot;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async, tungstenite::protocol::Message,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type WebSocketReader = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

pub(crate) struct WebSocketConnection {
    node_id: Uuid,
    token: SecretString,
    writer: Sender<Frame>,
    reader: Receiver<Frame>,
    sessions: TunnelSessions,
    uploads: SFTPActiveUploads,
    downloads: SFTPActiveDownloads,
}

fn generate_server_endpoint(mode: &Mode, server_host: &str, server_port: u16) -> String {
    let server_host = server_host
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_host);

    match mode {
        Mode::Development => {
            if server_port == 80 {
                format!("ws://{}", server_host)
            } else {
                format!("ws://{}:{}", server_host, server_port)
            }
        }
        Mode::Production => {
            if server_port == 443 {
                format!("wss://{}", server_host)
            } else {
                format!("wss://{}:{}", server_host, server_port)
            }
        }
    }
}

impl WebSocketConnection {
    pub fn new(node_id: Uuid, token: SecretString) -> Self {
        // Cap the outbound queue to avoid unbounded memory use when the socket is back-pressured.
        let (tx, rx) = channel::<Frame>(1024);
        Self {
            node_id,
            token,
            reader: rx,
            writer: tx,
            sessions: Arc::new(Default::default()),
            uploads: Arc::new(Default::default()),
            downloads: Arc::new(Default::default()),
        }
    }

    pub async fn connect(self, config: Arc<Env>) -> anyhow::Result<()> {
        info!("connecting ws...");

        let endpoint = format!(
            "{}/api/nodes/ws",
            generate_server_endpoint(&config.mode, &config.server_host, config.server_port)
        );

        info!("trying {endpoint}");

        let (stream, _) = connect_async(endpoint).await?;
        let (mut write, mut read) = stream.split();

        let node_id = self.node_id;
        let token = self.token.expose_secret().to_owned();

        let frame: Frame = NodeFrameData::Auth {
            token,
            node_id,
            version: crate::env::version().to_string(),
        }
        .into();

        write
            .send(Message::Binary(frame.to_bytes()?.into()))
            .await?;

        let (received_node_id, version) = read_auth_response(&mut read).await?;

        if node_id != received_node_id {
            error!(
                "CRITICAL: node_id mismatch. Expected: {}, Received: {}. \
                 This may indicate token corruption or server misconfiguration.",
                node_id, received_node_id
            );
            anyhow::bail!(
                "node_id mismatch: local={}, server={}",
                node_id,
                received_node_id
            )
        }

        info!(
            "agent authenticated successfully with server version {}",
            version
        );

        let mut rx = self.reader;
        let write_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if let Ok(data) = frame.to_bytes()
                    && let Err(err) = write.send(Message::Binary(data.into())).await
                {
                    warn!("failed to send frame: {err}");
                }
            }
        });

        let reader_task = spawn_reader_task(
            node_id,
            read,
            self.writer.clone(),
            Arc::clone(&config),
            Arc::clone(&self.sessions),
            Arc::clone(&self.uploads),
            Arc::clone(&self.downloads),
        )
        .await;

        let cancellation_token = CancellationToken::new();
        let heartbeat_task = spawn_heartbeat_task(
            self.writer.clone(),
            config.stats_refresh_interval as u64,
            cancellation_token.clone(),
        )
        .await;

        let ping_task = spawn_ping_task(
            self.writer.clone(),
            config.ping_interval as u64,
            cancellation_token.clone(),
        )
        .await;

        let cleanup_task = spawn_cleanup_task(
            self.uploads.clone(),
            self.downloads.clone(),
            cancellation_token.clone(),
        )
        .await;

        tokio::select! {
            _ = ping_task => warn!("ping task ended"),
            _ = write_task => warn!("write task ended"),
            _ = reader_task => warn!("read task ended"),
            _ = heartbeat_task => warn!("heartbeat task ended"),
            _ = cleanup_task => warn!("cleanup task ended"),
        }

        // Cancel background tasks to prevent them from trying to send on a closed channel
        cancellation_token.cancel();

        // close all active sessions
        info!("closing all active sessions");
        let session_keys: Vec<_> = self.sessions.iter().map(|entry| *entry.key()).collect();
        for key in session_keys {
            if let Some((_, session)) = self.sessions.remove(&key) {
                session.shutdown().await;
            }
        }

        // close all active uploads
        info!("closing all active uploads");
        let upload_keys: Vec<_> = self.uploads.iter().map(|entry| *entry.key()).collect();
        for key in upload_keys {
            if let Some((_, file_upload)) = self.uploads.remove(&key) {
                let _ = file_upload.sftp_file.sync_all().await;
            }
        }

        // close all active downloads
        info!("closing all active downloads");
        let download_keys: Vec<_> = self.downloads.iter().map(|entry| *entry.key()).collect();
        for key in download_keys {
            if let Some((_, file_download)) = self.downloads.remove(&key) {
                let _ = file_download.sftp_file.sync_all().await;
            }
        }

        Ok(())
    }
}

async fn spawn_cleanup_task(
    uploads: SFTPActiveUploads,
    downloads: SFTPActiveDownloads,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        const CLEANUP_INTERVAL: u64 = 300; // 5 minutes
        let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    crate::sftp::cleanup_abandoned_uploads(&uploads).await;
                    crate::sftp::cleanup_abandoned_downloads(&downloads).await;
                }
                _ = token.cancelled() => {
                    info!("file transfer cleanup task shutting down");
                    break;
                }
            }
        }
    })
}

async fn spawn_reader_task(
    target: Uuid,
    mut reader: WebSocketReader,
    sender: Sender<Frame>,
    config: Arc<Env>,
    sessions: TunnelSessions,
    uploads: SFTPActiveUploads,
    downloads: SFTPActiveDownloads,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(frame) = reader.next().await {
            match frame {
                Ok(Message::Binary(data)) => {
                    let frame = match Frame::decode(&data) {
                        Ok(frame) => frame,
                        Err(err) => {
                            warn!("received malformed frame: {err}");
                            return;
                        }
                    };

                    let data = match frame.data {
                        FrameData::Node(data) => data,
                        FrameData::Web(_) => {
                            warn!("received web frame, but expected a node frame");
                            return;
                        }
                    };

                    debug!("received node frame: {data:?}");

                    handle_message(
                        target, data, &sender, &config, &sessions, &uploads, &downloads,
                    )
                    .await;
                }
                Ok(Message::Close(reason)) => {
                    info!("received close message: {reason:?}");
                    break;
                }
                Err(err) => error!("error receiving frame: {err:?}"),
                _ => warn!("received unsupported socket frame"),
            }
        }
    })
}

async fn spawn_ping_task(
    sender: Sender<Frame>,
    interval: u64,
    cancellation_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let sent_at = now_millis();
                    send_frame_data(&sender, NodeFrameData::Ping { sent_at });
                }
                _ = cancellation_token.cancelled() => {
                    debug!("ping task cancelled");
                    break;
                }
            }
        }
    })
}

async fn spawn_heartbeat_task(
    sender: Sender<Frame>,
    interval: u64,
    cancellation_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let Some(stats) = Stats::get() else {
                        warn!("failed to get stats for heartbeat");
                        continue;
                    };
                    send_frame_data(&sender, NodeFrameData::Heartbeat { stats });
                }
                _ = cancellation_token.cancelled() => {
                    debug!("heartbeat task cancelled");
                    break;
                }
            }
        }
    })
}

async fn read_auth_response(reader: &mut WebSocketReader) -> anyhow::Result<(Uuid, String)> {
    match read_next_frame(reader).await {
        None => anyhow::bail!("failed to read auth response"),
        Some(frame) => {
            let NodeFrameData::AuthResponse {
                node_id,
                success,
                version,
            } = frame
            else {
                anyhow::bail!(
                    "wrong frame type, expected NodeFrameData::Auth, got {:?}",
                    frame
                )
            };

            if !success {
                anyhow::bail!("failed to authenticate node")
            }

            Ok((node_id, version))
        }
    }
}

async fn read_next_frame(reader: &mut WebSocketReader) -> Option<NodeFrameData> {
    if let Some(Ok(Message::Binary(data))) = reader.next().await {
        let frame = match Frame::decode(&data) {
            Ok(frame) => frame,
            Err(err) => {
                warn!("received malformed frame: {err}");
                return None;
            }
        };

        let node_frame = match frame.data {
            FrameData::Node(data) => data,
            FrameData::Web(_) => {
                warn!("received web frame, but expected a node frame");
                return None;
            }
        };

        info!("received node frame: {node_frame:?}");

        return Some(node_frame);
    }

    None
}

async fn handle_message(
    node_id: Uuid,
    data: NodeFrameData,
    sender: &Sender<Frame>,
    config: &Arc<Env>,
    sessions: &TunnelSessions,
    uploads: &SFTPActiveUploads,
    downloads: &SFTPActiveDownloads,
) {
    debug!("handling message: {data:?}");

    match data {
        NodeFrameData::OpenTunnel {
            protocol,
            cid,
            username,
            password,
            msg_id,
        } => {
            info!("received open tunnel with protocol {protocol}");

            if let Err(err) = ensure_credentials(sender, config, cid, &username, &password, msg_id)
            {
                warn!("credentials verification error: {err}");
                return;
            }

            info!("credentials verification succeeded");

            match Protocol::try_from(protocol) {
                Ok(Protocol::SFTP) => {
                    let auth = match config.ssh_auth_mode {
                        SSHAuthMethod::Password => SFTPConfigAuth::UsernamePassword(
                            username.expect("username validated by ensure_credentials"),
                            password.expect("password validated by ensure_credentials"),
                        ),
                        SSHAuthMethod::None => SFTPConfigAuth::Username(
                            username.expect("username validated by ensure_credentials"),
                        ),
                    };

                    start_sftp_tunnel(
                        sender, cid, config, auth, sessions, uploads, downloads, msg_id,
                    )
                    .await;
                }
                Ok(Protocol::SSH) => {
                    let auth = match config.ssh_auth_mode {
                        SSHAuthMethod::Password => SSHConfigAuth::UsernamePassword(
                            username.expect("username validated by ensure_credentials"),
                            password.expect("password validated by ensure_credentials"),
                        ),
                        SSHAuthMethod::None => SSHConfigAuth::Username(
                            username.expect("username validated by ensure_credentials"),
                        ),
                    };

                    start_ssh_tunnel(sender, node_id, cid, config, auth, sessions, msg_id).await;
                }
                Err(err) => warn!("invalid protocol value {protocol}: {err:?}"),
            }
        }
        NodeFrameData::Pong { sent_at } => {
            let now = now_millis();
            let rtt = now.saturating_sub(sent_at);
            debug!("received pong; round-trip={}ms (sent_at={sent_at})", rtt);
        }
        NodeFrameData::ConnectionDisconnect { cid } => {
            info!("received connection disconnect for {cid}");
            close_tunnels_for_cid(cid, sessions).await;
            close_uploads_for_cid(cid, uploads).await;
            close_downloads_for_cid(cid, downloads).await;
        }
        NodeFrameData::SSHWindowResize {
            cid,
            sid,
            cols,
            rows,
        } => {
            if let Err(err) = send_ssh_forward_resize(cid, sid, cols, rows, sessions).await {
                warn!("failed to forward resize: {err}");
            }
        }
        NodeFrameData::TunnelData {
            cid,
            protocol,
            sid,
            data,
        } => {
            if protocol == Protocol::SSH as u8 {
                if let Err(err) = send_ssh_tunnel_data(cid, sid, data, sessions).await {
                    warn!("failed to forward tunnel data: {err}");
                }
            } else {
                warn!("unsupported tunnel data for {protocol}: {sid:?}");
            }
        }
        NodeFrameData::SFTPList {
            cid,
            path,
            sid,
            msg_id,
        } => {
            if let Err(err) = send_sftp_list_data(cid, sid, path, sessions, msg_id).await {
                warn!("failed to forward sftp list data: {err}");
            }
        }
        NodeFrameData::SFTPUploadStart {
            cid,
            sid,
            msg_id,
            upload,
        } => {
            if let Err(err) = send_sftp_upload_start_data(cid, sid, msg_id, upload, sessions).await
            {
                warn!("failed to forward sftp upload start data: {err}");
            }
        }
        NodeFrameData::SFTPUpload {
            cid,
            sid,
            msg_id,
            chunk,
        } => {
            if let Err(err) = send_sftp_upload_data(cid, sid, msg_id, chunk, sessions).await {
                warn!("failed to forward sftp upload data: {err}");
            }
        }
        NodeFrameData::SFTPDownloadStart {
            cid,
            sid,
            msg_id,
            download,
        } => {
            if let Err(err) =
                send_sftp_download_start_data(cid, sid, msg_id, download, sessions).await
            {
                warn!("failed to forward sftp download start data: {err}");
            }
        }
        NodeFrameData::SFTPDownloadChunkRequest {
            cid,
            sid,
            msg_id,
            download_id,
            chunk_index,
        } => {
            if let Err(err) = send_sftp_download_chunk_request(
                cid,
                sid,
                msg_id,
                download_id,
                chunk_index,
                sessions,
            )
            .await
            {
                warn!("failed to handle sftp download chunk request: {err}");
            }
        }
        NodeFrameData::SFTPDownloadChunk {
            cid,
            sid,
            msg_id,
            chunk,
        } => {
            if let Err(err) = send_sftp_download_chunk_data(cid, sid, msg_id, chunk, sessions).await
            {
                warn!("failed to forward sftp download chunk data: {err}");
            }
        }
        NodeFrameData::SFTPDelete {
            cid,
            sid,
            msg_id,
            data,
        } => {
            if let Err(err) = send_sftp_delete_data(cid, sid, msg_id, data, sessions).await {
                warn!("failed to forward sftp delete data: {err}");
            }
        }
        o => warn!("not implemented yet: {o:?}"),
    }
}

async fn send_sftp_list_data(
    cid: Uuid,
    sid: u32,
    path: String,
    sessions: &TunnelSessions,
    msg_id: Option<u32>,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Sftp(stdin) = stdin else {
        anyhow::bail!(format!("no sftp tunnel found for connection {cid}"))
    };

    stdin
        .send(SFTPCommand::List(path, msg_id))
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_sftp_upload_start_data(
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    upload: phirepass_common::protocol::sftp::SFTPUploadStart,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Sftp(stdin) = stdin else {
        anyhow::bail!(format!("no sftp tunnel found for connection {cid}"))
    };

    stdin
        .send(SFTPCommand::UploadStart { upload, msg_id })
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_sftp_upload_data(
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    chunk: phirepass_common::protocol::sftp::SFTPUploadChunk,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Sftp(stdin) = stdin else {
        anyhow::bail!(format!("no sftp tunnel found for connection {cid}"))
    };

    stdin
        .send(SFTPCommand::Upload { chunk, msg_id })
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_sftp_delete_data(
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    data: phirepass_common::protocol::sftp::SFTPDelete,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Sftp(stdin) = stdin else {
        anyhow::bail!(format!("no sftp tunnel found for connection {cid}"))
    };

    stdin
        .send(SFTPCommand::Delete { data, msg_id })
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_sftp_download_start_data(
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    download: phirepass_common::protocol::sftp::SFTPDownloadStart,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Sftp(stdin) = stdin else {
        anyhow::bail!(format!("no sftp tunnel found for connection {cid}"))
    };

    stdin
        .send(SFTPCommand::DownloadStart { download, msg_id })
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_sftp_download_chunk_request(
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    download_id: u32,
    chunk_index: u32,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Sftp(stdin) = stdin else {
        anyhow::bail!(format!("no sftp tunnel found for connection {cid}"))
    };

    let chunk = phirepass_common::protocol::sftp::SFTPDownloadChunk {
        download_id,
        chunk_index,
        chunk_size: 0,
        data: Bytes::new(),
    };

    stdin
        .send(SFTPCommand::DownloadChunk { chunk, msg_id })
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_sftp_download_chunk_data(
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    chunk: phirepass_common::protocol::sftp::SFTPDownloadChunk,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Sftp(stdin) = stdin else {
        anyhow::bail!(format!("no sftp tunnel found for connection {cid}"))
    };

    stdin
        .send(SFTPCommand::DownloadChunk { chunk, msg_id })
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_ssh_tunnel_data(
    cid: Uuid,
    sid: u32,
    data: Bytes,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Ssh(stdin) = stdin else {
        anyhow::bail!(format!("no ssh tunnel found for connection {cid}"))
    };

    stdin
        .send(SSHCommand::Data(data))
        .await
        .map_err(|err| anyhow!(err))
}

async fn send_ssh_forward_resize(
    cid: Uuid,
    sid: u32,
    cols: u32,
    rows: u32,
    sessions: &TunnelSessions,
) -> anyhow::Result<()> {
    let stdin = sessions.get(&(cid, sid)).map(|s| s.get_stdin());

    let Some(stdin) = stdin else {
        anyhow::bail!(format!("no session found for connection {cid}"))
    };

    let SessionCommand::Ssh(stdin) = stdin else {
        anyhow::bail!(format!("no ssh tunnel found for connection {cid}"))
    };

    stdin
        .send(SSHCommand::Resize { cols, rows })
        .await
        .map_err(|err| anyhow!(err))
}

async fn close_downloads_for_cid(cid: Uuid, downloads: &SFTPActiveDownloads) {
    info!("closing downloads for connection {cid}");

    let keys_to_remove: Vec<(Uuid, u32)> = downloads
        .iter()
        .filter(|entry| entry.key().0.eq(&cid))
        .map(|entry| *entry.key())
        .collect();

    // Remove and cleanup each download
    for key in keys_to_remove {
        info!("removing sftp download by key {:?}", key);
        if let Some((_, file_download)) = downloads.remove(&key) {
            debug!(
                "closed sftp file for download cleanup: {}",
                file_download.filename
            );
            // FileDownload is dropped here, closing the sftp_file
        }
    }
}

async fn close_uploads_for_cid(cid: Uuid, uploads: &SFTPActiveUploads) {
    info!("closing uploads for connection {cid}");

    let keys_to_remove: Vec<(Uuid, u32)> = uploads
        .iter()
        .filter(|entry| entry.key().0.eq(&cid))
        .map(|entry| *entry.key())
        .collect();

    // Remove and shutdown each session
    for key in keys_to_remove {
        info!("removing sftp upload by key {:?}", key);
        if let Some((_, file_upload)) = uploads.remove(&key) {
            let _ = file_upload.sftp_file.sync_all().await;
        }
    }
}

async fn close_tunnels_for_cid(cid: Uuid, sessions: &TunnelSessions) {
    info!("closing tunnels for connection {cid}");

    let keys_to_remove: Vec<(Uuid, u32)> = sessions
        .iter()
        .filter(|entry| entry.key().0.eq(&cid))
        .map(|entry| *entry.key())
        .collect();

    // Remove and shutdown each session
    for key in keys_to_remove {
        info!("removing tunnel by key {:?}", key);
        if let Some((_, handle)) = sessions.remove(&key) {
            handle.shutdown().await;
        }
    }
}

fn ensure_credentials(
    sender: &Sender<Frame>,
    config: &Arc<Env>,
    cid: Uuid,
    username: &Option<String>,
    password: &Option<String>,
    msg_id: Option<u32>,
) -> anyhow::Result<()> {
    match username {
        None => {
            send_requires_username_error(sender, cid, msg_id);
            anyhow::bail!("received open tunnel without username")
        }
        Some(username) => {
            if username.trim().is_empty() {
                send_requires_username_error(sender, cid, msg_id);
                anyhow::bail!("received open tunnel without username")
            }
        }
    }

    if let SSHAuthMethod::Password = config.ssh_auth_mode {
        info!("what are we even doing here?");

        match password {
            Some(password) => {
                if password.trim().is_empty() {
                    send_requires_password_error(sender, cid, msg_id);
                    anyhow::bail!("received open tunnel without password")
                }
            }
            None => {
                send_requires_password_error(sender, cid, msg_id);
                anyhow::bail!("received open tunnel without password")
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn start_sftp_tunnel(
    tx: &Sender<Frame>,
    cid: Uuid,
    config: &Arc<Env>,
    credentials: SFTPConfigAuth,
    sessions: &TunnelSessions,
    uploads: &SFTPActiveUploads,
    downloads: &SFTPActiveDownloads,
    msg_id: Option<u32>,
) {
    let (stdin_tx, stdin_rx) = channel::<SFTPCommand>(2048);
    let (stop_tx, stop_rx) = oneshot::channel();
    let sender = tx.clone();
    let tx_for_opened = tx.clone();

    let conn = SFTPConnection::new(SFTPConfig {
        host: config.ssh_host.clone(),
        port: config.ssh_port,
        credentials,
        inactivity_timeout: config.get_ssh_inactivity_duration(),
    });

    let sid = conn.get_session_id();

    info!(
        "connecting sftp for connection {cid}: {}:{}",
        config.ssh_host, config.ssh_port
    );

    let uploads = uploads.clone();
    let downloads = downloads.clone();

    // Background task will run to completion or until stop_rx is triggered.
    // Not awaited here; cleanup is managed via the SessionHandle (stop_tx).
    let _sftp_task = tokio::spawn(async move {
        info!("sftp task started for connection {cid}");

        match conn
            .connect(
                cid, &sender, msg_id, &uploads, &downloads, stdin_rx, stop_rx,
            )
            .await
        {
            Ok(sid) => {
                info!("sftp connection {sid}:{cid} ended");
                send_frame_data(
                    &sender,
                    NodeFrameData::TunnelClosed {
                        protocol: Protocol::SFTP as u8,
                        cid,
                        sid,
                        msg_id,
                    },
                );
            }
            Err((id, err)) => {
                warn!("sftp connection error for {cid}: {err}");
                send_frame_data(
                    &tx_for_opened,
                    NodeFrameData::WebFrame {
                        id,
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: err.to_string(),
                            msg_id,
                        },
                    },
                );
            }
        }
    });

    let handle = SessionHandle::Sftp(SFTPSessionHandle {
        stop: Some(stop_tx),
        stdin: stdin_tx,
    });

    info!("sftp session handle {sid} created");

    let previous = sessions.insert((cid, sid), handle);

    if let Some(prev) = previous {
        info!("removing previous sftp session {cid}");
        prev.shutdown().await;
    }
}

async fn start_ssh_tunnel(
    tx: &Sender<Frame>,
    node_id: Uuid,
    cid: Uuid,
    config: &Arc<Env>,
    credentials: SSHConfigAuth,
    sessions: &TunnelSessions,
    msg_id: Option<u32>,
) {
    let (stdin_tx, stdin_rx) = channel::<SSHCommand>(512);
    let (stop_tx, stop_rx) = oneshot::channel();
    let sender = tx.clone();
    let tx_for_opened = tx.clone();

    let conn = SSHConnection::new(SSHConfig {
        host: config.ssh_host.clone(),
        port: config.ssh_port,
        credentials,
        inactivity_timeout: config.get_ssh_inactivity_duration(),
    });

    let sid = conn.get_session_id();

    info!(
        "connecting ssh for connection {cid}: {}:{}",
        config.ssh_host, config.ssh_port
    );

    // Background task will run to completion or until stop_rx is triggered.
    // Not awaited here; cleanup is managed via the SessionHandle (stop_tx).
    let _ssh_task = tokio::spawn(async move {
        info!("ssh task started for connection {cid}");

        match conn
            .connect(node_id, cid, &sender, msg_id, stdin_rx, stop_rx)
            .await
        {
            Ok(sid) => {
                info!("ssh connection {sid}:{cid} ended");
                send_frame_data(
                    &sender,
                    NodeFrameData::TunnelClosed {
                        protocol: Protocol::SSH as u8,
                        cid,
                        sid,
                        msg_id,
                    },
                );
            }
            Err((id, err)) => {
                warn!("ssh connection error for {cid}: {err}");
                send_frame_data(
                    &tx_for_opened,
                    NodeFrameData::WebFrame {
                        id,
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: err.to_string(),
                            msg_id,
                        },
                    },
                );
            }
        }
    });

    let handle = SessionHandle::Ssh(SSHSessionHandle {
        stop: Some(stop_tx),
        stdin: stdin_tx,
    });

    info!("ssh session handle {sid} created");

    let previous = sessions.insert((cid, sid), handle);

    if let Some(prev) = previous {
        info!("removing previous ssh session {cid}");
        prev.shutdown().await;
    }
}
