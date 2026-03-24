use crate::common::send_frame_data;
use crate::error::{AgentError, message_error};
use crate::session::generate_session_id;
use crate::sftp::actions::delete::delete_file;
use crate::sftp::actions::download;
use crate::sftp::actions::list_dir::send_directory_listing;
use crate::sftp::actions::upload::{start_upload, upload_file_chunk};
use crate::sftp::client::SFTPClient;
use crate::sftp::session::SFTPCommand;
use crate::sftp::{SFTPActiveDownloads, SFTPActiveUploads};
use log::{debug, info};
use phirepass_common::protocol::Protocol;
use phirepass_common::protocol::common::Frame;
use phirepass_common::protocol::node::{NodeFrameData, WebFrameId};
use russh::client::Handle;
use russh::{Disconnect, Preferred, client, kex};
use russh_sftp::client::SftpSession;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) enum SFTPConfigAuth {
    UsernamePassword(String, String),
    Username(String),
}

#[derive(Clone)]
pub(crate) struct SFTPConfig {
    pub host: String,
    pub port: u16,
    pub credentials: SFTPConfigAuth,
    pub inactivity_timeout: Option<Duration>,
}

type HandleType = Handle<SFTPClient>;

pub(crate) struct SFTPConnection {
    session_id: u32,
    config: SFTPConfig,
}

impl SFTPConnection {
    pub fn new(config: SFTPConfig) -> Self {
        let session_id = generate_session_id();
        Self { session_id, config }
    }

    pub fn get_session_id(&self) -> u32 {
        self.session_id
    }

    async fn create_client(&self) -> Result<HandleType, AgentError> {
        let sftp_config: SFTPConfig = self.config.clone();

        let config = Arc::new(client::Config {
            inactivity_timeout: self.config.inactivity_timeout,
            preferred: Preferred {
                kex: Cow::Owned(vec![
                    kex::CURVE25519_PRE_RFC_8731,
                    kex::EXTENSION_SUPPORT_AS_CLIENT,
                ]),
                ..Default::default()
            },
            ..<_>::default()
        });

        let sh = SFTPClient {};

        let mut client_handler =
            client::connect(config, (sftp_config.host, sftp_config.port), sh).await?;

        let auth_res = match sftp_config.credentials {
            SFTPConfigAuth::UsernamePassword(username, password) => {
                client_handler
                    .authenticate_password(username, password)
                    .await
            }
            SFTPConfigAuth::Username(username) => client_handler.authenticate_none(username).await,
        }?;

        if !auth_res.success() {
            return message_error::<HandleType>("SFTP authentication failed");
        }

        Ok(client_handler)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        cid: Uuid,
        tx: &Sender<Frame>,
        msg_id: Option<u32>,
        uploads: &SFTPActiveUploads,
        downloads: &SFTPActiveDownloads,
        mut cmd_rx: Receiver<SFTPCommand>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<u32, (WebFrameId, AgentError)> {
        debug!("connecting sftp...");
        let sid = self.get_session_id();

        send_frame_data(
            tx,
            NodeFrameData::TunnelOpened {
                protocol: Protocol::SFTP as u8,
                cid,
                sid,
                msg_id,
            },
        );

        let client = self
            .create_client()
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), e))?;

        debug!("sftp connected");

        let channel = client
            .channel_open_session()
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::Russh(e)))?;

        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::Russh(e)))?;
        let stream = channel.into_stream();
        let sftp = SftpSession::new(stream)
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::RusshSFTP(e)))?;

        info!("sftp[id={sid}] tunnel opened");

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    info!("shutdown signal received for sftp tunnel {cid}");
                    break;
                }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        SFTPCommand::List(folder, msg_id) => {
                            debug!("sftp list command received for folder {folder}: {msg_id:?}");
                            send_directory_listing(tx, &sftp, &folder, sid, msg_id).await;
                        }
                        SFTPCommand::DownloadStart { download, msg_id } => {
                            debug!("sftp download start command received for {}/{}: {msg_id:?}", download.path, download.filename);
                            download::start_download(tx, &sftp, &download, cid, sid, msg_id, downloads).await;
                        }
                        SFTPCommand::DownloadChunk { chunk, msg_id } => {
                            debug!("sftp download chunk command received for download_id {}: {msg_id:?}", chunk.download_id);
                            download::download_file_chunk(tx, cid, sid, msg_id, chunk.download_id, chunk.chunk_index, downloads).await;
                        }
                        SFTPCommand::UploadStart { upload, msg_id } => {
                            debug!("sftp upload start command received for {}/{}: {msg_id:?}", upload.remote_path, upload.filename);
                            start_upload(tx, &sftp, &upload, cid, sid, msg_id, uploads).await;
                        }
                        SFTPCommand::Upload { chunk, msg_id } => {
                            debug!("sftp upload chunk command received for upload_id {}: {msg_id:?}", chunk.upload_id);
                            upload_file_chunk(tx, &sftp, &chunk, cid, sid, msg_id, uploads).await;
                        }
                        SFTPCommand::Delete { data, msg_id } => {
                            debug!("sftp delete command received for {}/{}: {msg_id:?}", data.path, data.filename);
                            delete_file(tx, &sftp, &data, cid, sid, msg_id, uploads).await;
                        }
                    }
                }
            }
        }

        client
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::Russh(e)))?;

        Ok(sid)
    }
}
