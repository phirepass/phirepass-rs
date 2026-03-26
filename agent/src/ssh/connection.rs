use crate::common::{send_frame_data, send_tunnel_data};
use crate::error::{AgentError, message_error};
use crate::session::generate_session_id;
use crate::ssh::client::SSHClient;
use crate::ssh::session::SSHCommand;
use bytes::Bytes;
use log::{debug, info, warn};
use phirepass_common::protocol::Protocol;
use phirepass_common::protocol::common::Frame;
use phirepass_common::protocol::node::{NodeFrameData, WebFrameId};
use russh::client::Handle;
use russh::{ChannelMsg, Disconnect, Preferred, client, kex};
use std::borrow::Cow;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) enum SSHConfigAuth {
    UsernamePassword(String, String),
    Username(String),
}

#[derive(Clone)]
pub(crate) struct SSHConfig {
    pub host: String,
    pub port: u16,
    pub credentials: SSHConfigAuth,
    pub inactivity_timeout: Option<Duration>,
}

type HandleType = Handle<SSHClient>;

pub(crate) struct SSHConnection {
    session_id: u32,
    config: SSHConfig,
}

impl SSHConnection {
    pub fn new(config: SSHConfig) -> Self {
        let session_id = generate_session_id();
        Self { session_id, config }
    }

    pub fn get_session_id(&self) -> u32 {
        self.session_id
    }

    async fn create_client(&self) -> Result<HandleType, AgentError> {
        let ssh_config: SSHConfig = self.config.clone();

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

        let sh = SSHClient {};

        let mut client_handler =
            client::connect(config, (ssh_config.host, ssh_config.port), sh).await?;

        let auth_res = match ssh_config.credentials {
            SSHConfigAuth::UsernamePassword(username, password) => {
                client_handler
                    .authenticate_password(username, password)
                    .await
            }
            SSHConfigAuth::Username(username) => client_handler.authenticate_none(username).await,
        }?;

        if !auth_res.success() {
            return message_error::<HandleType>("SSH authentication failed");
        }

        Ok(client_handler)
    }

    pub async fn connect(
        &self,
        node_id: Uuid,
        cid: Uuid,
        tx: &Sender<Frame>,
        msg_id: Option<u32>,
        mut cmd_rx: Receiver<SSHCommand>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<u32, (WebFrameId, AgentError)> {
        debug!("connecting ssh...");

        let sid = self.get_session_id();

        send_frame_data(
            tx,
            NodeFrameData::TunnelOpened {
                protocol: Protocol::SSH as u8,
                cid,
                sid,
                msg_id,
            },
        );

        let client = self
            .create_client()
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), e))?;

        debug!("ssh connected");

        let mut channel = client
            .channel_open_session()
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::Russh(e)))?;

        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::Russh(e)))?;
        channel
            .request_shell(true)
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::Russh(e)))?;

        info!("ssh[id={sid}] tunnel opened");

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    info!("shutdown signal received for ssh tunnel {cid}");
                    break;
                }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        SSHCommand::Data(buf) => {
                            let bytes = Cursor::new(buf);
                            if let Err(err) = channel.data(bytes).await {
                                warn!("failed to send data to ssh channel {cid}: {err}");
                                break;
                            }
                        }
                        SSHCommand::Resize { cols, rows, px_width, px_height, } => {
                            if let Err(err) = channel.window_change(cols, rows, px_width, px_height).await {
                                warn!("failed to resize ssh channel {cid}: {err}");
                            }
                        }
                    }
                }
                msg = channel.wait() => {
                    let Some(msg) = msg else {
                        info!("ssh channel closed for {cid}");
                        break;
                    };

                    match msg {
                        ChannelMsg::Data { ref data } => {
                            send_tunnel_data(
                                tx,
                                sid,
                                node_id.to_string(),
                                Bytes::copy_from_slice(data),
                            )
                            .await;
                        }
                        ChannelMsg::Eof => {
                            debug!("ssh channel received EOF");
                            break;
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            warn!("ssh channel exited with status {}", exit_status);
                            if let Err(err) = channel.eof().await {
                                warn!("failed to send EOF to ssh channel: {err}");
                            }

                            break;
                        }
                        ChannelMsg::Close => {
                            debug!("ssh channel closed");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        if let Err(err) = channel.close().await {
            warn!("failed to close ssh channel for {cid}: {err}");
        }

        client
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
            .map_err(|e| (WebFrameId::SessionId(sid), AgentError::Russh(e)))?;

        Ok(sid)
    }
}
