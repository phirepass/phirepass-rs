use bytes::Bytes;
use log::debug;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;

#[derive(Clone, Debug)]
pub(crate) enum SSHCommand {
    Data(Bytes),
    Resize {
        cols: u32,
        rows: u32,
        px_width: u32,
        px_height: u32,
    },
}

#[derive(Debug)]
pub(crate) struct SSHSessionHandle {
    pub stdin: Sender<SSHCommand>,
    pub stop: Option<oneshot::Sender<()>>,
}

impl SSHSessionHandle {
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
            debug!("ssh self stopped sent");
        }
    }
}
