use crate::protocol::sftp::{
    SFTPDelete, SFTPDownloadChunk, SFTPDownloadStart, SFTPUploadChunk, SFTPUploadStart,
};
use crate::protocol::web::WebFrameData;
use crate::stats::Stats;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WebFrameId {
    SessionId(u32),
    ConnectionId(Uuid),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum NodeFrameData {
    Heartbeat {
        stats: Stats,
        sent_at: u64,
    },

    HeartbeatAck {
        sent_at: u64,
        received_at: u64,
    },

    /// agent has already logged in and acquired a token and a node_id,
    /// and it sends this request to validate
    Auth {
        token: String,
        node_id: Uuid,
        version: String,
    },

    /// server must validate the token again and again and respond
    AuthResponse {
        node_id: Uuid,
        success: bool,
        version: String,
    },

    OpenTunnel {
        protocol: u8,
        cid: Uuid,
        username: Option<String>,
        password: Option<String>,
        msg_id: Option<u32>, // custom web user supplied. easier to track responses and map them to requests
    },

    TunnelOpened {
        protocol: u8,
        cid: Uuid,
        sid: u32,            // tunnel session id. exists only after we have a tunnel opened
        msg_id: Option<u32>, // custom web user supplied. easier to track responses and map them to requests
    },

    TunnelData {
        protocol: u8,
        cid: Uuid,
        sid: u32,
        data: Bytes,
    },

    TunnelClosed {
        protocol: u8,
        cid: Uuid,
        sid: u32,
        msg_id: Option<u32>, // echo back the user supplied msg_id
    }, // notify web that the tunnel is closed

    SSHWindowResize {
        cid: Uuid,
        sid: u32,
        cols: u32,
        rows: u32,
    },

    SFTPList {
        cid: Uuid,
        path: String,
        sid: u32,
        msg_id: Option<u32>, // echo back the user supplied msg_id
    },

    SFTPDownloadStart {
        cid: Uuid,
        sid: u32,
        msg_id: Option<u32>,
        download: SFTPDownloadStart,
    },

    SFTPDownloadChunkRequest {
        cid: Uuid,
        sid: u32,
        msg_id: Option<u32>,
        download_id: u32,
        chunk_index: u32,
    },

    SFTPDownloadChunk {
        cid: Uuid,
        sid: u32,
        msg_id: Option<u32>,
        chunk: SFTPDownloadChunk,
    },

    SFTPUploadStart {
        cid: Uuid,
        sid: u32,
        msg_id: Option<u32>,
        upload: SFTPUploadStart,
    },

    SFTPUpload {
        cid: Uuid,
        sid: u32,
        msg_id: Option<u32>,
        chunk: SFTPUploadChunk,
    },

    SFTPDelete {
        cid: Uuid,
        sid: u32,
        msg_id: Option<u32>,
        data: SFTPDelete,
    },

    WebFrame {
        frame: WebFrameData,
        id: WebFrameId,
    },

    ConnectionDisconnect {
        cid: Uuid,
    },
}

impl NodeFrameData {
    pub fn code(&self) -> u8 {
        match self {
            NodeFrameData::Heartbeat { .. } => 1,
            NodeFrameData::HeartbeatAck { .. } => 2,
            NodeFrameData::Auth { .. } => 10,
            NodeFrameData::AuthResponse { .. } => 11,
            NodeFrameData::OpenTunnel { .. } => 20,
            NodeFrameData::TunnelOpened { .. } => 21,
            NodeFrameData::TunnelData { .. } => 22,
            NodeFrameData::TunnelClosed { .. } => 23,
            NodeFrameData::SSHWindowResize { .. } => 30,
            NodeFrameData::SFTPList { .. } => 31,
            NodeFrameData::SFTPDownloadStart { .. } => 32,
            NodeFrameData::SFTPDownloadChunkRequest { .. } => 33,
            NodeFrameData::SFTPDownloadChunk { .. } => 34,
            NodeFrameData::SFTPUploadStart { .. } => 35,
            NodeFrameData::SFTPUpload { .. } => 36,
            NodeFrameData::SFTPDelete { .. } => 37,
            NodeFrameData::WebFrame { .. } => 50,
            NodeFrameData::ConnectionDisconnect { .. } => 60,
        }
    }
}
