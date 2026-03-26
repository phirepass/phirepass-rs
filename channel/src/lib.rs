include!(concat!(env!("OUT_DIR"), "/version.rs"));

use bytes::Bytes;
use gloo_timers::callback::Interval;
use phirepass_common::protocol::common::Frame;
use phirepass_common::protocol::web::WebFrameData;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;
use web_sys::js_sys::Function;
use web_sys::js_sys::Uint8Array;
use web_sys::{BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket};

macro_rules! console_warn {
    ($($t:tt)*) => (warn(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn warn(s: &str);
}

#[derive(Default)]
struct ChannelState {
    socket: Option<WebSocket>,
    heartbeat: Option<Interval>,
}

#[derive(Default)]
struct ChannelClosures {
    on_open: Option<Closure<dyn FnMut()>>,
    on_message: Option<Closure<dyn FnMut(MessageEvent)>>,
    on_close: Option<Closure<dyn FnMut(CloseEvent)>>,
    on_error: Option<Closure<dyn FnMut(ErrorEvent)>>,
}

#[derive(Default)]
struct ChannelCallbacks {
    on_connection_open: Option<Function>,
    on_connection_error: Option<Function>,
    on_connection_close: Option<Function>,
    on_connection_message: Option<Function>,
    on_protocol_message: Option<Function>,
}

#[wasm_bindgen]
pub struct Channel {
    endpoint: String,
    node_id: String,
    server_id: Option<String>,
    state: Rc<RefCell<ChannelState>>,
    closures: Rc<RefCell<ChannelClosures>>,
    callbacks: Rc<RefCell<ChannelCallbacks>>,
}

impl Clone for Channel {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            node_id: self.node_id.clone(),
            server_id: self.server_id.clone(),
            state: self.state.clone(),
            closures: self.closures.clone(),
            callbacks: self.callbacks.clone(),
        }
    }
}

#[wasm_bindgen]
impl Channel {
    #[wasm_bindgen(constructor)]
    pub fn new(endpoint: String, node_id: String, server_id: Option<String>) -> Self {
        Self {
            endpoint,
            node_id,
            server_id,
            state: Rc::new(RefCell::new(ChannelState::default())),
            closures: Rc::new(RefCell::new(ChannelClosures::default())),
            callbacks: Rc::new(RefCell::new(ChannelCallbacks::default())),
        }
    }

    pub fn connect(&self) {
        let sub_protocols = match &self.server_id {
            None => self.node_id.as_str(),
            Some(server_id) => &format!("{},{}", self.node_id, server_id),
        };

        let socket = match WebSocket::new_with_str(self.endpoint.as_str(), sub_protocols) {
            Ok(ws) => ws,
            Err(err) => {
                console_warn!("{}", &format!("WebSocket init error: {err:?}"));
                return;
            }
        };

        socket.set_binary_type(BinaryType::Arraybuffer);

        {
            let mut state = self.state.borrow_mut();
            state.heartbeat = None;
            state.socket = Some(socket);
        }

        // on open

        let connected_callback = self.callbacks.borrow().on_connection_open.clone();
        let onopen = Closure::wrap(Box::new(move || {
            if let Some(cb) = connected_callback.as_ref() {
                let _ = cb.call0(&JsValue::NULL);
            }
        }) as Box<dyn FnMut()>);

        if let Some(ws) = self.state.borrow_mut().socket.as_ref() {
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        }

        // on error

        let connection_error_cb = self.callbacks.borrow().on_connection_error.clone();
        let onerror = Closure::wrap(Box::new(move |event: ErrorEvent| {
            if let Some(cb) = connection_error_cb.as_ref() {
                let _ = cb.call1(&JsValue::NULL, &JsValue::from(event));
            }
        }) as Box<dyn FnMut(ErrorEvent)>);

        if let Some(ws) = self.state.borrow_mut().socket.as_ref() {
            ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        }

        // on message
        let protocol_message_cb = self.callbacks.borrow().on_protocol_message.clone();
        let connection_message_cb = self.callbacks.borrow().on_connection_message.clone();
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            if let Some(cb) = connection_message_cb.as_ref() {
                let _ = cb.call1(&JsValue::NULL, &JsValue::from(&event));
            }
            if let Some(cb) = protocol_message_cb.as_ref() {
                handle_message(cb, &event);
            }
        }) as Box<dyn FnMut(MessageEvent)>);

        if let Some(ws) = self.state.borrow_mut().socket.as_ref() {
            ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        }

        // on close
        let connection_close_cb = self.callbacks.borrow().on_connection_close.clone();
        let onclose = Closure::wrap(Box::new(move |event: CloseEvent| {
            if let Some(cb) = connection_close_cb.as_ref() {
                let _ = cb.call1(&JsValue::NULL, &JsValue::from(event));
            }
        }) as Box<dyn FnMut(CloseEvent)>);

        if let Some(ws) = self.state.borrow_mut().socket.as_ref() {
            ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        }

        let mut closures = self.closures.borrow_mut();
        closures.on_open = Some(onopen);
        closures.on_error = Some(onerror);
        closures.on_message = Some(onmessage);
        closures.on_close = Some(onclose);
    }

    pub fn on_connection_open(&self, cb: Option<Function>) {
        self.callbacks.borrow_mut().on_connection_open = cb;
    }

    pub fn on_connection_error(&self, cb: Option<Function>) {
        self.callbacks.borrow_mut().on_connection_error = cb;
    }

    pub fn on_connection_message(&self, cb: Option<Function>) {
        self.callbacks.borrow_mut().on_connection_message = cb;
    }

    pub fn on_connection_close(&self, cb: Option<Function>) {
        self.callbacks.borrow_mut().on_connection_close = cb;
    }

    pub fn on_protocol_message(&self, cb: Option<Function>) {
        self.callbacks.borrow_mut().on_protocol_message = cb;
    }

    pub fn authenticate(&self, token: String, node_id: String, msg_id: Option<u32>) {
        self.send_frame_data(WebFrameData::Auth {
            token,
            node_id,
            version: version(),
            msg_id,
        })
    }

    pub fn stop_heartbeat(&self) {
        if let Some(interval) = self.state.borrow_mut().heartbeat.take() {
            interval.cancel();
        }

        self.state.borrow_mut().heartbeat = None;
    }

    pub fn start_heartbeat(&self, mut interval_as_millis: u32) {
        self.stop_heartbeat();

        if interval_as_millis == 0 {
            interval_as_millis = 15_000;
        }

        self.send_frame_data(WebFrameData::Heartbeat {});

        let channel = self.clone();
        let interval = Interval::new(interval_as_millis, move || {
            channel.send_frame_data(WebFrameData::Heartbeat {});
        });

        self.state.borrow_mut().heartbeat = Some(interval);
    }

    pub fn open_ssh_tunnel(
        &self,
        node_id: String,
        username: Option<String>,
        password: Option<String>,
        msg_id: Option<u32>,
    ) {
        self.send_frame_data(WebFrameData::OpenTunnel {
            protocol: Protocol::SSH as u8,
            node_id,
            username,
            password,
            msg_id,
        });
    }

    pub fn send_ssh_terminal_resize(
        &self,
        node_id: String,
        sid: u32,
        cols: u32,
        rows: u32,
        px_width: u32,
        px_height: u32,
    ) {
        self.send_frame_data(WebFrameData::SSHWindowResize {
            node_id,
            sid,
            cols,
            rows,
            px_width,
            px_height,
        });
    }

    pub fn send_ssh_tunnel_data(&self, node_id: String, sid: u32, data: String) {
        self.send_frame_data(WebFrameData::TunnelData {
            protocol: Protocol::SSH as u8,
            node_id,
            sid,
            data: Bytes::from(data.into_bytes()),
        });
    }

    pub fn open_sftp_tunnel(
        &self,
        node_id: String,
        username: Option<String>,
        password: Option<String>,
        msg_id: Option<u32>,
    ) {
        self.send_frame_data(WebFrameData::OpenTunnel {
            protocol: Protocol::SFTP as u8,
            node_id,
            username,
            password,
            msg_id,
        });
    }

    pub fn send_sftp_list_data(
        &self,
        node_id: String,
        sid: u32,
        path: String,
        msg_id: Option<u32>,
    ) {
        self.send_frame_data(WebFrameData::SFTPList {
            node_id,
            path,
            sid,
            msg_id,
        })
    }

    pub fn send_sftp_download_start(
        &self,
        node_id: String,
        sid: u32,
        path: String,
        filename: String,
        msg_id: Option<u32>,
    ) {
        let download = phirepass_common::protocol::sftp::SFTPDownloadStart { path, filename };
        self.send_frame_data(WebFrameData::SFTPDownloadStart {
            node_id,
            sid,
            msg_id,
            download,
        })
    }

    pub fn send_sftp_download_chunk(
        &self,
        node_id: String,
        sid: u32,
        download_id: u32,
        chunk_index: u32,
        msg_id: Option<u32>,
    ) {
        self.send_frame_data(WebFrameData::SFTPDownloadChunkRequest {
            node_id,
            sid,
            msg_id,
            download_id,
            chunk_index,
        })
    }

    pub fn send_sftp_upload_start(
        &self,
        node_id: String,
        sid: u32,
        filename: String,
        remote_path: String,
        total_chunks: u32,
        total_size: u64,
        msg_id: Option<u32>,
    ) {
        let upload = phirepass_common::protocol::sftp::SFTPUploadStart {
            filename,
            remote_path,
            total_chunks,
            total_size,
        };
        self.send_frame_data(WebFrameData::SFTPUploadStart {
            node_id,
            sid,
            msg_id,
            upload,
        })
    }

    pub fn send_sftp_upload_chunk(
        &self,
        node_id: String,
        sid: u32,
        upload_id: u32,
        chunk_index: u32,
        chunk_size: u32,
        data: Vec<u8>,
        msg_id: Option<u32>,
    ) {
        let chunk = phirepass_common::protocol::sftp::SFTPUploadChunk {
            upload_id,
            chunk_index,
            chunk_size,
            data: Bytes::from(data),
        };
        self.send_frame_data(WebFrameData::SFTPUpload {
            node_id,
            sid,
            msg_id,
            chunk,
        })
    }

    pub fn send_sftp_delete(
        &self,
        node_id: String,
        sid: u32,
        path: String,
        filename: String,
        msg_id: Option<u32>,
    ) {
        let data = phirepass_common::protocol::sftp::SFTPDelete { path, filename };
        self.send_frame_data(WebFrameData::SFTPDelete {
            node_id,
            sid,
            msg_id,
            data,
        })
    }

    pub fn is_connected(&self) -> bool {
        if let Some(socket) = self.state.borrow().socket.as_ref() {
            socket.ready_state() == WebSocket::OPEN
        } else {
            false
        }
    }

    pub fn is_disconnected(&self) -> bool {
        if let Some(socket) = self.state.borrow().socket.as_ref() {
            socket.ready_state() == WebSocket::CLOSED
        } else {
            false
        }
    }

    fn send_frame_data(&self, data: WebFrameData) {
        if !self.is_connected() {
            console_warn!("Cannot send raw message: socket not open");
            return;
        }

        let frame: Frame = data.into();

        match frame.to_bytes() {
            Ok(raw) => {
                if let Some(socket) = self.state.borrow().socket.as_ref()
                    && let Err(err) = socket.send_with_u8_array(raw.as_slice())
                {
                    console_warn!("{}", format!("Failed to send raw frame: {err:?}"));
                }
            }
            Err(err) => {
                console_warn!("Cannot send frame data: {err}");
            }
        }
    }

    pub fn disconnect(&self) {
        self.stop_heartbeat();
        if let Some(socket) = self.state.borrow_mut().socket.take() {
            let _ = socket.close();
        }
    }
}

#[repr(u8)]
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorType {
    Generic = 0,
    RequiresUsername = 100,
    RequiresPassword = 110,
}

#[repr(u8)]
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub enum Protocol {
    SSH = 0,
    SFTP = 1,
}

impl TryFrom<u8> for Protocol {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Protocol::SSH),
            _ => Err("Unknown protocol variant"),
        }
    }
}

fn handle_message(cb: &Function, event: &MessageEvent) {
    if let Some(text) = event.data().as_string() {
        console_warn!("received text from: {}", text);
        return;
    }

    let buffer: web_sys::js_sys::ArrayBuffer = match event.data().dyn_into() {
        Ok(buf) => buf,
        Err(err) => {
            console_warn!("error converting to array buffer: {err:?}");
            return;
        }
    };

    let view = Uint8Array::new(&buffer);
    let mut data = vec![0u8; view.length() as usize];
    view.copy_to(&mut data);

    let frame = match Frame::decode(&data) {
        Ok(frame) => frame,
        Err(err) => {
            console_warn!("received invalid frame: {err}");
            return;
        }
    };

    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);

    let js_value = match frame.serialize(&serializer) {
        Ok(msg) => msg,
        Err(err) => {
            console_warn!("error serializing frame: {}", err);
            return;
        }
    };

    let _ = cb.call1(&JsValue::NULL, &js_value);
}

#[wasm_bindgen]
pub fn version() -> String {
    VERSION.to_string()
}
