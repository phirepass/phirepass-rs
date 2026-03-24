use crate::db::redis::MemoryDB;
use crate::env::Env;
use async_trait::async_trait;
use log::{debug, info, warn};
use phirepass_common::server::ServerIdentifier;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session, http_proxy_service};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub static READY: AtomicBool = AtomicBool::new(false);

struct WsProxy {
    memory_db: Arc<MemoryDB>,
}

struct RequestCtx {
    node_id: Option<String>,
    server_id: Option<String>,
}

/// Extracts the node ID and server ID from the `sec-websocket-protocol` header.
/// According to the project's WebSocket implementation, the node ID is expected to be the first protocol
/// and the server ID is expected to be the second protocol in the list.
fn extract_protocols(req: &RequestHeader) -> (Option<String>, Option<String>) {
    let protocols: Vec<String> = req
        .headers
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let node_id = protocols.first().cloned();
    let server_id = protocols.get(1).cloned();

    (node_id, server_id)
}

impl WsProxy {
    pub fn new(memory_db: MemoryDB) -> Self {
        Self {
            memory_db: Arc::new(memory_db),
        }
    }

    async fn get_server_by_node_id(
        &self,
        node_id: &str,
        server_id: Option<&str>,
    ) -> anyhow::Result<ServerIdentifier> {
        info!("searching for server by user node {}", node_id);

        let memory_db = self.memory_db.clone();
        let server_str: String = memory_db
            .get_user_server_by_node_id(node_id, server_id)
            .await?;

        let server = ServerIdentifier::get_decoded(server_str)?;

        info!(
            "server found: {} {} {} {}",
            server.id, server.fqdn, server.private_ip, server.port
        );

        Ok(server)
    }

    async fn handle_healthz(&self, session: &mut Session) -> Result<bool> {
        debug!("healthz handler");

        let mut header = ResponseHeader::build(200, None)?;
        header.insert_header("content-length", "0")?;

        session
            .write_response_header(Box::new(header), true)
            .await?;

        Ok(true) // stop processing
    }

    async fn handle_readyz(&self, session: &mut Session) -> Result<bool> {
        debug!("readyz handler");

        let mut header = ResponseHeader::build(200, None)?;
        header.insert_header("content-length", "0")?;

        if READY.load(Ordering::Relaxed) {
            session
                .write_response_header(Box::new(header), true)
                .await?;
        } else {
            session.respond_error(503).await?;
        };

        Ok(true) // stop processing
    }

    async fn handle_proxy_web_ws(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        // Handle ws proxy

        let req = session.req_header();
        let (node_id, server_id) = extract_protocols(req);

        if node_id.is_none() {
            warn!("sec-websocket-protocol missing or empty");
            session.respond_error(400).await?;
            return Ok(true); // stop processing
        }

        ctx.node_id = node_id;
        if let Some(node_id) = ctx.node_id.as_ref() {
            debug!("node id found: {}", node_id);
        }

        ctx.server_id = server_id;
        if let Some(server_id) = ctx.server_id.as_ref() {
            debug!("server id found: {}", server_id);
        }

        Ok(false) // proceed further, do not stop
    }
}

#[async_trait]
impl ProxyHttp for WsProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            node_id: None,
            server_id: None,
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let Some(node_id) = ctx.node_id.as_ref() else {
            warn!("node_id missing before upstream selection");
            return Err(Error::new(HTTPStatus(400)));
        };

        info!("proxying request for node_id {}", node_id);

        let server_with_node = match ctx.server_id {
            Some(ref server_id) => self.get_server_by_node_id(node_id, Some(server_id)).await,
            None => self.get_server_by_node_id(node_id, None).await,
        };

        let server = match server_with_node {
            Ok(server) => server,
            Err(err) => {
                warn!("node could not be found: {err}");
                return Err(Error::new(HTTPStatus(400)));
            }
        };

        info!("proxying request to server {}", server.id);

        let peer = HttpPeer::new((server.private_ip, server.port), false, server.fqdn);
        debug!("proxying request for peer {}", peer);

        Ok(Box::new(peer))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        debug!("request_filter");

        let path = session.req_header().uri.path();
        debug!("request path detected: {}", path);

        match path {
            "/healthz" => self.handle_healthz(session).await,
            "/readyz" => self.handle_readyz(session).await,
            "/api/web/ws" => self.handle_proxy_web_ws(session, ctx).await,
            _ => {
                session.respond_error(422).await?;
                Err(Error::new_str("Unprocessable Content"))
            }
        }
    }
}

pub fn start(config: Env) -> anyhow::Result<()> {
    info!("running server on {} mode", config.mode);

    let memory_db = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(MemoryDB::create(&config))?
    };
    info!("connected to memorydb");

    let bind_addr = format!("{}:{}", config.host, config.port);
    info!("running proxy on {}", bind_addr);

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, WsProxy::new(memory_db));
    service.add_tcp(&bind_addr);
    info!("proxy prepared");

    server.add_service(service);
    info!("proxy running forever");

    READY.store(true, Ordering::Release);

    info!("server is ready to accept connections");

    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use http::header::HeaderValue;

    #[test]
    fn extract_protocols_none_when_missing_header() {
        let req = RequestHeader::build(Method::GET, b"/", None).unwrap();
        let (node_id, server_id) = extract_protocols(&req);
        assert!(node_id.is_none());
        assert!(server_id.is_none());
    }

    #[test]
    fn extract_protocols_none_when_empty_header() {
        let mut req = RequestHeader::build(Method::GET, b"/", None).unwrap();
        req.headers
            .insert("sec-websocket-protocol", HeaderValue::from_static(""));
        let (node_id, server_id) = extract_protocols(&req);
        assert!(node_id.is_none());
        assert!(server_id.is_none());
    }

    #[test]
    fn extract_protocols_first_and_second_non_empty_tokens() {
        let mut req = RequestHeader::build(Method::GET, b"/", None).unwrap();
        req.headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(" , node-1 , server-1 , other"),
        );
        let (node_id, server_id) = extract_protocols(&req);
        assert_eq!(node_id, Some("node-1".to_string()));
        assert_eq!(server_id, Some("server-1".to_string()));
    }

    #[test]
    fn extract_protocols_with_multiple_protocols() {
        let mut req = RequestHeader::build(Method::GET, b"/", None).unwrap();
        req.headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_static("node-123,server-456"),
        );
        let (node_id, server_id) = extract_protocols(&req);
        assert_eq!(node_id, Some("node-123".to_string()));
        assert_eq!(server_id, Some("server-456".to_string()));
    }
}
