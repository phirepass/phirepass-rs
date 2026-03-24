use crate::db::common::NodeRecord;
use crate::env::Env;
use anyhow::Context;
use log::debug;
use phirepass_common::server::ServerIdentifier;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

pub struct MemoryDB {
    // ConnectionManager is Arc-internally cheap to clone and is the recommended way
    // to share it across concurrent callers when the struct is behind Arc<MemoryDB>.
    manager: ConnectionManager,
}

impl MemoryDB {
    pub async fn create(config: &Env) -> anyhow::Result<Self> {
        let client = redis::Client::open(config.redis_database_url.clone())
            .context("failed to create redis client")?;

        let manager = ConnectionManager::new(client)
            .await
            .context("failed to create redis connection manager")?;

        Ok(Self { manager })
    }

    pub async fn set_node_connected(
        &self,
        node: &NodeRecord,
        server: &Arc<ServerIdentifier>,
    ) -> anyhow::Result<()> {
        self.update_node_stats(node, server, String::from(""))
            .await
            .context("failed to set node connected by updating node stats")
    }

    pub async fn save_server(
        &self,
        node_id: &Uuid,
        server_payload: &str,
        server_stats: &str,
    ) -> anyhow::Result<()> {
        let server_key = format!("phirepass:servers:{}", node_id);
        let fields_values = [("server", server_payload), ("stats", server_stats)];

        let mut conn = self.manager.clone();
        let (): () = conn.hset_multiple(&server_key, &fields_values).await?;
        let (): () = conn.expire(&server_key, 120i64).await?;

        Ok(())
    }

    pub async fn update_node_stats(
        &self,
        node: &NodeRecord,
        server: &Arc<ServerIdentifier>,
        stats_payload: String,
    ) -> anyhow::Result<()> {
        let node_payload = node.to_json()?;
        let server_payload = server.get_encoded()?;

        let node_key = format!("phirepass:users:{}:nodes:{}", node.user_id, node.id);
        let fields_values = [
            ("node", node_payload.as_str()),
            ("stats", stats_payload.as_str()),
            ("server", server_payload.as_str()),
        ];

        let mut conn = self.manager.clone();
        let (): () = conn.hset_multiple(&node_key, &fields_values).await?;
        let (): () = conn.expire(&node_key, 120i64).await?;

        Ok(())
    }

    pub async fn set_node_disconnected(&self, node: &NodeRecord) -> anyhow::Result<()> {
        let node_key = format!("phirepass:users:{}:nodes:{}", node.user_id, node.id);
        debug!("setting node disconnected by key {}", node_key);

        let mut conn = self.manager.clone();
        let (): () = conn.del(&node_key).await?;

        Ok(())
    }

    pub async fn set_connection_connected(
        &self,
        cid: &Uuid,
        ip: IpAddr,
        server: &Arc<ServerIdentifier>,
    ) -> anyhow::Result<()> {
        self.refresh_connection(cid, ip, server)
            .await
            .context("failed to set connection connected by refreshing the connection")
    }

    pub async fn set_connection_disconnected(&self, cid: &Uuid) -> anyhow::Result<()> {
        let connection_key = format!("phirepass:connections:{}", cid);
        debug!("setting connection disconnected by key {}", connection_key);

        let mut conn = self.manager.clone();
        let (): () = conn.del(&connection_key).await?;

        Ok(())
    }

    pub async fn refresh_connection(
        &self,
        cid: &Uuid,
        ip: IpAddr,
        server: &Arc<ServerIdentifier>,
    ) -> anyhow::Result<()> {
        let server_payload = server.get_encoded()?;

        let connection_key = format!("phirepass:connections:{}", cid);
        let connection_data = json!({
            "id": cid.to_string(),
            "ip": ip.to_string(),
        })
        .to_string();

        let fields_values = [
            ("connection", connection_data.as_str()),
            ("server", server_payload.as_str()),
        ];

        let mut conn = self.manager.clone();
        let (): () = conn.hset_multiple(&connection_key, &fields_values).await?;
        let (): () = conn.expire(&connection_key, 120i64).await?;

        Ok(())
    }
}
