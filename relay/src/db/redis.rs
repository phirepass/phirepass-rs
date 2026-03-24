use crate::env::Env;
use anyhow::Context;
use futures_util::StreamExt;
use log::{debug, warn};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;

pub struct MemoryDB {
    // ConnectionManager is Arc-internally inexpensive to clone and is the recommended way
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

    async fn scan_keys(&self, key: &str) -> anyhow::Result<Vec<String>> {
        let mut conn = self.manager.clone();
        let mut keys_stream: redis::AsyncIter<String> = conn.scan_match(key).await?;
        let mut keys = Vec::new();
        while let Some(key) = keys_stream.next().await {
            keys.push(key?);
        }
        Ok(keys)
    }

    async fn get_server(&self, key: &str) -> anyhow::Result<Option<String>> {
        let mut conn = self.manager.clone();
        let server: Option<String> = conn.hget(key, "server").await?;
        Ok(server)
    }

    async fn find_server_id_by_node_id(&self, node_id: &str) -> Option<String> {
        let key = format!("phirepass:users:*:nodes:{}", node_id);
        debug!("scan by key: {}", key);

        let keys = self.scan_keys(&key).await.ok()?;
        if keys.is_empty() {
            warn!("no entries found for key {}", key);
            None
        } else {
            Some(keys[0].to_owned())
        }
    }

    pub async fn get_user_server_by_node_id(
        &self,
        node_id: &str,
        server_id: Option<&str>,
    ) -> anyhow::Result<String> {
        debug!("get user server by node id: {}", node_id);

        let id = match server_id {
            Some(id) => {
                debug!("found server[id={id}] hint");
                id.to_owned()
            }
            None => {
                debug!("no server id hint found. fallback to key scanning.");
                if let Some(id) = self.find_server_id_by_node_id(node_id).await {
                    id
                } else {
                    anyhow::bail!("fail to find server by node id {}", node_id);
                }
            }
        };

        let server = self.get_server(id.as_str()).await?;
        let Some(server) = server else {
            warn!("server not found for id {}", id);
            anyhow::bail!("server not found for node {}", node_id)
        };

        Ok(server)
    }
}
