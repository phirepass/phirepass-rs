use crate::db::common::NodeRecord;
use crate::db::common::NodeClaimRecord;
use crate::db::common::TokenRecord;
use crate::env::Env;
use anyhow::Context;
use argon2::Argon2;
use log::warn;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct Database {
    pool: Mutex<PgPool>,
    database_url: String,
    max_connections: u32,
    pub hasher: Argon2<'static>,
}

impl Database {
    pub async fn create(config: &Env) -> anyhow::Result<Self> {
        let database_url = config.database_url.clone();
        let max_connections = config.database_max_connections;
        let pool = Self::connect_pool(&database_url, max_connections)
            .await
            .context("failed to connect to pool")?;

        let argon2 = Argon2::default();

        Ok(Self {
            pool: Mutex::new(pool),
            database_url,
            max_connections,
            hasher: argon2,
        })
    }

    async fn connect_pool(database_url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
        let opts = PgConnectOptions::from_str(database_url)
            .context("failed to parse database url")?
            .statement_cache_capacity(0);

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_with(opts)
            .await
            .context("failed to connect to pooled database")?;

        Ok(pool)
    }

    async fn ensure_pool(&self) -> anyhow::Result<PgPool> {
        let pool = { self.pool.lock().await.clone() };

        if pool.is_closed() {
            warn!("postgres pool is closed, reconnecting");
            return self.reconnect_pool().await;
        }

        if let Err(err) = pool.acquire().await {
            warn!("postgres pool acquire failed, reconnecting: {err}");
            return self.reconnect_pool().await;
        }

        Ok(pool)
    }

    async fn reconnect_pool(&self) -> anyhow::Result<PgPool> {
        let new_pool = Self::connect_pool(&self.database_url, self.max_connections)
            .await
            .context("failed to reconnect to pool")?;

        let mut pool_guard = self.pool.lock().await;
        *pool_guard = new_pool.clone();

        Ok(new_pool)
    }

    pub async fn create_node_from_token(&self, token: &TokenRecord) -> anyhow::Result<NodeRecord> {
        let name = format!("node-{}", Uuid::new_v4().to_string()[..8].to_string());
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;
        let node_record = sqlx::query_as::<_, NodeRecord>(
            r#"
            INSERT INTO nodes (user_id, token_id, name)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .persistent(false)
        .bind(token.user_id)
        .bind(token.id)
        .bind(name)
        .fetch_one(&pool)
        .await
        .context("failed to create node from token")?;

        Ok(node_record)
    }

    pub async fn create_node_from_token_exclusive(
        &self,
        token: &TokenRecord,
    ) -> anyhow::Result<NodeRecord> {
        if let Ok(existing_node) = self.get_node_by_token_id(&token.id).await {
            anyhow::bail!(
                "Token is already in use by node {}. \
                 Please close the existing connection or logout first before using this token again.",
                existing_node.id
            );
        }

        self.create_node_from_token(token)
            .await
            .context("failed to create node from token exclusively")
    }

    pub async fn get_node_by_id(&self, node_id: &Uuid) -> anyhow::Result<NodeRecord> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;
        let node_record = sqlx::query_as::<_, NodeRecord>(
            r#"
            SELECT *
            FROM nodes
            WHERE id = $1
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .fetch_one(&pool)
        .await
        .context("failed to retrieve node by id")?;

        Ok(node_record)
    }

    pub async fn get_node_by_token_id(&self, token_id: &Uuid) -> anyhow::Result<NodeRecord> {
        let pool = self.ensure_pool().await?;
        let node_record = sqlx::query_as::<_, NodeRecord>(
            r#"
            SELECT *
            FROM nodes
            WHERE token_id = $1
            "#,
        )
        .persistent(false)
        .bind(token_id)
        .fetch_one(&pool)
        .await
        .context("failed to retrieve node by token id")?;

        Ok(node_record)
    }

    pub async fn get_token_by_id(&self, token_id: &str) -> anyhow::Result<TokenRecord> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;
        let token_record = sqlx::query_as::<_, TokenRecord>(
            r#"
            SELECT *
            FROM pat_tokens
            WHERE token_id = $1
            "#,
        )
        .persistent(false)
        .bind(token_id)
        .fetch_one(&pool)
        .await
        .context("failed to retrieve token by id")?;

        Ok(token_record)
    }

    pub async fn delete_node(&self, node_id: &Uuid) -> anyhow::Result<()> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;
        sqlx::query(
            r#"
            DELETE FROM nodes
            WHERE id = $1
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .execute(&pool)
        .await
        .context("failed to delete node by id")?;

        Ok(())
    }

    pub async fn get_node_by_public_key(
        &self,
        public_key: &str,
    ) -> anyhow::Result<Option<NodeClaimRecord>> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;
        let node_record = sqlx::query_as::<_, NodeClaimRecord>(
            r#"
            SELECT id, user_id, public_key, hostname, metadata, created_at, last_seen, revoked
            FROM nodes
            WHERE public_key = $1
            "#,
        )
        .persistent(false)
        .bind(public_key)
        .fetch_optional(&pool)
        .await
        .context("failed to retrieve node by public key")?;

        Ok(node_record)
    }

    pub async fn claim_node_by_public_key(
        &self,
        user_id: Uuid,
        public_key: &str,
        hostname: &str,
        metadata: &Value,
    ) -> anyhow::Result<NodeClaimRecord> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;

        let node_record = sqlx::query_as::<_, NodeClaimRecord>(
            r#"
            INSERT INTO nodes (user_id, token_id, name, public_key, hostname, metadata)
            VALUES ($1, NULL, NULL, $2, $3, $4)
            ON CONFLICT (public_key)
            DO UPDATE SET
                hostname = EXCLUDED.hostname,
                metadata = EXCLUDED.metadata
            RETURNING id, user_id, public_key, hostname, metadata, created_at, last_seen, revoked
            "#,
        )
        .persistent(false)
        .bind(user_id)
        .bind(public_key)
        .bind(hostname)
        .bind(metadata)
        .fetch_one(&pool)
        .await
        .context("failed to claim node by public key")?;

        Ok(node_record)
    }
}
