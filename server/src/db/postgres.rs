use crate::db::common::AuthChallengeRecord;
use crate::db::common::NodeClaimRecord;
use crate::db::common::NodeRecord;
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

    pub async fn get_node_by_id(&self, node_id: &Uuid) -> anyhow::Result<NodeRecord> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;
        let node_record = sqlx::query_as::<_, NodeRecord>(
            r#"
            SELECT id, user_id, hostname, created_at
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
            INSERT INTO nodes (user_id, public_key, hostname, metadata)
            VALUES ($1, $2, $3, $4)
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

    pub async fn get_node_claim_by_id(&self, node_id: &Uuid) -> anyhow::Result<NodeClaimRecord> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;

        let node_record = sqlx::query_as::<_, NodeClaimRecord>(
            r#"
            SELECT id, user_id, public_key, hostname, metadata, created_at, last_seen, revoked
            FROM nodes
            WHERE id = $1
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .fetch_one(&pool)
        .await
        .context("failed to retrieve node claim by id")?;

        Ok(node_record)
    }

    pub async fn get_node_claim_by_id_optional(
        &self,
        node_id: &Uuid,
    ) -> anyhow::Result<Option<NodeClaimRecord>> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;

        let node_record = sqlx::query_as::<_, NodeClaimRecord>(
            r#"
            SELECT id, user_id, public_key, hostname, metadata, created_at, last_seen, revoked
            FROM nodes
            WHERE id = $1
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .fetch_optional(&pool)
        .await
        .context("failed to retrieve node claim by id")?;

        Ok(node_record)
    }

    pub async fn upsert_auth_challenge(
        &self,
        node_id: &Uuid,
        challenge: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;

        sqlx::query(
            r#"
            INSERT INTO auth_challenges (node_id, challenge, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (node_id)
            DO UPDATE SET
                challenge = EXCLUDED.challenge,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .bind(challenge)
        .bind(expires_at)
        .execute(&pool)
        .await
        .context("failed to upsert auth challenge")?;

        Ok(())
    }

    pub async fn get_auth_challenge(
        &self,
        node_id: &Uuid,
        challenge: &str,
    ) -> anyhow::Result<Option<AuthChallengeRecord>> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;

        let challenge_record = sqlx::query_as::<_, AuthChallengeRecord>(
            r#"
            SELECT node_id, challenge, expires_at
            FROM auth_challenges
            WHERE node_id = $1 AND challenge = $2
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .bind(challenge)
        .fetch_optional(&pool)
        .await
        .context("failed to get auth challenge")?;

        Ok(challenge_record)
    }

    pub async fn consume_auth_challenge(
        &self,
        node_id: &Uuid,
        challenge: &str,
    ) -> anyhow::Result<()> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;

        sqlx::query(
            r#"
            DELETE FROM auth_challenges
            WHERE node_id = $1 AND challenge = $2
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .bind(challenge)
        .execute(&pool)
        .await
        .context("failed to consume auth challenge")?;

        Ok(())
    }

    pub async fn touch_node_last_seen(&self, node_id: &Uuid) -> anyhow::Result<()> {
        let pool = self.ensure_pool().await.context("failed to ensure pool")?;

        sqlx::query(
            r#"
            UPDATE nodes
            SET last_seen = NOW()
            WHERE id = $1
            "#,
        )
        .persistent(false)
        .bind(node_id)
        .execute(&pool)
        .await
        .context("failed to update node last_seen")?;

        Ok(())
    }
}
