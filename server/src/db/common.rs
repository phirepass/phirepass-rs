use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct TokenRecord {
    pub id: Uuid,
    pub token_id: String,
    pub token_hash: String,
    pub user_id: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

#[derive(Debug, sqlx::FromRow, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct NodeRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

impl NodeRecord {
    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct NodeClaimRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub hostname: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub revoked: bool,
}
