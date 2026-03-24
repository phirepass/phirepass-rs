use crate::db::postgres::Database;
use crate::env::Env;
use crate::http::AppState;
use axum::Json;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub node_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub node_id: Uuid,
    pub challenge: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub access_token: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeJwtClaims {
    node_id: Uuid,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedNode {
    pub node_id: Uuid,
}

pub async fn create_auth_challenge(
    State(state): State<AppState>,
    Json(payload): Json<ChallengeRequest>,
) -> Response {
    let challenge = generate_challenge();

    let maybe_node = match state
        .db
        .get_node_claim_by_id_optional(&payload.node_id)
        .await
    {
        Ok(node) => node,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "code": "CHALLENGE_LOOKUP_FAILED",
                    "error": "failed to create challenge"
                })),
            )
                .into_response();
        }
    };

    if let Some(node) = maybe_node
        && !node.revoked
    {
        let expires_at = Utc::now() + Duration::seconds(state.env.challenge_ttl_secs);

        if state
            .db
            .upsert_auth_challenge(&node.id, &challenge, expires_at)
            .await
            .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "code": "CHALLENGE_WRITE_FAILED",
                    "error": "failed to create challenge"
                })),
            )
                .into_response();
        }
    }

    (StatusCode::OK, Json(json!(ChallengeResponse { challenge }))).into_response()
}

pub async fn verify_auth_challenge(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Response {
    let unauthorized_verify = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "code": "AUTH_VERIFY_FAILED",
                "error": "authentication failed"
            })),
        )
            .into_response()
    };

    let node = match state.db.get_node_claim_by_id(&payload.node_id).await {
        Ok(node) => node,
        Err(_) => {
            return unauthorized_verify();
        }
    };

    if node.revoked {
        return unauthorized_verify();
    }

    let challenge_record = match state
        .db
        .get_auth_challenge(&payload.node_id, payload.challenge.trim())
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return unauthorized_verify();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "code": "AUTH_CHALLENGE_LOOKUP_FAILED",
                    "error": err.to_string()
                })),
            )
                .into_response();
        }
    };

    // Challenges are one-time: consume before cryptographic verification to limit replay attempts.
    if let Err(err) = state
        .db
        .consume_auth_challenge(&payload.node_id, payload.challenge.trim())
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "code": "AUTH_CHALLENGE_CONSUME_FAILED",
                "error": err.to_string()
            })),
        )
            .into_response();
    }

    if challenge_record.expires_at <= Utc::now() {
        return unauthorized_verify();
    }

    if let Err(err) = verify_signature(
        node.public_key.as_str(),
        payload.challenge.trim(),
        payload.signature.trim(),
    ) {
        let _ = err;
        return unauthorized_verify();
    }

    let (access_token, expires_at) = match issue_node_jwt(&state.env, payload.node_id) {
        Ok(result) => result,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "code": "AUTH_JWT_ISSUE_FAILED",
                    "error": err.to_string()
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!(VerifyResponse {
            access_token,
            expires_at,
        })),
    )
        .into_response()
}

pub async fn heartbeat(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedNode>,
) -> Response {
    if let Err(err) = state.db.touch_node_last_seen(&auth.node_id).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"success": false, "error": err.to_string()})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "node_id": auth.node_id,
            "last_seen": Utc::now(),
        })),
    )
        .into_response()
}

pub async fn require_node_jwt(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match extract_bearer_token(request.headers()) {
        Ok(token) => token,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"success": false, "error": err.to_string()})),
            )
                .into_response();
        }
    };

    let auth = match authenticate_node_jwt(&state, &token).await {
        Ok(auth) => auth,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"success": false, "error": err.to_string()})),
            )
                .into_response();
        }
    };

    request.extensions_mut().insert(auth);
    next.run(request).await
}

pub async fn authenticate_node_jwt(
    state: &AppState,
    token: &str,
) -> anyhow::Result<AuthenticatedNode> {
    authenticate_node_jwt_with(state.db.as_ref(), state.env.as_ref(), token).await
}

async fn authenticate_node_jwt_with(
    db: &Database,
    env: &Env,
    token: &str,
) -> anyhow::Result<AuthenticatedNode> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = ["exp".to_string()].into();

    let claims = decode::<NodeJwtClaims>(
        token,
        &DecodingKey::from_secret(env.jwt_secret.as_bytes()),
        &validation,
    )?
    .claims;

    let node = db.get_node_claim_by_id(&claims.node_id).await?;
    if node.revoked {
        anyhow::bail!("node is revoked")
    }

    Ok(AuthenticatedNode {
        node_id: claims.node_id,
    })
}

fn generate_challenge() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn verify_signature(public_key: &str, challenge: &str, signature: &str) -> anyhow::Result<()> {
    let pk = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|_| anyhow::anyhow!("invalid public key encoding"))?;

    let sig = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| anyhow::anyhow!("invalid signature encoding"))?;

    let pk: [u8; 32] = pk
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must decode to 32 bytes"))?;

    let verifying_key =
        VerifyingKey::from_bytes(&pk).map_err(|_| anyhow::anyhow!("invalid ed25519 public key"))?;

    let signature =
        Signature::from_slice(&sig).map_err(|_| anyhow::anyhow!("invalid ed25519 signature"))?;

    verifying_key
        .verify(challenge.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("signature verification failed"))
}

fn issue_node_jwt(env: &Env, node_id: Uuid) -> anyhow::Result<(String, chrono::DateTime<Utc>)> {
    let iat = Utc::now();
    let expires_at = iat + Duration::seconds(env.jwt_ttl_secs);

    let claims = NodeJwtClaims {
        node_id,
        exp: expires_at.timestamp() as usize,
        iat: iat.timestamp() as usize,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(env.jwt_secret.as_bytes()),
    )?;

    Ok((token, expires_at))
}

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> anyhow::Result<String> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| anyhow::anyhow!("missing authorization header"))?;

    let header = header
        .to_str()
        .map_err(|_| anyhow::anyhow!("invalid authorization header"))?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| anyhow::anyhow!("expected Bearer token"))?
        .trim();

    if token.is_empty() {
        anyhow::bail!("bearer token is empty")
    }

    Ok(token.to_string())
}
