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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn test_env(jwt_ttl_secs: i64) -> Env {
        Env {
            mode: phirepass_common::env::Mode::Development,
            fqdn: "localhost".into(),
            ip_source: axum_client_ip::ClientIpSource::ConnectInfo,
            host: "127.0.0.1".into(),
            port: 8080,
            access_control_allowed_origin: None,
            database_url: "postgres://localhost/test".into(),
            database_max_connections: 1,
            redis_database_url: "redis://localhost".into(),
            jwt_secret: "test-secret-key-for-unit-tests".into(),
            jwt_ttl_secs,
            challenge_ttl_secs: 60,
        }
    }

    // ── JWT round-trip ────────────────────────────────────────────────────────

    #[test]
    fn issue_and_decode_jwt_round_trip() {
        let env = test_env(300);
        let node_id = Uuid::new_v4();
        let (token, expires_at) = issue_node_jwt(&env, node_id).unwrap();

        assert!(!token.is_empty());
        assert!(expires_at > Utc::now());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims = ["exp".to_string()].into();

        let data = decode::<NodeJwtClaims>(
            &token,
            &DecodingKey::from_secret(env.jwt_secret.as_bytes()),
            &validation,
        )
        .unwrap();

        assert_eq!(data.claims.node_id, node_id);
    }

    #[test]
    fn jwt_rejected_with_wrong_secret() {
        let env = test_env(300);
        let node_id = Uuid::new_v4();
        let (token, _) = issue_node_jwt(&env, node_id).unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims = ["exp".to_string()].into();

        let result = decode::<NodeJwtClaims>(
            &token,
            &DecodingKey::from_secret(b"wrong-secret"),
            &validation,
        );

        assert!(result.is_err());
    }

    #[test]
    fn expired_jwt_is_rejected() {
        // ttl = -120 so the token expired 2 minutes ago. We also set leeway = 0 so the test
        // does not depend on the library's default leeway window (60 s).
        let env = test_env(-120);
        let node_id = Uuid::new_v4();
        let (token, _) = issue_node_jwt(&env, node_id).unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 0;
        validation.required_spec_claims = ["exp".to_string()].into();

        let result = decode::<NodeJwtClaims>(
            &token,
            &DecodingKey::from_secret(env.jwt_secret.as_bytes()),
            &validation,
        );

        assert!(result.is_err(), "expired token should be rejected");
    }

    // ── Ed25519 signature verification ────────────────────────────────────────

    #[test]
    fn valid_signature_is_accepted() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let challenge = "test-challenge-string";
        let signature = signing_key.sign(challenge.as_bytes());

        let public_key_b64 = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        assert!(verify_signature(&public_key_b64, challenge, &signature_b64).is_ok());
    }

    #[test]
    fn tampered_challenge_fails_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let challenge = "original-challenge";
        let signature = signing_key.sign(challenge.as_bytes());

        let public_key_b64 = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        // Verify against a *different* challenge
        assert!(verify_signature(&public_key_b64, "tampered-challenge", &signature_b64).is_err());
    }

    #[test]
    fn invalid_public_key_encoding_returns_error() {
        let result = verify_signature("not-valid-base64!!!", "challenge", "signature");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid public key encoding")
        );
    }

    #[test]
    fn wrong_length_public_key_returns_error() {
        // Valid base64 but not 32 bytes
        let short_key = URL_SAFE_NO_PAD.encode(b"tooshort");
        let result = verify_signature(&short_key, "challenge", "signature");
        assert!(result.is_err());
    }

    // ── challenge generation ──────────────────────────────────────────────────

    #[test]
    fn generate_challenge_is_nonempty_and_unique() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert!(!c1.is_empty());
        assert_ne!(c1, c2, "two challenges should be distinct");
    }

    #[test]
    fn generate_challenge_is_valid_base64() {
        let challenge = generate_challenge();
        assert!(
            URL_SAFE_NO_PAD.decode(&challenge).is_ok(),
            "challenge should be valid URL-safe base64"
        );
    }

    // ── bearer token extraction ───────────────────────────────────────────────

    #[test]
    fn extract_bearer_token_from_valid_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer my-token-value".parse().unwrap(),
        );

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "my-token-value");
    }

    #[test]
    fn extract_bearer_token_trims_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer   padded-token  ".parse().unwrap(),
        );

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "padded-token");
    }

    #[test]
    fn extract_bearer_token_missing_header_returns_error() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing authorization header")
        );
    }

    #[test]
    fn extract_bearer_token_wrong_scheme_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );

        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected Bearer token")
        );
    }

    #[test]
    fn extract_bearer_token_empty_token_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer ".parse().unwrap(),
        );

        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("bearer token is empty")
        );
    }
}
