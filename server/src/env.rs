use axum_client_ip::ClientIpSource;
use envconfig::Envconfig;
use phirepass_common::env::Mode;

#[derive(Envconfig)]
pub(crate) struct Env {
    #[envconfig(from = "APP_MODE", default = "production")]
    pub mode: Mode,

    #[envconfig(from = "FQDN", default = "localhost")]
    pub fqdn: String,

    #[envconfig(from = "IP_SOURCE", default = "ConnectInfo")]
    pub(crate) ip_source: ClientIpSource,

    #[envconfig(from = "HOST", default = "0.0.0.0")]
    pub host: String,

    #[envconfig(from = "PORT", default = "8080")]
    pub port: u16,

    #[envconfig(from = "ACCESS_CONTROL_ALLOW_ORIGIN")]
    pub access_control_allowed_origin: Option<String>,

    #[envconfig(from = "DATABASE_URL")]
    pub database_url: String,

    #[envconfig(from = "DATABASE_MAX_CONNECTIONS", default = "5")]
    pub database_max_connections: u32,

    #[envconfig(from = "REDIS_DATABASE_URL")]
    pub redis_database_url: String,

    #[envconfig(from = "JWT_SECRET")]
    pub jwt_secret: String,

    #[envconfig(from = "JWT_TTL_SECS", default = "300")]
    pub jwt_ttl_secs: i64,

    #[envconfig(from = "CHALLENGE_TTL_SECS", default = "60")]
    pub challenge_ttl_secs: i64,
}

pub fn init() -> anyhow::Result<Env> {
    let config = Env::init_from_env()?;
    Ok(config)
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
