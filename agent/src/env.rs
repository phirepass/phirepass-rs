use crate::ssh::auth::SSHAuthMethod;
use envconfig::Envconfig;
use phirepass_common::env::Mode;
use std::env;
use std::time::Duration;

#[derive(Envconfig, Debug)]
pub(crate) struct Env {
    #[envconfig(from = "APP_MODE", default = "production")]
    pub mode: Mode,

    #[envconfig(from = "HOST", default = "0.0.0.0")]
    pub host: String,

    #[envconfig(from = "PORT", default = "8081")]
    pub port: u16,

    #[envconfig(from = "STATS_REFRESH_INTERVAL", default = "30")]
    pub stats_refresh_interval: u16,

    #[envconfig(from = "PING_INTERVAL", default = "30")]
    pub ping_interval: u16,

    #[envconfig(from = "SERVER_HOST", default = "api.phirepass.com")]
    pub server_host: String,

    #[envconfig(from = "SERVER_PORT", default = "443")]
    pub server_port: u16,

    #[envconfig(from = "SSH_HOST", default = "localhost")]
    pub ssh_host: String,

    #[envconfig(from = "SSH_PORT", default = "22")]
    pub ssh_port: u16,

    #[envconfig(from = "SSH_AUTH_METHOD", default = "password")]
    pub ssh_auth_mode: SSHAuthMethod,

    #[envconfig(from = "SSH_INACTIVITY_PERIOD", default = "3600")] // 1 hour
    pub ssh_inactivity_secs: u64,
}

impl Env {
    pub fn get_ssh_inactivity_duration(&self) -> Option<Duration> {
        match self.ssh_inactivity_secs {
            0 => None,
            o => Some(Duration::from_secs(o)),
        }
    }
}

pub(crate) fn init() -> anyhow::Result<Env> {
    let config = Env::init_from_env()?;
    Ok(config)
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
