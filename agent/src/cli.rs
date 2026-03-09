use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Start the agent
    Start(StartArgs),
    /// Login
    Login(LoginArgs),
    /// Logout and delete node from server
    Logout(LogoutArgs),
    /// Print version information
    Version,
}

#[derive(Args, Debug)]
pub(crate) struct StartArgs {
    /// Read token from a mounted file (recommended for CI/K8s/Docker secrets)
    #[arg(long, value_name = "PATH")]
    pub token_from_file: Option<PathBuf>,

    /// Server host to connect to
    #[arg(long)]
    pub server_host: Option<String>,

    /// Server port to connect to
    #[arg(long)]
    pub server_port: Option<u16>,
}

#[derive(Args, Debug)]
pub(crate) struct LoginArgs {
    /// Read token from a mounted file (recommended for CI/K8s/Docker secrets)
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<PathBuf>,

    /// Read token from stdin (recommended for Docker)
    #[arg(long)]
    pub from_stdin: bool,

    /// Server host to connect to
    #[cfg_attr(debug_assertions, arg(long, default_value = "localhost"))]
    #[cfg_attr(not(debug_assertions), arg(long, default_value = "api.phirepass.com"))]
    pub server_host: String,

    /// Server port to connect to
    #[cfg_attr(debug_assertions, arg(long, default_value_t = 8080))]
    #[cfg_attr(not(debug_assertions), arg(long, default_value_t = 443))]
    pub server_port: u16,
}

#[derive(Args, Debug)]
pub(crate) struct LogoutArgs {
    /// Server host to connect to
    #[cfg_attr(debug_assertions, arg(long, default_value = "localhost"))]
    #[cfg_attr(not(debug_assertions), arg(long, default_value = "api.phirepass.com"))]
    pub server_host: String,

    /// Server port to connect to
    #[cfg_attr(debug_assertions, arg(long, default_value_t = 8080))]
    #[cfg_attr(not(debug_assertions), arg(long, default_value_t = 443))]
    pub server_port: u16,
}

pub(crate) fn parse() -> Cli {
    Cli::parse()
}
