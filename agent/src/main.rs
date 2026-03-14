use crate::agent::save_token;
use phirepass_common::runtime::RuntimeBuilder;
use std::fs;

mod agent;
mod cli;
mod common;
mod creds;
mod env;
mod error;
mod http;
mod session;
mod sftp;
mod ssh;
mod ws;

fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto provider");

    let rt = RuntimeBuilder::create().with_worker_threads(2).build()?;

    rt.block_on(async {
        let cli = cli::parse();
        phirepass_common::logger::init("phirepass:agent");
        match cli.command {
            None => {
                let config = env::init()?;
                agent::start(config).await
            }
            Some(cli::Commands::Start(args)) => {
                let config = env::init()?;

                if let Some(path_to_token) = args.token_from_file {
                    let server_host = args.server_host.unwrap_or(config.server_host.to_owned());
                    let server_port = args.server_port.unwrap_or(config.server_port);
                    let token = fs::read_to_string(path_to_token)?;
                    save_token(server_host.as_str(), server_port, &token).await?;
                }

                agent::start(config).await
            }
            Some(cli::Commands::Login(args)) => {
                agent::login(
                    args.server_host,
                    args.server_port,
                    args.from_file,
                    args.from_stdin,
                )
                .await
            }
            Some(cli::Commands::Logout(args)) => {
                agent::logout(args.server_host, args.server_port).await
            }
            Some(cli::Commands::Version) => {
                println!("{}", env::version());
                Ok(())
            }
        }
    })
}
