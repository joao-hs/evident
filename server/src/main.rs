use clap::Parser;
use log::{LevelFilter, error, info, warn};
use tonic::transport::Server;

use crate::{
    handlers::remote_attestation::RemoteAttestationHandler,
    services::remote_attestation::SecurePlatformEvidenceService,
};

mod domain;
mod handlers;
mod proto;
mod services;
mod target_info;
mod collectors;

#[derive(Parser)]
#[command(name = "evident-server")]
#[command(about = "CVM Attestation Server", long_about = None)]
struct Args {
    #[arg(short, long, action, default_value_t = false)]
    debug: bool,

    #[arg(short, long, default_value_t = 5000)]
    port: u16,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let log_level = if args.debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    env_logger::Builder::new().filter_level(log_level).init();

    if args.debug {
        warn!("debug mode is enabled. do **not** run in production with this mode");
    }

    #[cfg(feature = "snp_mock")]
    {
        warn!("mocking secure hardware platform. do **not** run in production with this mode");
    }

    collectors::initialize().await?;

    let platform_evidence_service =
        RemoteAttestationHandler::create(SecurePlatformEvidenceService::new());

    let mut server_router = Server::builder().add_service(platform_evidence_service);

    if args.debug {
        server_router = server_router.add_service(handlers::create_reflection_service()?)
    }

    let running_server = server_router.serve(
        format!("0.0.0.0:{}", args.port)
            .parse()
            .expect("Invalid address"),
    );

    info!("serving on port {}", args.port);

    if let Err(e) = running_server.await {
        error!("Server error: {e}");
        return Err(e.into());
    }

    Ok(())
}
