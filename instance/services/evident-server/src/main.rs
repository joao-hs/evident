use crate::{
    handlers::attester_service_handler::AttesterServiceHandler,
    services::attester_service::AttesterService,
};
use common_core::{constants, proto::attester_service_server::AttesterServiceServer};
use log::{LevelFilter, error, info};
use p384::{PublicKey, ecdsa::SigningKey, pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey};
use std::fs;
use tonic::transport::{Identity, Server, ServerTlsConfig};

mod collectors;
mod handlers;
mod init;
mod services;
mod target_info;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let log_level = if target_info::DEBUG {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    env_logger::Builder::new().filter_level(log_level).init();

    if target_info::DEBUG {
        log::debug!("Debug mode is enabled");
    }

    let tls = {
        let cert = fs::read(constants::GRPC_EVIDENT_SERVER_CERTIFICATE_PATH)?;
        let key = fs::read(constants::GRPC_EVIDENT_SERVER_PRIVATE_KEY_PATH)?;

        ServerTlsConfig::new().identity(Identity::from_pem(cert, key))
    };

    let instance_pub_key = {
        let bytes = fs::read(constants::INSTANCE_PUBLIC_KEY_PATH)?;
        PublicKey::from_public_key_der(&bytes)
    }?;
    let instance_private_key = {
        let bytes = fs::read(constants::INSTANCE_PRIVATE_KEY_PATH)?;
        SigningKey::from_pkcs8_der(bytes.as_slice())
    }?;

    collectors::initialize().await?;

    let attester_service = AttesterService::new(instance_pub_key);

    let attester_service_handler =
        AttesterServiceHandler::new(attester_service, instance_pub_key, instance_private_key);

    let server_router = Server::builder()
        .tls_config(tls)?
        .add_service(AttesterServiceServer::new(attester_service_handler));

    let running_server = server_router.serve(
        format!("0.0.0.0:{}", constants::EVIDENT_SERVER_PORT)
            .parse()
            .expect("Invalid address"),
    );

    info!("Serving on port {}", constants::EVIDENT_SERVER_PORT);

    #[cfg(feature = "request_certificate")]
    tokio::spawn(async {
        if let Err(e) = init::request_certificate(env!("CERTIFICATE_ISSUER_ENDPOINT").trim()).await
        {
            error!("Failed to request certificate: {e}");
        }
    });

    if let Err(e) = running_server.await {
        error!("Server error: {e}");
        return Err(e.into());
    }

    Ok(())
}
