use crate::{
    handlers::attester_service_handler::{AttesterServiceHandler, attach_request_id},
    services::attester_service::AttesterService,
};
use common_core::{
    constants,
    proto::{self, attester_service_server::AttesterServiceServer},
};
use log::{LevelFilter, error, info};
use p384::{PublicKey, ecdsa::SigningKey, pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey};
use std::fs;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use x509_parser::{
    pem::parse_x509_pem,
    prelude::{FromDer, X509Certificate},
};

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

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

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
    let instance_certificate_der: Vec<u8> = {
        let cert_pem_bytes = fs::read(constants::INSTANCE_SELF_SIGNED_CERTIFICATE_PATH)?;
        let (_, cert_pem) = parse_x509_pem(cert_pem_bytes.as_slice())?;
        let (_, cert_der) = X509Certificate::from_der(&cert_pem.contents)?;
        cert_der.as_raw().to_vec()
    };
    let instance_certificate = proto::Certificate {
        r#type: proto::CertificateType::X509.into(),
        encoding: proto::CertificateEncoding::Der.into(),
        data: instance_certificate_der,
    };

    collectors::initialize().await?;

    let attester_service = AttesterService::new(instance_pub_key, instance_certificate.clone());

    let attester_service_handler = AttesterServiceHandler::new(
        attester_service,
        instance_pub_key,
        instance_private_key,
        instance_certificate.clone(),
    );

    let server_router =
        Server::builder()
            .tls_config(tls)?
            .add_service(AttesterServiceServer::with_interceptor(
                attester_service_handler,
                attach_request_id,
            ));

    let running_server = server_router.serve(
        format!("0.0.0.0:{}", constants::EVIDENT_SERVER_PORT)
            .parse()
            .expect("Invalid address"),
    );

    info!("Serving on port {}", constants::EVIDENT_SERVER_PORT);

    #[cfg(feature = "request_certificate")]
    tokio::spawn(async {
        if let Err(e) =
            init::request_certificate(target_info::CERTIFICATE_ISSUER_ENDPOINT.trim()).await
        {
            error!("Failed to request certificate: {e}");
        }
    });

    #[cfg(not(feature = "request_certificate"))]
    {
        sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;
    }

    if let Err(e) = running_server.await {
        error!("Server error: {e}");
        return Err(e.into());
    }

    Ok(())
}
