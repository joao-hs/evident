use std::{
    fs,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use base64::Engine;
use common_core::{
    constants,
    proto::{
        self, AdditionalArtifactsBundle, Certificate, CertificateChain, CertificateEncoding,
        CertificateType, Csr, CsrEncoding, CsrFormat, EllipticCurve, KeyAlgorithm, KeyEncoding,
        MakeCredentialInputBundle, SignedAdditionalArtifactsBundle,
        certificate_issuer_verifier_service_client::CertificateIssuerVerifierServiceClient,
        public_key::KeyParams,
    },
};
use hyper_util::rt::TokioIo;
use log::{debug, info};
use p384::{
    PublicKey,
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey},
};
use prost::Message;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{ServerName, UnixTime},
};
use signature::Verifier;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{CertificateDer, Endpoint, Uri};
use tower::Service;
use x509_parser::{
    pem::parse_x509_pem,
    prelude::{FromDer, X509Certificate},
};

use crate::{collectors, target_info::TARGET_TYPE_PROTO};

// In evident framework, TLS is used for a single purpose: channel integrity and confidentiality protection.
// This makes it vulnerable to MitM attacks. Requesting a certificate is only benefitial for honest actors;
// A malicious certificate issuer can issue a certificate for this instance, but it would ultimately only
// compromise the availability of the service, not the security of the instance.
// Future work: evident-keygen generates a CSR to use with gRPC server and gets signed by a trusted CA.
#[derive(Debug)]
struct TemporarySkipServerVerification;

impl ServerCertVerifier for TemporarySkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Accepts any certificate unconditionally.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone)]
struct TemporarySkipVerifyTlsConnector {
    tls_config: Arc<ClientConfig>,
}

impl TemporarySkipVerifyTlsConnector {
    fn new() -> Self {
        let mut tls_config = ClientConfig::builder()
            .dangerous() // opt-in to the unsafe API
            .with_custom_certificate_verifier(Arc::new(TemporarySkipServerVerification {}))
            .with_no_client_auth(); // no mTLS

        tls_config.alpn_protocols = vec![b"h2".to_vec()]; // support HTTP/2

        Self {
            tls_config: Arc::new(tls_config),
        }
    }
}

impl Service<Uri> for TemporarySkipVerifyTlsConnector {
    // TokioIo wraps tokio's AsyncRead/Write into hyper's IO traits,
    // which is what tonic's Channel needs internally.
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let config = self.tls_config.clone();

        Box::pin(async move {
            let host = uri.host().ok_or("URI has no host")?;
            let port = uri.port_u16().unwrap_or(443);

            let tcp = TcpStream::connect(format!("{host}:{port}")).await?;

            let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
                match ip {
                    std::net::IpAddr::V4(v4) => {
                        ServerName::IpAddress(rustls::pki_types::IpAddr::V4(
                            rustls::pki_types::Ipv4Addr::from(v4.octets()),
                        ))
                    }
                    std::net::IpAddr::V6(v6) => {
                        ServerName::IpAddress(rustls::pki_types::IpAddr::V6(v6.into()))
                    }
                }
            } else {
                ServerName::try_from(host.to_owned())
                    .map_err(|e| format!("invalid server name '{host}': {e}"))?
            };

            let tls_stream = TlsConnector::from(config).connect(server_name, tcp).await?;

            Ok(TokioIo::new(tls_stream))
        })
    }
}

pub async fn request_certificate(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting certificate request flow");
    debug!("Target endpoint: {target}");
    // 1. Build the "SignedAdditionalArtifactsBundle" message
    //  - Needs the instance's key pair
    //  - Needs to serialize a "AdditionalArtifactsBundle" message
    //    - Needs to construct a "PublicKey" message from the instance's public key
    //    - Needs to construct the "MakeCredentialInputBundle" message
    //      - Needs to contruct a "PublicKey" message with the EK public key
    //      - Needs to fetch the AK key name from the TPM
    //    - Needs to construct the "CSR" message with the instance's certificate signing request
    //    - Needs to construct the "Certificate" message with the gRPC's TLS certificate
    let request = {
        debug!(
            "Loading instance private key from {}",
            constants::INSTANCE_PRIVATE_KEY_PATH
        );
        let instance_private_key = {
            let bytes = fs::read(constants::INSTANCE_PRIVATE_KEY_PATH)?;
            SigningKey::from_pkcs8_der(bytes.as_slice())
        }?;

        debug!(
            "Loading instance public key from {}",
            constants::INSTANCE_PUBLIC_KEY_PATH
        );
        let instance_pub_key = {
            let bytes = fs::read(constants::INSTANCE_PUBLIC_KEY_PATH)?;
            PublicKey::from_public_key_der(&bytes)
        }?;

        debug!(
            "Loading instance self-signed certificate from {}",
            constants::INSTANCE_SELF_SIGNED_CERTIFICATE_PATH
        );
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

        let instance_pub_key_proto = proto::PublicKey {
            algorithm: KeyAlgorithm::Ec.into(),
            encoding: KeyEncoding::SpkiDer.into(),
            key_data: instance_pub_key.to_public_key_der()?.to_vec(),
            certificate: Some(instance_certificate),
            key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
        };

        debug!(
            "Loading instance CSR from {}",
            constants::INSTANCE_CERTIFICATE_SIGNING_REQUEST_PATH
        );
        let csr_proto = Csr {
            data: fs::read(constants::INSTANCE_CERTIFICATE_SIGNING_REQUEST_PATH)?,
            encoding: CsrEncoding::Pem.into(),
            format: CsrFormat::Pkcs10.into(),
        };

        debug!(
            "Loading gRPC TLS certificate from {}",
            constants::GRPC_EVIDENT_SERVER_CERTIFICATE_PATH
        );
        let grpc_tls_cert_proto = Certificate {
            r#type: CertificateType::X509.into(),
            encoding: CertificateEncoding::Pem.into(),
            data: fs::read(constants::GRPC_EVIDENT_SERVER_CERTIFICATE_PATH)?,
        };

        #[cfg(feature = "snp_ec2")]
        let make_credential_input = {
            debug!("Collecting TPM endorsement key and AK key name");
            Some(MakeCredentialInputBundle {
                tpm_endorsement_key: Some(proto::PublicKey {
                    algorithm: KeyAlgorithm::Ec.into(),
                    encoding: KeyEncoding::SpkiDer.into(),
                    key_data: collectors::get_ek_pub_key().await?,
                    certificate: None,
                    key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
                }),
                tpm_attestation_key_name: collectors::get_ak_key_name().await?,
            })
        };

        #[cfg(not(feature = "snp_ec2"))]
        let make_credential_input = None;

        let additional_artifacts_bundle_proto = AdditionalArtifactsBundle {
            target_type: TARGET_TYPE_PROTO.into(),
            instance_key: Some(instance_pub_key_proto.clone()),
            make_credential_input,
            instance_csr: Some(csr_proto),
            grpc_server_certificate: Some(grpc_tls_cert_proto),
        };

        debug!("Serializing additional artifacts bundle");
        let serialized_additional_artifacts_bundle =
            additional_artifacts_bundle_proto.encode_to_vec();
        debug!("Signing additional artifacts bundle");
        let signature = {
            let sig: Signature =
                instance_private_key.sign(serialized_additional_artifacts_bundle.as_slice());
            sig.to_der().as_bytes().to_vec()
        };

        SignedAdditionalArtifactsBundle {
            serialized_additional_artifacts_bundle,
            signature,
            signing_key: Some(instance_pub_key_proto.clone()),
        }
    };

    // 2. Call the gRPC "RequestInstanceKeyAttestationCertificate"
    info!("Connecting to certificate issuer over gRPC");
    // must have "http://" scheme for tonic's Endpoint
    // in practice, the custom connector will do its own TLS
    // the server is running gRPC with TLS, and it is oblivious to
    // the customer connector existance.
    let target_with_scheme = if target.starts_with("http://") {
        target.to_owned()
    } else if target.starts_with("https://") {
        target.replacen("https://", "http://", 1)
    } else {
        format!("http://{target}")
    };
    let channel = Endpoint::try_from(target_with_scheme)?
        // .tls_config(ClientTlsConfig::new())?
        .connect_with_connector(TemporarySkipVerifyTlsConnector::new())
        .await?;

    let mut client = CertificateIssuerVerifierServiceClient::new(channel);

    info!("Requesting instance key attestation certificate");
    let response = client
        .request_instance_key_attestation_certificate(request)
        .await
        .map_err(|e| format!("gRPC request failed: {:#?}", e))?;

    // 3. Validate the response's signature
    info!("Validating response signature");
    let signed_cert_chain = response.into_inner();
    let cert_chain_bytes = signed_cert_chain.serialized_certificate_chain;
    match signed_cert_chain.signing_key {
        Some(signing_key) if signing_key.encoding() == KeyEncoding::SpkiDer => match signing_key
            .algorithm
        {
            x if x == KeyAlgorithm::Ec as i32 => match signing_key.key_params {
                Some(KeyParams::EllipticCurve(curve)) if curve == EllipticCurve::P384.into() => {
                    let public_key = VerifyingKey::from_public_key_der(&signing_key.key_data)?;
                    let signature = Signature::from_der(signed_cert_chain.signature.as_slice())?;
                    public_key.verify(cert_chain_bytes.as_slice(), &signature)?;
                }
                Some(KeyParams::EllipticCurve(curve)) => {
                    todo!("unsupported elliptic curve: {curve}")
                }
                _ => return Err("missing key parameters for EC signing key".into()),
            },
            x if x == KeyAlgorithm::Rsa as i32 => todo!(),
            _ => return Err("unsupported signing key algorithm".into()),
        },
        _ => return Err("response is missing signing key".into()),
    }

    // 4. Process the response
    //  - Contains a list of certificates that represent a certificate chain for the instance's public key
    //  - Needs to verify the certificate chain and store it in the filesystem
    info!("Decoding certificate chain");
    let cert_chain = CertificateChain::decode(cert_chain_bytes.as_ref())?.certificates;
    if cert_chain.is_empty() {
        return Err("certificate chain is empty".into());
    }

    let mut pem_chain = String::new();
    for (index, cert) in cert_chain.iter().enumerate() {
        debug!("Processing certificate {} in chain", index + 1);
        match cert.encoding {
            x if x == CertificateEncoding::Pem as i32 => {
                // Assume the data is already PEM; append as UTF-8
                let s = String::from_utf8(cert.data.clone())?;
                // Ensure a single trailing newline between entries
                if !pem_chain.is_empty() && !pem_chain.ends_with('\n') {
                    pem_chain.push('\n');
                }
                pem_chain.push_str(&s);
                if !pem_chain.ends_with('\n') {
                    pem_chain.push('\n');
                }
            }
            x if x == CertificateEncoding::Der as i32 => {
                // Convert DER to PEM
                let b64 = base64::engine::general_purpose::STANDARD;
                let pem = b64.encode(cert.data.clone());
                let pem_entry = format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    pem
                );
                // Ensure a single trailing newline between entries
                if !pem_chain.is_empty() && !pem_chain.ends_with('\n') {
                    pem_chain.push('\n');
                }
                pem_chain.push_str(&pem_entry);
            }
            _ => todo!(),
        }
    }

    // Write the concatenated PEM chain to disk
    info!(
        "Writing certificate chain to {}",
        constants::INSTANCE_CERTIFICATE_PATH
    );
    fs::write(constants::INSTANCE_CERTIFICATE_PATH, pem_chain.as_bytes())?;

    // 4. Notify systemd that the service is ready
    info!("Notifying systemd that the service is ready");
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;
    info!("Certificate request flow completed");
    Ok(())
}
