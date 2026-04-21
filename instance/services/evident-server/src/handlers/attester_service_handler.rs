use crate::services::attester_service;
use common_core::proto::attester_service_server::AttesterService;
use common_core::proto::public_key::KeyParams;
use common_core::proto::{
    self, Certificate, EllipticCurve, GetAdditionalArtifactsRequest, GetEvidenceRequest,
    KeyAlgorithm, KeyEncoding, SignedAdditionalArtifactsBundle, SignedEvidenceBundle,
};
use log::{debug, error, info};
use p384::ecdsa::signature::SignatureEncoding;
use p384::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::SignerMut},
    pkcs8::EncodePublicKey,
};
use prost::Message;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub u64);

pub fn attach_request_id(
    mut request: tonic::Request<()>,
) -> Result<tonic::Request<()>, tonic::Status> {
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    request.extensions_mut().insert(RequestId(request_id));
    Ok(request)
}

fn request_id_from_request<T>(request: &tonic::Request<T>) -> u64 {
    request
        .extensions()
        .get::<RequestId>()
        .map(|id| id.0)
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct AttesterServiceHandler {
    attester_service: attester_service::AttesterService,
    instance_public_key: PublicKey,
    instance_private_key: SigningKey,
    instance_certificate: Certificate,
}

impl AttesterServiceHandler {
    pub fn new(
        attester_service: attester_service::AttesterService,
        instance_public_key: PublicKey,
        instance_private_key: SigningKey,
        instance_certificate: Certificate,
    ) -> Self {
        Self {
            attester_service,
            instance_public_key,
            instance_private_key,
            instance_certificate,
        }
    }
}

#[tonic::async_trait]
impl AttesterService for AttesterServiceHandler {
    async fn get_additional_artifacts(
        &self,
        request: tonic::Request<GetAdditionalArtifactsRequest>,
    ) -> Result<tonic::Response<SignedAdditionalArtifactsBundle>, tonic::Status> {
        let request_id = request_id_from_request(&request);
        info!("request_id={request_id} start get_additional_artifacts");

        let additional_artifacts_bundle = self
            .attester_service
            .get_additional_artifacts()
            .await
            .map_err(|e| {
                error!("request_id={request_id} get_additional_artifacts failed: {e}");
                tonic::Status::internal(format!("Failed to get additional artifacts: {e}"))
            })?;
        debug!("request_id={request_id} additional artifacts bundle created");

        let serialized_additional_artifacts_bundle = additional_artifacts_bundle.encode_to_vec();
        debug!(
            "request_id={request_id} serialized additional artifacts bundle ({} bytes)",
            serialized_additional_artifacts_bundle.len()
        );

        let signature: Signature = self
            .instance_private_key
            .clone()
            .sign(serialized_additional_artifacts_bundle.as_slice());

        let public_key_der = self
            .instance_public_key
            .to_public_key_der()
            .map_err(|_| tonic::Status::internal("Failed to encode public key in DER format"))?;

        let response = tonic::Response::new(SignedAdditionalArtifactsBundle {
            serialized_additional_artifacts_bundle,
            signature: signature.to_der().to_vec(),
            signing_key: Some(proto::PublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data: public_key_der.to_vec(),
                certificate: Some(self.instance_certificate.clone()),
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
        });
        info!("request_id={request_id} end get_additional_artifacts");

        Ok(response)
    }

    async fn get_evidence(
        &self,
        request: tonic::Request<GetEvidenceRequest>,
    ) -> Result<tonic::Response<SignedEvidenceBundle>, tonic::Status> {
        let request_id = request_id_from_request(&request);
        info!("request_id={request_id} start get_evidence");

        let req = request.into_inner();

        let nonce = req.nonce.as_slice();
        let activate_credential_bundle = req.activate_credential_bundle;
        debug!(
            "request_id={request_id} get_evidence request parsed (nonce_len={}, activate_credential_bundle_present={})",
            nonce.len(),
            activate_credential_bundle.is_some()
        );

        let evidence_bundle = self
            .attester_service
            .get_evidence(nonce, activate_credential_bundle)
            .await
            .map_err(|e| {
                error!("request_id={request_id} get_evidence failed: {e}");
                tonic::Status::internal(format!("Failed to get evidence: {e}"))
            })?;
        debug!("request_id={request_id} evidence bundle collected");

        let serialized_evidence_bundle = evidence_bundle.encode_to_vec();
        debug!(
            "request_id={request_id} serialized evidence bundle ({} bytes)",
            serialized_evidence_bundle.len()
        );

        let signature: Signature = self
            .instance_private_key
            .clone()
            .sign(serialized_evidence_bundle.as_slice());

        let public_key_der = self
            .instance_public_key
            .to_public_key_der()
            .map_err(|_| tonic::Status::internal("Failed to encode public key in DER format"))?;

        let response = tonic::Response::new(SignedEvidenceBundle {
            serialized_evidence_bundle,
            signature: signature.to_der().to_vec(),
            signing_key: Some(proto::PublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data: public_key_der.to_vec(),
                certificate: Some(self.instance_certificate.clone()),
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
        });
        info!("request_id={request_id} end get_evidence");

        Ok(response)
    }
}
