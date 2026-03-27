use crate::services::attester_service;
use common_core::proto::attester_service_server::AttesterService;
use common_core::proto::public_key::KeyParams;
use common_core::proto::{
    self, EllipticCurve, GetAdditionalArtifactsRequest, GetEvidenceRequest, KeyAlgorithm,
    KeyEncoding, SignedAdditionalArtifactsBundle, SignedEvidenceBundle,
};
use p384::ecdsa::signature::SignatureEncoding;
use p384::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::SignerMut},
    pkcs8::EncodePublicKey,
};
use prost::Message;

#[derive(Clone)]
pub struct AttesterServiceHandler {
    attester_service: attester_service::AttesterService,
    instance_public_key: PublicKey,
    instance_private_key: SigningKey,
}

impl AttesterServiceHandler {
    pub fn new(
        attester_service: attester_service::AttesterService,
        instance_public_key: PublicKey,
        instance_private_key: SigningKey,
    ) -> Self {
        Self {
            attester_service,
            instance_public_key,
            instance_private_key,
        }
    }
}

#[tonic::async_trait]
impl AttesterService for AttesterServiceHandler {
    async fn get_additional_artifacts(
        &self,
        _request: tonic::Request<GetAdditionalArtifactsRequest>,
    ) -> Result<tonic::Response<SignedAdditionalArtifactsBundle>, tonic::Status> {
        let additional_artifacts_bundle = self
            .attester_service
            .get_additional_artifacts()
            .await
            .map_err(|e| {
                tonic::Status::internal(format!("Failed to get additional artifacts: {e}"))
            })?;

        let serialized_additional_artifacts_bundle = additional_artifacts_bundle.encode_to_vec();

        let signature: Signature = self
            .instance_private_key
            .clone()
            .sign(serialized_additional_artifacts_bundle.as_slice());

        let public_key_der = self
            .instance_public_key
            .to_public_key_der()
            .map_err(|_| tonic::Status::internal("Failed to encode public key in DER format"))?;

        Ok(tonic::Response::new(SignedAdditionalArtifactsBundle {
            serialized_additional_artifacts_bundle,
            signature: signature.to_der().to_vec(),
            signing_key: Some(proto::PublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data: public_key_der.to_vec(),
                certificate: None,
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
        }))
    }

    async fn get_evidence(
        &self,
        request: tonic::Request<GetEvidenceRequest>,
    ) -> Result<tonic::Response<SignedEvidenceBundle>, tonic::Status> {
        let req = request.into_inner();

        let nonce = req.nonce.as_slice();
        let activate_credentia_bundle = req.activate_credential_bundle;

        let evidence_bundle = self
            .attester_service
            .get_evidence(nonce, activate_credentia_bundle)
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to get evidence: {e}")))?;

        let serialized_evidence_bundle = evidence_bundle.encode_to_vec();

        let signature: Signature = self
            .instance_private_key
            .clone()
            .sign(serialized_evidence_bundle.as_slice());

        let public_key_der = self
            .instance_public_key
            .to_public_key_der()
            .map_err(|_| tonic::Status::internal("Failed to encode public key in DER format"))?;

        Ok(tonic::Response::new(SignedEvidenceBundle {
            serialized_evidence_bundle,
            signature: signature.to_der().to_vec(),
            signing_key: Some(proto::PublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data: public_key_der.to_vec(),
                certificate: None,
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
        }))
    }
}
