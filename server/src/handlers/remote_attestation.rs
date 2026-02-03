use crate::{
    collectors::error::EvidenceCollectionError, domain::evidence::EvidenceBundle, proto::{
        self,
        remote_attestation_service_server::{
            RemoteAttestationService, RemoteAttestationServiceServer,
        },
    }, services::remote_attestation::SecurePlatformEvidenceService
};
use log::error;
use tonic::Response;

#[derive(Clone)]
pub struct RemoteAttestationHandler {
    evidence_service: SecurePlatformEvidenceService,
}

impl RemoteAttestationHandler {
    pub fn create(service: SecurePlatformEvidenceService) -> RemoteAttestationServiceServer<Self> {
        RemoteAttestationServiceServer::new(Self {
            evidence_service: service,
        })
    }
}

#[tonic::async_trait]
impl RemoteAttestationService for RemoteAttestationHandler {
    async fn get_evidence(
        &self,
        request: tonic::Request<proto::GetEvidenceRequest>,
    ) -> Result<tonic::Response<proto::GetEvidenceResponse>, tonic::Status> {
        let req = request.into_inner();

        let nonce = req.nonce.as_slice();

        let EvidenceBundle { hardware, software } =
            self.evidence_service.generate_evidence(nonce).await?;

        Ok(Response::new(proto::GetEvidenceResponse {
            evidence: Some(proto::Evidence {
                hardware_evidence: Some(proto::HardwareEvidence {
                    raw: hardware.raw,
                    certificate: hardware.cert,
                }),
                software_evidence: Some(proto::SoftwareEvidence {
                    signed_raw: software.signed_raw,
                    signature: software.signature,
                    certificate: software.cert,
                }),
            }),
        }))
    }
}

impl From<EvidenceCollectionError> for tonic::Status {
    fn from(err: EvidenceCollectionError) -> Self {
        error!("evidence collection error: {:?}", err);
        match err {
            EvidenceCollectionError::InvalidNonce(e) => Self::invalid_argument(e),
            _ => Self::internal("internal error"),
        }
    }
}
