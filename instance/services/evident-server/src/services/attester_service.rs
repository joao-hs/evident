use std::fs;

use crate::{collectors, target_info::TARGET_TYPE_PROTO};
use common_core::{
    constants,
    errors::{AttestationError, EvidentError},
    proto::{
        self, ActivateCredentialBundle, AdditionalArtifactsBundle, Certificate,
        CertificateEncoding, CertificateType, Csr, CsrEncoding, CsrFormat, EllipticCurve,
        EvidenceBundle, KeyAlgorithm, KeyEncoding, MakeCredentialInputBundle,
        public_key::KeyParams,
    },
};
use p384::PublicKey;
use p384::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone)]
pub struct AttesterService {
    instance_public_key: PublicKey,
    instance_certificate: Certificate,
}

impl AttesterService {
    pub fn new(instance_public_key: PublicKey, instance_certificate: Certificate) -> Self {
        Self {
            instance_public_key,
            instance_certificate,
        }
    }

    pub async fn get_additional_artifacts(
        &self,
    ) -> Result<AdditionalArtifactsBundle, EvidentError> {
        let pk_der = {
            self.instance_public_key.to_public_key_der().map_err(|e| {
                AttestationError::CodecError(format!("failed to encode instance public key: {e}"))
            })?
        };

        // TODO: Refactor this to get the MakeCredentialInputBundle from the specific collector module
        #[cfg(feature = "snp_ec2")]
        let make_credential_input = Some(MakeCredentialInputBundle {
            tpm_endorsement_key: Some(proto::PublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data: collectors::get_ek_pub_key().await?,
                certificate: None,
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
            tpm_attestation_key_name: collectors::get_ak_key_name().await?,
        });

        #[cfg(feature = "snp_gce")]
        let make_credential_input = None;

        Ok(AdditionalArtifactsBundle {
            target_type: TARGET_TYPE_PROTO.into(),
            instance_key: Some(proto::PublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data: pk_der.to_vec(),
                certificate: Some(self.instance_certificate.clone()),
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
            make_credential_input,
            instance_csr: Some(Csr {
                data: fs::read(constants::INSTANCE_CERTIFICATE_SIGNING_REQUEST_PATH)?,
                encoding: CsrEncoding::Pem.into(),
                format: CsrFormat::Pkcs10.into(),
            }),
            grpc_server_certificate: Some(Certificate {
                r#type: CertificateType::X509.into(),
                encoding: CertificateEncoding::Pem.into(),
                data: fs::read(constants::GRPC_EVIDENT_SERVER_CERTIFICATE_PATH)?,
            }),
        })
    }

    pub async fn get_evidence(
        &self,
        nonce_slice: &[u8],
        activate_credential_bundle: Option<ActivateCredentialBundle>,
    ) -> Result<EvidenceBundle, EvidentError> {
        let secret_opt: Option<Vec<u8>> = if let Some(bundle) = activate_credential_bundle {
            Some(
                collectors::activate_credential(bundle.credential_blob, bundle.encrypted_secret)
                    .await?,
            )
        } else {
            None
        };

        let pk_der = {
            self.instance_public_key.to_public_key_der().map_err(|e| {
                AttestationError::CodecError(format!("failed to encode instance public key: {e}"))
            })?
        };

        let hardware_user_data_hasher = {
            let mut hasher = Sha512::new(); // hardware evidence takes a 64-byte user data == SHA-512 output
            hasher.update(nonce_slice);
            hasher.update(pk_der.as_ref()); // if measurement captures the code, the public key is now bound to this component's trustability
            collectors::bind_elements(&mut hasher).await;
            if let Some(secret) = secret_opt.as_deref() {
                hasher.update(secret);
            }
            hasher
        };

        let software_user_data_hasher = {
            let mut hasher = Sha256::new(); // software evidence takes a 32-byte user data == SHA-256 output
            hasher.update(nonce_slice);
            hasher.update(pk_der.as_ref()); // if measurement captures the code, the public key is now bound to this component's trustability
            if let Some(secret) = secret_opt.as_deref() {
                hasher.update(secret);
            }
            hasher
        };

        let evidence_bundle =
            collectors::collect_evidence(hardware_user_data_hasher, software_user_data_hasher)
                .await?;

        Ok(evidence_bundle)
    }
}
