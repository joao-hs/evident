use crate::target_info::{TARGET_TYPE, TargetTypeEnum, VMPL};
use common_core::{
    errors::{AttestationError, EvidentError},
    proto::{
        Certificate, CertificateEncoding, CertificateType, EllipticCurve, Evidence, KeyAlgorithm,
        KeyEncoding, PublicKey, evidence_bundle::HardwareEvidence, public_key::KeyParams,
    },
};
use log::debug;
use sev::firmware::{guest::Firmware, host::CertType};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::HardwareEvidenceCollector;

pub struct Ec2GceSnpWrapper {
    firmware: Firmware,
}

impl Ec2GceSnpWrapper {
    pub fn new() -> Result<Self, EvidentError> {
        let firmware = Firmware::open()?;
        Ok(Self { firmware })
    }
}

impl HardwareEvidenceCollector for Ec2GceSnpWrapper {
    fn collect_hardware_evidence(
        &mut self,
        user_data: [u8; 64],
    ) -> Result<HardwareEvidence, EvidentError> {
        let instr_collect_start = std::time::Instant::now();
        debug!("Starting hardware evidence collection...");
        let (raw_report, cert_chain) = self.firmware.get_ext_report(
            Some(1), // Current ABI version
            Some(user_data),
            Some(VMPL as u32),
        )?;
        debug!(
            "collect_hardware_evidence: collected raw report in {:?}",
            instr_collect_start.elapsed()
        );

        let signed_raw = raw_report
            .get(0x0..=0x29f)
            .ok_or_else(|| {
                AttestationError::CodecError(
                    "raw report is too short to contain the signed portion".to_string(),
                )
            })?
            .to_vec();

        let signature = raw_report
            .get(0x2A0..=0x49F)
            .ok_or_else(|| {
                AttestationError::CodecError(
                    "raw report is too short to contain the signature portion".to_string(),
                )
            })?
            .to_vec();

        let wanted = match TARGET_TYPE {
            TargetTypeEnum::SnpEc2 => CertType::VLEK,
            TargetTypeEnum::SnpGce => CertType::VCEK,
        };

        let certificate = cert_chain
            .and_then(|chain| {
                chain
                    .into_iter()
                    .find(|cert| cert.cert_type == wanted)
                    .map(|cert| cert.data.clone())
            })
            .ok_or_else(|| {
                AttestationError::CertificateNotFound(format!(
                    "{wanted:?} certificate not found in the certificate chain"
                ))
            })?;

        let key_data = {
            let (_, parsed_cert) = X509Certificate::from_der(&certificate).map_err(|e| {
                AttestationError::CodecError(format!("failed to parse certificate: {:?}", e))
            })?;
            let spki = parsed_cert.tbs_certificate.subject_pki;
            spki.raw.to_vec()
        };

        let ret = HardwareEvidence::SnpEvidence(Evidence {
            signed_raw,
            signature,
            signing_key: Some(PublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data,
                certificate: Some(Certificate {
                    r#type: CertificateType::X509.into(),
                    encoding: CertificateEncoding::Der.into(),
                    data: certificate,
                }),
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
        });
        debug!(
            "collect_hardware_evidence: constructed HardwareEvidence in {:?}",
            instr_collect_start.elapsed()
        );
        Ok(ret)
    }

    fn bind_elements(&self, _hasher: &mut dyn sha2::digest::DynDigest) {
        // No SNP-specific elements to bind for EC2/GCE SNP
    }
}
