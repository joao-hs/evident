use sev::firmware::{guest::Firmware, host::CertType};
use sha2::Sha512;

use crate::collectors::error::EvidenceCollectionError;
use crate::collectors::nonce;
use crate::{domain::evidence::HardwareEvidence, target_info};

pub fn ec2_gce_initialize() -> Result<(), EvidenceCollectionError> {
    // No specific initialization needed for EC2/GCE SNP evidence collection
    Ok(())
}

pub fn ec2_gce_collect_hardware_evidence(
    nonce: Option<&[u8]>,
) -> Result<HardwareEvidence, EvidenceCollectionError> {
    let nonce = nonce::format_nonce::<64, Sha512>(nonce);

    if nonce.len() != 64 {
        return Err(EvidenceCollectionError::InvalidNonce(format!(
            "Expected nonce length of 64 bytes, got {} bytes",
            nonce.len()
        )));
    }

    let mut firmware = Firmware::open()?;

    let (raw_report, cert_chain) = firmware.get_ext_report(
        Some(1), // Current ABI version
        Some(nonce),
        Some(target_info::SNP_VMPL as u32),
    )?;

    let certificate = cert_chain
        .and_then(|cert_chain| {
            cert_chain
                .into_iter()
                .find(|cert| cert.cert_type == CertType::VCEK)
                .map(|vcek_cert| vcek_cert.data.clone())
        })
        .ok_or_else(|| {
            EvidenceCollectionError::InternalError("(snp:report:cert) vcek certificate was not included in the extended attestation report".to_string())
        })?;

    Ok(HardwareEvidence {
        raw: raw_report,
        cert: certificate,
    })
}
