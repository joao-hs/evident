pub mod error;
#[cfg(any(feature = "snp_gce", feature = "snp_ec2", feature = "snp_avm", feature = "snp_mock"))]
pub mod snp;
pub mod tpm;

mod nonce;

use crate::domain::evidence::EvidenceBundle;
use error::EvidenceCollectionError;

pub async fn initialize() -> Result<(), EvidenceCollectionError> {
    snp::initialize().await?;
    tpm::initialize().await?;
    Ok(())
}

pub async fn collect_evidence(
    nonce: Option<&[u8]>,
) -> Result<EvidenceBundle, EvidenceCollectionError> {
    let hardware_evidence = snp::collect_hardware_evidence(nonce).await?;
    let software_evidence = tpm::collect_software_evidence(nonce).await?;
    Ok(EvidenceBundle {
        hardware: hardware_evidence.clone(),
        software: software_evidence.clone(),
    })
}
