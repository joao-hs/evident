use common_core::{errors::EvidentError, proto::EvidenceBundle};
use sha2::digest::{Digest, DynDigest};

use crate::target_info::TARGET_TYPE_PROTO;

mod snp;
mod tpm;

pub async fn initialize() -> Result<(), EvidentError> {
    snp::initialize().await?;
    tpm::initialize().await?;
    Ok(())
}

pub async fn collect_evidence<
    H: Digest<OutputSize = sha2::digest::consts::U64>,
    S: Digest<OutputSize = sha2::digest::consts::U32>,
>(
    hw_user_data_hasher: H,
    sw_user_data_hasher: S,
) -> Result<EvidenceBundle, EvidentError> {
    let hardware_evidence =
        snp::collect_hardware_evidence(hw_user_data_hasher.finalize().into()).await?;

    let software_evidence =
        tpm::collect_software_evidence(sw_user_data_hasher.finalize().into()).await?;

    Ok(EvidenceBundle {
        target_type: TARGET_TYPE_PROTO.into(),
        hardware_evidence: Some(hardware_evidence),
        software_evidence: Some(software_evidence),
    })
}

pub async fn bind_elements(hasher: &mut (dyn DynDigest + Send)) {
    snp::bind_elements(hasher).await;
    tpm::bind_elements(hasher).await;
}

pub async fn get_ek_pub_key() -> Result<Vec<u8>, EvidentError> {
    tpm::get_ek_pub_key().await
}

pub async fn get_ak_key_name() -> Result<Vec<u8>, EvidentError> {
    tpm::get_ak_key_name().await
}

pub async fn activate_credential(
    credential_blob: Vec<u8>,
    encrypted_secret: Vec<u8>,
) -> Result<Vec<u8>, EvidentError> {
    tpm::activate_credential(credential_blob, encrypted_secret).await
}
