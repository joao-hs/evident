use crate::target_info::{
    TARGET_TYPE,
    TargetTypeEnum::{SnpEc2, SnpGce},
};
use common_core::{errors::EvidentError, proto::evidence_bundle::HardwareEvidence};
use ec2_gce::{ec2_gce_collect_hardware_evidence, ec2_gce_initialize};
use sha2::digest::DynDigest;

mod ec2_gce;

pub async fn initialize() -> Result<(), EvidentError> {
    match TARGET_TYPE {
        SnpEc2 | SnpGce => ec2_gce_initialize(),
    }
}

pub async fn collect_hardware_evidence(nonce: [u8; 64]) -> Result<HardwareEvidence, EvidentError> {
    match TARGET_TYPE {
        SnpEc2 | SnpGce => ec2_gce_collect_hardware_evidence(nonce),
    }
}

pub async fn bind_elements(_hasher: &mut (dyn DynDigest + Send)) {
    // No specific SNP elements to bind
}
