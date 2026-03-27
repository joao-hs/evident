use crate::target_info::{
    TARGET_TYPE,
    TargetTypeEnum::{SnpEc2, SnpGce},
};
use common_core::{errors::EvidentError, proto::evidence_bundle::HardwareEvidence};
use ec2_gce::{ec2_gce_collect_hardware_evidence, ec2_gce_initialize};
use sha2::digest::DynDigest;

mod ec2_gce;

pub async fn initialize() -> Result<(), EvidentError> {
    #[cfg(feature = "local")]
    {
        println!("SNP collector initialized in local mode. Skipping...");
        return Ok(());
    }

    match TARGET_TYPE {
        SnpEc2 | SnpGce => ec2_gce_initialize(),
    }
}

pub async fn collect_hardware_evidence(nonce: [u8; 64]) -> Result<HardwareEvidence, EvidentError> {
    #[cfg(feature = "local")]
    {
        use common_core::proto::{Evidence, PublicKey};

        println!("Collecting hardware evidence in local mode. Giving bogus evidence...");
        return Ok(HardwareEvidence::SnpEvidence(Evidence {
            // all zeros
            signed_raw: vec![0; 512],
            signature: vec![0; 512],
            signing_key: None,
        }));
    }
    match TARGET_TYPE {
        SnpEc2 | SnpGce => ec2_gce_collect_hardware_evidence(nonce),
    }
}

pub async fn bind_elements(_hasher: &mut (dyn DynDigest + Send)) {
    // No specific SNP elements to bind
}
