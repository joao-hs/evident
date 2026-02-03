use cfg_if::cfg_if;

use crate::{collectors::error::EvidenceCollectionError, domain::evidence::HardwareEvidence};

cfg_if! {
    if #[cfg(feature = "snp_avm")] {
        mod avm;
        pub use avm::avm_initialize as specific_initialize;
        pub use avm::avm_collect_hardware_evidence as collect_specific_hardware_evidence;
    } else if #[cfg(any(feature = "snp_ec2", feature = "snp_gce"))] {
        mod ec2_gce;
        pub use ec2_gce::ec2_gce_initialize as specific_initialize;
        pub use ec2_gce::ec2_gce_collect_hardware_evidence as collect_specific_hardware_evidence;
    } else if #[cfg(feature = "snp_mock")] {
        mod mock;
        pub use mock::mock_initialize as specific_initialize;
        pub use mock::mock_collect_hardware_evidence as collect_specific_hardware_evidence;
    } else {
        panic!("unknown hardware evidence collection strategy")
    }
}

pub async fn initialize() -> Result<(), EvidenceCollectionError> {
    specific_initialize()
}

pub async fn collect_hardware_evidence(
    nonce: Option<&[u8]>,
) -> Result<HardwareEvidence, EvidenceCollectionError> {
    collect_specific_hardware_evidence(nonce)
}
