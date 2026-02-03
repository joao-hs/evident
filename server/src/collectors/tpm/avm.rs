use crate::{domain::evidence::SoftwareEvidence, wrappers::error::PlatformAPIWrapperError};

pub fn avm_collect_software_evidence(
    nonce: Option<[u8; 64]>,
) -> Result<SoftwareEvidence, PlatformAPIWrapperError> {
    todo!();
}
