use crate::domain::evidence::HardwareEvidence;
use crate::wrappers::error::PlatformAPIWrapperError;

pub fn avm_collect_hardware_evidence(
    nonce: Option<[u8; 64]>,
) -> Result<HardwareEvidence, PlatfromAPIWrapperError> {
    todo!();
}
