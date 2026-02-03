use crate::domain::evidence::HardwareEvidence;
use crate::wrappers::error::PlatformAPIWrapperError;

pub fn mock_collect_hardware_evidence(
    nonce: Option<[u8; 64]>,
) -> Result<HardwareEvidence, PlatformAPIWrapperError> {
    todo!()
}
