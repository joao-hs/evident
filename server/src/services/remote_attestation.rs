use crate::{
    collectors::{self, error::EvidenceCollectionError},
    domain::{evidence::EvidenceBundle},
};

#[derive(Clone)]
pub struct SecurePlatformEvidenceService {}

impl SecurePlatformEvidenceService {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn generate_evidence(
        &self,
        nonce_slice: &[u8],
    ) -> Result<EvidenceBundle, EvidenceCollectionError> {
        let nonce_option = if nonce_slice.is_empty() {
            None
        } else {
            Some(nonce_slice)
        };
        Ok(collectors::collect_evidence(nonce_option).await?)
    }
}
