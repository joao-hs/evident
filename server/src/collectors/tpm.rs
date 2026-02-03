use cfg_if::cfg_if;
use tokio::sync::Mutex;
use once_cell::sync::Lazy;

use crate::{collectors::{error::EvidenceCollectionError}, domain::evidence::SoftwareEvidence};

cfg_if! {
    if #[cfg(feature = "snp_avm")] {
        mod avm;
        pub use avm::AvmTpmWrapper as TpmWrapper;
    } else if #[cfg(feature = "snp_ec2")]{
        mod ec2;
        pub use ec2::Ec2TpmWrapper as TpmWrapper;
    } else if #[cfg(feature = "snp_gce")]{
        mod gce;
        pub use gce::GceTpmWrapper as TpmWrapper;
    }
}

pub trait SoftwareEvidenceCollector {
    fn collect_software_evidence(&self, nonce: Option<&[u8]>) -> Result<SoftwareEvidence, EvidenceCollectionError>;
}

static TPM_WRAPPER: Lazy<Mutex<TpmWrapper>> = Lazy::new(|| {
    Mutex::new(TpmWrapper::new().expect("Failed to initialize TPM Wrapper"))
});

pub async fn initialize() -> Result<(), EvidenceCollectionError> {
    let _ = TPM_WRAPPER.lock().await; // will create the TpmWrapper instance
    Ok(())
}

pub async fn collect_software_evidence(nonce: Option<&[u8]>) -> Result<SoftwareEvidence, EvidenceCollectionError> {
    let tpm_wrapper = TPM_WRAPPER.lock().await;
    tpm_wrapper.collect_software_evidence(nonce)
}
