use crate::target_info::{TARGET_TYPE, TargetTypeEnum};
use common_core::{errors::EvidentError, proto::evidence_bundle::SoftwareEvidence};
use ec2::Ec2TpmWrapper;
use gce::GceTpmWrapper;
use once_cell::sync::Lazy;
use sha2::digest::DynDigest;
use tokio::sync::Mutex;

mod ec2;
mod gce;

pub trait SoftwareEvidenceCollector: Send + Sync {
    fn collect_software_evidence(
        &self,
        user_data: [u8; 32],
    ) -> Result<SoftwareEvidence, EvidentError>;

    fn bind_elements(&self, hasher: &mut dyn DynDigest);

    fn get_ek_pub_key(&self) -> Result<Vec<u8>, EvidentError>;

    fn get_ak_key_name(&self) -> Result<Vec<u8>, EvidentError>;

    fn activate_credential(
        &self,
        credential_blob: Vec<u8>,
        encrypted_secret: Vec<u8>,
    ) -> Result<Vec<u8>, EvidentError>;
}

static TPM_WRAPPER: Lazy<Mutex<Box<dyn SoftwareEvidenceCollector>>> = Lazy::new(|| {
    let wrapper: Box<dyn SoftwareEvidenceCollector> = match TARGET_TYPE {
        TargetTypeEnum::SnpEc2 => {
            Box::new(Ec2TpmWrapper::new().expect("Failed to initialize Ec2TpmWrapper"))
        }
        TargetTypeEnum::SnpGce => {
            Box::new(GceTpmWrapper::new().expect("Failed to initialize GceTpmWrapper"))
        }
    };
    Mutex::new(wrapper)
});

pub async fn initialize() -> Result<(), EvidentError> {
    #[cfg(feature = "local")]
    {
        println!("TPM collector initialized in local mode. Skipping...");
        return Ok(());
    }

    let _ = TPM_WRAPPER.lock().await;
    Ok(())
}

pub async fn collect_software_evidence(nonce: [u8; 32]) -> Result<SoftwareEvidence, EvidentError> {
    #[cfg(feature = "local")]
    {
        use common_core::proto::Evidence;

        println!("Collecting software evidence in local mode. Giving bogus evidence...");
        return Ok(SoftwareEvidence::TpmEvidence(Evidence {
            signed_raw: vec![0; 512],
            signature: vec![0; 512],
            signing_key: None,
        }));
    }
    let tpm_wrapper = TPM_WRAPPER.lock().await;
    tpm_wrapper.collect_software_evidence(nonce)
}

pub async fn bind_elements(hasher: &mut (dyn DynDigest + Send)) {
    #[cfg(feature = "local")]
    {
        println!("Binding elements in local mode. Skipping...");
        return;
    }
    let tpm_wrapper = TPM_WRAPPER.lock().await;
    tpm_wrapper.bind_elements(hasher);
}

pub async fn get_ek_pub_key() -> Result<Vec<u8>, EvidentError> {
    #[cfg(feature = "local")]
    {
        println!("Getting EK pub key in local mode. Giving bogus key...");
        return Ok(vec![0; 256]);
    }
    let tpm_wrapper = TPM_WRAPPER.lock().await;
    tpm_wrapper.get_ek_pub_key()
}

pub async fn get_ak_key_name() -> Result<Vec<u8>, EvidentError> {
    #[cfg(feature = "local")]
    {
        println!("Getting AK pub name in local mode. Giving bogus key...");
        return Ok(vec![0; 256]);
    }
    let tpm_wrapper = TPM_WRAPPER.lock().await;
    tpm_wrapper.get_ak_key_name()
}

pub async fn activate_credential(
    credential_blob: Vec<u8>,
    encrypted_secret: Vec<u8>,
) -> Result<Vec<u8>, EvidentError> {
    #[cfg(feature = "local")]
    {
        println!("Activating credential in local mode. Giving bogus secret...");
        return Ok(vec![0; 256]);
    }
    let tpm_wrapper = TPM_WRAPPER.lock().await;
    tpm_wrapper.activate_credential(credential_blob, encrypted_secret)
}
