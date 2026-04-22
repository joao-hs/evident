use crate::target_info::{TARGET_TYPE, TargetTypeEnum};
use common_core::{errors::EvidentError, proto::evidence_bundle::HardwareEvidence};
use ec2_gce::Ec2GceSnpWrapper;
use log::debug;
use once_cell::sync::Lazy;
use sha2::digest::DynDigest;
use tokio::sync::Mutex;

mod ec2_gce;

pub trait HardwareEvidenceCollector: Send + Sync {
    fn collect_hardware_evidence(
        &mut self,
        user_data: [u8; 64],
    ) -> Result<HardwareEvidence, EvidentError>;

    fn bind_elements(&self, hasher: &mut dyn DynDigest);
}

static SNP_WRAPPER: Lazy<Mutex<Box<dyn HardwareEvidenceCollector>>> = Lazy::new(|| {
    let wrapper: Box<dyn HardwareEvidenceCollector> = match TARGET_TYPE {
        TargetTypeEnum::SnpEc2 | TargetTypeEnum::SnpGce => {
            Box::new(Ec2GceSnpWrapper::new().expect("Failed to initialize Ec2GceSnpWrapper"))
        }
    };
    Mutex::new(wrapper)
});

pub async fn initialize() -> Result<(), EvidentError> {
    let _ = SNP_WRAPPER.lock().await;
    Ok(())
}

pub async fn collect_hardware_evidence(nonce: [u8; 64]) -> Result<HardwareEvidence, EvidentError> {
    let instr_collect_start = std::time::Instant::now();
    let mut snp_wrapper = SNP_WRAPPER.lock().await;
    let instr_lock_acquired = std::time::Instant::now();
    debug!(
        "collect_hardware_evidence: waited for lock {:?}",
        instr_collect_start.elapsed()
    );
    let ret = snp_wrapper.collect_hardware_evidence(nonce);
    debug!(
        "collect_hardware_evidence: collected hardware evidence in {:?}",
        instr_lock_acquired.elapsed()
    );
    drop(snp_wrapper);
    debug!(
        "collect_hardware_evidence: held lock for {:?}",
        instr_lock_acquired
    );
    ret
}

pub async fn bind_elements(hasher: &mut (dyn DynDigest + Send)) {
    let instr_collect_start = std::time::Instant::now();
    let snp_wrapper = SNP_WRAPPER.lock().await;
    let instr_lock_acquired = std::time::Instant::now();
    debug!(
        "bind_elements: waited for lock {:?}",
        instr_collect_start.elapsed()
    );
    snp_wrapper.bind_elements(hasher);
    debug!(
        "bind_elements: collected hardware evidence in {:?}",
        instr_lock_acquired.elapsed()
    );
    drop(snp_wrapper);
    debug!("bind_elements: held lock for {:?}", instr_lock_acquired);
}
