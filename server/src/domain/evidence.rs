pub struct EvidenceBundle {
    pub hardware: HardwareEvidence,
    pub software: SoftwareEvidence,
}

#[derive(Clone)]
pub struct HardwareEvidence {
    pub raw: Vec<u8>,
    pub cert: Vec<u8>,
}

#[derive(Clone)]
pub struct SoftwareEvidence {
    pub signed_raw: Vec<u8>,
    pub signature: Vec<u8>,
    pub cert: Vec<u8>,
}
