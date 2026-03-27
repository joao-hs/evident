use common_core::proto;

// ==============================
// TARGET_TYPE
// ==============================
#[allow(dead_code)]
pub enum TargetTypeEnum {
    SnpEc2,
    SnpGce,
    // Add more target types here as needed
}

#[cfg(feature = "snp_ec2")]
pub const TARGET_TYPE: TargetTypeEnum = TargetTypeEnum::SnpEc2;

#[cfg(feature = "snp_gce")]
pub const TARGET_TYPE: TargetTypeEnum = TargetTypeEnum::SnpGce;

pub const TARGET_TYPE_PROTO: proto::TargetType = match TARGET_TYPE {
    TargetTypeEnum::SnpEc2 => proto::TargetType::SnpEc2,
    TargetTypeEnum::SnpGce => proto::TargetType::SnpGce,
    _ => proto::TargetType::Unspecified,
};

// ==============================
// VMPL
// ==============================
#[allow(dead_code)]
pub enum VmplEnum {
    Vmpl0,
    Vmpl1,
    Vmpl2,
    Vmpl3,
}

#[cfg(feature = "snp_ec2")]
pub const VMPL: VmplEnum = VmplEnum::Vmpl0;

#[cfg(feature = "snp_gce")]
pub const VMPL: VmplEnum = VmplEnum::Vmpl0;

// ==============================
// DEBUG
// ==============================
#[cfg(feature = "debug")]
pub const DEBUG: bool = true;

#[cfg(not(feature = "debug"))]
pub const DEBUG: bool = false;
