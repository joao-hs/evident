use cfg_if::cfg_if;

pub const TARGET_TYPE: TargetTypeEnum = {
    cfg_if! {
        if #[cfg(feature = "snp_ec2")] {
            TargetTypeEnum::SnpEc2
        } else if #[cfg(feature = "snp_avm")] {
            TargetTypeEnum::SnpAvm
        } else if #[cfg(feature = "snp_gce")] {
            TargetTypeEnum::SnpGce
        } else if #[cfg(feature = "snp_qemu")]{
            TargetTypeEnum::SnpQemu
        } else if #[cfg(feature = "snp_mock")]{
            TargetTypeEnum::SnpMock
        } else {
            panic!("invalid compilation target type")
        }
    }
};

pub const SNP_VMPL: SnpVmplEnum = {
    cfg_if! {
        if #[cfg(feature = "snp_avm")] {
            SnpVmplEnum::Vmpl2
        } else if #[cfg(any(
            feature = "snp_ec2",
            feature = "snp_gce",
            feature = "qemu_vmpl0"
        ))] {
            SnpVmplEnum::Vmpl0
        } else if #[cfg(feature = "qemu_vmpl1")] {
            SnpVmplEnum::Vmpl1
        } else if #[cfg(feature = "qemu_vmpl2")] {
            SnpVmplEnum::Vmpl2
        } else if #[cfg(feature = "qemu_vmpl3")] {
            SnpVmplEnum::Vmpl3
        } else {
            // Default case
            SnpVmplEnum::Vmpl0
        }
    }
};

pub enum TargetTypeEnum {
    SnpEc2,
    SnpAvm,
    SnpGce,
    SnpQemu,
    SnpMock,
}

pub enum SnpVmplEnum {
    Vmpl0 = 0,
    Vmpl1 = 1,
    Vmpl2 = 2,
    Vmpl3 = 3,
}


// #[repr(u32)]
// pub enum VtpmKnownHandles {
//     Unknown = 0x0,
//     AvmAk = 0x81000003,
//     // GceEk = 0x81000001,
//     // GceAk = 0x81008F00, // used by go-tpm-tools for ECC (https://github.com/google/go-tpm-tools/blob/d94cf988f2d5731919f476bda1be5641f6164e52/client/handles.go#L31C38-L31C48)
// }
