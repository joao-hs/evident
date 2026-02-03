use std::panic;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vmm_type_count = [
        cfg!(feature = "snp_avm"),
        cfg!(feature = "snp_ec2"),
        cfg!(feature = "snp_gce"),
        cfg!(feature = "snp_qemu"),
        cfg!(feature = "snp_mock"),
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    if vmm_type_count != 1 {
        panic!("Exactly one VMM type feature must be enabled at a time.")
    }

    let qemu_vmpl_count = [
        cfg!(feature = "qemu_vmpl0"),
        cfg!(feature = "qemu_vmpl1"),
        cfg!(feature = "qemu_vmpl2"),
        cfg!(feature = "qemu_vmpl3"),
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    if cfg!(feature = "snp_qemu") && qemu_vmpl_count != 1 {
        panic!("You must set the guest VMPL where the evident server will run.")
    }

    if !cfg!(feature = "snp_qemu") && qemu_vmpl_count != 0 {
        panic!("Conflict of build features. Cannot set VMPL for cloud provider managed VMM.")
    }

    tonic_prost_build::configure()
        .file_descriptor_set_path("proto/descriptor.bin")
        .compile_protos(
            &["proto/remote_attestation/v1/remote_attestation.proto"],
            &["proto"],
        )?;
    Ok(())
}
