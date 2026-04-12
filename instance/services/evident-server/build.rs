use std::panic;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(feature = "debug") {
        return Ok(());
    }

    if cfg!(feature = "request_certificate") {
        // Ensure the environment variable is set before compiling
        env!("CERTIFICATE_ISSUER_ENDPOINT");
    }

    let vmm_type_count = [cfg!(feature = "snp_ec2"), cfg!(feature = "snp_gce")]
        .iter()
        .filter(|&&x| x)
        .count();

    if vmm_type_count != 1 {
        panic!("Exactly one VMM type feature must be enabled at a time.")
    }

    Ok(())
}
