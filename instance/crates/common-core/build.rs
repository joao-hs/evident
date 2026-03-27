fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .file_descriptor_set_path("proto/descriptor.bin")
        .compile_protos(
            &[
                "proto/evident_protocol/v1/pubkey.proto",
                "proto/evident_protocol/v1/verifier_attester.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
