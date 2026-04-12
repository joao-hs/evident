use common_core::constants;
use nix::unistd::{Gid, Uid, chown};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P384_SHA384, PublicKeyData,
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use time::{Duration, OffsetDateTime};

fn ensure_parent_dir(path: &str, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| format!("path has no parent: {path}"))?;

    fs::create_dir_all(parent)?;
    set_owner_and_mode(parent, mode)?;
    Ok(())
}

fn set_owner_and_mode(path: &Path, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn write_file(path: &str, contents: &[u8], mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(mode)
        .open(path)?;
    file.write_all(contents)?;
    set_owner_and_mode(Path::new(path), mode)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure parent directories exist
    ensure_parent_dir(constants::INSTANCE_CERTIFICATE_PATH, 0o755)?;
    ensure_parent_dir(constants::INSTANCE_CERTIFICATE_SIGNING_REQUEST_PATH, 0o755)?;
    ensure_parent_dir(constants::INSTANCE_PUBLIC_KEY_PATH, 0o755)?;
    ensure_parent_dir(constants::INSTANCE_PRIVATE_KEY_PATH, 0o700)?;
    ensure_parent_dir(constants::GRPC_EVIDENT_SERVER_CERTIFICATE_PATH, 0o755)?;
    ensure_parent_dir(constants::GRPC_EVIDENT_SERVER_PUBLIC_KEY_PATH, 0o755)?;
    ensure_parent_dir(constants::GRPC_EVIDENT_SERVER_PRIVATE_KEY_PATH, 0o700)?;

    // --- gRPC Server TLS key pair ---
    {
        // Generate a PKCS#8 PEM private key using ECDSA P-384 / SHA-384
        let grpc_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        write_file(
            constants::GRPC_EVIDENT_SERVER_PRIVATE_KEY_PATH,
            grpc_key.serialize_pem().as_bytes(),
            0o400,
        )?;

        // Generate a self-signed X.509 certificate with CN=evident-server, valid for 3650 days
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "evident-server");
        params.distinguished_name = dn;
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = params.not_before + Duration::days(3650);

        let cert = params.self_signed(&grpc_key)?;
        write_file(
            constants::GRPC_EVIDENT_SERVER_CERTIFICATE_PATH,
            cert.pem().as_bytes(),
            0o444,
        )?;
    }

    // --- Instance key pair ---
    {
        let instance_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        write_file(
            constants::INSTANCE_PRIVATE_KEY_PATH,
            instance_key.serialized_der(),
            0o400,
        )?;

        let instance_public = instance_key.subject_public_key_info();
        write_file(
            constants::INSTANCE_PUBLIC_KEY_PATH,
            instance_public.as_slice(),
            0o444,
        )?;

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "evident-instance");
        params.distinguished_name = dn;

        // TODO: we can add SAN entries here if needed
        let csr = params.serialize_request(&instance_key)?;
        write_file(
            constants::INSTANCE_CERTIFICATE_SIGNING_REQUEST_PATH,
            csr.pem()?.as_bytes(),
            0o444,
        )?;

        params.not_before = OffsetDateTime::now_utc();
        params.not_after = params.not_before + Duration::days(3650);

        let cert = params.self_signed(&instance_key)?;
        write_file(
            constants::INSTANCE_SELF_SIGNED_CERTIFICATE_PATH,
            cert.pem().as_bytes(),
            0o444,
        )?;
    }

    Ok(())
}
