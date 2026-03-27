use crate::target_info::{TARGET_TYPE, TargetTypeEnum, VMPL};
use common_core::{
    errors::{AttestationError, EvidentError},
    proto::{
        Certificate, CertificateEncoding, CertificateType, EllipticCurve, Evidence, KeyAlgorithm,
        KeyEncoding, PublicKey, evidence_bundle::HardwareEvidence, public_key::KeyParams,
    },
};
use sev::firmware::{guest::Firmware, host::CertType};
use x509_parser::prelude::{FromDer, X509Certificate};

pub fn ec2_gce_initialize() -> Result<(), EvidentError> {
    // No specific initialization needed for EC2/GCE SNP evidence collection
    Ok(())
}

pub fn ec2_gce_collect_hardware_evidence(
    user_data: [u8; 64],
) -> Result<HardwareEvidence, EvidentError> {
    let mut firmware = Firmware::open()?;

    let (raw_report, cert_chain) = firmware.get_ext_report(
        Some(1), // Current ABI version
        Some(user_data),
        Some(VMPL as u32),
    )?;

    let signed_raw = raw_report
        .get(0x0..=0x29f)
        .ok_or_else(|| {
            AttestationError::CodecError(
                "raw report is too short to contain the signed portion".to_string(),
            )
        })?
        .to_vec();

    let signature = raw_report
        .get(0x2A0..=0x49F)
        .ok_or_else(|| {
            AttestationError::CodecError(
                "raw report is too short to contain the signature portion".to_string(),
            )
        })?
        .to_vec();

    let wanted = match TARGET_TYPE {
        TargetTypeEnum::SnpEc2 => CertType::VLEK,
        TargetTypeEnum::SnpGce => CertType::VCEK,
    };

    let certificate = cert_chain
        .and_then(|chain| {
            chain
                .into_iter()
                .find(|cert| cert.cert_type == wanted)
                .map(|cert| cert.data.clone())
        })
        .ok_or_else(|| {
            AttestationError::CertificateNotFound(format!(
                "{wanted:?} certificate not found in the certificate chain"
            ))
        })?;

    let key_data = {
        let (_, parsed_cert) = X509Certificate::from_der(&certificate).map_err(|e| {
            AttestationError::CodecError(format!("failed to parse certificate: {:?}", e))
        })?;
        let spki = parsed_cert.tbs_certificate.subject_pki;
        spki.raw.to_vec()
    };

    Ok(HardwareEvidence::SnpEvidence(Evidence {
        signed_raw,
        signature,
        signing_key: Some(PublicKey {
            algorithm: KeyAlgorithm::Ec.into(),
            encoding: KeyEncoding::SpkiDer.into(),
            key_data,
            certificate: Some(Certificate {
                r#type: CertificateType::X509.into(),
                encoding: CertificateEncoding::Der.into(),
                data: certificate,
            }),
            key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
        }),
    }))
}
