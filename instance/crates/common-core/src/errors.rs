use sev::error::{AttestationReportError, FirmwareError, UserApiError};
use thiserror::Error;
use tss_esapi::constants::Tss2ResponseCode;

#[derive(Debug, Error)]
pub enum EvidentError {
    #[error(transparent)]
    AttestationError(#[from] AttestationError),

    #[error(transparent)]
    SnpError(#[from] SnpError),

    #[error(transparent)]
    TpmError(#[from] TpmError),

    #[error("Error: I/O: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("Error: Attestation: Codec: {0}")]
    CodecError(String),
    #[error("Error: Attestation: CertificateNotFound: {0}")]
    CertificateNotFound(String),
    #[error("Error: Attestation: UnexpectedKeyType: {0}")]
    UnexpectedKeyType(String),
    #[error("Error: Attestation: LockError: {0}")]
    LockError(String),
    #[error("Error: Attestation: UnexpectedSignatureAlgorithm: {0}")]
    UnexpectedSignatureAlgorithm(String),
}

#[derive(Debug, Error)]
pub enum SnpError {
    #[error("Error: SNP: Firmware: {0}")]
    FirmwareError(String),
    #[error("Error: SNP: I/O: {0}")]
    IOError(String),
    #[error("Error: SNP: API: {0}")]
    ApiError(String),
    #[error("Error: SNP: VMM: {0}")]
    VmmError(String),
    #[error("Error: SNP: UUID: {0}")]
    UuidError(String),
    #[error("Error: SNP: Hashstick: {0}")]
    HashstickError(String),
    #[error("Error: SNP: Invalid VMPL")]
    VmplError,
    #[error("Error: SNP: Attestation Report: {0}")]
    AttestationReportError(String),
    #[error("Error: SNP: Unknown")]
    Unknown,
}

impl From<sev::error::UserApiError> for EvidentError {
    fn from(value: UserApiError) -> Self {
        EvidentError::SnpError(SnpError::from(value))
    }
}

impl From<sev::error::UserApiError> for SnpError {
    fn from(value: sev::error::UserApiError) -> Self {
        match value {
            UserApiError::FirmwareError(firmware_error) => {
                SnpError::FirmwareError(match firmware_error {
                    FirmwareError::KnownSevError(sev_error) => format!("SEV: {sev_error:?}"),
                    FirmwareError::UnknownSevError(sev_error) => {
                        format!("Unknown SEV: {sev_error:?}")
                    }
                    FirmwareError::IoError(error) => format!("I/O: {error:?}"),
                })
            }
            UserApiError::IOError(error) => SnpError::IOError(format!("{error:?}")),
            UserApiError::ApiError(cert_error) => SnpError::ApiError(format!("{cert_error:?}")),
            UserApiError::VmmError(vmm_error) => SnpError::VmmError(format!("{vmm_error:?}")),
            UserApiError::UuidError(error) => SnpError::UuidError(format!("{error:?}")),
            UserApiError::HashstickError(hashstick_error) => {
                SnpError::HashstickError(format!("{hashstick_error:?}"))
            }
            UserApiError::VmplError => SnpError::VmplError,
            UserApiError::AttestationReportError(attestation_report_error) => {
                SnpError::AttestationReportError(match attestation_report_error {
                    AttestationReportError::UnsupportedReportVersion(e) => {
                        format!("Unsupported report version: {e:?}")
                    }
                    AttestationReportError::UnsupportedField(e) => {
                        format!("Unsupported field: {e:?}")
                    }
                    AttestationReportError::MaskedChipId => "MASK_CHIP_ID enabled".to_string(),
                })
            }
            UserApiError::Unknown => SnpError::Unknown,
        }
    }
}

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("Error: TPM: {0}")]
    WrapperError(String),
    #[error("Error: TPM: TSS2: {0}")]
    Tss2Error(String),
}

impl From<tss_esapi::Error> for EvidentError {
    fn from(value: tss_esapi::Error) -> Self {
        EvidentError::TpmError(TpmError::from(value))
    }
}

impl From<tss_esapi::Error> for TpmError {
    fn from(value: tss_esapi::Error) -> Self {
        match value {
            tss_esapi::Error::WrapperError(wrapper_error_kind) => {
                TpmError::WrapperError(format!("{wrapper_error_kind:?}"))
            }
            tss_esapi::Error::Tss2Error(tss2_response_code) => {
                TpmError::Tss2Error(match tss2_response_code {
                    Tss2ResponseCode::Success => "Success".to_string(),
                    Tss2ResponseCode::FormatZero(format_zero_response_code) => {
                        format!("FormatZero: {format_zero_response_code:?}")
                    }
                    Tss2ResponseCode::FormatOne(format_one_response_code) => {
                        format!("FormatOne: {format_one_response_code:?}")
                    }
                })
            }
        }
    }
}
