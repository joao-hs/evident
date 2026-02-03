#[derive(Debug, thiserror::Error)]
pub enum EvidenceCollectionError {
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("IO error ocurred: {0}")]
    IOError(#[from] std::io::Error),

    #[error("SEV error occurred: {0}")]
    SnpError(#[from] sev::error::UserApiError),

    #[error("TSS ESAPI error occurred: {0}")]
    TssEsapiError(#[from] tss_esapi::Error),

    #[error("Internal error: {0}")]
    InternalError(String),
}

