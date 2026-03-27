use crate::collectors::tpm::SoftwareEvidenceCollector;
use common_core::{
    errors::{AttestationError, EvidentError},
    proto::{
        Certificate, CertificateEncoding, CertificateType, EllipticCurve, Evidence, KeyAlgorithm,
        KeyEncoding, PublicKey as ProtoPublicKey, evidence_bundle::SoftwareEvidence,
        public_key::KeyParams,
    },
};
use hex::ToHex;
use log::{debug, warn};
use nom::{IResult, bytes::complete::take};
use p256::{PublicKey, ecdsa, pkcs8::EncodePublicKey};
use sha2::digest::DynDigest;
use std::sync::{Arc, Mutex};
use tss_esapi::{
    Context, TctiNameConf,
    constants::{SessionType, Tss2ResponseCodeKind},
    handles::{
        KeyHandle, NvIndexHandle, NvIndexTpmHandle, PersistentTpmHandle, SessionHandle, TpmHandle,
    },
    interface_types::{
        algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
        resource_handles::{Hierarchy, NvAuth, Provision},
    },
    structures::{
        Data, PcrSelectionListBuilder, PcrSlot, Public, SignatureScheme, SymmetricDefinition,
    },
    traits::{Marshall, UnMarshall},
};
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

// const GCE_RSA_EK_CERT: u32 = 0x1C00002;
// const GCE_ECC_EK_CERT: u32 = 0x1C0000A;
// const GCE_RSA_AK_CERT: u32 = 0x1C10000;
// const GCE_RSA_AK_TEMPLATE: u32 = 0x1C10001;
const GCE_ECC_AK_CERT: u32 = 0x1C10002;
const GCE_ECC_AK_TEMPLATE: u32 = 0x1C10003;
const GCE_ECC_AK_PERSISTENT_HANDLE: u32 = 0x81018000;

const PCR_SLOTS: [PcrSlot; 3] = [PcrSlot::Slot4, PcrSlot::Slot11, PcrSlot::Slot12];

pub struct GceTpmWrapper {
    context: Arc<Mutex<Context>>,

    ak_handle: KeyHandle,
    ak_public_key_data: Vec<u8>,

    ak_certificate: Vec<u8>,
}

impl GceTpmWrapper {
    pub fn new() -> Result<Self, EvidentError> {
        debug!("Initializing GceTpmWrapper...");

        let tcti = TctiNameConf::Device(Default::default());
        debug!("Created TCTI configuration: {:?}", tcti);

        let mut context = Context::new(tcti)?;
        debug!("Created TPM context");

        let (ak_handle, ak_certificate) = Self::with_new_session(&mut context, |context| {
            debug!("Starting new session to create primary ECC AK and retrieve certificate");

            let (ak_handle, _ak_public) = Self::create_primary_ecc_ak(context)?;

            let ak_certificate = Self::get_ecc_ak_certificate(context)?;

            Ok((ak_handle, ak_certificate))
        })?;

        let ak_public_key_data = Self::with_new_session(&mut context, |context| {
            Self::read_ak_public_key_data(context, ak_handle)
        })?;

        debug!("Successfully initialized GceTpmWrapper");

        Ok(GceTpmWrapper {
            context: Arc::new(Mutex::new(context)),
            ak_handle,
            ak_certificate,
            ak_public_key_data,
        })
    }

    fn create_primary_ecc_ak(context: &mut Context) -> Result<(KeyHandle, Public), EvidentError> {
        debug!("Starting creation of primary ECC AK...");

        let template_handle = NvIndexTpmHandle::new(GCE_ECC_AK_TEMPLATE)?;
        debug!(
            "Resolved NV index handle for ECC AK template: {:?}",
            template_handle
        );

        let template_handle: NvIndexHandle = context
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(template_handle.into()))?
            .into();
        debug!(
            "Loaded NV index handle into TPM context: {:?}",
            template_handle
        );

        let (template_public, _) =
            context.execute_without_session(|ctx| ctx.nv_read_public(template_handle))?;
        let template_data_size = template_public.data_size();
        debug!(
            "Read NV public data for template, size: {} bytes",
            template_data_size
        );

        let auth_handle = NvAuth::NvIndex(template_handle);
        debug!("Using NV auth handle: {:?}", auth_handle);

        let nv_read_result = context.nv_read(
            auth_handle,
            template_handle,
            u16::try_from(template_data_size).map_err(|e| {
                AttestationError::CodecError(format!(
                    "template size could not be converted to u16 {e}",
                ))
            })?,
            0, // offset
        )?;
        debug!(
            "Read NV data for template, size: {} bytes",
            nv_read_result.value().len()
        );

        let template_data = nv_read_result.value();
        debug!("Unmarshalling template data...");

        let public_template = Public::unmarshall(template_data)?;
        debug!("Successfully unmarshalled public template");

        debug!("Creating primary key using the unmarshalled template...");
        let primary_key_result = context.create_primary(
            Hierarchy::Endorsement,
            public_template,
            None,
            None,
            None,
            None,
        )?;
        debug!(
            "Successfully created primary key. Key handle: {:?}, Public: {:?}",
            primary_key_result.key_handle, primary_key_result.out_public
        );

        if let Err(e) = context.evict_control(
            Provision::Owner,
            primary_key_result.key_handle.into(),
            PersistentTpmHandle::new(GCE_ECC_AK_PERSISTENT_HANDLE)?.into(),
        ) {
            match e {
                tss_esapi::Error::Tss2Error(tss2_response_code) => {
                    // if tss2_response_code is present and is NvDefined, warn message
                    // else return error
                    if let Some(Tss2ResponseCodeKind::NvDefined) = tss2_response_code.kind() {
                        // probably the server has restarted in current VM's lifetime
                        warn!(
                            "Persistent handle {GCE_ECC_AK_PERSISTENT_HANDLE:#X} is already occupied, assuming it is the ECC AK. Error details: {e:?}"
                        );
                    } else {
                        return Err(EvidentError::from(e));
                    }
                }
                tss_esapi::Error::WrapperError(_) => return Err(EvidentError::from(e)),
            }
        }

        debug!(
            "Key handle made persistent at address: {}",
            GCE_ECC_AK_PERSISTENT_HANDLE
        );

        let ak_handle: KeyHandle = context
            .execute_without_session(|ctx| {
                ctx.tr_from_tpm_public(TpmHandle::try_from(GCE_ECC_AK_PERSISTENT_HANDLE)?)
            })?
            .into();
        debug!("Resolved persistent handle for ECC AK: {:?}", ak_handle);

        Ok((ak_handle, primary_key_result.out_public))
    }

    fn read_ak_public_key_data(
        context: &mut Context,
        ak_handle: KeyHandle,
    ) -> Result<Vec<u8>, EvidentError> {
        debug!("Reading AK public key data...");

        let (ak_loaded_public, _, _) =
            context.execute_without_session(|ctx| ctx.read_public(ak_handle))?;
        let attrs = ak_loaded_public.object_attributes();
        debug!("Loaded AK capabilities - Sign: {}", attrs.sign_encrypt());
        debug!("Loaded AK capabilities - Decrypt: {}", attrs.decrypt());
        debug!(
            "Loaded AK capabilities - Restricted: {}",
            attrs.restricted()
        );
        debug!("Loaded AK capabilities - Fixed TPM: {}", attrs.fixed_tpm());
        debug!(
            "Loaded AK capabilities - Fixed Parent: {}",
            attrs.fixed_parent()
        );
        debug!(
            "Loaded AK capabilities - User With Auth: {}",
            attrs.user_with_auth()
        );
        debug!(
            "Loaded AK capabilities - Admin With Policy: {}",
            attrs.admin_with_policy()
        );

        match ak_loaded_public {
            Public::Ecc {
                parameters: ecc_params,
                unique: ecc_unique,
                ..
            } => {
                let curve = ecc_params.ecc_curve();
                debug!("AK ECC curve ID: {:?}", curve);

                let x_bytes = ecc_unique.x().value();
                let y_bytes = ecc_unique.y().value();
                debug!("AK ECC public key X coordinate: `{}`", hex::encode(x_bytes));
                debug!("AK ECC public key Y coordinate: `{}`", hex::encode(y_bytes));

                let mut public_key_bytes = vec![0x04]; // Uncompressed point indicator
                public_key_bytes.extend_from_slice(x_bytes);
                public_key_bytes.extend_from_slice(y_bytes);

                let ecc_public_key =
                    PublicKey::from_sec1_bytes(&public_key_bytes).map_err(|e| {
                        AttestationError::CodecError(format!(
                            "failed to parse ECC AK public key bytes: {e}"
                        ))
                    })?;
                debug!(
                    "Successfully parsed ECC AK public key ({} bytes): `{}`",
                    public_key_bytes.len(),
                    hex::encode(&public_key_bytes)
                );

                Ok(ecc_public_key
                    .to_public_key_der()
                    .map_err(|e| {
                        AttestationError::CodecError(format!(
                            "failed to encode ecc ak public key to der format: {e}"
                        ))
                    })?
                    .to_vec())
            }
            _ => Err(AttestationError::UnexpectedKeyType(
                "loaded ak is not of ecc type".to_string(),
            )
            .into()),
        }
    }

    fn get_ecc_ak_certificate(context: &mut Context) -> Result<Vec<u8>, EvidentError> {
        debug!("Starting retrieval of ECC AK certificate...");

        let nv_index_handle = NvIndexTpmHandle::new(GCE_ECC_AK_CERT)?;
        debug!(
            "Resolved NV index handle for ECC AK certificate: {:?}",
            nv_index_handle
        );

        let nv_index_handle: NvIndexHandle = context
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_index_handle.into()))?
            .into();
        debug!(
            "Loaded NV index handle into TPM context: {:?}",
            nv_index_handle
        );

        let (nv_public, _) =
            context.execute_without_session(|ctx| ctx.nv_read_public(nv_index_handle))?;
        let nv_data_size = nv_public.data_size();
        debug!(
            "Read NV public data for certificate, size: {} bytes",
            nv_data_size
        );

        let auth_handle = NvAuth::NvIndex(nv_index_handle);
        debug!("Using NV auth handle: {:?}", auth_handle);

        let nv_read_result = context.nv_read(
            auth_handle,
            nv_index_handle,
            u16::try_from(nv_data_size).map_err(|e| {
                AttestationError::CodecError(format!(
                    "certificate size could not be converted to u16: {e}"
                ))
            })?,
            0, // offset
        )?;
        debug!(
            "Read NV data for certificate, size: {} bytes",
            nv_read_result.value().len()
        );

        let ak_cert_data = nv_read_result.value().to_vec();
        debug!(
            "Successfully retrieved ECC AK certificate ({} bytes): `{}`",
            ak_cert_data.len(),
            hex::encode(&ak_cert_data)
        );

        let (_, x509_cert) = X509Certificate::from_der(&ak_cert_data).map_err(|e| {
            AttestationError::CodecError(format!(
                "failed to parse ECC AK certificate DER data: {e}"
            ))
        })?;
        debug!("Successfully parsed ECC AK certificate DER data");

        let public_key = x509_cert.public_key().raw.to_vec();
        debug!(
            "Extracted public key from ECC AK certificate: {}",
            hex::encode(&public_key)
        );

        x509_cert
            .extensions()
            .iter()
            .filter_map(|ext| {
                if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                    Some(aia.accessdescs.iter())
                } else {
                    None
                }
            })
            .flatten()
            .for_each(|access_desc| {
                debug!(
                    "Authority Information Access - Method: {:?}, Location: {:?}",
                    access_desc.access_method, access_desc.access_location
                );
            });

        let signature: String = x509_cert.signature_value.encode_hex();
        debug!(
            "Extracted signature from ECC AK certificate: `{}`",
            signature
        );

        Ok(ak_cert_data)
    }

    fn with_new_session<F, R>(context: &mut Context, f: F) -> Result<R, EvidentError>
    where
        F: FnOnce(&mut Context) -> Result<R, EvidentError>,
    {
        debug!("Creating a new session for the provided operation...");
        let session = context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?;
        context.set_sessions((session, None, None));

        let result = f(context);
        debug!("Operation executed within the session");

        context.clear_sessions();
        debug!("All sessions ended in the TPM context");

        if let Some(auth_session) = session {
            let session_handle: SessionHandle = auth_session.into();
            context.flush_context(session_handle.into())?;
            debug!(
                "Session handle flushed from TPM context: {:?}",
                auth_session
            );
        }

        result
    }
}

impl SoftwareEvidenceCollector for GceTpmWrapper {
    fn collect_software_evidence(&self, nonce: [u8; 32]) -> Result<SoftwareEvidence, EvidentError> {
        debug!("Starting software evidence collection...");

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &PCR_SLOTS)
            .build()?;
        debug!("PCR selection list built: {:?}", pcr_selection_list);

        let user_data = Data::try_from(nonce.as_slice())?;
        debug!("Nonce converted to TPM Data structure");

        let mut context_guard = self.context.lock().map_err(|_| {
            AttestationError::LockError(
                "could not obtain lock for using context, possibly another thread panicked while holding the lock".to_string(),
            )
        })?;
        debug!("Successfully acquired lock on TPM context");

        let (attest, tpmt_signature) = Self::with_new_session(&mut context_guard, |context| {
            debug!("Starting TPM quote operation...");
            let result = context.quote(
                self.ak_handle,
                user_data,
                SignatureScheme::Null,
                pcr_selection_list,
            )?;
            debug!("TPM quote operation completed successfully");
            Ok(result)
        })?;
        debug!("Quote and signature obtained from TPM");

        drop(context_guard);
        debug!("Released lock on TPM context");

        let quoted_data = attest.marshall()?;
        debug!("Attestation data marshalled into raw bytes");

        if tpmt_signature.algorithm() != SignatureSchemeAlgorithm::EcDsa {
            debug!(
                "Unsupported TPM signature algorithm: {:?}",
                tpmt_signature.algorithm()
            );
            return Err(AttestationError::UnexpectedSignatureAlgorithm(format!(
                "unsupported tpm signature algorithm: {:?}",
                tpmt_signature.algorithm()
            ))
            .into());
        }

        let tpmt_signature_bytes = tpmt_signature.marshall()?;
        debug!("TPMT_SIGNATURE marshalled into raw bytes");

        let (_, signature) = ecdsa_signature(&tpmt_signature_bytes).map_err(|e| {
            debug!("Failed to parse TPM signature: {:?}", e);
            AttestationError::CodecError(
                "failed to parse tpm signature into ecdsa format".to_string(),
            )
        })?;

        let signature_bytes = signature.to_der().to_bytes();

        debug!("Software evidence collection completed successfully");
        Ok(SoftwareEvidence::TpmEvidence(Evidence {
            signed_raw: quoted_data,
            signature: signature_bytes.to_vec(),
            signing_key: Some(ProtoPublicKey {
                algorithm: KeyAlgorithm::Ec.into(),
                encoding: KeyEncoding::SpkiDer.into(),
                key_data: self.ak_public_key_data.clone(),
                certificate: Some(Certificate {
                    r#type: CertificateType::X509.into(),
                    encoding: CertificateEncoding::Der.into(),
                    data: self.ak_certificate.clone(),
                }),
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P256.into())),
            }),
        }))
    }

    fn bind_elements(&self, hasher: &mut dyn DynDigest) {
        hasher.update(&self.ak_certificate);
    }

    fn get_ek_pub_key(&self) -> Result<Vec<u8>, EvidentError> {
        panic!("no need to use this method for GCE TPM");
    }

    fn get_ak_key_name(&self) -> Result<Vec<u8>, EvidentError> {
        panic!("no need to use this method for GCE TPM");
    }

    fn activate_credential(
        &self,
        _credential_blob: Vec<u8>,
        _encrypted_secret: Vec<u8>,
    ) -> Result<Vec<u8>, EvidentError> {
        panic!("no need to use this method for GCE TPM");
    }
}

fn ecdsa_signature(input: &[u8]) -> IResult<&[u8], ecdsa::Signature> {
    // First two bytes: Signature Algorithm ID; for ecdsa should be 0x0018
    let (input, sig_alg_id) = take(2usize)(input)?;
    if sig_alg_id != [0x00, 0x18] {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    // Next two bytes: Hashing Algorithm ID; for SHA256 should be 0x000B
    let (input, hash_alg_id) = take(2usize)(input)?;
    if hash_alg_id != [0x00, 0x0B] {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    // Two components (r and s) of the ECDSA signature, prefixed with two bytes each for their length
    let (input, r_len_bytes) = take(2usize)(input)?;
    let r_len = u16::from_be_bytes(<[u8; 2]>::try_from(r_len_bytes).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?) as usize;
    let (input, r_bytes) = take(r_len)(input)?;

    let (input, s_len_bytes) = take(2usize)(input)?;
    let s_len = u16::from_be_bytes(<[u8; 2]>::try_from(s_len_bytes).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?) as usize;
    let (input, s_bytes) = take(s_len)(input)?;

    let r_array: [u8; 32] = r_bytes.try_into().map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?;
    let s_array: [u8; 32] = s_bytes.try_into().map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?;
    let mut signature_raw_bytes = [0u8; 64];
    signature_raw_bytes[..32].copy_from_slice(&r_array);
    signature_raw_bytes[32..].copy_from_slice(&s_array);
    let signature =
        ecdsa::Signature::from_bytes(signature_raw_bytes.as_slice().into()).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
        })?;
    Ok((input, signature))
}
