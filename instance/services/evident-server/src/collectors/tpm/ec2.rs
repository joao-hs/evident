use crate::collectors::tpm::SoftwareEvidenceCollector;
use common_core::{
    errors::{AttestationError, EvidentError, TpmError},
    proto::{
        EllipticCurve, Evidence, KeyAlgorithm, KeyEncoding, PublicKey as ProtoPublicKey,
        evidence_bundle::SoftwareEvidence, public_key::KeyParams,
    },
};
use log::{debug, warn};
use nom::{IResult, bytes::complete::take};
use p384::{PublicKey, ecdsa, pkcs8::EncodePublicKey};
use sha2::digest::DynDigest;
use std::sync::{Arc, Mutex};
use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    constants::{SessionType, Tss2ResponseCodeKind},
    handles::{KeyHandle, PersistentTpmHandle, SessionHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
        resource_handles::Provision,
    },
    structures::{
        Data, EccPoint, EccScheme, EncryptedSecret, HashScheme, IdObject,
        KeyDerivationFunctionScheme, PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder,
        PublicEccParametersBuilder, SignatureScheme, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    traits::Marshall,
};

// EC2's NitroTPM starts with:

// - an SRK (ECC) at 0x81000001
//   - Name algorithm: SHA256
//   - fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt
//   - Curve ID: NIST p256
//   - Symmetric algorithm/mode/keybits: AES / CFB / 128
// const EC2_SRK_PERSISTENT_HANDLE: u32 = 0x81000001;

// - an EK (RSA) at 0x81010001
//   - Name algorithm: SHA256
//   - fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt
//   - bits: 2048
//   - Symmetric algorithm/mode/keybits: AES / CFB / 128
//   - auth policy: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
// const EC2_RSA_EK_PERSISTENT_HANDLE: u32 = 0x81010001;

// - an EK (ECC) at 0x81010016
//   - Name algorithm: SHA384
//   - fixedtpm|fixedparent|sensitivedataorigin|userwithauth|adminwithpolicy|restricted|decrypt
//   - Curve ID: NIST p384
//   - Symmetric algorithm/mode/keybits: AES / CFB / 256
//   - auth policy: b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12
const EC2_ECC_EK_PERSISTENT_HANDLE: u32 = 0x81010016;
const EC2_ECC_AK_PERSISTENT_HANDLE: u32 = 0x81018000;

const PCR_SLOTS: [PcrSlot; 3] = [PcrSlot::Slot4, PcrSlot::Slot11, PcrSlot::Slot12];

pub struct Ec2TpmWrapper {
    context: Arc<Mutex<Context>>,

    ek_handle: KeyHandle,
    ak_handle: KeyHandle,
    ak_public_key_data: Vec<u8>,
}

impl Ec2TpmWrapper {
    pub fn new() -> Result<Self, EvidentError> {
        debug!("Initializing GceTpmWrapper...");

        let tcti = TctiNameConf::Device(Default::default());
        debug!("Created TCTI configuration: {:?}", tcti);

        let mut context = Context::new(tcti)?;
        debug!("Created TPM context");

        let ek_handle: KeyHandle = context
            .execute_without_session(|ctx| {
                ctx.tr_from_tpm_public(
                    PersistentTpmHandle::new(EC2_ECC_EK_PERSISTENT_HANDLE)?.into(),
                )
            })?
            .into();

        let ak_handle: KeyHandle = Self::with_new_session(&mut context, |context| {
            Self::create_ecc_ak(context, ek_handle)
        })?;

        let ak_public_key_data: Vec<u8> = Self::with_new_session(&mut context, |context| {
            Self::get_ak_public_key_data(context, ak_handle)
        })?;
        debug!("Successfully initialized Ec2TpmWrapper");

        Ok(Self {
            context: Arc::new(Mutex::new(context)),
            ek_handle,
            ak_handle,
            ak_public_key_data,
        })
    }

    fn create_ecc_ak(
        context: &mut Context,
        ek_handle: KeyHandle,
    ) -> Result<KeyHandle, EvidentError> {
        debug!("Creating ECC Attestation Key (AK) under the EK...");

        // 1. Create the AK template
        let ak_template_builder = PublicBuilder::new();
        let ak_template = ak_template_builder
            .with_name_hashing_algorithm(HashingAlgorithm::Sha384)
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_restricted(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_sign_encrypt(true)
                    .with_no_da(true)
                    .with_decrypt(false)
                    .with_encrypted_duplication(false)
                    .build()?,
            )
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .with_restricted(true)
                    .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_curve(EccCurve::NistP384)
                    .with_is_signing_key(true)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()?,
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?;

        // 2. Create the AK under the EK
        let result = context.create(ek_handle, ak_template, None, None, None, None)?;

        let ak_loaded_handle = context.load(ek_handle, result.out_private, result.out_public)?;

        debug!(
            "Successfully created and loaded ECC AK with handle: {:?}",
            ak_loaded_handle
        );

        // 3. Make the AK persistent at a well-known handle
        if let Err(e) = context.evict_control(
            Provision::Owner,
            ak_loaded_handle.into(),
            PersistentTpmHandle::new(EC2_ECC_AK_PERSISTENT_HANDLE)?.into(),
        ) {
            match e {
                tss_esapi::Error::Tss2Error(tss2_response_code) => {
                    // if tss2_response_code is present and is NvDefined, warn message
                    // else return error
                    if let Some(Tss2ResponseCodeKind::NvDefined) = tss2_response_code.kind() {
                        // probably the server has restarted in current VM's lifetime
                        warn!(
                            "Persistent handle {EC2_ECC_AK_PERSISTENT_HANDLE:#X} is already occupied, assuming it is the ECC AK. Error details: {e:?}"
                        );
                    } else {
                        return Err(EvidentError::from(e));
                    }
                }
                tss_esapi::Error::WrapperError(_) => return Err(EvidentError::from(e)),
            }
        }

        debug!(
            "ECC AK persisted at handle: 0x{:08x}",
            EC2_ECC_AK_PERSISTENT_HANDLE
        );

        let ak_handle: KeyHandle = context
            .execute_without_session(|ctx| {
                ctx.tr_from_tpm_public(TpmHandle::try_from(EC2_ECC_AK_PERSISTENT_HANDLE)?)
            })?
            .into();

        Ok(ak_handle)
    }

    fn get_ak_public_key_data(
        context: &mut Context,
        ak_handle: KeyHandle,
    ) -> Result<Vec<u8>, EvidentError> {
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
                            "failed to parse ecc ak public key bytes: {e}"
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
                            "failed to encode public key to der format: {e}"
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

impl SoftwareEvidenceCollector for Ec2TpmWrapper {
    fn collect_software_evidence(
        &self,
        user_data: [u8; 32],
    ) -> Result<SoftwareEvidence, EvidentError> {
        debug!("Starting software evidence collection...");

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &PCR_SLOTS)
            .build()?;
        debug!("PCR selection list built: {:?}", pcr_selection_list);

        let user_data = Data::try_from(user_data.as_slice())?;
        debug!("Nonce converted to TPM Data structure");

        let mut context_guard = self.context.lock().map_err(|e| {
            AttestationError::LockError(format!(
                "could not obtain lock for using context, possibly another thread panicked while holding the lock: {e}"
            ))
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
                "unsupported TPM signature algorithm: {:?}",
                tpmt_signature.algorithm()
            ))
            .into());
        }

        let tpmt_signature_bytes = tpmt_signature.marshall()?;
        debug!("TPMT_SIGNATURE marshalled into raw bytes");

        let (_, signature) = ecdsa_signature(&tpmt_signature_bytes).map_err(|e| {
            AttestationError::CodecError(format!(
                "failed to parse tpm signature into ecdsa format: {e}"
            ))
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
                certificate: None,
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
        }))
    }

    fn bind_elements(&self, hasher: &mut dyn DynDigest) {
        hasher.update(&self.ak_public_key_data);
    }

    fn get_ek_pub_key(&self) -> Result<Vec<u8>, EvidentError> {
        let mut context_guard = self.context.lock().map_err(|_| {
            AttestationError::LockError(
                "could not obtain lock for using context, possibly another thread panicked while holding the lock".to_string(),
            )
        })?;

        context_guard.execute_without_session(|ctx| {
            let (ek_public, _, _) = ctx
                .read_public(self.ek_handle)
                .map_err(|e| EvidentError::TpmError(TpmError::from(e)))?;
            match ek_public {
                Public::Ecc { unique, .. } => {
                    let public_key_bytes = {
                        let mut bytes = vec![0x04]; // Uncompressed point indicator
                        bytes.extend_from_slice(unique.x().value());
                        bytes.extend_from_slice(unique.y().value());
                        bytes
                    };

                    PublicKey::from_sec1_bytes(&public_key_bytes)
                        .map_err(|e| {
                            EvidentError::AttestationError(AttestationError::CodecError(format!(
                                "failed to parse ecc ek public key bytes: {e}"
                            )))
                        })?
                        .to_public_key_der()
                        .map(|key| key.to_vec())
                        .map_err(|e| {
                            EvidentError::AttestationError(AttestationError::CodecError(format!(
                                "failed to encode ecc ek public key to der format: {e}"
                            )))
                        })
                }
                _ => Err(EvidentError::AttestationError(
                    AttestationError::UnexpectedKeyType("loaded EK is not of ECC type".to_string()),
                )),
            }
        })
    }

    fn get_ak_key_name(&self) -> Result<Vec<u8>, EvidentError> {
        let mut context_guard = self.context.lock().map_err(|_| {
            AttestationError::LockError(
                "could not obtain lock for using context, possibly another thread panicked while holding the lock".to_string(),
            )
        })?;

        context_guard.execute_without_session(|ctx| {
            let ak_name = ctx.tr_get_name(self.ak_handle.into())?;
            Ok(ak_name.value().to_vec())
        })
    }

    fn activate_credential(
        &self,
        credential_blob: Vec<u8>,
        encrypted_secret: Vec<u8>,
    ) -> Result<Vec<u8>, EvidentError> {
        let mut context_guard = self
            .context
            .lock()
            .map_err(|e| {
                AttestationError::LockError(format!(
                    "could not obtain lock for using context, possibly another thread panicked while holding the lock: {e}"
                ))
            })?;

        let secret = Self::with_new_session(&mut context_guard, |context| {
            let id_object = IdObject::try_from(credential_blob)?;
            let encrypted_secret = EncryptedSecret::try_from(encrypted_secret)?;

            Ok(context.activate_credential(
                self.ak_handle,
                self.ek_handle,
                id_object,
                encrypted_secret,
            )?)
        })?;

        Ok(secret.value().to_vec())
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

    let r_array: [u8; 48] = r_bytes.try_into().map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?;
    let s_array: [u8; 48] = s_bytes.try_into().map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?;
    let mut signature_raw_bytes = [0u8; 96];
    signature_raw_bytes[..48].copy_from_slice(&r_array);
    signature_raw_bytes[48..].copy_from_slice(&s_array);
    let signature =
        ecdsa::Signature::from_bytes(signature_raw_bytes.as_slice().into()).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
        })?;
    Ok((input, signature))
}
