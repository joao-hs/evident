use crate::collectors::tpm::SoftwareEvidenceCollector;
use common_core::{
    errors::{AttestationError, EvidentError, TpmError},
    proto::{
        EllipticCurve, Evidence, KeyAlgorithm, KeyEncoding, PublicKey as ProtoPublicKey,
        evidence_bundle::SoftwareEvidence, public_key::KeyParams,
    },
};
use log::{debug, error, warn};
use nom::{IResult, bytes::complete::take};
use p384::{PublicKey, ecdsa, pkcs8::EncodePublicKey};
use sha2::digest::DynDigest;
use std::sync::{Arc, Mutex};
use tss_esapi::{Context, handles::KeyHandle, structures::PcrSlot};

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
    ak_public_key_spki_bytes: Vec<u8>,
}

impl Ec2TpmWrapper {
    pub fn new() -> Result<Self, EvidentError> {
        use tss_esapi::{TctiNameConf, handles::PersistentTpmHandle};

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

        let ak_public_key_spki_bytes: Vec<u8> = Self::with_new_session(&mut context, |context| {
            Self::get_ak_public_key_spki_bytes(context, ak_handle)
        })?;
        debug!("Successfully initialized Ec2TpmWrapper");

        Ok(Self {
            context: Arc::new(Mutex::new(context)),
            ek_handle,
            ak_handle,
            ak_public_key_spki_bytes,
        })
    }

    fn create_ecc_ak(
        context: &mut Context,
        ek_handle: KeyHandle,
    ) -> Result<KeyHandle, EvidentError> {
        use tss_esapi::{
            attributes::ObjectAttributesBuilder,
            constants::Tss2ResponseCodeKind,
            handles::{PersistentTpmHandle, TpmHandle},
            interface_types::{
                algorithm::{HashingAlgorithm, PublicAlgorithm},
                ecc::EccCurve,
                resource_handles::Provision,
            },
            structures::{
                EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PublicBuilder,
                PublicEccParametersBuilder, SymmetricDefinitionObject,
            },
        };

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

    fn get_ak_public_key_spki_bytes(
        context: &mut Context,
        ak_handle: KeyHandle,
    ) -> Result<Vec<u8>, EvidentError> {
        use tss_esapi::structures::Public;

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
        use tss_esapi::{
            constants::SessionType, handles::SessionHandle,
            interface_types::algorithm::HashingAlgorithm, structures::SymmetricDefinition,
        };

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

        if let Some(s) = session {
            let h: SessionHandle = s.into();
            context.flush_context(h.into())?;
        }

        result
    }
}

impl SoftwareEvidenceCollector for Ec2TpmWrapper {
    fn collect_software_evidence(
        &self,
        user_data: [u8; 32],
    ) -> Result<SoftwareEvidence, EvidentError> {
        use tss_esapi::{
            interface_types::algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
            structures::{Data, PcrSelectionListBuilder, SignatureScheme},
            traits::Marshall,
        };

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
                key_data: self.ak_public_key_spki_bytes.clone(),
                certificate: None,
                key_params: Some(KeyParams::EllipticCurve(EllipticCurve::P384.into())),
            }),
        }))
    }

    fn bind_elements(&self, hasher: &mut dyn DynDigest) {
        hasher.update(&self.ak_public_key_spki_bytes);
    }

    fn get_ek_pub_key(&self) -> Result<Vec<u8>, EvidentError> {
        use tss_esapi::structures::Public;

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
        use tss_esapi::{
            attributes::SessionAttributesBuilder,
            constants::SessionType,
            handles::{AuthHandle, SessionHandle},
            interface_types::{
                algorithm::HashingAlgorithm,
                session_handles::{AuthSession, PolicySession},
            },
            structures::{Auth, Digest, EncryptedSecret, IdObject, Nonce, SymmetricDefinition},
        };

        let credential_blob = IdObject::try_from(&credential_blob[2..]).inspect_err(|e| {
            error!("activate_credential: IdObject::try_from failed: {e:?}");
        })?;
        debug!("activate_credential: parsed IdObject ok");
        let encrypted_secret =
            EncryptedSecret::try_from(&encrypted_secret[2..]).inspect_err(|e| {
                error!("activate_credential: EncryptedSecret::try_from failed: {e:?}");
            })?;
        debug!("activate_credential: parsed EncryptedSecret ok");

        let mut context = self
            .context
            .lock()
            .map_err(|_|{
                error!("activate_credential: context lock poisoned");
                AttestationError::LockError("could not obtain lock for using context, possibly another thread panicked while holding the lock".to_string())
            })?;
        debug!("activate_credential: acquired context lock");

        context
            .tr_set_auth(self.ek_handle.into(), Auth::default())
            .inspect_err(|e| {
                error!("activate_credential: tr_set_auth(EK) failed: {e:?}");
            })?;
        debug!("activate_credential: tr_set_auth(EK) ok");
        context
            .tr_set_auth(self.ak_handle.into(), Auth::default())
            .inspect_err(|e| {
                error!("activate_credential: tr_set_auth(AK) failed: {e:?}");
            })?;
        debug!("activate_credential: tr_set_auth(AK) ok");

        // let session1 = context.start_auth_session(
        //     None,
        //     None,
        //     None,
        //     SessionType::Hmac,
        //     SymmetricDefinition::AES_256_CFB,
        //     HashingAlgorithm::Sha256,
        // )?;

        // let session2 = context.start_auth_session(
        //     None,
        //     None,
        //     None,
        //     SessionType::Policy,
        //     SymmetricDefinition::AES_256_CFB,
        //     HashingAlgorithm::Sha384, // must match the EK's name algorithm
        // )?;

        debug!(
            "activate_credential: calling ActivateCredential (activateHandle=AK {:?}, keyHandle=EK {:?}, shandle1=Password, shandle2=policy, shandle3=enc)",
            self.ak_handle, self.ek_handle,
        );
        let cert_info: Digest = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password), // shandle1: AK auth
                    Some(AuthSession::Password), // shandle2: EK auth
                    None,
                ),
                |ctx| {
                    ctx.activate_credential(
                        self.ak_handle,
                        self.ek_handle,
                        credential_blob,
                        encrypted_secret,
                    )
                },
            )
            .inspect_err(|e| {
                error!("activate_credential: Esys_ActivateCredential failed: {e:?}");
            })?;
        debug!(
            "activate_credential: ActivateCredential ok; certInfo={} bytes",
            cert_info.value().len(),
        );

        debug!("activate_credential: exit ok");
        Ok(cert_info.value().to_vec())
    }

    // fn activate_credential(
    //     &self,
    //     credential_blob: Vec<u8>,
    //     encrypted_secret: Vec<u8>,
    // ) -> Result<Vec<u8>, EvidentError> {
    //     use tss_esapi::{
    //         constants::SessionType,
    //         handles::{AuthHandle, SessionHandle},
    //         interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
    //         structures::{EncryptedSecret, IdObject, SymmetricDefinition},
    //     };

    //     let mut context = self
    //         .context
    //         .lock()
    //         .map_err(|e| AttestationError::LockError(format!("could not obtain lock for using context, possibly another thread panicked while holding the lock: {e}")))?;

    //     // The caller already gives us TPM-native byte representations.
    //     let credential_blob = IdObject::try_from(credential_blob)?;
    //     let encrypted_secret = EncryptedSecret::try_from(encrypted_secret)?;

    //     // Your AK was created with user_with_auth=true but with empty auth, so make that explicit.
    //     // context.tr_set_auth(self.ak_handle.into(), Default::default())?;
    //     // context.tr_set_auth(self.ek_handle.into(), Default::default())?;

    //     // Session 1 authorizes the first handle of ActivateCredential: the AK.
    //     let ak_auth_session = context.start_auth_session(
    //         None,
    //         None,
    //         None,
    //         SessionType::Hmac,
    //         SymmetricDefinition::AES_256_CFB,
    //         HashingAlgorithm::Sha256,
    //     )?;

    //     // Session 2 authorizes the second handle of ActivateCredential: the EK.
    //     //
    //     // IMPORTANT: for the NitroTPM ECC EK at 0x81010016, the policy digest is SHA384-sized,
    //     // so the policy session must also be SHA384.
    //     let ek_policy_session = context.start_auth_session(
    //         None,
    //         None,
    //         None,
    //         SessionType::Policy,
    //         SymmetricDefinition::AES_256_CFB,
    //         HashingAlgorithm::Sha384,
    //     )?;

    //     let result = (|| -> Result<Vec<u8>, EvidentError> {
    //         let policy_session = ek_policy_session.ok_or_else(|| {
    //             AttestationError::CodecError("failed to create EK policy session".to_string())
    //         })?;

    //         context.set_sessions((ak_auth_session, ek_policy_session, None));

    //         context.policy_secret(
    //             PolicySession::try_from(policy_session)?,
    //             AuthHandle::Endorsement,
    //             Default::default(),
    //             Default::default(),
    //             Default::default(),
    //             None,
    //         )?;

    //         let cert_info = context.activate_credential(
    //             self.ak_handle,
    //             self.ek_handle,
    //             credential_blob,
    //             encrypted_secret,
    //         )?;

    //         Ok(cert_info.value().to_vec())
    //     })();

    //     context.clear_sessions();

    //     if let Some(s) = ak_auth_session {
    //         let h: SessionHandle = s.into();
    //         context.flush_context(h.into())?;
    //     }

    //     if let Some(s) = ek_policy_session {
    //         let h: SessionHandle = s.into();
    //         context.flush_context(h.into())?;
    //     }

    //     result
    // }

    // fn activate_credential(
    //     &self,
    //     credential_blob: Vec<u8>,
    //     encrypted_secret: Vec<u8>,
    // ) -> Result<Vec<u8>, EvidentError> {
    //     let mut context_guard = self
    //         .context
    //         .lock()
    //         .map_err(|e| {
    //             AttestationError::LockError(format!(
    //                 "could not obtain lock for using context, possibly another thread panicked while holding the lock: {e}"
    //             ))
    //         })?;

    //     fn strip_outer_tpm2b(buf: &[u8]) -> Result<&[u8], EvidentError> {
    //         if buf.len() < 2 {
    //             return Err(AttestationError::CodecError(
    //                 "TPM2B buffer too short for size prefix".to_string(),
    //             )
    //             .into());
    //         }

    //         let inner_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;

    //         if buf.len() != 2 + inner_len {
    //             return Err(AttestationError::CodecError(format!(
    //                 "TPM2B size mismatch: prefix says {inner_len}, total buffer is {}",
    //                 buf.len()
    //             ))
    //             .into());
    //         }

    //         Ok(&buf[2..])
    //     }

    //     // Go MakeCredential returns full TPM2B blobs; tss-esapi wants the inner payload.
    //     let id_object = IdObject::try_from(strip_outer_tpm2b(&credential_blob)?.to_vec())?;
    //     let enc_secret = EncryptedSecret::try_from(strip_outer_tpm2b(&encrypted_secret)?.to_vec())?;

    //     // Session 1: HMAC auth for AK (activateHandle)
    //     let ak_auth_session = context_guard
    //         .start_auth_session(
    //             None,
    //             None,
    //             None,
    //             SessionType::Hmac,
    //             SymmetricDefinition::Null,
    //             HashingAlgorithm::Sha256,
    //         )?
    //         .ok_or_else(|| {
    //             EvidentError::AttestationError(AttestationError::CodecError(
    //                 "failed to create AK auth session".to_string(),
    //             ))
    //         })?;

    //     // Make absolutely sure the AK auth is the empty default.
    //     context_guard.tr_set_auth(
    //         self.ak_handle.into(),
    //         tss_esapi::structures::Auth::default(),
    //     )?;

    //     // Session 2: policy session for EK (keyHandle)
    //     let policy_auth_session = context_guard
    //         .start_auth_session(
    //             None,
    //             None,
    //             None,
    //             SessionType::Policy,
    //             SymmetricDefinition::Null,
    //             HashingAlgorithm::Sha384,
    //         )?
    //         .ok_or_else(|| {
    //             EvidentError::AttestationError(AttestationError::CodecError(
    //                 "failed to create EK policy session".to_string(),
    //             ))
    //         })?;

    //     let policy_session = PolicySession::try_from(policy_auth_session)?;

    //     let policy_result = context_guard.execute_with_nullauth_session(|ctx| {
    //         ctx.policy_secret(
    //             policy_session,
    //             AuthHandle::Endorsement,
    //             Default::default(),
    //             Default::default(),
    //             Default::default(),
    //             None,
    //         )
    //     });

    //     if let Err(e) = policy_result {
    //         let _ = context_guard.flush_context(SessionHandle::from(ak_auth_session).into());
    //         let _ = context_guard.flush_context(SessionHandle::from(policy_auth_session).into());
    //         return Err(EvidentError::from(e));
    //     }

    //     let result = context_guard.execute_with_sessions(
    //         (Some(ak_auth_session), Some(policy_auth_session), None),
    //         |ctx| {
    //             ctx.activate_credential(
    //                 self.ak_handle.into(),
    //                 self.ek_handle.into(),
    //                 id_object,
    //                 enc_secret,
    //             )
    //         },
    //     );

    //     let _ = context_guard.flush_context(SessionHandle::from(ak_auth_session).into());
    //     let _ = context_guard.flush_context(SessionHandle::from(policy_auth_session).into());

    //     Ok(result?.value().to_vec())
    // }
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

fn is_valid_credential_blob(blob: Vec<u8>) -> bool {
    if blob.len() < 5 {
        return false;
    }

    let outer_size = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    if outer_size != blob.len() - 2 {
        return false;
    }

    let hmac_size = u16::from_be_bytes([blob[2], blob[3]]) as usize;

    if hmac_size == 0 {
        return false;
    }

    if 4 + hmac_size > blob.len() {
        return false;
    }

    let enc_identity_len = blob.len() - (4 + hmac_size);
    if enc_identity_len == 0 {
        return false;
    }

    true
}

fn is_valid_encrypted_secret_ecc(secret: Vec<u8>) -> bool {
    if secret.len() < 8 {
        return false;
    }

    let outer_size = u16::from_be_bytes([secret[0], secret[1]]) as usize;
    if outer_size != secret.len() - 2 {
        return false;
    }

    let x_size = u16::from_be_bytes([secret[2], secret[3]]) as usize;
    if x_size == 0 {
        return false;
    }

    let x_end = 4 + x_size;
    if x_end + 2 > secret.len() {
        return false;
    }

    let y_size = u16::from_be_bytes([secret[x_end], secret[x_end + 1]]) as usize;
    if y_size == 0 {
        return false;
    }

    let y_end = x_end + 2 + y_size;
    if y_end != secret.len() {
        return false;
    }

    true
}

fn is_valid_encrypted_secret_ecc_p384(secret: Vec<u8>) -> bool {
    if !is_valid_encrypted_secret_ecc(secret.clone()) {
        return false;
    }

    let x_size = u16::from_be_bytes([secret[2], secret[3]]) as usize;
    let x_end = 4 + x_size;
    let y_size = u16::from_be_bytes([secret[x_end], secret[x_end + 1]]) as usize;

    x_size == 48 && y_size == 48
}
