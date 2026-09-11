//! Portage de `internal/hsm` : accès à la clé de signature de l'unité
//! d'horodatage (TSU) via PKCS#11. La clé privée ne quitte jamais le token —
//! seule cette crate est autorisée à contenir du `unsafe` dans le workspace
//! (bindings PKCS#11 via la crate `cryptoki`).
//!
//! Le trait [`SigningToken`] joue le rôle de `crypto.Signer` côté Go : le
//! reste du workspace (`oe-tsa-core`, notamment) ne dépend que de ce trait,
//! jamais directement de `cryptoki`, ce qui permet de le tester avec
//! [`SoftwareToken`] sans matériel PKCS#11 réel (SoftHSM2 y compris).

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use sha2::{Digest, Sha256};

/// Paramètres d'ouverture du token (équivalent de `hsm.Options` en Go).
#[derive(Debug, Clone)]
pub struct Options {
    pub module_path: String,
    pub token_label: String,
    pub key_label: String,
    pub pin: String,
}

/// Algorithme de hachage pour lequel une signature RSA PKCS#1 v1.5 est
/// demandée. Le préfixe `DigestInfo` (RFC 3447 annexe B) est ajouté par cette
/// crate avant l'appel PKCS#11 `CKM_RSA_PKCS`, à l'identique de ce que fait
/// `crypto/rsa` côté Go pour un `crypto.Signer` RSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlg {
    pub fn expected_len(self) -> usize {
        match self {
            DigestAlg::Sha256 => 32,
            DigestAlg::Sha384 => 48,
            DigestAlg::Sha512 => 64,
        }
    }

    /// Préfixe ASN.1 `DigestInfo` (RFC 3447 annexe B.1) pour cet algorithme.
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            DigestAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            DigestAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            DigestAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    fn wrap(self, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        if digest.len() != self.expected_len() {
            return Err(HsmError::DigestLength {
                alg: self,
                expected: self.expected_len(),
                actual: digest.len(),
            });
        }
        let mut out = Vec::with_capacity(self.digest_info_prefix().len() + digest.len());
        out.extend_from_slice(self.digest_info_prefix());
        out.extend_from_slice(digest);
        Ok(out)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("hsm: ouverture du token {token_label:?} via {module_path}: {source}")]
    Open {
        module_path: String,
        token_label: String,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("hsm: jeton introuvable pour le label {0:?}")]
    TokenNotFound(String),
    #[error("hsm: recherche de la clé {key_label:?}: {source}")]
    FindKey {
        key_label: String,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("hsm: bi-clé introuvable sur le token")]
    KeyNotFound,
    #[error("hsm: génération de la bi-clé RSA-{bits}: {source}")]
    GenerateKey {
        bits: u64,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("hsm: digest {alg:?} de longueur invalide (attendu {expected}, reçu {actual})")]
    DigestLength {
        alg: DigestAlg,
        expected: usize,
        actual: usize,
    },
    #[error("hsm: opération PKCS#11: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),
    #[error("hsm: signature logicielle de test: {0}")]
    SoftwareSign(#[from] rsa::Error),
    #[error("hsm: encodage SubjectPublicKeyInfo: {0}")]
    PublicKeyEncoding(rsa::pkcs8::spki::Error),
}

/// Équivalent de `crypto.Signer` : signe un digest déjà calculé sans jamais
/// exposer la clé privée.
pub trait SigningToken {
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Clé publique correspondante, encodée SubjectPublicKeyInfo (DER).
    /// Sert à vérifier, avant de signer, que la clé du token correspond bien
    /// au certificat publié (reproduit la vérification faite par `tsa.New`
    /// côté Go via `x509.MarshalPKIXPublicKey`).
    fn public_key_der(&self) -> Result<Vec<u8>, HsmError>;
}

/// CKA_ID stable et non vide dérivé du label de clé — reproduit `hsm.Open`
/// (Go), qui s'en sert pour apparier clé privée et clé publique.
fn key_id(key_label: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key_label.as_bytes());
    hasher.finalize()[..8].to_vec()
}

/// Implémentation réelle : token PKCS#11 (SoftHSM2 en dev/CI, HSM FIPS en prod).
pub struct Pkcs11Token {
    session: Session,
    key_id: Vec<u8>,
    key_label: String,
}

impl Pkcs11Token {
    pub fn open(o: &Options) -> Result<Self, HsmError> {
        let pkcs11 = Pkcs11::new(&o.module_path).map_err(|source| HsmError::Open {
            module_path: o.module_path.clone(),
            token_label: o.token_label.clone(),
            source,
        })?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|source| HsmError::Open {
                module_path: o.module_path.clone(),
                token_label: o.token_label.clone(),
                source,
            })?;

        let slot = pkcs11
            .get_slots_with_token()?
            .into_iter()
            .find(|slot| {
                pkcs11
                    .get_token_info(*slot)
                    .map(|info| info.label() == o.token_label)
                    .unwrap_or(false)
            })
            .ok_or_else(|| HsmError::TokenNotFound(o.token_label.clone()))?;

        let session = pkcs11.open_rw_session(slot)?;
        session.login(UserType::User, Some(&AuthPin::from(o.pin.clone())))?;

        Ok(Self {
            session,
            key_id: key_id(&o.key_label),
            key_label: o.key_label.clone(),
        })
    }

    fn find_private_key(&self) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        let keys = self
            .session
            .find_objects(&template)
            .map_err(|source| HsmError::FindKey {
                key_label: self.key_label.clone(),
                source,
            })?;
        keys.into_iter().next().ok_or(HsmError::KeyNotFound)
    }

    /// Génère une bi-clé RSA dans le token (équivalent de `Token.GenerateRSAKey`).
    pub fn generate_rsa_key(&self, bits: u64) -> Result<(), HsmError> {
        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01]; // 65537
        let pub_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::ModulusBits(bits.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        let priv_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        self.session
            .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template)
            .map_err(|source| HsmError::GenerateKey { bits, source })?;
        Ok(())
    }

    /// Lit le module et l'exposant public de la bi-clé (RSA) sur le token.
    /// Utilisé pour vérifier après coup qu'une signature produite par
    /// [`SigningToken::sign_digest`] correspond bien à la clé publiée, sans
    /// jamais accéder à la clé privée.
    pub fn rsa_public_components(&self) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(self.key_id.clone()),
            Attribute::Label(self.key_label.clone().into_bytes()),
        ];
        let keys = self
            .session
            .find_objects(&template)
            .map_err(|source| HsmError::FindKey {
                key_label: self.key_label.clone(),
                source,
            })?;
        let key = keys.into_iter().next().ok_or(HsmError::KeyNotFound)?;

        let attrs = self.session.get_attributes(
            key,
            &[
                cryptoki::object::AttributeType::Modulus,
                cryptoki::object::AttributeType::PublicExponent,
            ],
        )?;
        let mut modulus = None;
        let mut exponent = None;
        for attr in attrs {
            match attr {
                Attribute::Modulus(v) => modulus = Some(v),
                Attribute::PublicExponent(v) => exponent = Some(v),
                _ => {}
            }
        }
        Ok((
            modulus.ok_or(HsmError::KeyNotFound)?,
            exponent.ok_or(HsmError::KeyNotFound)?,
        ))
    }
}

impl SigningToken for Pkcs11Token {
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key = self.find_private_key()?;
        let digest_info = alg.wrap(digest)?;
        Ok(self.session.sign(&Mechanism::RsaPkcs, key, &digest_info)?)
    }

    fn public_key_der(&self) -> Result<Vec<u8>, HsmError> {
        let (modulus, exponent) = self.rsa_public_components()?;
        let public_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&modulus),
            rsa::BigUint::from_bytes_be(&exponent),
        )
        .map_err(HsmError::SoftwareSign)?;
        use rsa::pkcs8::EncodePublicKey;
        public_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(HsmError::PublicKeyEncoding)
    }
}

/// Rend n'importe quel [`SigningToken`] utilisable depuis plusieurs threads
/// à la fois (`Sync`), en sérialisant les appels derrière un verrou.
/// Nécessaire pour `Pkcs11Token` : une session `cryptoki` est `Send` mais
/// pas `Sync` (un seul appel PKCS#11 à la fois par session), ce qui
/// empêcherait de la partager entre les gestionnaires concurrents d'un
/// serveur HTTP (jalon J7) sans ce wrapper.
pub struct SyncToken<T>(std::sync::Mutex<T>);

impl<T> SyncToken<T> {
    pub fn new(inner: T) -> Self {
        Self(std::sync::Mutex::new(inner))
    }
}

impl<T: SigningToken> SigningToken for SyncToken<T> {
    fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.0
            .lock()
            .expect("verrou de token empoisonné")
            .sign_digest(alg, digest)
    }

    fn public_key_der(&self) -> Result<Vec<u8>, HsmError> {
        self.0
            .lock()
            .expect("verrou de token empoisonné")
            .public_key_der()
    }
}

/// Implémentation logicielle de [`SigningToken`], utilisée par les tests de
/// `oe-hsm` et des crates qui en dépendent (`oe-tsa-core`, notamment) pour
/// vérifier la logique métier sans matériel PKCS#11 réel. Ne doit jamais être
/// utilisée en production : la clé privée vit en mémoire du processus.
pub mod testing {
    use super::{DigestAlg, HsmError, SigningToken};
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::{Sha256, Sha384, Sha512};

    pub struct SoftwareToken {
        key: RsaPrivateKey,
    }

    impl SoftwareToken {
        /// Génère une bi-clé RSA de test (jamais persistée).
        pub fn generate(bits: usize) -> Self {
            let mut rng = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rng, bits).expect("génération de clé RSA de test");
            Self { key }
        }

        pub fn public_key(&self) -> RsaPublicKey {
            RsaPublicKey::from(&self.key)
        }

        /// Charge une clé de test existante (PEM PKCS#8), pour les tests qui
        /// doivent faire correspondre la clé à un certificat déjà émis.
        pub fn from_pkcs8_pem(pem: &str) -> Result<Self, rsa::pkcs8::Error> {
            use rsa::pkcs8::DecodePrivateKey;
            Ok(Self {
                key: RsaPrivateKey::from_pkcs8_pem(pem)?,
            })
        }
    }

    impl SigningToken for SoftwareToken {
        fn sign_digest(&self, alg: DigestAlg, digest: &[u8]) -> Result<Vec<u8>, HsmError> {
            if digest.len() != alg.expected_len() {
                return Err(HsmError::DigestLength {
                    alg,
                    expected: alg.expected_len(),
                    actual: digest.len(),
                });
            }
            let signature = match alg {
                DigestAlg::Sha256 => self.key.sign(Pkcs1v15Sign::new::<Sha256>(), digest),
                DigestAlg::Sha384 => self.key.sign(Pkcs1v15Sign::new::<Sha384>(), digest),
                DigestAlg::Sha512 => self.key.sign(Pkcs1v15Sign::new::<Sha512>(), digest),
            };
            signature.map_err(HsmError::SoftwareSign)
        }

        fn public_key_der(&self) -> Result<Vec<u8>, HsmError> {
            use rsa::pkcs8::EncodePublicKey;
            self.public_key()
                .to_public_key_der()
                .map(|doc| doc.as_bytes().to_vec())
                .map_err(HsmError::PublicKeyEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_info_prefix_rejects_wrong_length() {
        let err = DigestAlg::Sha256.wrap(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, HsmError::DigestLength { .. }));
    }

    #[test]
    fn digest_info_wraps_expected_length() {
        let digest = [0x42u8; 32];
        let wrapped = DigestAlg::Sha256.wrap(&digest).unwrap();
        assert_eq!(wrapped.len(), 19 + 32);
        assert_eq!(&wrapped[19..], &digest[..]);
    }

    #[test]
    fn key_id_is_stable_for_same_label() {
        assert_eq!(key_id("tsu-signing-key"), key_id("tsu-signing-key"));
        assert_ne!(key_id("tsu-signing-key"), key_id("other-key"));
        assert_eq!(key_id("tsu-signing-key").len(), 8);
    }
}
