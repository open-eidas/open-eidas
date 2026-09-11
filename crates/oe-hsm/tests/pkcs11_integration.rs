//! Test d'intégration de `Pkcs11Token` contre un vrai module PKCS#11
//! (SoftHSM2), jalon J2 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! Ignoré par défaut (`#[ignore]`) : il suppose qu'un token de développement
//! a été initialisé au préalable via `scripts/setup-softhsm-dev.sh` et que
//! `SOFTHSM2_CONF` pointe dessus. Lancer :
//!
//! ```text
//! ./scripts/setup-softhsm-dev.sh
//! SOFTHSM2_CONF=$(pwd)/target/softhsm-dev/softhsm2.conf \
//!     cargo test -p oe-hsm --test pkcs11_integration -- --ignored
//! ```

use oe_hsm::{DigestAlg, Options, Pkcs11Token, SigningToken};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

const MODULE_PATH: &str = "/usr/lib/softhsm/libsofthsm2.so";
const TOKEN_LABEL: &str = "open-eidas-tsa-dev-test";
const KEY_LABEL: &str = "tsu-signing-key-it";
const PIN: &str = "1234";

#[test]
#[ignore = "nécessite SOFTHSM2_CONF et un token initialisé (scripts/setup-softhsm-dev.sh)"]
fn generates_and_signs_with_a_real_softhsm2_token() {
    let options = Options {
        module_path: MODULE_PATH.to_string(),
        token_label: TOKEN_LABEL.to_string(),
        key_label: KEY_LABEL.to_string(),
        pin: PIN.to_string(),
    };
    let token = Pkcs11Token::open(&options).expect("ouverture du token de test");

    // Idempotent : ignore l'échec si la bi-clé existe déjà d'un lancement précédent.
    let _ = token.generate_rsa_key(3072);

    let (modulus, exponent) = token
        .rsa_public_components()
        .expect("lecture de la clé publique");
    let public_key = RsaPublicKey::new(
        BigUint::from_bytes_be(&modulus),
        BigUint::from_bytes_be(&exponent),
    )
    .expect("reconstruction de la clé publique RSA");
    assert!(public_key.size() * 8 >= 3072, "taille de clé inattendue");

    let message = b"tests/fixtures/rfc3161 -- oe-hsm integration";
    let digest = Sha256::digest(message);

    let signature = token
        .sign_digest(DigestAlg::Sha256, &digest)
        .expect("signature via le token PKCS#11");

    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .expect("la signature produite par le token doit être valide pour sa propre clé publique");

    let der = token
        .public_key_der()
        .expect("encodage SubjectPublicKeyInfo");
    let decoded = RsaPublicKey::from_public_key_der(&der).expect("clé publique DER invalide");
    assert_eq!(
        decoded, public_key,
        "public_key_der doit correspondre à la clé publique du token"
    );
}
