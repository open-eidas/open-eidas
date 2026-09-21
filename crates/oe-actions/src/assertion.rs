//! Re-vérification d'une assertion WebAuthn conservée, hors de toute cérémonie
//! (docs/WEBUI.md §21, `operators audit`).
//!
//! `decision_evidence` garde, pour chaque signature, les octets bruts que
//! l'authentificateur a produits. Un auditeur peut donc les vérifier a posteriori
//! contre la clé publique du registre, sans rejouer la cérémonie : c'est ce qui
//! distingue une ligne forgée en SQL d'une signature qu'on ne peut pas produire.
//!
//! Seul ES256 (ECDSA P-256) est pris en charge, l'algorithme que les
//! authentificateurs admis produisent ; toute autre clé est signalée comme non
//! vérifiable plutôt que tenue pour bonne.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use sha2::{Digest, Sha256};

fn b64(v: &serde_json::Value, what: &str) -> Result<Vec<u8>, String> {
    let s = v.as_str().ok_or_else(|| format!("{what} absent"))?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("{what} illisible: {e}"))
}

/// Vérifie la signature d'une assertion et le lien avec le challenge attendu.
///
/// `cose_key` est la clé publique telle que la bibliothèque la sérialise
/// (`cred.cred` du JSON de la clé). La signature porte sur
/// `authenticatorData ‖ SHA-256(clientDataJSON)` ; `clientDataJSON` doit être de
/// type `webauthn.get` et porter le challenge que `ca-server` avait émis.
pub(crate) fn verify_assertion(
    cose_key: &serde_json::Value,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    expected_challenge: &[u8],
) -> Result<(), String> {
    let alg = cose_key
        .get("type_")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if alg != "ES256" {
        return Err(format!(
            "algorithme {alg:?} non vérifiable par l'audit (seul ES256 l'est)"
        ));
    }
    let ec = cose_key
        .pointer("/key/EC_EC2")
        .ok_or("clé publique EC illisible")?;
    if ec.get("curve").and_then(|v| v.as_str()) != Some("SECP256R1") {
        return Err("courbe autre que P-256".to_string());
    }
    let x = BigNum::from_slice(&b64(&ec["x"], "coordonnée x")?).map_err(|e| e.to_string())?;
    let y = BigNum::from_slice(&b64(&ec["y"], "coordonnée y")?).map_err(|e| e.to_string())?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| e.to_string())?;
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .map_err(|e| format!("point hors de la courbe: {e}"))?;
    let pkey = PKey::from_ec_key(key).map_err(|e| e.to_string())?;

    // Le contexte : une assertion (`get`), liée au challenge de cette signature.
    let client: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| format!("clientDataJSON illisible: {e}"))?;
    if client.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err("clientDataJSON n'est pas de type webauthn.get".to_string());
    }
    let challenge = b64(&client["challenge"], "challenge")?;
    if challenge != expected_challenge {
        return Err("le challenge signé n'est pas celui qui avait été émis".to_string());
    }

    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).map_err(|e| e.to_string())?;
    verifier
        .update(authenticator_data)
        .map_err(|e| e.to_string())?;
    verifier
        .update(&Sha256::digest(client_data_json))
        .map_err(|e| e.to_string())?;
    match verifier.verify(signature) {
        Ok(true) => Ok(()),
        _ => Err("signature invalide".to_string()),
    }
}
