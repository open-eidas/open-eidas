//! Options WebAuthn de la même forme qu'une vraie authentification, pour un nom
//! qui n'existe pas dans le registre (docs/WEBUI.md §16, « Connexion par nom,
//! réponses uniformes ») : sans cela, la forme même de la réponse (liste de
//! clés vide contre liste non vide) trahirait qu'un nom n'existe pas.
//!
//! Ce module ne connaît aucun secret : c'est à l'appelant de dériver
//! `decoy_credential_id` d'une façon stable pour un même nom et non prévisible
//! sans lui (par exemple `HMAC-SHA256(secret_du_service, nom)`), pour que la
//! même requête reçoive toujours la même forme de réponse.
//!
//! Limite assumée (consignée dans WEBUI §16) : une seule clé factice, comme le
//! cas le plus courant d'un opérateur ; un opérateur qui en porterait
//! plusieurs resterait distinguable par le nombre de clés proposées.

use webauthn_rs_proto::{
    AllowCredentials, PublicKeyCredentialHints, PublicKeyCredentialRequestOptions,
    RequestAuthenticationExtensions, RequestChallengeResponse, UserVerificationPolicy,
};

/// Doit rester égal à `webauthn_rs::DEFAULT_AUTHENTICATOR_TIMEOUT`, la valeur
/// que rend une vraie authentification tant que le service ne fixe pas un
/// délai explicite (ni `oe_webauthn::Verifier`, ni `ca-server`, ne le font).
const DEFAULT_AUTHENTICATOR_TIMEOUT_MILLIS: u32 = 300_000;

/// Même longueur que `webauthn_rs_core::constants::CHALLENGE_SIZE_BYTES`.
const CHALLENGE_SIZE_BYTES: usize = 32;

/// Construit un défi d'authentification de la même forme que
/// [`crate::Verifier::start_authentication`] rendrait pour un opérateur réel
/// muni d'une seule clé : mêmes champs, mêmes valeurs par défaut, seule la
/// clé proposée (`decoy_credential_id`) et le challenge (réel, tiré au hasard
/// à chaque appel, jamais dérivé du nom) diffèrent d'un cas réel.
pub fn decoy_authentication_challenge(
    rp_id: &str,
    decoy_credential_id: &[u8],
) -> RequestChallengeResponse {
    use rand::RngCore;
    let mut challenge = [0u8; CHALLENGE_SIZE_BYTES];
    rand::thread_rng().fill_bytes(&mut challenge);
    RequestChallengeResponse {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: challenge.to_vec().into(),
            timeout: Some(DEFAULT_AUTHENTICATOR_TIMEOUT_MILLIS),
            rp_id: rp_id.to_string(),
            allow_credentials: vec![AllowCredentials {
                type_: "public-key".to_string(),
                id: decoy_credential_id.to_vec().into(),
                transports: None,
            }],
            user_verification: UserVerificationPolicy::Required,
            hints: Some(vec![
                PublicKeyCredentialHints::SecurityKey,
                PublicKeyCredentialHints::ClientDevice,
            ]),
            extensions: Some(RequestAuthenticationExtensions {
                appid: None,
                uvm: Some(true),
                hmac_get_secret: None,
            }),
        },
        mediation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::decoy_authentication_challenge;

    #[test]
    fn two_calls_never_repeat_the_same_challenge() {
        let a = decoy_authentication_challenge("console.example.com", b"decoy");
        let b = decoy_authentication_challenge("console.example.com", b"decoy");
        assert_ne!(a.public_key.challenge, b.public_key.challenge);
    }

    #[test]
    fn the_shape_matches_a_single_real_credential() {
        let r = decoy_authentication_challenge("console.example.com", b"decoy-id");
        assert_eq!(r.public_key.rp_id, "console.example.com");
        assert_eq!(r.public_key.allow_credentials.len(), 1);
        assert_eq!(r.public_key.allow_credentials[0].id.as_ref(), b"decoy-id");
        assert_eq!(r.public_key.challenge.as_ref().len(), 32);
    }
}
