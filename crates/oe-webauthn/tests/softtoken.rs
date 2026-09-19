//! Vérifie `oe-webauthn` contre un authentificateur logiciel réel
//! (`SoftToken`), qui exécute le protocole : vraies paires de clés, vraie
//! attestation « packed » signée par une racine, vraies assertions. Même
//! doctrine que le reste du dépôt (SoftHSM2 pour PKCS#11) : tester contre un
//! système qui fait réellement le travail, pas contre des objets fabriqués.
//!
//! Limite assumée : `SoftToken` ne produit jamais le drapeau BE (clé
//! synchronisable) ni de compteur croissant garanti. Le refus de BE à
//! l'enregistrement est celui de la bibliothèque (vérifié dans son code, pas
//! ici), et son contrôle à l'assertion n'est pas exercé par ce test.

use oe_webauthn::{trusted_models, Error, TrustedModel, Url, Uuid, Verifier};
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

const RP_ID: &str = "console.example.com";

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

/// Un authentificateur neuf et le PEM de la racine qui signe son attestation.
fn token() -> (WebauthnAuthenticator<SoftToken>, Vec<u8>) {
    let (token, root) = // `true` : la clé déclare la vérification de l'utilisateur faite, comme si
    // le PIN avait été saisi (le vérificateur l'exige, §2).
    SoftToken::new(true).expect("SoftToken");
    (
        WebauthnAuthenticator::new(token),
        root.to_pem().expect("PEM de la racine"),
    )
}

fn verifier(root_pem: &[u8], aaguid: Uuid) -> Verifier {
    let models = trusted_models(&[TrustedModel {
        root_pem,
        aaguid,
        description: "SoftToken (test)",
    }])
    .expect("liste blanche");
    Verifier::new(RP_ID, &origin(), "Open eIDAS Console — test", models).expect("vérificateur")
}

#[test]
fn a_listed_key_registers_and_signs() {
    let (mut authn, root) = token();
    let v = verifier(&root, AAGUID);

    let (options, state) = v
        .start_registration(Uuid::new_v4(), "alice", None)
        .expect("début d'enregistrement");
    let reg = authn.do_registration(origin(), options).expect("client");
    let key = v.finish_registration(&reg, &state).expect("clé admise");

    let (challenge, auth_state) = v.start_authentication(&[key]).expect("challenge");
    let response = authn
        .do_authentication(origin(), challenge)
        .expect("client");
    let assertion = v
        .finish_authentication(&response, &auth_state, 0)
        .expect("assertion valide");
    assert!(!assertion.credential_id.is_empty());
}

#[test]
fn a_model_absent_from_the_whitelist_is_refused_even_under_a_trusted_root() {
    let (mut authn, root) = token();
    // Bonne racine, mais l'association n'a retenu qu'un autre modèle.
    let v = verifier(&root, Uuid::from_u128(0x1234));

    let (options, state) = v.start_registration(Uuid::new_v4(), "alice", None).unwrap();
    let reg = authn.do_registration(origin(), options).unwrap();
    let err = v.finish_registration(&reg, &state).unwrap_err();
    eprintln!("AAGUID hors liste -> {err}");
    assert!(matches!(err, Error::Rejected(_)));
}

#[test]
fn a_key_attested_by_an_unknown_root_is_refused() {
    let (mut authn, _its_own_root) = token();
    // La liste blanche ne connaît que la racine d'un *autre* authentificateur.
    let (_other, other_root) = token();
    let v = verifier(&other_root, AAGUID);

    let (options, state) = v.start_registration(Uuid::new_v4(), "alice", None).unwrap();
    let reg = authn.do_registration(origin(), options).unwrap();
    let err = v.finish_registration(&reg, &state).unwrap_err();
    eprintln!("racine inconnue -> {err}");
    assert!(matches!(err, Error::Rejected(_)));
}

#[test]
fn an_assertion_replayed_against_a_new_challenge_is_refused() {
    let (mut authn, root) = token();
    let v = verifier(&root, AAGUID);
    let (options, state) = v.start_registration(Uuid::new_v4(), "alice", None).unwrap();
    let reg = authn.do_registration(origin(), options).unwrap();
    let key = v.finish_registration(&reg, &state).unwrap();

    let (c1, s1) = v.start_authentication(std::slice::from_ref(&key)).unwrap();
    let first = authn.do_authentication(origin(), c1).unwrap();
    v.finish_authentication(&first, &s1, 0)
        .expect("première fois");

    // Un attaquant rejoue la capture face à un nouveau challenge : refusé,
    // le challenge signé n'est pas celui qu'on vient d'émettre.
    let (_c2, s2) = v.start_authentication(&[key]).unwrap();
    assert!(matches!(
        v.finish_authentication(&first, &s2, 0),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn an_assertion_from_another_origin_is_refused() {
    let (mut authn, root) = token();
    let v = verifier(&root, AAGUID);
    let (options, state) = v.start_registration(Uuid::new_v4(), "alice", None).unwrap();
    let reg = authn.do_registration(origin(), options).unwrap();
    let key = v.finish_registration(&reg, &state).unwrap();

    let (challenge, auth_state) = v.start_authentication(&[key]).unwrap();
    // Le client accepte un sous-domaine, le serveur ne doit pas (§2 : RP ID
    // étroit, une page d'un autre sous-domaine ne doit rien pouvoir obtenir).
    let elsewhere = Url::parse("https://auth.console.example.com").unwrap();
    let response = authn.do_authentication(elsewhere, challenge).unwrap();
    assert!(matches!(
        v.finish_authentication(&response, &auth_state, 0),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn a_counter_that_does_not_advance_is_a_presumed_clone() {
    let (mut authn, root) = token();
    let v = verifier(&root, AAGUID);
    let (options, state) = v.start_registration(Uuid::new_v4(), "alice", None).unwrap();
    let reg = authn.do_registration(origin(), options).unwrap();
    let key = v.finish_registration(&reg, &state).unwrap();

    let (challenge, auth_state) = v.start_authentication(&[key]).unwrap();
    let response = authn.do_authentication(origin(), challenge).unwrap();

    // Déjà vu jusqu'à un compteur supérieur : l'assertion recule.
    assert!(matches!(
        v.finish_authentication(&response, &auth_state, 1_000_000),
        Err(Error::CounterRegression {
            last: 1_000_000,
            ..
        })
    ));
    // Jamais vu de compteur positif : un authentificateur sans compteur
    // (toujours 0) reste admis.
    v.finish_authentication(&response, &auth_state, 0)
        .expect("compteur jamais positif");
}

#[test]
fn the_verifier_refuses_to_start_with_inconsistent_settings() {
    let (_authn, root) = token();
    let models = || {
        trusted_models(&[TrustedModel {
            root_pem: &root,
            aaguid: AAGUID,
            description: "SoftToken (test)",
        }])
        .unwrap()
    };

    // RP ID plus large que l'hôte : ouvrirait la porte aux autres sous-domaines.
    assert!(matches!(
        Verifier::new("example.com", &origin(), "x", models()),
        Err(Error::Config(_))
    ));
    // RP ID différent de l'hôte.
    assert!(matches!(
        Verifier::new("autre.example.com", &origin(), "x", models()),
        Err(Error::Config(_))
    ));
    // Origine en clair.
    let http = Url::parse("http://console.example.com").unwrap();
    assert!(matches!(
        Verifier::new(RP_ID, &http, "x", models()),
        Err(Error::Config(_))
    ));
    // Liste blanche vide : aucune clé ne pourrait être admise.
    assert!(matches!(trusted_models(&[]), Err(Error::NoTrustedModel)));
}
