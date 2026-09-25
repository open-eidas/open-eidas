//! La configuration de `ra-console`, exécutée pour de vrai : ce que voit
//! l'opérateur d'exploitation quand il manque quelque chose. Sans base : la
//! configuration est refusée avant toute connexion.

use std::process::Command;

fn run(args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ra-console"));
    cmd.args(args);
    for key in [
        "OPENEIDAS_DATABASE_URL",
        "OPENEIDAS_CA_INTERNAL_URL",
        "OPENEIDAS_INTERNAL_TLS_CERT_FILE",
        "OPENEIDAS_INTERNAL_TLS_KEY_FILE",
        "OPENEIDAS_CA_CERT_FILE",
        "OPENEIDAS_ENROLL_URL",
        "OPENEIDAS_ENROLL_HMAC_KEY",
        "OPENEIDAS_WEBAUTHN_RP_ID",
        "OPENEIDAS_WEBAUTHN_ORIGIN",
        "OPENEIDAS_WEBAUTHN_MODELS_FILE",
        "OPENEIDAS_LOGIN_DECOY_SECRET",
    ] {
        cmd.env_remove(key);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn serve_names_what_is_missing() {
    let (code, err) = run(&["serve"], &[]);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_CA_INTERNAL_URL"), "{err}");

    // Le lien interne est en https : un lien en clair est refusé d'emblée.
    let (code, err) = run(
        &["serve"],
        &[("OPENEIDAS_CA_INTERNAL_URL", "http://ca:8321")],
    );
    assert_eq!(code, 1);
    assert!(err.contains("https"), "{err}");

    let base = [
        ("OPENEIDAS_CA_INTERNAL_URL", "https://ca:8321"),
        ("OPENEIDAS_DATABASE_URL", "postgres://x@127.0.0.1:1/x"),
        ("OPENEIDAS_INTERNAL_TLS_CERT_FILE", "/nulle/part.pem"),
        ("OPENEIDAS_INTERNAL_TLS_KEY_FILE", "/nulle/part.key"),
    ];
    let (code, err) = run(&["serve"], &base);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_CA_CERT_FILE"), "{err}");

    // La vérification des connexions (§15, étape 1c) est elle aussi exigée.
    let mut with_ca_cert = base.to_vec();
    with_ca_cert.push(("OPENEIDAS_CA_CERT_FILE", "/nulle/part.pem"));
    let (code, err) = run(&["serve"], &with_ca_cert);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_WEBAUTHN_RP_ID"), "{err}");

    let mut with_rp_id = with_ca_cert.clone();
    with_rp_id.push(("OPENEIDAS_WEBAUTHN_RP_ID", "console.example.com"));
    let (code, err) = run(&["serve"], &with_rp_id);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_WEBAUTHN_ORIGIN"), "{err}");

    let mut with_origin = with_rp_id.clone();
    with_origin.push(("OPENEIDAS_WEBAUTHN_ORIGIN", "https://console.example.com"));
    let (code, err) = run(&["serve"], &with_origin);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_WEBAUTHN_MODELS_FILE"), "{err}");

    let mut with_models = with_origin.clone();
    with_models.push(("OPENEIDAS_WEBAUTHN_MODELS_FILE", "/nulle/part.json"));
    let (code, err) = run(&["serve"], &with_models);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_LOGIN_DECOY_SECRET"), "{err}");

    // Un secret trop court est refusé, pas seulement son absence.
    let mut with_short_secret = with_models.clone();
    with_short_secret.push(("OPENEIDAS_LOGIN_DECOY_SECRET", "trop-court"));
    let (code, err) = run(&["serve"], &with_short_secret);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_LOGIN_DECOY_SECRET"), "{err}");
}

#[test]
fn internal_cert_needs_the_enrollment_settings_but_no_database() {
    let (code, err) = run(&["internal-cert"], &[]);
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_INTERNAL_TLS_CERT_FILE"), "{err}");

    let (code, err) = run(
        &["internal-cert"],
        &[
            ("OPENEIDAS_INTERNAL_TLS_CERT_FILE", "/tmp/x.pem"),
            ("OPENEIDAS_INTERNAL_TLS_KEY_FILE", "/tmp/x.key"),
        ],
    );
    assert_eq!(code, 1);
    assert!(err.contains("OPENEIDAS_ENROLL_URL"), "{err}");
    // Jamais la base : une commande de Jour 0 ne demande pas d'accès à la base.
    assert!(!err.contains("DATABASE"), "{err}");
}
