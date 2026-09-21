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
