//! Exécute le vrai binaire `ca-server operators bootstrap-admin` contre un
//! PostgreSQL (docs/WEBUI.md §10) : ce que voit l'opérateur, pas seulement ce
//! que fait la bibliothèque.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use sqlx::postgres::PgPoolOptions;
use std::process::Command;

fn token_chars(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[tokio::test]
async fn standard_output_carries_only_the_token() {
    let Ok(base) = std::env::var("OE_CASTORE_TEST_DSN") else {
        eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
        return;
    };

    // Base neuve : la commande ouvre le magasin, donc migre, et écrit une
    // notice de migration au premier passage comme au second.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("cli_{nanos}");
    let admin = PgPoolOptions::new().connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let (head, _) = base.rsplit_once('/').unwrap();
    let dsn = format!("{head}/{name}");
    let audit = std::env::temp_dir().join(format!("{name}.audit.log"));

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ca-server"))
            .args(["operators", "bootstrap-admin", "alice"])
            .env("OPENEIDAS_DB_DSN", &dsn)
            .env("OPENEIDAS_ISSUING_PIN", "1234")
            .env("OPENEIDAS_PKI_PUBLIC_URL", "https://pki.example.test")
            .env("OPENEIDAS_AUDIT_FILE", &audit)
            .output()
            .expect("lancement de ca-server")
    };

    let mut tokens = Vec::new();
    // Deux passages : le second ré-invite, et sqlx y écrit une notice
    // (« relation _sqlx_migrations already exists »).
    for pass in 1..=2 {
        let out = run();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "passage {pass} : {stderr}");

        let token = stdout.trim_end_matches('\n');
        assert_eq!(
            token.len(),
            43,
            "passage {pass} : la sortie standard doit être le seul jeton, obtenu {stdout:?}"
        );
        assert!(token_chars(token), "passage {pass} : {token:?}");
        assert!(
            stderr.contains("Invitation créée"),
            "passage {pass} : {stderr}"
        );
        assert!(
            !stderr.contains(token),
            "le jeton ne doit pas être répété sur la sortie d'erreur"
        );
        tokens.push(token.to_string());
    }
    assert_ne!(tokens[0], tokens[1], "chaque invitation a son propre jeton");

    let _ = std::fs::remove_file(&audit);
}
