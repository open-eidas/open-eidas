//! Test décisif du jalon J6 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`) : `Authority`
//! produit un jeton RFC 3161 réel pour chaque cas du corpus
//! `tests/fixtures/rfc3161/`, et ce jeton est vérifié comme valide par
//! `openssl ts -verify` — un vérificateur tiers indépendant de ce dépôt,
//! exactement comme le fait `helm-kind-smoke-test` côté Go.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use der::Decode;
use oe_hsm::{testing::SoftwareToken, DigestAlg};
use oe_tsa_core::{Authority, Clock, Options};
use x509_cert::Certificate;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/tsa"
    ))
}

fn rfc3161_corpus_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/rfc3161"
    ))
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<time::OffsetDateTime, String> {
        Ok(time::OffsetDateTime::now_utc())
    }
}

fn load_authority() -> Authority {
    let dir = fixtures_dir();
    let key_pem =
        std::fs::read_to_string(dir.join("tsu-key.pem")).expect("lecture de la clé de test");
    let cert_pem =
        std::fs::read_to_string(dir.join("tsu-cert.pem")).expect("lecture du certificat de test");

    let signer = SoftwareToken::from_pkcs8_pem(&key_pem).expect("chargement de la clé RSA de test");

    let cert_block = pem::parse(cert_pem.as_bytes()).expect("PEM invalide");
    let certificate =
        Certificate::from_der(cert_block.contents()).expect("certificat DER invalide");

    Authority::new(Options {
        signer: Arc::new(signer),
        certificate,
        chain: Vec::new(),
        policy: der::asn1::ObjectIdentifier::new("1.3.6.1.4.1.99999.1.1.1").unwrap(),
        accuracy: std::time::Duration::from_secs(1),
        signing_digest: DigestAlg::Sha256,
        clock: Arc::new(FixedClock),
        recorder: None,
    })
    .expect("construction de l'autorité")
}

fn openssl_verify_token(resp_der_path: &Path, query_path: &Path, cert_path: &Path) {
    // openssl ts -reply attend directement le TimeStampResp (ce que nous produisons) ;
    // -verify redemande la requête d'origine pour contrôler le nonce/imprint.
    let output = Command::new("openssl")
        .args([
            "ts",
            "-reply",
            "-in",
            resp_der_path.to_str().unwrap(),
            "-text",
        ])
        .output()
        .expect("exécution d'openssl");
    assert!(
        output.status.success(),
        "openssl ts -reply -text a échoué: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new("openssl")
        .args([
            "ts",
            "-verify",
            "-in",
            resp_der_path.to_str().unwrap(),
            "-queryfile",
            query_path.to_str().unwrap(),
            "-CAfile",
            cert_path.to_str().unwrap(),
            "-untrusted",
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("exécution d'openssl ts -verify");
    assert!(
        output.status.success(),
        "openssl ts -verify a rejeté le jeton produit par oe-tsa-core:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn produces_tokens_accepted_by_openssl_for_every_granted_case_in_the_corpus() {
    let authority = load_authority();
    let cert_path = fixtures_dir().join("tsu-cert.pem");

    let mut checked = 0;
    for entry in std::fs::read_dir(rfc3161_corpus_dir()).expect("corpus introuvable") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() || path.file_name().is_some_and(|n| n == "keys") {
            continue;
        }
        let request_path = path.join("request.der");
        if !request_path.exists() {
            continue;
        }
        let has_response = path.join("response.der").exists();
        if !has_response {
            // Cas de rejet du corpus : couvert par les tests unitaires
            // d'oe-tsa-core, pas par ce test bout-en-bout.
            continue;
        }

        let req_der = std::fs::read(&request_path).unwrap();
        let resp_der = authority
            .timestamp(&req_der)
            .unwrap_or_else(|e| panic!("horodatage refusé pour {path:?}: {e}"));

        let out_path = std::env::temp_dir().join(format!(
            "oe-tsa-core-e2e-{}.der",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&out_path, &resp_der).unwrap();

        openssl_verify_token(&out_path, &request_path, &cert_path);
        let _ = std::fs::remove_file(&out_path);
        checked += 1;
    }
    assert!(
        checked >= 3,
        "le corpus devrait fournir au moins 3 cas accordés, {checked} vérifiés"
    );
}
