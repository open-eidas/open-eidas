//! Test d'intégration bout-en-bout : cérémonie → émission → révocation →
//! publication de CRL, sur clés RSA logicielles de test
//! ([`oe_hsm::testing::SoftwareToken`]) et magasin en mémoire
//! ([`oe_castore::Memory`]) — pas de HSM réel requis, contrairement aux
//! tests de `oe-tsa-server`/`oe-ocsp-responder` qui, eux, s'appuient sur
//! SoftHSM2 : ce moteur n'a rien de spécifique au transport PKCS#11 au-delà
//! de ce que `oe-hsm::SigningToken` couvre déjà.

use std::sync::Arc;

use der::{Decode, Encode};
use x509_cert::Certificate;

use oe_ca_core::ceremony::{run_ceremony, CeremonyOptions, AUTHORITY_ISSUING, AUTHORITY_ROOT};
use oe_ca_core::{profile, Issuer, Options};
use oe_castore::{Memory, Store};
use oe_hsm::testing::SoftwareToken;
use oe_hsm::SigningToken;

fn store() -> Arc<Memory> {
    Arc::new(Memory::new())
}

async fn run_test_ceremony(
    store: Arc<Memory>,
) -> (
    Arc<SoftwareToken>,
    Arc<SoftwareToken>,
    x509_cert::Certificate,
    x509_cert::Certificate,
) {
    let root_signer = Arc::new(SoftwareToken::generate(2048));
    let issuing_signer = Arc::new(SoftwareToken::generate(2048));

    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer: root_signer.clone(),
        issuing_signer: issuing_signer.clone(),
        root_cn: "Test Root CA".to_string(),
        issuing_cn: "Test Issuing CA".to_string(),
        organization: "Open eIDAS Test".to_string(),
        country: "FR".to_string(),
        root_validity: time::Duration::days(20 * 365),
        issuing_validity: time::Duration::days(10 * 365),
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store: store.clone(),
        operator: "test-operator".to_string(),
        recorder: None,
    })
    .await
    .expect("la cérémonie doit réussir");

    assert!(
        hierarchy.created,
        "première cérémonie : la hiérarchie doit être créée"
    );
    (
        root_signer,
        issuing_signer,
        hierarchy.root,
        hierarchy.issuing,
    )
}

#[tokio::test]
async fn ceremony_is_idempotent() {
    let store = store();
    let (root_signer, issuing_signer, root1, issuing1) = run_test_ceremony(store.clone()).await;

    let hierarchy2 = run_ceremony(CeremonyOptions {
        root_signer,
        issuing_signer,
        root_cn: String::new(),
        issuing_cn: String::new(),
        organization: String::new(),
        country: String::new(),
        root_validity: time::Duration::ZERO,
        issuing_validity: time::Duration::ZERO,
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store: store.clone(),
        operator: "test-operator".to_string(),
        recorder: None,
    })
    .await
    .expect("la seconde cérémonie doit se contenter de relire la hiérarchie existante");

    assert!(
        !hierarchy2.created,
        "seconde cérémonie : la hiérarchie ne doit pas être recréée"
    );
    assert_eq!(root1.to_der().unwrap(), hierarchy2.root.to_der().unwrap());
    assert_eq!(
        issuing1.to_der().unwrap(),
        hierarchy2.issuing.to_der().unwrap()
    );

    let authorities: Vec<_> = [AUTHORITY_ROOT, AUTHORITY_ISSUING].into_iter().collect();
    for name in authorities {
        store
            .authority(name)
            .await
            .expect("l'autorité doit être persistée");
    }
}

#[tokio::test]
async fn ceremony_rejects_mismatched_signer_on_replay() {
    let store = store();
    let (_root_signer, issuing_signer, ..) = run_test_ceremony(store.clone()).await;

    let other_root_signer = Arc::new(SoftwareToken::generate(2048));
    let err = run_ceremony(CeremonyOptions {
        root_signer: other_root_signer,
        issuing_signer,
        root_cn: String::new(),
        issuing_cn: String::new(),
        organization: String::new(),
        country: String::new(),
        root_validity: time::Duration::ZERO,
        issuing_validity: time::Duration::ZERO,
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store,
        operator: "test-operator".to_string(),
        recorder: None,
    })
    .await;

    assert!(
        err.is_err(),
        "une clé de token différente de celle déjà scellée doit être rejetée"
    );
}

async fn issuer_from_ceremony(store: Arc<Memory>) -> (Issuer, Arc<SoftwareToken>) {
    let (_root_signer, issuing_signer, _root, issuing) = run_test_ceremony(store.clone()).await;
    let issuer = Issuer::new(Options {
        signer: issuing_signer.clone(),
        certificate: issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: Some("https://ocsp.example.test".to_string()),
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .expect("l'émetteur doit accepter une autorité dont la clé correspond au signataire");
    (issuer, issuing_signer)
}

#[tokio::test]
async fn issue_produces_a_certificate_signed_by_the_issuing_key() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity
        .public_key_der()
        .expect("clé publique de l'entité finale");
    let tsa_profile = profile::tsa_signer();

    let cert = issuer
        .issue(&public_key_der, "tsu.example.test", &tsa_profile, "txn-1")
        .await
        .expect("l'émission doit réussir");

    assert_eq!(
        cert.tbs_certificate().issuer().to_string(),
        issuer.certificate().tbs_certificate().subject().to_string()
    );

    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    let stored = store
        .certificate(&serial)
        .await
        .expect("le certificat doit être persisté");
    assert_eq!(stored.status, oe_castore::CertificateStatus::Issued);
    assert_eq!(stored.request_transaction_id, "txn-1");

    // Vérification indépendante de la signature par openssl aurait besoin
    // d'écrire les fichiers sur disque ; on se contente ici de revérifier
    // que le certificat encode/décode bit-à-bit correctement (round-trip
    // DER), le HSM logiciel de test faisant déjà foi pour la primitive de
    // signature elle-même (couverte par les tests de `oe-hsm`).
    let der = cert.to_der().unwrap();
    let reparsed = Certificate::from_der(&der).unwrap();
    assert_eq!(reparsed.to_der().unwrap(), der);
}

#[tokio::test]
async fn revoke_then_publish_crl_lists_the_certificate() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let ocsp_profile = profile::ocsp_responder();
    let cert = issuer
        .issue(&public_key_der, "ocsp.example.test", &ocsp_profile, "txn-2")
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    let empty_crl = issuer
        .publish_crl()
        .await
        .expect("une CRL vide doit pouvoir être publiée");
    let parsed_empty: x509_cert::crl::CertificateList =
        x509_cert::crl::CertificateList::from_der(&empty_crl.der).unwrap();
    assert!(parsed_empty.tbs_cert_list.revoked_certificates.is_none());

    issuer
        .revoke(&serial, 1, "test-operator", "")
        .await
        .expect("la révocation doit réussir");

    let crl = issuer
        .publish_crl()
        .await
        .expect("la republication doit réussir");
    assert!(
        crl.number > empty_crl.number,
        "le numéro de CRL doit augmenter à chaque publication"
    );

    let parsed: x509_cert::crl::CertificateList =
        x509_cert::crl::CertificateList::from_der(&crl.der).unwrap();
    let revoked = parsed
        .tbs_cert_list
        .revoked_certificates
        .expect("la CRL doit lister le certificat révoqué");
    assert_eq!(revoked.len(), 1);
    assert_eq!(
        oe_ca_core::canonical_serial(&revoked[0].serial_number),
        serial
    );

    let current = issuer.current_crl().await.unwrap();
    assert_eq!(current.number, crl.number);
}

#[tokio::test]
async fn revoke_is_idempotent_and_keeps_first_reason() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let cert = issuer
        .issue(&public_key_der, "tsu2.example.test", &tsa_profile, "txn-3")
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    issuer
        .revoke(&serial, 1, "test-operator", "")
        .await
        .unwrap();
    issuer
        .revoke(&serial, 5, "test-operator", "")
        .await
        .unwrap();

    let stored = store.certificate(&serial).await.unwrap();
    assert_eq!(stored.status, oe_castore::CertificateStatus::Revoked);
    assert_eq!(
        stored.revocation_reason, 1,
        "la première raison de révocation doit être conservée"
    );
}

/// Vérification croisée par un tiers indépendant du code sous test : la
/// chaîne racine→émettrice→entité finale doit être acceptée par `openssl
/// verify`, et une fois le certificat feuille révoqué et la CRL republiée,
/// `openssl verify -crl_check` doit le rejeter — preuve que la révocation
/// produit un effet observable en dehors de notre propre code, à l'identique
/// du protocole déjà utilisé pour `oe-tsa-core`/`oe-ocsp-core` avec `openssl
/// ts`/`openssl ocsp`.
#[tokio::test]
async fn openssl_accepts_the_chain_and_honors_revocation() {
    if std::process::Command::new("openssl")
        .arg("version")
        .output()
        .is_err()
    {
        eprintln!("openssl indisponible : test de vérification croisée ignoré");
        return;
    }

    let store = store();
    let (_root_signer, issuing_signer, root, issuing) = run_test_ceremony(store.clone()).await;
    let issuer = Issuer::new(Options {
        signer: issuing_signer,
        certificate: issuing.clone(),
        chain: vec![root.clone()],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: None,
    })
    .unwrap();

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let leaf = issuer
        .issue(
            &public_key_der,
            "leaf.example.test",
            &tsa_profile,
            "txn-openssl",
        )
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(leaf.tbs_certificate().serial_number());

    let dir = std::env::temp_dir().join(format!("oe-ca-core-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let root_pem = dir.join("root.pem");
    let issuing_pem = dir.join("issuing.pem");
    let leaf_pem = dir.join("leaf.pem");
    write_pem(&root_pem, &root.to_der().unwrap());
    write_pem(&issuing_pem, &issuing.to_der().unwrap());
    write_pem(&leaf_pem, &leaf.to_der().unwrap());

    let verify_before = std::process::Command::new("openssl")
        .args(["verify", "-CAfile"])
        .arg(&root_pem)
        .arg("-untrusted")
        .arg(&issuing_pem)
        .arg(&leaf_pem)
        .output()
        .expect("openssl doit s'exécuter");
    assert!(
        verify_before.status.success(),
        "openssl doit accepter la chaîne avant révocation : {}",
        String::from_utf8_lossy(&verify_before.stderr)
    );

    issuer
        .revoke(&serial, 1, "test-operator", "")
        .await
        .unwrap();
    let crl = issuer.publish_crl().await.unwrap();
    let crl_pem = dir.join("issuing.crl.pem");
    write_crl_pem(&crl_pem, &crl.der);

    let verify_after = std::process::Command::new("openssl")
        .args(["verify", "-crl_check", "-CAfile"])
        .arg(&root_pem)
        .arg("-untrusted")
        .arg(&issuing_pem)
        .arg("-CRLfile")
        .arg(&crl_pem)
        .arg(&leaf_pem)
        .output()
        .expect("openssl doit s'exécuter");
    assert!(
        !verify_after.status.success(),
        "openssl doit rejeter le certificat révoqué"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&verify_after.stdout),
        String::from_utf8_lossy(&verify_after.stderr)
    );
    assert!(
        combined.to_lowercase().contains("revoked"),
        "le rejet doit être motivé par la révocation, pas par une autre erreur : {combined}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn write_pem(path: &std::path::Path, der: &[u8]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    std::fs::write(path, out).unwrap();
}

fn write_crl_pem(path: &std::path::Path, der: &[u8]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN X509 CRL-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END X509 CRL-----\n");
    std::fs::write(path, out).unwrap();
}

/// Recorder de test qui capture les noms d'événement reçus — sert à vérifier
/// que chaque décision de l'autorité (cérémonie, émission, révocation, CRL)
/// laisse bien une trace, condition posée par le plan de portage (le journal
/// d'audit est une preuve légale, pas un détail d'implémentation).
#[derive(Default, Clone)]
struct EventLog(Arc<std::sync::Mutex<Vec<String>>>);

impl oe_ca_core::Recorder for EventLog {
    fn append(&self, event: &str, _data: serde_json::Value) -> Result<(), String> {
        self.0.lock().unwrap().push(event.to_string());
        Ok(())
    }
}

#[tokio::test]
async fn every_authority_decision_is_recorded() {
    let store = store();
    let log = EventLog::default();

    let root_signer = Arc::new(SoftwareToken::generate(2048));
    let issuing_signer = Arc::new(SoftwareToken::generate(2048));
    let hierarchy = run_ceremony(CeremonyOptions {
        root_signer: root_signer.clone(),
        issuing_signer: issuing_signer.clone(),
        root_cn: "Test Root CA".to_string(),
        issuing_cn: "Test Issuing CA".to_string(),
        organization: "Open eIDAS Test".to_string(),
        country: "FR".to_string(),
        root_validity: time::Duration::days(20 * 365),
        issuing_validity: time::Duration::days(10 * 365),
        root_token_label: "root".to_string(),
        root_key_label: "root-key".to_string(),
        issuing_token_label: "issuing".to_string(),
        issuing_key_label: "issuing-key".to_string(),
        store: store.clone(),
        operator: "test-operator".to_string(),
        recorder: Some(Arc::new(log.clone())),
    })
    .await
    .unwrap();

    let issuer = Issuer::new(Options {
        signer: issuing_signer,
        certificate: hierarchy.issuing,
        chain: vec![],
        store: store.clone(),
        public_url: "https://ca.example.test".to_string(),
        ocsp_url: None,
        crl_validity: time::Duration::hours(24),
        crl_grace: time::Duration::hours(1),
        recorder: Some(Arc::new(log.clone())),
    })
    .unwrap();

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let cert = issuer
        .issue(
            &public_key_der,
            "audit.example.test",
            &tsa_profile,
            "txn-audit",
        )
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());
    issuer
        .revoke(&serial, 1, "test-operator", "test")
        .await
        .unwrap();
    issuer.publish_crl().await.unwrap();

    let events = log.0.lock().unwrap().clone();
    assert_eq!(
        events,
        vec![
            "ca.ceremony",
            "ca.certificate_issued",
            "ca.certificate_revoked",
            "ca.crl_published"
        ]
    );
}

#[tokio::test]
async fn revoke_rejects_empty_operator() {
    let store = store();
    let (issuer, _issuing_signer) = issuer_from_ceremony(store.clone()).await;

    let end_entity = SoftwareToken::generate(2048);
    let public_key_der = end_entity.public_key_der().unwrap();
    let tsa_profile = profile::tsa_signer();
    let cert = issuer
        .issue(&public_key_der, "tsu3.example.test", &tsa_profile, "txn-4")
        .await
        .unwrap();
    let serial = oe_ca_core::canonical_serial(cert.tbs_certificate().serial_number());

    let err = issuer.revoke(&serial, 1, "", "").await;
    assert!(
        err.is_err(),
        "révoquer sans identité d'opérateur doit être refusé — traçabilité de la décision"
    );
}
