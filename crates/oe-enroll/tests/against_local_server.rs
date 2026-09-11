//! Vérifie `oe-enroll::Client` contre un serveur d'enrôlement minimal (une
//! reproduction ciblée de `POST /api/v1/enroll`) — jalon J9 du plan de
//! migration (`/home/philippe/.claude/plans/witty-hopping-nest.md`). Le
//! serveur de test contrôle réellement la signature HMAC et la
//! preuve-de-possession de la CSR reçue, pour prouver que le client Rust
//! produit un artefact conforme au protocole, pas seulement plausible.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use der::{Decode, Encode};
use hmac::{Hmac, Mac};
use oe_hsm::testing::SoftwareToken;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::request::CertReq;

const HMAC_SECRET: &str = "secret-partage-de-test";

#[derive(Deserialize)]
struct IncomingRequest {
    profile: String,
    pkcs10: String,
    signature: String,
}

#[derive(Serialize)]
struct OutgoingResponse {
    transaction_id: String,
    retry_after: i64,
    certificate: Option<String>,
    chain: Vec<String>,
    error: String,
}

fn fixtures_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/tsa"
    ))
}

async fn handle_enroll(
    State(issued_cert_pem): State<Arc<String>>,
    Json(body): Json<IncomingRequest>,
) -> Json<OutgoingResponse> {
    assert_eq!(body.profile, "tsa_signer");

    // 1. La CSR doit être un PEM PKCS#10 valide.
    let block = pem::parse(body.pkcs10.as_bytes()).expect("CSR PEM invalide");
    assert_eq!(block.tag(), "CERTIFICATE REQUEST");
    let csr_der = block.contents();
    let csr = CertReq::from_der(csr_der).expect("CSR DER invalide");

    // 2. La signature HMAC doit correspondre au secret partagé, sur les
    //    octets DER exacts de la CSR (comme raflow.Signature côté Go).
    let mut mac = Hmac::<Sha256>::new_from_slice(HMAC_SECRET.as_bytes()).unwrap();
    mac.update(csr_der);
    let expected = hex::encode(mac.finalize().into_bytes());
    assert_eq!(body.signature, expected, "signature HMAC invalide");

    // 3. Preuve de possession : la CSR doit être auto-signée valablement
    //    par la clé publique qu'elle embarque.
    let spki_der = csr.info.public_key.to_der().unwrap();
    let public_key =
        RsaPublicKey::from_public_key_der(&spki_der).expect("clé publique de la CSR invalide");
    let info_der = csr.info.to_der().unwrap();
    let digest = Sha256::digest(&info_der);
    public_key
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &digest,
            csr.signature.raw_bytes(),
        )
        .expect("la CSR doit être auto-signée valablement");

    Json(OutgoingResponse {
        transaction_id: "tx-test".to_string(),
        retry_after: 0,
        certificate: Some((*issued_cert_pem).clone()),
        chain: vec![],
        error: String::new(),
    })
}

#[tokio::test]
async fn enrolls_a_certificate_from_a_conformant_ca_endpoint() {
    let issued_cert_pem =
        Arc::new(std::fs::read_to_string(fixtures_dir().join("tsu-cert.pem")).unwrap());

    let app = Router::new()
        .route("/api/v1/enroll", post(handle_enroll))
        .with_state(issued_cert_pem.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = oe_enroll::Client::new(oe_enroll::Options {
        endpoint: format!("http://{addr}/api/v1/enroll"),
        profile: "tsa_signer".to_string(),
        hmac_secret: HMAC_SECRET.to_string(),
        insecure: true,
        ..Default::default()
    })
    .expect("construction du client d'enrôlement");

    let signer = SoftwareToken::generate(3072);
    let result = client
        .request(
            &signer,
            oe_enroll::Subject {
                common_name: "Open eIDAS TSU (test)".to_string(),
            },
        )
        .await
        .expect("l'enrôlement doit réussir");

    assert!(result.chain.is_empty());
    // Vérifie qu'on retrouve bien le certificat émis par le serveur de test.
    assert_eq!(result.certificate.to_der().unwrap(), {
        let block = pem::parse(issued_cert_pem.as_bytes()).unwrap();
        block.contents().to_vec()
    });
}
