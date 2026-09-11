//! Vérifie `oe-replicate::Client` contre un vrai serveur HTTP (un serveur
//! WebDAV minimal, juste assez pour accepter un PUT authentifié) — jalon J8
//! du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::put;
use axum::Router;

#[derive(Default)]
struct Received {
    path: Option<String>,
    body: Option<Vec<u8>>,
    auth: Option<String>,
}

async fn handle_put(
    State(state): State<Arc<Mutex<Received>>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    let mut r = state.lock().unwrap();
    r.path = Some(path);
    r.body = Some(body.to_vec());
    r.auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    StatusCode::CREATED
}

#[tokio::test]
async fn replicates_content_via_webdav_put() {
    let state = Arc::new(Mutex::new(Received::default()));
    let app = Router::new()
        .route("/open-eidas/{*path}", put(handle_put))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = oe_replicate::Client::new(oe_replicate::Options {
        url: format!("http://{addr}/open-eidas/"),
        username: "auditeur".to_string(),
        password: "secret".to_string(),
        ..Default::default()
    })
    .expect("construction du client de réplication");

    let content = b"audit-log-scelle-2026-09-11.jsonl".to_vec();
    let result = client
        .replicate("audit-2026-09-11T00-00-00Z.log", content.clone())
        .await
        .expect("la réplication doit réussir");

    assert_eq!(result.bytes, content.len());
    assert_eq!(result.sha256.len(), 64);

    let received = state.lock().unwrap();
    assert_eq!(
        received.path.as_deref(),
        Some("audit-2026-09-11T00-00-00Z.log")
    );
    assert_eq!(received.body.as_deref(), Some(content.as_slice()));
    assert!(
        received.auth.as_deref().unwrap_or("").starts_with("Basic "),
        "authentification de base attendue"
    );
}

#[tokio::test]
async fn rejects_missing_url() {
    let err = oe_replicate::Client::new(oe_replicate::Options::default()).unwrap_err();
    assert!(matches!(err, oe_replicate::ReplicateError::MissingUrl));
}
