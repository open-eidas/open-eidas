//! `oe-s3` contre un vrai serveur HTTP (pas contre une valeur fabriquée) :
//! un compartiment MinIO/Garage/Ceph réel n'est pas disponible dans cet
//! environnement de développement (image non accessible sur le registre),
//! donc ce test fait tourner un serveur qui se comporte comme le ferait un
//! service S3-compatible pour PUT/GET — et vérifie au passage que les
//! requêtes envoyées sont bien signées (paramètres `X-Amz-*`).

use axum::extract::{Path, State};
use axum::http::{Method, StatusCode};
use axum::routing::any;
use axum::Router;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Objects(Mutex<HashMap<String, Vec<u8>>>);

async fn handle(
    State(objects): State<Arc<Objects>>,
    method: Method,
    Path((bucket, key)): Path<(String, String)>,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> (StatusCode, Vec<u8>) {
    // La requête doit être signée : sans ça, un vrai service S3 la
    // refuserait (403). On le vérifie ici plutôt que de faire confiance
    // aveuglément à la bibliothèque de signature.
    assert!(
        uri.query().unwrap_or("").contains("X-Amz-Signature"),
        "requête non signée : {uri}"
    );
    let full_key = format!("{bucket}/{key}");
    match method {
        Method::PUT => {
            objects.0.lock().unwrap().insert(full_key, body.to_vec());
            (StatusCode::OK, Vec::new())
        }
        Method::GET => match objects.0.lock().unwrap().get(&full_key) {
            Some(bytes) => (StatusCode::OK, bytes.clone()),
            None => (StatusCode::NOT_FOUND, Vec::new()),
        },
        _ => (StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
    }
}

/// Un point de terminaison, jamais opérationnel : renvoie toujours 500,
/// pour exercer le chemin d'erreur.
async fn handle_failing() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn options(endpoint: String) -> oe_s3::Options {
    oe_s3::Options {
        endpoint,
        bucket: "audit".to_string(),
        region: "us-east-1".to_string(),
        access_key: "test".to_string(),
        secret_key: "test-secret-au-moins-16-octets".to_string(),
        timeout: std::time::Duration::from_secs(5),
    }
}

#[tokio::test]
async fn put_then_get_round_trips_the_object() {
    let app = Router::new()
        .route("/{bucket}/{*key}", any(handle))
        .with_state(Arc::new(Objects::default()));
    let endpoint = serve(app).await;
    let client = oe_s3::Client::new(options(endpoint)).unwrap();

    client
        .put("journaux/ca-server.log", b"contenu du journal".to_vec())
        .await
        .unwrap();
    let read_back = client.get("journaux/ca-server.log").await.unwrap();
    assert_eq!(read_back, b"contenu du journal");
}

#[tokio::test]
async fn a_missing_object_is_a_get_error() {
    let app = Router::new()
        .route("/{bucket}/{*key}", any(handle))
        .with_state(Arc::new(Objects::default()));
    let endpoint = serve(app).await;
    let client = oe_s3::Client::new(options(endpoint)).unwrap();

    let err = client.get("jamais-écrit.log").await.unwrap_err();
    assert!(matches!(err, oe_s3::S3Error::GetStatus { status: 404, .. }));
}

#[tokio::test]
async fn a_put_against_an_unavailable_service_fails() {
    let app = Router::new().route("/{*path}", any(handle_failing));
    let endpoint = serve(app).await;
    let client = oe_s3::Client::new(options(endpoint)).unwrap();

    let err = client.put("x.log", b"x".to_vec()).await.unwrap_err();
    assert!(matches!(err, oe_s3::S3Error::PutStatus { status: 500, .. }));
}
