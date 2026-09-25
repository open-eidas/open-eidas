//! Routes de `ra-console`. Pour l'instant : `/healthz` (aucune authentification
//! d'opérateur n'est encore branchée).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sqlx::PgPool;

use crate::ca_link::{CaLink, Relayed};
use crate::login::{LoginError, LoginService};

/// Assez pour un objet d'attestation, pas pour bourrer la mémoire.
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct AppState {
    pub pool: PgPool,
    pub link: CaLink,
    pub login: LoginService,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(handle_health))
        .route(
            "/api/v1/webauthn/register/begin",
            post(handle_register_begin),
        )
        .route(
            "/api/v1/webauthn/register/finish",
            post(handle_register_finish),
        )
        .route("/api/v1/webauthn/login/begin", post(handle_login_begin))
        .route("/api/v1/webauthn/login/finish", post(handle_login_finish))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Sain seulement si la base répond ET si le lien vers `ca-server` fonctionne :
/// une console qui ne peut pas relayer d'action ne doit pas se déclarer prête.
async fn handle_health(State(state): State<Arc<AppState>>) -> Response {
    let base = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    let lien = state.link.ping().await.map_err(|e| e.to_string());

    let ok = base.is_ok() && lien.is_ok();
    let describe = |r: &Result<(), String>| match r {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("ko : {e}"),
    };
    let body = serde_json::json!({
        "statut": if ok { "ok" } else { "degrade" },
        "version": env!("CARGO_PKG_VERSION"),
        "base": describe(&base),
        "lien_ca": describe(&lien),
        "certificat_client_expire_le": state
            .link
            .client_certificate_expires()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    });
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

/// `{"error": "<code>", "message": "..."}` (docs/WEBUI.md §5), sans trace interne.
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": code, "message": message })),
    )
        .into_response()
}

/// Une route qui relaie des JSON n'accepte que du JSON déclaré : un navigateur ne
/// peut pas envoyer `application/json` d'un autre site sans pré-requête CORS, ce qui
/// ferme les envois « aveugles » d'un formulaire piégé.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
}

fn unsupported_media_type() -> Response {
    error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
        "Content-Type: application/json attendu",
    )
}

/// Ce que `ca-server` a répondu, rendu tel quel pour un refus de sa part (le code
/// et le message sont faits pour cela) ; une panne, elle, ne fuit aucun détail.
fn relayed(result: Result<Relayed, crate::ca_link::LinkError>) -> Response {
    match result {
        Ok(r) if r.status < 500 => (
            StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(r.body),
        )
            .into_response(),
        Ok(r) => {
            tracing::error!(statut = r.status, "ca-server a refusé de servir");
            error(
                StatusCode::BAD_GATEWAY,
                "ca_unavailable",
                "ca-server est indisponible",
            )
        }
        Err(e) => {
            tracing::error!(erreur = %e, "lien vers ca-server en échec");
            error(
                StatusCode::BAD_GATEWAY,
                "ca_unavailable",
                "ca-server est injoignable",
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBegin {
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinish {
    ceremony_id: String,
    /// La sortie brute de `navigator.credentials.create` : la console ne la lit
    /// pas, elle ne la comprend pas, elle la relaie. C'est `ca-server` qui vérifie
    /// l'attestation.
    credential: serde_json::Value,
}

/// Une valeur d'identifiant de cérémonie : un UUID, rien d'autre.
fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// `POST /api/v1/webauthn/register/begin` : l'invité présente son jeton
/// d'invitation, `ca-server` rend les options WebAuthn (docs/WEBUI.md §5, §10). Le
/// jeton est le seul secret de cette route : il n'est ni journalisé ni renvoyé.
async fn handle_register_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: RegisterBegin = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    if req.token.is_empty() || req.token.len() > 256 {
        return error(StatusCode::BAD_REQUEST, "bad_request", "jeton invalide");
    }
    relayed(
        state
            .link
            .post(
                "/internal/v1/register/begin",
                &serde_json::json!({ "token": req.token }),
            )
            .await,
    )
}

/// `POST /api/v1/webauthn/register/finish` : l'attestation est relayée telle
/// quelle. `ca-server` la vérifie contre la liste blanche de modèles et range la
/// clé ; la console n'en garde rien.
async fn handle_register_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: RegisterFinish = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    if !looks_like_uuid(&req.ceremony_id) || !req.credential.is_object() {
        return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide");
    }
    relayed(
        state
            .link
            .post(
                "/internal/v1/register/finish",
                &serde_json::json!({
                    "ceremony_id": req.ceremony_id,
                    "credential": req.credential,
                }),
            )
            .await,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBegin {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinish {
    challenge_id: String,
    /// La sortie brute de `navigator.credentials.get` : vérifiée par
    /// `ra-console` elle-même (§16), jamais relayée à `ca-server`.
    credential: serde_json::Value,
}

/// Un nom d'opérateur : ce qu'un humain saisit, pas un identifiant technique.
/// Une longueur bornée suffit à écarter un corps abusif avant toute requête ;
/// le reste (existe ou non) ne se voit jamais dans la réponse (§16).
fn looks_like_a_name(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 256
}

/// `POST /api/v1/webauthn/login/begin` : options WebAuthn de même forme que le
/// nom existe ou non (docs/WEBUI.md §16). Ni `ca-server` ni son lien interne ne
/// sont sollicités : le registre en lecture seule suffit.
async fn handle_login_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: LoginBegin = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    if !looks_like_a_name(&req.name) {
        return error(StatusCode::BAD_REQUEST, "bad_request", "nom invalide");
    }
    match state.login.begin(&req.name).await {
        Ok(begun) => Json(serde_json::json!({
            "challenge_id": begun.challenge_id,
            "webauthn": begun.options.public_key,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!(erreur = %e, "login/begin : base indisponible");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service indisponible",
            )
        }
    }
}

/// `POST /api/v1/webauthn/login/finish` : assertion vérifiée contre le
/// registre en lecture seule. Ne rend pas encore de session (1c-2, docs/WEBUI.md
/// §15 étape 1c) : seulement l'identité, une fois l'assertion admise.
async fn handle_login_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json(&headers) {
        return unsupported_media_type();
    }
    let req: LoginFinish = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "corps invalide"),
    };
    let Ok(challenge_id) = req.challenge_id.parse() else {
        return invalid_credential();
    };
    let credential = match serde_json::from_value(req.credential) {
        Ok(c) => c,
        Err(_) => return invalid_credential(),
    };
    match state.login.finish(challenge_id, &credential).await {
        Ok(v) => Json(serde_json::json!({
            "operator": v.operator,
            "role": v.role.as_str(),
        }))
        .into_response(),
        Err(LoginError::Invalid) => invalid_credential(),
    }
}

/// Une seule forme pour tout refus de `login/finish` (§16) : nom inconnu,
/// leurre, challenge périmé ou déjà consommé, clé révoquée, opérateur
/// désactivé, signature refusée, compteur en régression ne se distinguent
/// jamais de l'extérieur.
fn invalid_credential() -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        "invalid_credential",
        "identifiants invalides",
    )
}
