//! Routes de `ra-console`. Pour l'instant : `/healthz` (aucune authentification
//! d'opérateur n'est encore branchée).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sqlx::PgPool;

use crate::ca_link::CaLink;

pub struct AppState {
    pub pool: PgPool,
    pub link: CaLink,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(handle_health))
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
