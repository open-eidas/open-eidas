//! API HTTP de la CA — portage de `cmd/ca-server/server.go`.
//!
//! Les chemins de publication (`/download/<CN>.cer` et `.crl`) sont
//! exactement ceux qu'OpenXPKI servait auparavant : les URL déjà gravées
//! dans les extensions CDP/AIA des certificats émis restent valables, et le
//! répondeur OCSP retrouve la CRL au même endroit.

use std::sync::{Arc, RwLock};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use der::Encode;
use serde::{Deserialize, Serialize};

struct CrlCache {
    crl: Option<oe_castore::Crl>,
    err: Option<String>,
}

pub struct Server {
    issuer: Arc<oe_ca_core::Issuer>,
    flow: Arc<oe_raflow::Flow>,
    version: String,
    ca_der: Vec<u8>,
    ca_pem: String,
    crl_path: String,
    ca_path: String,
    cache: RwLock<CrlCache>,
}

impl Server {
    pub fn new(
        issuer: Arc<oe_ca_core::Issuer>,
        flow: Arc<oe_raflow::Flow>,
        version: String,
    ) -> Server {
        let name = oe_certs::file_name(&common_name(issuer.certificate()));
        let ca_der = issuer.certificate().to_der().unwrap_or_default();
        let mut ca_pem = String::new();
        for c in issuer.full_chain() {
            if let Ok(der) = c.to_der() {
                ca_pem.push_str(&pem_block("CERTIFICATE", &der));
            }
        }
        Server {
            issuer,
            flow,
            version,
            ca_der,
            ca_pem,
            crl_path: format!("/download/{name}.crl"),
            ca_path: format!("/download/{name}.cer"),
            cache: RwLock::new(CrlCache {
                crl: None,
                err: None,
            }),
        }
    }

    pub fn issuer(&self) -> &oe_ca_core::Issuer {
        &self.issuer
    }

    /// Publie une CRL immédiatement puis à intervalle régulier, jusqu'à
    /// annulation du token. La première publication est bloquante : le
    /// service ne doit pas se déclarer prêt sans état de révocation
    /// servable.
    pub async fn start_crl_publication(
        self: &Arc<Self>,
        every: std::time::Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), String> {
        self.publish_crl()
            .await
            .map_err(|e| format!("publication initiale de la CRL: {e}"))?;
        let server = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = server.publish_crl().await {
                            // L'ancienne CRL reste servie : elle est encore
                            // valide jusqu'à son nextUpdate, et /healthz
                            // bascule en dégradé dès qu'elle ne l'est plus.
                            tracing::error!(erreur = %e, "publication de la CRL impossible, conservation de la précédente");
                        }
                    }
                    _ = shutdown.changed() => return,
                }
            }
        });
        Ok(())
    }

    async fn publish_crl(&self) -> Result<(), String> {
        match self.issuer.publish_crl().await {
            Ok(crl) => {
                tracing::info!(numero = crl.number, next_update = %crl.next_update, "CRL publiée");
                let mut cache = self.cache.write().unwrap();
                cache.crl = Some(crl);
                cache.err = None;
                Ok(())
            }
            Err(e) => {
                self.cache.write().unwrap().err = Some(e.to_string());
                Err(e.to_string())
            }
        }
    }

    /// Relit le registre plutôt que le seul cache mémoire : une révocation
    /// décidée par une commande d'exploitation (`ca-server revoke`) publie
    /// une nouvelle CRL depuis un AUTRE processus, et une révocation qui
    /// n'est pas servie ne protège personne. Le cache ne sert que de repli
    /// si le registre est momentanément injoignable.
    async fn current_crl(&self) -> Result<oe_castore::Crl, String> {
        match self.issuer.current_crl().await {
            Ok(latest) => {
                let mut cache = self.cache.write().unwrap();
                if cache.crl.as_ref().is_none_or(|c| latest.number > c.number) {
                    cache.crl = Some(latest.clone());
                }
                Ok(latest)
            }
            Err(e) => {
                let cached = self.cache.read().unwrap().crl.clone();
                match cached {
                    Some(c) => {
                        tracing::warn!(erreur = %e, numero = c.number, "registre injoignable, CRL servie depuis le cache");
                        Ok(c)
                    }
                    None => Err(e.to_string()),
                }
            }
        }
    }
}

fn common_name(cert: &x509_cert::Certificate) -> String {
    const OID_CN: &str = "2.5.4.3";
    let cn_oid = der::asn1::ObjectIdentifier::new(OID_CN).expect("OID constant invalide");
    cert.tbs_certificate()
        .subject()
        .iter()
        .find(|atv| atv.oid == cn_oid)
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
        .unwrap_or_default()
}

fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn router(server: Arc<Server>, max_request_bytes: usize) -> Router {
    let ca_path = server.ca_path.clone();
    let crl_path = server.crl_path.clone();
    Router::new()
        .route("/api/v1/enroll", axum::routing::post(handle_enroll))
        .route("/api/v1/ca.pem", get(handle_ca_pem))
        .route("/api/v1/conformance", get(handle_conformance))
        .route(&ca_path, get(handle_ca_der))
        .route(&crl_path, get(handle_crl))
        .route("/healthz", get(handle_health))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .with_state(server)
}

/// Le protocole est défini par ce dépôt : la CSR est transmise en PEM, la
/// signature est le HMAC-SHA256 hexadécimal de ses octets DER (voir
/// `oe_raflow::signature`).
#[derive(Deserialize)]
struct EnrollRequest {
    profile: String,
    pkcs10: String,
    signature: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    state: String,
    transaction_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    chain: Vec<String>,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// Accepte la CSR en PEM ou en base64 de son DER : le premier est ce que
/// produisent les outils courants, le second évite aux clients JSON de
/// transporter des sauts de ligne.
fn decode_csr(raw: &str) -> Result<Vec<u8>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("champ pkcs10 vide".to_string());
    }
    if raw.starts_with("-----BEGIN") {
        let (label, doc) =
            der::Document::from_pem(raw).map_err(|e| format!("bloc PEM illisible: {e}"))?;
        if label != "CERTIFICATE REQUEST" {
            return Err(format!(
                "bloc PEM de type {label:?}, attendu CERTIFICATE REQUEST"
            ));
        }
        return Ok(doc.into_vec());
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| "champ pkcs10 : ni PEM ni base64 exploitable".to_string())
}

async fn handle_enroll(
    State(server): State<Arc<Server>>,
    Json(req): Json<EnrollRequest>,
) -> Response {
    let csr_der = match decode_csr(&req.pkcs10) {
        Ok(der) => der,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };

    let result = match server
        .flow
        .submit(&csr_der, &req.profile, &req.signature)
        .await
    {
        Ok(r) => r,
        // Volontairement laconique : distinguer « secret faux » de « CSR
        // invalide » renseignerait un attaquant sur ce qu'il doit corriger.
        Err(oe_raflow::RaflowError::Unauthenticated) => {
            return error_response(StatusCode::UNAUTHORIZED, "demande non authentifiée")
        }
        Err(e @ oe_raflow::RaflowError::Rejected { .. }) => {
            return error_response(StatusCode::FORBIDDEN, e.to_string())
        }
        Err(e) => {
            tracing::warn!(erreur = %e, "enrôlement refusé");
            return error_response(StatusCode::BAD_REQUEST, e.to_string());
        }
    };

    let mut resp = EnrollResponse {
        state: request_state_str(result.state).to_string(),
        transaction_id: result.transaction_id,
        retry_after: None,
        certificate: None,
        chain: vec![],
    };
    let status = if result.state == oe_castore::RequestState::Pending {
        // 202 Accepted : la demande est enregistrée, la décision appartient
        // à un opérateur RA. Le client reviendra.
        resp.retry_after = result.retry_after.map(|d| d.whole_seconds());
        StatusCode::ACCEPTED
    } else {
        if let Some(cert) = &result.certificate {
            resp.certificate = cert.to_der().ok().map(|der| pem_block("CERTIFICATE", &der));
        }
        resp.chain = result
            .chain
            .iter()
            .filter_map(|c| c.to_der().ok())
            .map(|der| pem_block("CERTIFICATE", &der))
            .collect();
        StatusCode::OK
    };
    (status, Json(resp)).into_response()
}

fn request_state_str(s: oe_castore::RequestState) -> &'static str {
    match s {
        oe_castore::RequestState::Pending => "PENDING",
        oe_castore::RequestState::Approved => "APPROVED",
        oe_castore::RequestState::Issued => "ISSUED",
        oe_castore::RequestState::Rejected => "REJECTED",
    }
}

async fn handle_ca_pem(State(server): State<Arc<Server>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        server.ca_pem.clone(),
    )
}

/// Sert le certificat de la CA émettrice au format DER, à l'adresse exacte
/// que porte l'extension AIA `ca_issuers` des certificats émis.
async fn handle_ca_der(State(server): State<Arc<Server>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/pkix-cert")],
        server.ca_der.clone(),
    )
}

async fn handle_crl(State(server): State<Arc<Server>>) -> Response {
    match server.current_crl().await {
        Ok(crl) => ([(header::CONTENT_TYPE, "application/pkix-crl")], crl.der).into_response(),
        Err(e) => {
            tracing::error!(erreur = %e, "CRL indisponible");
            (StatusCode::SERVICE_UNAVAILABLE, "aucune CRL publiée").into_response()
        }
    }
}

/// Sert la matrice ETSI telle que l'instance qui tourne l'applique : un
/// auditeur peut ainsi comparer le document du dépôt à ce que le service
/// déclare réellement.
async fn handle_conformance(State(server): State<Arc<Server>>) -> impl IntoResponse {
    let matrix = oe_conformance::system_matrix();
    let entries: Vec<_> = matrix
        .0
        .iter()
        .map(|e| {
            serde_json::json!({
                "norme": e.requirement.standard,
                "clause": e.requirement.clause,
                "exigence": e.requirement.title,
                "statut": e.status.label(),
                "mecanisme": e.mechanism,
                "test": e.test,
                "cible": e.target,
            })
        })
        .collect();
    let comptes: serde_json::Map<String, serde_json::Value> = matrix
        .counts()
        .into_iter()
        .map(|(status, n)| (status.label().to_string(), serde_json::Value::from(n)))
        .collect();
    let (coherente, incoherence) = match matrix.validate() {
        Ok(()) => (true, None),
        Err(msg) => (false, Some(msg)),
    };
    Json(serde_json::json!({
        "version": server.version,
        "comptes": comptes,
        "normes": matrix.standards(),
        "exigences": entries,
        "matrice_coherente": coherente,
        "incoherence": incoherence,
    }))
}

/// Bascule en dégradé dès que l'état de révocation n'est plus servable : un
/// service qui ne peut plus dire ce qui est révoqué ne doit pas se déclarer
/// sain (ETSI EN 319 411-1 §6.3.10).
async fn handle_health(State(server): State<Arc<Server>>) -> Response {
    let crl_result = server.current_crl().await;
    let cached_err = server.cache.read().unwrap().err.clone();

    let mut status = StatusCode::OK;
    let mut statut = "ok";
    let mut detail = String::new();
    let mut crl_numero = None;
    let mut crl_next_update = None;

    match &crl_result {
        Err(_) => {
            statut = "degrade";
            detail = "aucune CRL publiée".to_string();
            status = StatusCode::SERVICE_UNAVAILABLE;
        }
        Ok(crl) => {
            if time::OffsetDateTime::now_utc() > crl.next_update {
                statut = "degrade";
                detail = format!("la CRL publiée est périmée depuis le {}", crl.next_update);
                status = StatusCode::SERVICE_UNAVAILABLE;
            }
            crl_numero = Some(crl.number);
            crl_next_update = Some(crl.next_update.to_string());
        }
    }
    if detail.is_empty() {
        if let Some(err) = cached_err {
            detail = format!("dernière publication en échec : {err}");
        }
    }

    let body = serde_json::json!({
        "statut": statut,
        "version": server.version,
        "emettrice": server.issuer.certificate().tbs_certificate().subject().to_string(),
        "crl_numero": crl_numero,
        "crl_next_update": crl_next_update,
        "detail": if detail.is_empty() { None } else { Some(detail) },
    });
    (status, Json(body)).into_response()
}
