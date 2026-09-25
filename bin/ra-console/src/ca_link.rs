//! Le lien mTLS de `ra-console` vers `ca-server` (docs/WEBUI.md §16 « Lien
//! interne »).
//!
//! Le mTLS ne prouve qu'une chose : les deux bouts sont bien ce qu'ils disent. Il
//! ne donne aucun pouvoir à la console, qui n'agit que par des signatures
//! d'opérateurs que `ca-server` vérifie lui-même.
//!
//! Côté console, on ne s'en remet pas aux valeurs par défaut de la bibliothèque
//! TLS. Le serveur doit présenter un certificat qui (1) remonte à la CA émettrice,
//! seule racine de confiance, (2) porte `serverAuth` **seul** et la politique
//! dédiée `internal_server` qu'aucun autre profil ne porte, (3) a pour `dNSName`
//! le nom auquel on se connecte. Un certificat de TSU ou d'identité qui porterait
//! `serverAuth` ne suffit donc pas.

use std::time::Duration;

use der::Decode;
use x509_cert::Certificate;

use crate::config::LinkConfig;

/// Avertir quand le certificat client approche de son échéance : le
/// renouvellement demande une approbation humaine (§14).
const RENEWAL_WARNING: time::Duration = time::Duration::days(30);

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("configuration du lien interne : {0}")]
    Config(String),
    #[error("certificat client de la console refusé : {0}")]
    ClientCertificate(String),
    #[error("ca-server injoignable : {0}")]
    Unreachable(String),
    #[error("certificat de ca-server refusé : {0}")]
    ServerCertificate(String),
    #[error("réponse inattendue de ca-server : {0}")]
    Unexpected(String),
}

pub struct CaLink {
    client: reqwest::Client,
    base: reqwest::Url,
    host: String,
    client_not_after: time::OffsetDateTime,
}

fn read(path: &str, what: &str) -> Result<Vec<u8>, LinkError> {
    std::fs::read(path).map_err(|e| LinkError::Config(format!("{what} ({path}) : {e}")))
}

fn unix(t: &x509_cert::time::Time) -> u64 {
    t.to_unix_duration().as_secs()
}

fn to_offset(t: &x509_cert::time::Time) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(unix(t) as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

fn common_name(cert: &Certificate) -> String {
    let cn = der::asn1::ObjectIdentifier::new("2.5.4.3").expect("OID constant invalide");
    cert.tbs_certificate()
        .subject()
        .iter()
        .find(|atv| atv.oid == cn)
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
        .unwrap_or_default()
}

/// Contrôles du certificat client, avant de s'en servir : mieux vaut refuser de
/// démarrer que découvrir, à la première action, que `ca-server` ferme la porte.
pub fn check_own_certificate(
    cert: &Certificate,
    now: time::OffsetDateTime,
) -> Result<time::OffsetDateTime, LinkError> {
    oe_conformance::check_internal_client_certificate("certificat client", cert)
        .map_err(LinkError::ClientCertificate)?;
    if common_name(cert) != oe_conformance::INTERNAL_CLIENT_CN {
        return Err(LinkError::ClientCertificate(format!(
            "nom courant {:?}, attendu {:?}",
            common_name(cert),
            oe_conformance::INTERNAL_CLIENT_CN
        )));
    }
    let validity = cert.tbs_certificate().validity();
    let (not_before, not_after) = (
        to_offset(&validity.not_before),
        to_offset(&validity.not_after),
    );
    if now < not_before || now > not_after {
        return Err(LinkError::ClientCertificate(format!(
            "hors de sa période de validité ({not_before} → {not_after})"
        )));
    }
    Ok(not_after)
}

/// Contrôles explicites du certificat que présente `ca-server`.
pub fn check_server_certificate(
    der: &[u8],
    host: &str,
    now: time::OffsetDateTime,
) -> Result<(), LinkError> {
    let cert = Certificate::from_der(der)
        .map_err(|e| LinkError::ServerCertificate(format!("illisible : {e}")))?;
    oe_conformance::check_internal_server_certificate("certificat de ca-server", &cert)
        .map_err(LinkError::ServerCertificate)?;
    let names = oe_conformance::dns_names(&cert);
    if !names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
        return Err(LinkError::ServerCertificate(format!(
            "le SAN {names:?} ne porte pas {host:?}"
        )));
    }
    let validity = cert.tbs_certificate().validity();
    if now < to_offset(&validity.not_before) || now > to_offset(&validity.not_after) {
        return Err(LinkError::ServerCertificate(
            "hors de sa période de validité".to_string(),
        ));
    }
    Ok(())
}

impl CaLink {
    pub fn new(cfg: &LinkConfig) -> Result<CaLink, LinkError> {
        let base = reqwest::Url::parse(&cfg.ca_url)
            .map_err(|e| LinkError::Config(format!("URL {:?} : {e}", cfg.ca_url)))?;
        if base.scheme() != "https" {
            return Err(LinkError::Config(
                "le lien interne est en https (mTLS)".to_string(),
            ));
        }
        let host = base
            .host_str()
            .ok_or_else(|| LinkError::Config("URL sans nom d'hôte".to_string()))?
            .to_string();

        let cert_pem = read(&cfg.cert_file, "certificat client")?;
        let key_pem = read(&cfg.key_file, "clé du client")?;
        let ca_pem = read(&cfg.ca_file, "certificat de la CA")?;

        let leaf = oe_certs::parse_pem(&cert_pem)
            .map_err(|e| LinkError::ClientCertificate(e.to_string()))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                LinkError::ClientCertificate("aucun certificat dans le fichier".into())
            })?;
        let now = time::OffsetDateTime::now_utc();
        let not_after = check_own_certificate(&leaf, now)?;
        if not_after - now < RENEWAL_WARNING {
            tracing::warn!(
                expire_le = %not_after,
                "le certificat client du lien interne expire dans moins de 30 jours : à renouveler"
            );
        }

        let mut identity = cert_pem.clone();
        identity.extend_from_slice(b"\n");
        identity.extend_from_slice(&key_pem);
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            // La CA émettrice est la seule racine : ni magasin du système, ni autre.
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| LinkError::Config(format!("certificat de la CA : {e}")))?,
            )
            .identity(
                reqwest::Identity::from_pem(&identity)
                    .map_err(|e| LinkError::Config(format!("certificat et clé du client : {e}")))?,
            )
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .https_only(true)
            .tls_info(true)
            .redirect(reqwest::redirect::Policy::none())
            // Pas de connexion réutilisée : `ca-server` ne contrôle le certificat client
            // (révocation comprise) qu'à la poignée de main. Une connexion gardée
            // ouverte survivrait à la révocation du certificat de la console ; le
            // trafic d'une console d'exploitation est assez faible pour payer une
            // poignée de main par requête.
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| LinkError::Config(e.to_string()))?;

        Ok(CaLink {
            client,
            base,
            host,
            client_not_after: not_after,
        })
    }

    /// Fin de validité du certificat client de la console.
    pub fn client_certificate_expires(&self) -> time::OffsetDateTime {
        self.client_not_after
    }

    /// Envoie une requête et contrôle, **à chaque réponse**, le certificat que
    /// `ca-server` a présenté (politique, SAN, validité) : le contrôle ne se limite
    /// pas à la sonde. Rend le statut et le corps JSON, quel que soit le statut :
    /// interpréter un refus de `ca-server` revient à l'appelant.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Relayed, LinkError> {
        let response = request
            .send()
            .await
            .map_err(|e| LinkError::Unreachable(format!("{e:#}")))?;
        let der = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|i| i.peer_certificate())
            .ok_or_else(|| LinkError::ServerCertificate("aucun certificat présenté".into()))?
            .to_vec();
        check_server_certificate(&der, &self.host, time::OffsetDateTime::now_utc())?;

        let status = response.status().as_u16();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            LinkError::Unexpected(format!("corps non JSON (statut {status}) : {e}"))
        })?;
        Ok(Relayed { status, body })
    }

    /// Relaie un corps JSON à une route interne de `ca-server`. Le corps est celui
    /// que la console a **reconstruit** à partir de champs qu'elle a validés : elle
    /// ne fait jamais suivre tel quel ce qu'un navigateur lui a envoyé.
    pub async fn post(&self, path: &str, body: &serde_json::Value) -> Result<Relayed, LinkError> {
        let url = self
            .base
            .join(path)
            .map_err(|e| LinkError::Config(e.to_string()))?;
        self.send(self.client.post(url).json(body)).await
    }

    /// Sonde le lien : poignée de main mTLS, contrôle explicite du certificat de
    /// `ca-server`, puis `GET /internal/v1/ping`.
    pub async fn ping(&self) -> Result<(), LinkError> {
        let url = self
            .base
            .join("/internal/v1/ping")
            .map_err(|e| LinkError::Config(e.to_string()))?;
        let relayed = self.send(self.client.get(url)).await?;
        if !(200..300).contains(&relayed.status) {
            return Err(LinkError::Unexpected(format!("statut {}", relayed.status)));
        }
        if relayed.body["ok"] != true {
            return Err(LinkError::Unexpected(relayed.body.to_string()));
        }
        Ok(())
    }
}

/// La réponse de `ca-server` à une requête relayée.
#[derive(Debug)]
pub struct Relayed {
    pub status: u16,
    pub body: serde_json::Value,
}
