//! Client S3-compatible minimal (docs/WEBUI.md §7, §15 étape 2b-B) : de quoi
//! déposer et relire le journal d'audit sur un stockage objet **auto-hébergé**
//! (MinIO, Garage, Ceph…), jamais un service géré (AWS ou équivalent) — même
//! esprit souverain que `oe-replicate` (WebDAV), décision de l'association.
//!
//! `rusty-s3` construit et signe les requêtes (SigV4, « Sans-IO ») ; ce crate
//! ne fait qu'y adjoindre `reqwest` pour les envoyer, comme `oe-replicate` le
//! fait déjà pour WebDAV — pas de dépendance au SDK AWS complet.
//!
//! Style d'URL **path** (`https://endpoint/bucket/clé`), pas *virtual-host*
//! (`https://bucket.endpoint/clé`) : le second exige un certificat TLS et un
//! DNS génériques pour chaque compartiment, rarement en place sur un
//! déploiement auto-hébergé.

use std::time::Duration;

use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};

#[derive(Debug, thiserror::Error)]
pub enum S3Error {
    #[error("URL du point de terminaison invalide : {0}")]
    InvalidEndpoint(#[from] url::ParseError),
    #[error("compartiment invalide : {0}")]
    InvalidBucket(#[from] rusty_s3::BucketError),
    #[error("PUT {url} : {source}")]
    Put { url: String, source: reqwest::Error },
    #[error("PUT {url} : HTTP {status}")]
    PutStatus { url: String, status: u16 },
    #[error("GET {url} : {source}")]
    Get { url: String, source: reqwest::Error },
    #[error("GET {url} : HTTP {status}")]
    GetStatus { url: String, status: u16 },
}

pub struct Options {
    /// `https://s3.example.org` — jamais le nom du compartiment dans l'hôte
    /// (style path, voir la documentation du module).
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub timeout: Duration,
}

/// Le temps de validité de l'URL signée, pas celui de la requête elle-même
/// (`reqwest::Client::timeout` la borne séparément) : assez large pour
/// couvrir un envoi lent, jamais réutilisée au-delà.
const SIGNATURE_TTL: Duration = Duration::from_secs(60);

pub struct Client {
    bucket: Bucket,
    credentials: Credentials,
    http: reqwest::Client,
}

impl Client {
    pub fn new(opts: Options) -> Result<Client, S3Error> {
        let endpoint = opts.endpoint.parse()?;
        let bucket = Bucket::new(endpoint, UrlStyle::Path, opts.bucket, opts.region)?;
        let http = reqwest::Client::builder()
            .timeout(opts.timeout)
            .build()
            .map_err(|e| S3Error::Put {
                url: opts.endpoint.clone(),
                source: e,
            })?;
        Ok(Client {
            bucket,
            credentials: Credentials::new(opts.access_key, opts.secret_key),
            http,
        })
    }

    /// Dépose `body` sous la clé `key`, en écrasant l'objet existant s'il y
    /// en a un : c'est le journal entier qui est renvoyé à chaque appel
    /// (docs/WEBUI.md §7), pas un ajout incrémental — S3 ne connaît pas
    /// d'écriture partielle.
    pub async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), S3Error> {
        let action = self.bucket.put_object(Some(&self.credentials), key);
        let url = action.sign(SIGNATURE_TTL);
        let res = self
            .http
            .put(url.clone())
            .body(body)
            .send()
            .await
            .map_err(|e| S3Error::Put {
                url: url.to_string(),
                source: e,
            })?;
        if !res.status().is_success() {
            return Err(S3Error::PutStatus {
                url: url.to_string(),
                status: res.status().as_u16(),
            });
        }
        Ok(())
    }

    /// Relit l'objet déposé sous `key` (étape 2b-D, `audit/search`).
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        let action = self.bucket.get_object(Some(&self.credentials), key);
        let url = action.sign(SIGNATURE_TTL);
        let res = self
            .http
            .get(url.clone())
            .send()
            .await
            .map_err(|e| S3Error::Get {
                url: url.to_string(),
                source: e,
            })?;
        if !res.status().is_success() {
            return Err(S3Error::GetStatus {
                url: url.to_string(),
                status: res.status().as_u16(),
            });
        }
        res.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| S3Error::Get {
                url: url.to_string(),
                source: e,
            })
    }
}
