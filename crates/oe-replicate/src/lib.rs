//! Portage de `internal/replicate` : copie le journal d'audit vers un
//! stockage distant après chaque scellement, afin qu'une défaillance ou une
//! compromission de l'instance ne fasse pas disparaître la seule copie du
//! journal. Jalon J8 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`).
//!
//! Protocole WebDAV (PUT authentifié) : le plus petit dénominateur commun
//! côté hébergement souverain, sans imposer de dépendance à un fournisseur
//! cloud particulier.

use std::time::Duration;

use sha2::{Digest, Sha256};

pub struct Options {
    /// URL de base WebDAV, par ex. `https://dav.example.org/open-eidas/`.
    pub url: String,
    pub username: String,
    pub password: String,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            url: String::new(),
            username: String::new(),
            password: String::new(),
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplicateError {
    #[error("replicate: URL WebDAV manquante")]
    MissingUrl,
    #[error("replicate: URL invalide: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("PUT {url}: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("PUT {url}: HTTP {status}")]
    Status {
        url: String,
        status: reqwest::StatusCode,
    },
}

#[derive(Debug)]
pub struct Client {
    base: url::Url,
    username: String,
    password: String,
    http: reqwest::Client,
}

impl Client {
    /// Construit un client de réplication. L'appelant est responsable de ne
    /// pas en construire lorsque la réplication est désactivée (URL vide).
    pub fn new(opts: Options) -> Result<Client, ReplicateError> {
        if opts.url.is_empty() {
            return Err(ReplicateError::MissingUrl);
        }
        let base = url::Url::parse(&opts.url)?;
        let http = reqwest::Client::builder()
            .timeout(opts.timeout)
            .build()
            .map_err(|e| ReplicateError::Http {
                url: opts.url.clone(),
                source: e,
            })?;
        Ok(Client {
            base,
            username: opts.username,
            password: opts.password,
            http,
        })
    }
}

/// Résume une réplication réussie.
#[derive(Debug, Clone)]
pub struct ReplicateResult {
    pub url: String,
    pub bytes: usize,
    pub sha256: String,
}

impl Client {
    /// Dépose le contenu donné sous le nom indiqué. Le nom porte
    /// l'horodatage de l'appelant : chaque scellement produit donc une copie
    /// distincte, ce qui protège aussi contre un PUT écrasant une version
    /// saine par une version déjà corrompue localement.
    pub async fn replicate(
        &self,
        filename: &str,
        content: Vec<u8>,
    ) -> Result<ReplicateResult, ReplicateError> {
        let mut target = self.base.clone();
        let joined = format!(
            "{}/{}",
            target.path().trim_end_matches('/'),
            filename.trim_start_matches('/')
        );
        target.set_path(&joined);

        let mut req = self
            .http
            .put(target.clone())
            .header("Content-Type", "application/octet-stream");
        if !self.username.is_empty() {
            req = req.basic_auth(&self.username, Some(&self.password));
        }
        let len = content.len();
        let resp = req
            .body(content.clone())
            .send()
            .await
            .map_err(|e| ReplicateError::Http {
                url: target.to_string(),
                source: e,
            })?;

        let status = resp.status();
        if !matches!(status.as_u16(), 200 | 201 | 204) {
            return Err(ReplicateError::Status {
                url: target.to_string(),
                status,
            });
        }

        let sum = Sha256::digest(&content);
        Ok(ReplicateResult {
            url: target.to_string(),
            bytes: len,
            sha256: hex::encode(sum),
        })
    }
}
