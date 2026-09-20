//! Paramètres de `ra-console`, pilotés par variables d'environnement (12-factor).

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    /// DSN du rôle PostgreSQL **de ra-console** (jamais celui de `ca-server`, ni un
    /// superutilisateur) : le démarrage refuse un rôle qui pourrait écrire dans les
    /// tables de la CA (`db_guard`).
    pub database_url: String,
    pub link: LinkConfig,
    pub enroll: EnrollConfig,
}

/// Le lien mTLS vers `ca-server` (docs/WEBUI.md §16 « Lien interne »).
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// `https://<nom DNS du service>:<port interne>`. Le nom doit figurer au SAN du
    /// certificat `internal_server` de la CA.
    pub ca_url: String,
    /// Certificat `internal_client` de la console et sa clé (PEM).
    pub cert_file: String,
    pub key_file: String,
    /// Certificat de la CA émettrice, seule racine de confiance du lien (PEM).
    pub ca_file: String,
}

/// Demande du certificat client (`ra-console internal-cert`).
#[derive(Debug, Clone)]
pub struct EnrollConfig {
    /// API d'enrôlement publique de la CA (`http://ca:8320/api/v1/enroll`).
    pub url: String,
    pub hmac_key: String,
    pub timeout: Duration,
}

fn required(key: &str) -> Result<String, String> {
    match std::env::var(key).ok().filter(|v| !v.is_empty()) {
        Some(v) => Ok(v),
        None => Err(format!("{key} est obligatoire")),
    }
}

fn optional(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

impl Config {
    /// Ce que `serve` exige. La demande du certificat (`enroll`) n'y est pas :
    /// une console qui tourne n'a pas besoin du secret d'enrôlement.
    pub fn load() -> Result<Config, String> {
        let ca_url = required("OPENEIDAS_CA_INTERNAL_URL")?;
        if !ca_url.starts_with("https://") {
            return Err(format!(
                "OPENEIDAS_CA_INTERNAL_URL={ca_url:?} : le lien interne est en https (mTLS)"
            ));
        }
        Ok(Config {
            listen: optional("OPENEIDAS_RA_LISTEN", ":8330"),
            database_url: required("OPENEIDAS_DATABASE_URL")?,
            link: LinkConfig {
                ca_url,
                cert_file: required("OPENEIDAS_INTERNAL_TLS_CERT_FILE")?,
                key_file: required("OPENEIDAS_INTERNAL_TLS_KEY_FILE")?,
                ca_file: required("OPENEIDAS_CA_CERT_FILE")?,
            },
            enroll: EnrollConfig::from_env_lenient(),
        })
    }

    /// Ce que `internal-cert` exige, en plus des fichiers du lien : l'API
    /// d'enrôlement et le secret partagé. Pas de base de données.
    pub fn load_for_enrollment() -> Result<(LinkConfig, EnrollConfig), String> {
        let link = LinkConfig {
            ca_url: optional("OPENEIDAS_CA_INTERNAL_URL", ""),
            cert_file: required("OPENEIDAS_INTERNAL_TLS_CERT_FILE")?,
            key_file: required("OPENEIDAS_INTERNAL_TLS_KEY_FILE")?,
            ca_file: optional("OPENEIDAS_CA_CERT_FILE", ""),
        };
        let enroll = EnrollConfig {
            url: required("OPENEIDAS_ENROLL_URL")?,
            hmac_key: required("OPENEIDAS_ENROLL_HMAC_KEY")?,
            timeout: enroll_timeout()?,
        };
        Ok((link, enroll))
    }
}

fn enroll_timeout() -> Result<Duration, String> {
    match std::env::var("OPENEIDAS_ENROLL_TIMEOUT_SECONDS")
        .ok()
        .filter(|v| !v.is_empty())
    {
        None => Ok(Duration::from_secs(10 * 60)),
        Some(v) => v
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| format!("OPENEIDAS_ENROLL_TIMEOUT_SECONDS: entier attendu, reçu {v:?}")),
    }
}

impl EnrollConfig {
    fn from_env_lenient() -> EnrollConfig {
        EnrollConfig {
            url: optional("OPENEIDAS_ENROLL_URL", ""),
            hmac_key: String::new(),
            timeout: Duration::from_secs(10 * 60),
        }
    }
}
