//! Paramètres de l'autorité de certification, pilotés par variables
//! d'environnement (12-factor) — portage de `cmd/ca-server/config.go`, jeu
//! séparé de `oe-config` (celui-ci porte des champs propres à `tsa-server`
//! que `ca-server` n'a pas : politique RFC 3161, contreseing, etc.).

use std::time::Duration;

pub struct Config {
    pub listen: String,
    pub shutdown_timeout: Duration,
    pub max_request_bytes: usize,

    /// DSN PostgreSQL du registre de la CA.
    pub dsn: String,

    pub pkcs11_module: String,
    /// La racine et l'émettrice vivent dans deux tokens distincts : la
    /// racine ne sert qu'à la cérémonie et n'a aucune raison d'être
    /// accessible au service en fonctionnement.
    pub root_token_label: String,
    pub root_key_label: String,
    pub root_pin: String,
    pub issuing_token_label: String,
    pub issuing_key_label: String,
    pub issuing_pin: String,
    pub key_bits: u64,

    pub root_cn: String,
    pub issuing_cn: String,
    pub organization: String,
    pub country: String,
    pub root_validity: time::Duration,
    pub issuing_validity: time::Duration,
    /// Identifie qui conduit la cérémonie ; consigné au procès-verbal (ETSI
    /// EN 319 411-1 §6.5.1).
    pub ceremony_operator: String,

    /// Adresse à laquelle cette CA est joignable par qui vérifie un
    /// certificat : gravée dans les extensions CDP et AIA. À ne pas
    /// confondre avec l'adresse interne à laquelle les services de la pile
    /// joignent la CA pour s'enrôler.
    pub public_url: String,
    pub ocsp_url: String,

    pub enroll_hmac_key: String,

    pub crl_validity: time::Duration,
    pub crl_refresh: Duration,
    pub crl_grace: time::Duration,

    pub audit_file: String,
}

fn env_str(key: &str, fallback: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| fallback.to_string())
}

fn env_u64(key: &str, fallback: u64) -> Result<u64, String> {
    match std::env::var(key).ok().filter(|v| !v.is_empty()) {
        None => Ok(fallback),
        Some(v) => v.parse().map_err(|_| format!("{key}: entier attendu, reçu {v:?}")),
    }
}

fn env_i64(key: &str, fallback: i64) -> Result<i64, String> {
    match std::env::var(key).ok().filter(|v| !v.is_empty()) {
        None => Ok(fallback),
        Some(v) => v.parse().map_err(|_| format!("{key}: entier attendu, reçu {v:?}")),
    }
}

/// Sous-ensemble de `time.ParseDuration` (Go) suffisant ici : "5m", "30s", "24h".
fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit() && c != '.')?);
    let value: f64 = num.parse().ok()?;
    let secs = match unit {
        "ns" => value / 1e9,
        "us" | "µs" => value / 1e6,
        "ms" => value / 1e3,
        "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(secs))
}

fn env_duration(key: &str, fallback: Duration) -> Result<Duration, String> {
    match std::env::var(key).ok().filter(|v| !v.is_empty()) {
        None => Ok(fallback),
        Some(v) => parse_go_duration(&v).ok_or_else(|| format!("{key}: durée attendue (ex. 1h, 24h), reçu {v:?}")),
    }
}

fn to_time_duration(d: Duration, fallback: time::Duration) -> time::Duration {
    time::Duration::try_from(d).unwrap_or(fallback)
}

impl Config {
    pub fn load() -> Result<Config, String> {
        let key_bits = env_u64("OPENEIDAS_CA_KEY_BITS", 4096)?;
        // Une CA signe des certificats qui lui survivent : sa clé est tenue
        // à une exigence au moins égale à celle des entités finales (ETSI
        // TS 119 312).
        if key_bits < 3072 {
            return Err(format!("OPENEIDAS_CA_KEY_BITS={key_bits}: ETSI TS 119 312 impose au moins 3072 bits pour RSA"));
        }

        let dsn = env_str("OPENEIDAS_DB_DSN", "");
        if dsn.is_empty() {
            return Err("OPENEIDAS_DB_DSN est obligatoire (DSN PostgreSQL du registre de la CA)".to_string());
        }
        let issuing_pin = std::env::var("OPENEIDAS_ISSUING_PIN").unwrap_or_default();
        if issuing_pin.is_empty() {
            return Err("OPENEIDAS_ISSUING_PIN est obligatoire (code PIN du token PKCS#11 de la CA émettrice)".to_string());
        }
        let public_url = env_str("OPENEIDAS_PKI_PUBLIC_URL", "");
        if public_url.is_empty() {
            return Err("OPENEIDAS_PKI_PUBLIC_URL est obligatoire (adresse publique gravée dans les extensions CDP/AIA)".to_string());
        }
        let root_pin = std::env::var("OPENEIDAS_ROOT_PIN").unwrap_or_default();
        // La racine et l'émettrice peuvent partager un PIN en démonstration ;
        // en production, ce sont deux tokens distincts sous deux contrôles
        // distincts — voir docs/CA.md.
        let root_pin = if root_pin.is_empty() { issuing_pin.clone() } else { root_pin };

        let max_request_bytes = env_i64("OPENEIDAS_MAX_REQUEST_BYTES", 64 * 1024)?.max(0) as usize;
        let root_validity = to_time_duration(env_duration("OPENEIDAS_ROOT_VALIDITY", Duration::from_secs(20 * 365 * 24 * 3600))?, time::Duration::days(20 * 365));
        let issuing_validity = to_time_duration(env_duration("OPENEIDAS_ISSUING_VALIDITY", Duration::from_secs(10 * 365 * 24 * 3600))?, time::Duration::days(10 * 365));
        let crl_validity = to_time_duration(env_duration("OPENEIDAS_CRL_VALIDITY", Duration::from_secs(24 * 3600))?, time::Duration::hours(24));
        // La CRL est republiée bien avant d'expirer : un répondeur OCSP qui
        // n'obtiendrait qu'une CRL périmée refuse de répondre plutôt que de
        // garantir un statut obsolète.
        let crl_refresh = env_duration("OPENEIDAS_CRL_REFRESH", Duration::from_secs(3600))?;
        let crl_grace = to_time_duration(env_duration("OPENEIDAS_CRL_GRACE", Duration::from_secs(30 * 24 * 3600))?, time::Duration::days(30));

        Ok(Config {
            listen: env_str("OPENEIDAS_LISTEN", ":8320"),
            shutdown_timeout: Duration::from_secs(15),
            max_request_bytes,
            dsn,
            pkcs11_module: env_str("OPENEIDAS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"),
            root_token_label: env_str("OPENEIDAS_ROOT_TOKEN_LABEL", "open-eidas-root"),
            root_key_label: env_str("OPENEIDAS_ROOT_KEY_LABEL", "root-ca-key"),
            root_pin,
            issuing_token_label: env_str("OPENEIDAS_ISSUING_TOKEN_LABEL", "open-eidas-issuing"),
            issuing_key_label: env_str("OPENEIDAS_ISSUING_KEY_LABEL", "issuing-ca-key"),
            issuing_pin,
            key_bits,
            root_cn: env_str("OPENEIDAS_ROOT_CN", "Open eIDAS Root CA"),
            issuing_cn: env_str("OPENEIDAS_ISSUING_CN", "Open eIDAS Issuing CA"),
            organization: env_str("OPENEIDAS_CA_ORGANIZATION", "Open eIDAS"),
            country: env_str("OPENEIDAS_CA_COUNTRY", "FR"),
            root_validity,
            issuing_validity,
            ceremony_operator: env_str("OPENEIDAS_CEREMONY_OPERATOR", ""),
            public_url,
            ocsp_url: env_str("OPENEIDAS_OCSP_PUBLIC_URL", ""),
            enroll_hmac_key: std::env::var("OPENEIDAS_ENROLL_HMAC_KEY").unwrap_or_default(),
            crl_validity,
            crl_refresh,
            crl_grace,
            audit_file: env_str("OPENEIDAS_AUDIT_FILE", "/var/lib/open-eidas/state/ca-audit.log"),
        })
    }
}
