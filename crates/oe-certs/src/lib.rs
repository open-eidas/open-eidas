//! Portage de `internal/certs` : lecture et écriture des fichiers PEM
//! manipulés par les services (certificat TSU/OCSP/CA et chaîne d'émission).
//!
//! Voir `internal/certs/certs.go` pour la référence Go — en particulier
//! [`file_name`], dont la dérivation doit rester strictement identique des deux
//! côtés (Go et Rust) tant que l'émetteur, le serveur de publication et le
//! répondeur OCSP ne sont pas tous portés simultanément : une divergence
//! romprait silencieusement les URL CDP/AIA déjà gravées dans des certificats
//! émis par le binaire Go.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

#[derive(Debug, thiserror::Error)]
pub enum CertsError {
    #[error("erreur d'entrée/sortie: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificat PEM invalide: {0}")]
    InvalidCertificate(#[from] der::Error),
    #[error("aucun certificat trouvé dans les données PEM")]
    Empty,
}

/// Lit un fichier PEM et retourne tous les certificats qu'il contient.
pub fn load_file(path: impl AsRef<Path>) -> Result<Vec<Certificate>, CertsError> {
    let raw = fs::read(path)?;
    parse_pem(&raw)
}

/// Comme [`load_file`], mais tolère un fichier absent (retourne une liste vide).
pub fn load_file_optional(path: impl AsRef<Path>) -> Result<Vec<Certificate>, CertsError> {
    match load_file(path) {
        Ok(certs) => Ok(certs),
        Err(CertsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Parse tous les blocs `CERTIFICATE` d'un buffer PEM.
pub fn parse_pem(raw: &[u8]) -> Result<Vec<Certificate>, CertsError> {
    let mut out = Vec::new();
    for block in pem::parse_many(raw).unwrap_or_default() {
        if block.tag() != "CERTIFICATE" {
            continue;
        }
        out.push(Certificate::from_der(block.contents())?);
    }
    if out.is_empty() {
        return Err(CertsError::Empty);
    }
    Ok(out)
}

/// Écrit une liste de certificats au format PEM, en créant les répertoires
/// parents si nécessaire.
pub fn write_file(path: impl AsRef<Path>, certs: &[Certificate]) -> Result<(), CertsError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    for cert in certs {
        let der = cert.to_der().map_err(CertsError::InvalidCertificate)?;
        let block = pem::Pem::new("CERTIFICATE", der);
        f.write_all(pem::encode(&block).as_bytes())?;
    }
    f.flush()?;
    Ok(())
}

static SAFE_FILE_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^\w-]").unwrap());

/// Dérive d'un nom courant (CN) le nom de fichier sous lequel la CA publie son
/// certificat et sa CRL, par exemple « Open eIDAS Issuing CA » →
/// « Open_eIDAS_Issuing_CA ». Doit rester identique à `certs.FileName` (Go).
pub fn file_name(common_name: &str) -> String {
    SAFE_FILE_NAME.replace_all(common_name, "_").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_replaces_non_word_characters() {
        assert_eq!(file_name("Open eIDAS Issuing CA"), "Open_eIDAS_Issuing_CA");
        assert_eq!(file_name("a/b\\c:d"), "a_b_c_d");
    }

    #[test]
    fn load_file_optional_tolerates_missing_file() {
        let certs = load_file_optional("/nonexistent/path/does-not-exist.pem").unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn parse_pem_rejects_empty_input() {
        let err = parse_pem(b"").unwrap_err();
        assert!(matches!(err, CertsError::Empty));
    }
}
