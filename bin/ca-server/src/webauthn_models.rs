//! Chargement de la liste blanche de modèles de clés d'opérateur
//! (docs/WEBUI.md §2, décision O6).
//!
//! Le fichier est versionné dans le dépôt de déploiement et revu comme du
//! code : aucun appel réseau à l'exécution. Une liste vide est refusée (aucune
//! clé ne pourrait être admise), comme un AAGUID ou une racine illisibles.
//!
//! ```json
//! [{"description": "YubiKey 5 (série X)", "aaguid": "…uuid…", "root_pem": "-----BEGIN CERTIFICATE-----…"}]
//! ```

use oe_webauthn::{AttestationCaList, TrustedModel, Uuid};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    description: String,
    aaguid: Uuid,
    root_pem: String,
}

pub fn parse(json: &str) -> Result<AttestationCaList, String> {
    let entries: Vec<Entry> =
        serde_json::from_str(json).map_err(|e| format!("liste de modèles illisible : {e}"))?;
    let models: Vec<TrustedModel<'_>> = entries
        .iter()
        .map(|e| TrustedModel {
            root_pem: e.root_pem.as_bytes(),
            aaguid: e.aaguid,
            description: &e.description,
        })
        .collect();
    oe_webauthn::trusted_models(&models).map_err(|e| e.to_string())
}

pub fn load(path: &str) -> Result<AttestationCaList, String> {
    let json = std::fs::read_to_string(path).map_err(|e| format!("{path} : {e}"))?;
    parse(&json).map_err(|e| format!("{path} : {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_list_is_refused() {
        assert!(parse("[]").is_err());
    }

    #[test]
    fn an_unreadable_root_is_refused() {
        let json = r#"[{"description":"x","aaguid":"00000000-0000-0000-0000-000000000000","root_pem":"pas un PEM"}]"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        assert!(parse(r#"[{"description":"x","aaguid":"00000000-0000-0000-0000-000000000000","root_pem":"","extra":1}]"#).is_err());
    }
}
