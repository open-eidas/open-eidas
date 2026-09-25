//! Chargement de la liste blanche de modèles de clés d'opérateur, pour
//! vérifier les connexions (docs/WEBUI.md §2, §15 étape 1c, décision O6).
//!
//! Même format et même doctrine que `ca_server::webauthn_models` (fichier
//! versionné dans le dépôt de déploiement, revu comme du code, aucun appel
//! réseau à l'exécution) : les deux services doivent admettre les mêmes
//! modèles, sinon une clé enregistrée par l'un serait refusée par l'autre. Le
//! module est dupliqué plutôt que partagé pour que `ra-console` ne dépende
//! d'aucun code propre à `ca-server` (§16).
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
