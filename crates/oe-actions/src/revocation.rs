//! Révocation d'un certificat par une action signée (docs/WEBUI.md §5, §8).
//!
//! `ca-server` branche ici l'autorité qui sait révoquer et republier la CRL ;
//! ce module n'a pas de HSM à connaître. La signature de l'opérateur `ca_operateur`
//! est vérifiée par `Service::execute` avant que rien de ce qui suit ne soit appelé.
//!
//! **Pas encore de double contrôle.** Le §5 prévoit le M-sur-N (§8) pour cette
//! action ; il n'existe pas, et l'action se comporte donc, pour l'instant,
//! comme `ca-server revoke` : un seul opérateur nominatif, tracé au journal.

use std::sync::Arc;

use oe_castore::{CertificateStatus, StoreError};

use crate::{Action, Error, Service};

/// L'autorité qui révoque. Implémentée par `ca-server` sur `oe_ca_core::Issuer`.
#[async_trait::async_trait]
pub trait Revoker: Send + Sync {
    /// Inscrit la révocation. Échoue si le certificat est inconnu.
    async fn revoke(
        &self,
        serial: &[u8],
        reason: i32,
        operator: &str,
        comment: &str,
    ) -> Result<(), String>;

    /// Produit et enregistre une nouvelle CRL ; rend son numéro.
    async fn publish_crl(&self) -> Result<i64, String>;
}

/// Motifs admis : ceux qui ont un sens pour un certificat d'entité finale et
/// qu'on sait publier. Sont exclus « unspecified » (0), « certificateHold » (6,
/// réversible, ce système ne sait pas lever), « removeFromCRL » (8, réservé aux
/// CRL delta) et les motifs propres aux autorités (2, 10).
const ALLOWED_REASONS: [i32; 5] = [1, 3, 4, 5, 9];

fn decode_serial(serial: &str) -> Result<Vec<u8>, Error> {
    let canonical = !serial.is_empty()
        && serial
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    if !canonical || !serial.len().is_multiple_of(2) {
        return Err(Error::BadRequest(
            "numéro de série : hexadécimal minuscule de longueur paire attendu".to_string(),
        ));
    }
    hex::decode(serial).map_err(|e| Error::BadRequest(e.to_string()))
}

impl Service {
    /// Contrôles sur l'état *actuel* : réalisés à l'émission du challenge puis
    /// de nouveau juste avant l'exécution.
    pub(crate) async fn check_revocation(&self, action: &Action) -> Result<(), Error> {
        let Action::RevokeCertificate {
            serial,
            reason,
            comment,
        } = action
        else {
            return Err(Error::BadRequest("pas une révocation".to_string()));
        };
        if self.revoker.is_none() {
            return Err(Error::Denied(
                "la révocation de certificat n'est pas configurée sur ce service".to_string(),
            ));
        }
        if !ALLOWED_REASONS.contains(reason) {
            return Err(Error::BadRequest(format!(
                "motif {reason} refusé : motifs admis {ALLOWED_REASONS:?} (RFC 5280 §5.3.1)"
            )));
        }
        if comment.trim().is_empty() {
            return Err(Error::BadRequest(
                "une révocation exige un commentaire écrit".to_string(),
            ));
        }
        let bytes = decode_serial(serial)?;
        let cert = match self.store.certificate(&bytes).await {
            Ok(c) => c,
            Err(StoreError::NotFound) => {
                return Err(Error::Denied("certificat inconnu".to_string()))
            }
            Err(e) => return Err(Error::Effect(e.to_string())),
        };
        match cert.status {
            CertificateStatus::Issued => Ok(()),
            CertificateStatus::Revoked => Err(Error::Denied("certificat déjà révoqué".to_string())),
            CertificateStatus::Reserved => Err(Error::Denied("certificat jamais émis".to_string())),
        }
    }

    /// Révoque, puis republie la CRL. Si la publication échoue, la révocation
    /// reste acquise : la refuser maintenant demanderait une nouvelle signature
    /// pour un certificat déjà révoqué. La CRL suit à la prochaine publication
    /// périodique ; l'échec est journalisé et rendu à l'appelant.
    pub(crate) async fn revoke_certificate(
        &self,
        serial: &str,
        reason: i32,
        operator: &str,
        comment: &str,
    ) -> Result<serde_json::Value, Error> {
        let revoker: &Arc<dyn Revoker> = self
            .revoker
            .as_ref()
            .ok_or_else(|| Error::Effect("révocation non configurée".to_string()))?;
        let bytes = decode_serial(serial)?;
        revoker
            .revoke(&bytes, reason, operator, comment)
            .await
            .map_err(Error::Effect)?;
        match revoker.publish_crl().await {
            Ok(number) => Ok(serde_json::json!({
                "serial": serial, "reason": reason, "crl_number": number, "crl_published": true,
            })),
            Err(e) => {
                let _ = self.journal.append(
                    "operators.crl_publication_failed",
                    serde_json::json!({ "serie": serial, "erreur": e }),
                );
                Ok(serde_json::json!({
                    "serial": serial, "reason": reason, "crl_published": false,
                }))
            }
        }
    }
}
