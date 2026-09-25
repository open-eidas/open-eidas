//! Politique du double contrôle (docs/WEBUI.md §8, §10).
//!
//! C'est `ca-server` qui décide combien de signatures une action exige, à
//! partir de son code : le seuil n'est jamais lu d'une requête. Il est figé sur
//! la ligne de l'action à l'émission du premier challenge (`actions.required_signatures`).

use crate::{Action, Error, Role, Service};

/// Temps pendant lequel une action figée peut recevoir la signature suivante.
/// Chaque challenge WebAuthn reste, lui, limité à `CHALLENGE_TTL` : la fenêtre
/// laisse le temps de joindre un second opérateur, y compris hors heures ouvrées.
pub const QUORUM_WINDOW: time::Duration = time::Duration::hours(24);

/// Signatures exigées pour les actions à double contrôle.
pub const QUORUM: u32 = 2;

impl Service {
    /// Nombre de signatures d'opérateurs distincts que cette action exige,
    /// d'après l'état *actuel* du registre.
    pub(crate) async fn required_signatures(&self, action: &Action) -> Result<u32, Error> {
        Ok(match action {
            // Révoquer un certificat : deux `ca_operateur` (§5).
            Action::RevokeCertificate { .. } => QUORUM,
            // Créer un administrateur, ou changer le rôle de l'un d'eux : le
            // seul rôle qui modifie le registre lui-même (§10).
            Action::InviteOperator {
                role: Role::Admin, ..
            }
            | Action::SetRole {
                role: Role::Admin, ..
            } => QUORUM,
            Action::SetRole { operator, .. } => {
                let current: Option<String> =
                    sqlx::query_scalar("SELECT role FROM operators WHERE name = $1")
                        .bind(operator)
                        .fetch_optional(self.registry.pool())
                        .await?;
                if current.as_deref() == Some(Role::Admin.as_str()) {
                    QUORUM
                } else {
                    1
                }
            }
            _ => 1,
        })
    }

    /// Refuse de *créer* une action à plusieurs signatures que le rôle ne pourra
    /// jamais réunir (§21) : la laisser en attente indéfiniment ferait croire à
    /// l'opérateur qu'un second signataire va venir, alors qu'il n'existe pas.
    /// Seuls comptent les titulaires actifs : non désactivés et munis d'au moins
    /// une clé non révoquée.
    pub(crate) async fn ensure_enough_holders(
        &self,
        action: &Action,
        required: u32,
    ) -> Result<(), Error> {
        let roles: Vec<String> = action
            .allowed_roles()
            .iter()
            .map(|r| r.as_str().to_string())
            .collect();
        let holders: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT o.id) FROM operators o
             JOIN webauthn_credentials c ON c.operator_id = o.id
             WHERE o.role = ANY($1) AND o.disabled_at IS NULL AND c.revoked_at IS NULL",
        )
        .bind(&roles)
        .fetch_one(self.registry.pool())
        .await?;
        if (holders as u32) < required {
            return Err(Error::Denied(format!(
                "cette action exige {required} signatures, mais il n'y a que {holders} titulaire(s) \
                 actif(s) du rôle {}: elle ne pourrait jamais aboutir",
                roles.join(" ou ")
            )));
        }
        Ok(())
    }
}
