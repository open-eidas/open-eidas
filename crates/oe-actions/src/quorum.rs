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
}
