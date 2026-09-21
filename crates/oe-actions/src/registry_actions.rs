//! Actions signées sur le registre des opérateurs (docs/WEBUI.md §10) :
//! inviter, confirmer une clé, révoquer une clé, changer un rôle.
//!
//! Un seul chemin de code sert au contrôle et à l'exécution : [`Service::run_registry_action`]
//! joue l'action dans une transaction, puis la valide (`apply`) ou l'annule. À
//! l'émission du challenge, on la joue à blanc ; à l'exécution, pour de bon. Ce
//! que l'administrateur voit refusé avant de signer est donc exactement ce qui
//! serait refusé après.
//!
//! Créer ou retirer un rôle `admin` exige deux administrateurs (§10, §8) : le
//! nombre de signatures de l'action (`quorum`) est recontrôlé ici, à chaque fois,
//! contre l'état du registre à ce moment-là, pas seulement à l'émission.

use oe_webauthn::{AttestedPasskey, Uuid};
use sqlx::Row;
use time::OffsetDateTime;

use crate::enrollment::key_fingerprint;
use crate::onboarding::{new_token, valid_name, MAX_INVITE_TTL, MIN_INVITE_TTL};
use crate::registry::{insert_credential, NewCredential, Operator, Role};
use crate::{Action, Error, Service};
use sha2::{Digest, Sha256};

const QUORUM_REQUIRED: &str =
    "créer ou retirer un rôle admin exige la signature de deux administrateurs (docs/WEBUI.md §10, §8)";

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl Service {
    pub(crate) async fn run_registry_action(
        &self,
        action: &Action,
        actor: &Operator,
        now: OffsetDateTime,
        apply: bool,
        quorum: u32,
    ) -> Result<serde_json::Value, Error> {
        let mut tx = self.registry.pool().begin().await?;
        let result = match action {
            Action::InviteOperator {
                name,
                role,
                ttl_minutes,
            } => {
                valid_name(name)?;
                if *role == Role::Admin && quorum < crate::quorum::QUORUM {
                    return Err(Error::Denied(QUORUM_REQUIRED.to_string()));
                }
                let ttl = time::Duration::minutes(*ttl_minutes);
                if !(MIN_INVITE_TTL..=MAX_INVITE_TTL).contains(&ttl) {
                    return Err(Error::BadRequest(
                        "durée de l'invitation hors de 1 minute à 24 heures".to_string(),
                    ));
                }
                let taken: bool =
                    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM operators WHERE name = $1)")
                        .bind(name)
                        .fetch_one(&mut *tx)
                        .await?;
                if taken {
                    return Err(Error::BadRequest(format!(
                        "le nom {name:?} est déjà pris par un autre opérateur"
                    )));
                }
                let operator_id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO operators (id, name, role, created_at, created_by)
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(operator_id)
                .bind(name)
                .bind(role.as_str())
                .bind(now)
                .bind(&actor.name)
                .execute(&mut *tx)
                .await?;
                let token = new_token();
                let invite_id = Uuid::new_v4();
                let expires_at = now + ttl;
                sqlx::query(
                    "INSERT INTO operator_invites
                       (id, operator_id, token_hash, created_by, created_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(invite_id)
                .bind(operator_id)
                .bind(Sha256::digest(token.as_bytes()).to_vec())
                .bind(&actor.name)
                .bind(now)
                .bind(expires_at)
                .execute(&mut *tx)
                .await?;
                if apply {
                    // Jamais le jeton : seulement l'identifiant de l'invitation.
                    self.journal
                        .append(
                            "operators.invited",
                            serde_json::json!({
                                "operateur": name,
                                "operator_id": operator_id.to_string(),
                                "role": role.as_str(),
                                "invite_id": invite_id.to_string(),
                                "par": actor.name,
                                "expire_a": rfc3339(expires_at),
                            }),
                        )
                        .map_err(Error::Journal)?;
                }
                serde_json::json!({
                    "operator": name,
                    "operator_id": operator_id,
                    "invite_token": token,
                    "expires_at": rfc3339(expires_at),
                })
            }

            Action::ConfirmKey {
                credential_id,
                key_fingerprint: signed_fingerprint,
            } => {
                let row = sqlx::query(
                    "SELECT p.operator_id, p.passkey, p.aaguid, p.attestation_format,
                            p.attestation_object, p.expires_at, i.created_by,
                            o.name, o.disabled_at
                     FROM pending_credentials p
                     JOIN operator_invites i ON i.id = p.invite_id
                     JOIN operators o ON o.id = p.operator_id
                     WHERE p.credential_id = $1
                     FOR UPDATE OF p",
                )
                .bind(credential_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| Error::Denied("clé en attente inconnue".to_string()))?;
                let operator_id: Uuid = row.get("operator_id");
                let expires_at: OffsetDateTime = row.get("expires_at");
                let disabled: Option<OffsetDateTime> = row.get("disabled_at");
                let owner: String = row.get("name");
                if expires_at <= now {
                    return Err(Error::Denied("clé en attente expirée".to_string()));
                }
                if disabled.is_some() {
                    return Err(Error::Denied("opérateur désactivé".to_string()));
                }
                // Confirmer sa propre clé annulerait le contrôle d'un tiers.
                if operator_id == actor.id {
                    return Err(Error::Denied(
                        "un opérateur ne confirme pas sa propre clé".to_string(),
                    ));
                }
                let passkey: AttestedPasskey = serde_json::from_value(row.get("passkey"))
                    .map_err(|e| Error::Effect(format!("clé en attente illisible : {e}")))?;
                if key_fingerprint(&passkey)? != *signed_fingerprint {
                    return Err(Error::Denied(
                        "l'empreinte signée n'est pas celle de la clé en attente".to_string(),
                    ));
                }
                let created_by: String = row.get("created_by");
                let format: String = row.get("attestation_format");
                let attestation: Vec<u8> = row.get("attestation_object");
                insert_credential(
                    &mut tx,
                    NewCredential {
                        operator_id,
                        passkey: &passkey,
                        aaguid: row.get("aaguid"),
                        attestation_format: &format,
                        attestation_object: &attestation,
                        label: "",
                        initiated_by: &created_by,
                        confirmed_by: Some(&actor.name),
                    },
                    now,
                )
                .await?;
                sqlx::query("DELETE FROM pending_credentials WHERE credential_id = $1")
                    .bind(credential_id)
                    .execute(&mut *tx)
                    .await?;
                if apply {
                    self.journal
                        .append(
                            "operators.key_confirmed",
                            serde_json::json!({
                                "operateur": owner,
                                "operator_id": operator_id.to_string(),
                                "credential_id": credential_id,
                                "empreinte": signed_fingerprint,
                                "initiee_par": created_by,
                                "confirmee_par": actor.name,
                            }),
                        )
                        .map_err(Error::Journal)?;
                }
                serde_json::json!({ "operator": owner, "credential_id": credential_id })
            }

            Action::RevokeKey {
                credential_id,
                reason,
            } => {
                if reason.trim().is_empty() {
                    return Err(Error::BadRequest(
                        "une révocation de clé exige un motif écrit".to_string(),
                    ));
                }
                let row = sqlx::query(
                    "SELECT c.operator_id, c.revoked_at, o.name, o.role
                     FROM webauthn_credentials c JOIN operators o ON o.id = c.operator_id
                     WHERE c.credential_id = $1
                     FOR UPDATE OF c",
                )
                .bind(credential_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| Error::Denied("clé inconnue".to_string()))?;
                let revoked: Option<OffsetDateTime> = row.get("revoked_at");
                if revoked.is_some() {
                    return Err(Error::Denied("clé déjà révoquée".to_string()));
                }
                let owner: String = row.get("name");
                let owner_role: String = row.get("role");
                if owner_role == Role::Admin.as_str() {
                    // Ne jamais laisser le système sans administrateur actif :
                    // la voie de secours est `recover-admin` (§21), pas ceci.
                    let others: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM webauthn_credentials c
                         JOIN operators o ON o.id = c.operator_id
                         WHERE o.role = 'admin' AND o.disabled_at IS NULL
                           AND c.revoked_at IS NULL AND c.credential_id <> $1",
                    )
                    .bind(credential_id)
                    .fetch_one(&mut *tx)
                    .await?;
                    if others == 0 {
                        return Err(Error::Denied(
                            "cette révocation laisserait le système sans administrateur actif"
                                .to_string(),
                        ));
                    }
                }
                sqlx::query(
                    "UPDATE webauthn_credentials
                     SET revoked_at = $2, revoked_by = $3, revoked_reason = $4
                     WHERE credential_id = $1",
                )
                .bind(credential_id)
                .bind(now)
                .bind(&actor.name)
                .bind(reason)
                .execute(&mut *tx)
                .await?;
                if apply {
                    self.journal
                        .append(
                            "operators.key_revoked",
                            serde_json::json!({
                                "operateur": owner,
                                "credential_id": credential_id,
                                "motif": reason,
                                "par": actor.name,
                            }),
                        )
                        .map_err(Error::Journal)?;
                }
                serde_json::json!({ "operator": owner, "credential_id": credential_id })
            }

            Action::SetRole { operator, role } => {
                if *role == Role::Admin && quorum < crate::quorum::QUORUM {
                    return Err(Error::Denied(QUORUM_REQUIRED.to_string()));
                }
                let row = sqlx::query(
                    "SELECT id, role, disabled_at FROM operators WHERE name = $1 FOR UPDATE",
                )
                .bind(operator)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| Error::Denied("opérateur inconnu".to_string()))?;
                let id: Uuid = row.get("id");
                let current: String = row.get("role");
                let disabled: Option<OffsetDateTime> = row.get("disabled_at");
                if disabled.is_some() {
                    return Err(Error::Denied("opérateur désactivé".to_string()));
                }
                if id == actor.id {
                    return Err(Error::Denied(
                        "un opérateur ne change pas son propre rôle".to_string(),
                    ));
                }
                if current == Role::Admin.as_str() && quorum < crate::quorum::QUORUM {
                    return Err(Error::Denied(QUORUM_REQUIRED.to_string()));
                }
                if current == role.as_str() {
                    return Err(Error::BadRequest(format!(
                        "{operator:?} a déjà le rôle {}",
                        role.as_str()
                    )));
                }
                sqlx::query("UPDATE operators SET role = $2 WHERE id = $1")
                    .bind(id)
                    .bind(role.as_str())
                    .execute(&mut *tx)
                    .await?;
                if apply {
                    self.journal
                        .append(
                            "operators.role_changed",
                            serde_json::json!({
                                "operateur": operator,
                                "ancien_role": current,
                                "nouveau_role": role.as_str(),
                                "par": actor.name,
                            }),
                        )
                        .map_err(Error::Journal)?;
                }
                serde_json::json!({ "operator": operator, "role": role.as_str() })
            }

            Action::ApproveRequest { .. }
            | Action::RejectRequest { .. }
            | Action::RevokeCertificate { .. } => {
                return Err(Error::BadRequest(
                    "action hors du registre des opérateurs".to_string(),
                ))
            }
        };
        if apply {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        Ok(result)
    }
}
