//! Enregistrement de la clé d'un opérateur avec son jeton d'invitation
//! (docs/WEBUI.md §5 `register/*`, §10).
//!
//! Le jeton prouve qu'un administrateur a invité cette personne ; il ne prouve
//! rien de la clé. C'est l'attestation du fabricant, confrontée à la liste
//! blanche, qui le fait. Deux issues :
//!
//!   * invitation d'amorçage (`bootstrap-admin`) : la clé entre directement
//!     dans le registre, sans quoi personne ne pourrait la confirmer, puisque
//!     aucune clé n'existe encore pour signer ;
//!   * toute autre invitation : la clé reste dans `pending_credentials`. Elle ne
//!     permet ni de se connecter ni d'agir tant qu'un administrateur n'a pas
//!     signé sa confirmation (tranche suivante).
//!
//! L'écriture, le passage du jeton à « consommé » et l'événement du journal
//! forment un tout : le journal d'abord, la validation ensuite (échec fermé).

use oe_webauthn::{
    summarize_attestation, AttestedPasskeyRegistration, CreationChallengeResponse,
    RegisterPublicKeyCredential, Uuid,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::OffsetDateTime;

use crate::onboarding::RECOVERY;
use crate::registry::{credential_id, insert_credential, NewCredential};
use crate::{Error, Service, CHALLENGE_TTL};

/// Marque des invitations créées par l'amorçage local (`created_by`).
const BOOTSTRAP: &str = "bootstrap-admin";

/// Même verrou que `bootstrap_admin` : l'amorçage et l'activation de sa clé ne
/// s'exécutent pas en parallèle.
const BOOTSTRAP_LOCK: i64 = 0x0EB0_07AD;

/// Une clé en attente de confirmation expire si personne ne la confirme.
pub const PENDING_TTL: time::Duration = time::Duration::hours(72);

/// Bornes du nombre de cérémonies en mémoire, contre l'accumulation.
const MAX_CEREMONIES: usize = 1024;

/// Message unique pour tous les refus d'invitation : inconnue, expirée,
/// consommée ou opérateur désactivé ne se distinguent pas de l'extérieur.
const INVALID_INVITE: &str = "invitation invalide ou expirée";

pub(crate) struct PendingRegistration {
    invite_id: Uuid,
    operator_id: Uuid,
    state: AttestedPasskeyRegistration,
    expires_at: OffsetDateTime,
}

/// Une cérémonie d'enregistrement ouverte.
pub struct RegistrationBegun {
    pub ceremony_id: Uuid,
    pub operator: String,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Dans le registre : la clé peut se connecter et signer.
    Active,
    /// Rangée hors du registre, en attente de la confirmation d'un admin.
    PendingConfirmation,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyStatus::Active => "active",
            KeyStatus::PendingConfirmation => "pending_confirmation",
        }
    }
}

#[derive(Debug)]
pub struct Registered {
    pub operator: String,
    pub credential_id: String,
    pub status: KeyStatus,
    /// Empreinte de la clé publique, que l'invité lit sur son écran et que
    /// l'administrateur compare à la sienne avant de confirmer (§5, §10).
    pub key_fingerprint: String,
    pub aaguid: Uuid,
}

struct Invite {
    id: Uuid,
    operator_id: Uuid,
    operator: String,
    created_by: String,
    expires_at: OffsetDateTime,
}

/// SHA-256 de la clé publique, en groupes de 4 hexadécimaux majuscules
/// (`3F9A C012 …`), pour une lecture à voix haute.
///
/// Calculée sur la représentation de la clé publique COSE que sérialise la
/// bibliothèque : stable pour une clé donnée, mais liée à cette forme. Elle ne
/// sert qu'à la comparaison faite pendant la confirmation.
pub fn key_fingerprint(passkey: &oe_webauthn::AttestedPasskey) -> Result<String, Error> {
    let value = serde_json::to_value(passkey).map_err(|e| Error::BadRequest(e.to_string()))?;
    let cose = value
        .pointer("/cred/cred")
        .ok_or_else(|| Error::BadRequest("clé publique introuvable".to_string()))?;
    let canonical = serde_json::to_string(cose).map_err(|e| Error::BadRequest(e.to_string()))?;
    let hex = hex::encode_upper(Sha256::digest(canonical.as_bytes()));
    Ok(hex
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" "))
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == "23505")
}

impl Service {
    /// Une invitation vivante : non consommée, non expirée, opérateur actif.
    async fn live_invite(&self, by: InviteKey<'_>, now: OffsetDateTime) -> Result<Invite, Error> {
        let (clause, bind_hash, bind_id): (&str, Option<Vec<u8>>, Option<Uuid>) = match by {
            InviteKey::Token(t) => (
                "i.token_hash = $1",
                Some(Sha256::digest(t.as_bytes()).to_vec()),
                None,
            ),
            InviteKey::Id(id) => ("i.id = $1", None, Some(id)),
        };
        let sql = format!(
            "SELECT i.id, i.operator_id, i.created_by, i.expires_at, o.name
             FROM operator_invites i JOIN operators o ON o.id = i.operator_id
             WHERE {clause} AND i.consumed_at IS NULL AND i.expires_at > $2
               AND o.disabled_at IS NULL"
        );
        let q = sqlx::query(&sql);
        let q = match (bind_hash, bind_id) {
            (Some(h), _) => q.bind(h),
            (_, Some(id)) => q.bind(id),
            _ => unreachable!("une clé d'invitation a toujours l'un ou l'autre"),
        };
        let row = q
            .bind(now)
            .fetch_optional(self.registry.pool())
            .await?
            .ok_or_else(|| Error::Denied(INVALID_INVITE.to_string()))?;
        Ok(Invite {
            id: row.get("id"),
            operator_id: row.get("operator_id"),
            operator: row.get("name"),
            created_by: row.get("created_by"),
            expires_at: row.get("expires_at"),
        })
    }

    /// Ouvre la cérémonie d'enregistrement. Ne consomme pas le jeton : un
    /// navigateur qui échoue ou une clé mal branchée se réessaient.
    pub async fn begin_registration(&self, token: &str) -> Result<RegistrationBegun, Error> {
        self.ensure_open()?;
        let now = self.now();
        let invite = self.live_invite(InviteKey::Token(token), now).await?;

        // Les clés déjà connues de cet opérateur ne sont pas proposées à
        // nouveau : l'authentificateur refuse de se réenregistrer.
        let known: Vec<_> = self
            .registry
            .active_keys(invite.operator_id)
            .await?
            .iter()
            .map(|k| k.passkey.cred_id().clone())
            .collect();
        let (options, state) = self.verifier.start_registration(
            invite.operator_id,
            &invite.operator,
            (!known.is_empty()).then_some(known),
        )?;

        let ceremony_id = Uuid::new_v4();
        let expires_at = (now + CHALLENGE_TTL).min(invite.expires_at);
        {
            let mut map = self.registrations.lock().expect("verrou des cérémonies");
            map.retain(|_, p| p.expires_at > now);
            // Une seule cérémonie vivante par invitation.
            map.retain(|_, p| p.invite_id != invite.id);
            if map.len() >= MAX_CEREMONIES {
                return Err(Error::Denied(
                    "trop de cérémonies en cours, réessayer plus tard".to_string(),
                ));
            }
            map.insert(
                ceremony_id,
                PendingRegistration {
                    invite_id: invite.id,
                    operator_id: invite.operator_id,
                    state,
                    expires_at,
                },
            );
        }
        Ok(RegistrationBegun {
            ceremony_id,
            operator: invite.operator,
            options,
        })
    }

    /// Vérifie l'attestation et range la clé. Une seule tentative par
    /// cérémonie : l'état sort de la mémoire quoi qu'il arrive ensuite.
    pub async fn finish_registration(
        &self,
        ceremony_id: Uuid,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<Registered, Error> {
        self.ensure_open()?;
        let now = self.now();
        let pending = self
            .registrations
            .lock()
            .expect("verrou des cérémonies")
            .remove(&ceremony_id)
            .ok_or(Error::StateLost)?;
        if now > pending.expires_at {
            return Err(Error::Expired);
        }

        // L'invitation a pu être consommée ou éteinte depuis `begin`.
        let invite = self
            .live_invite(InviteKey::Id(pending.invite_id), now)
            .await?;
        if invite.operator_id != pending.operator_id {
            return Err(Error::Denied(INVALID_INVITE.to_string()));
        }

        let passkey = self
            .verifier
            .finish_registration(credential, &pending.state)?;
        let summary = summarize_attestation(&passkey)?;
        let cred_id = credential_id(passkey.cred_id().as_ref());
        let fingerprint = key_fingerprint(&passkey)?;
        let attestation = credential.response.attestation_object.as_ref();
        let bootstrap = invite.created_by == BOOTSTRAP;
        let recovery = invite.created_by == RECOVERY;
        let direct = bootstrap || recovery;
        let status = if direct {
            KeyStatus::Active
        } else {
            KeyStatus::PendingConfirmation
        };

        let mut tx = self.registry.pool().begin().await?;
        if direct {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(BOOTSTRAP_LOCK)
                .execute(&mut *tx)
                .await?;
        }
        if bootstrap {
            // Comme à l'amorçage : sur un système qui a déjà un administrateur
            // actif, une invitation d'amorçage encore vivante ne donne rien. La
            // récupération, elle, sert précisément quand les administrateurs
            // « actifs » ont perdu leurs clés : pas de contrôle ici.
            let active_admin: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM operators o
                     JOIN webauthn_credentials c ON c.operator_id = o.id
                     WHERE o.role = 'admin' AND o.disabled_at IS NULL AND c.revoked_at IS NULL)",
            )
            .fetch_one(&mut *tx)
            .await?;
            if active_admin {
                return Err(Error::Denied(
                    "un administrateur actif existe déjà : l'invitation d'amorçage ne sert plus"
                        .to_string(),
                ));
            }
        }

        let consumed = sqlx::query(
            "UPDATE operator_invites SET consumed_at = $2
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2",
        )
        .bind(invite.id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(Error::Denied(INVALID_INVITE.to_string()));
        }

        let stored = if direct {
            insert_credential(
                &mut tx,
                NewCredential {
                    operator_id: invite.operator_id,
                    passkey: &passkey,
                    aaguid: summary.aaguid,
                    attestation_format: summary.format,
                    attestation_object: attestation,
                    label: if bootstrap {
                        "amorçage"
                    } else {
                        "récupération"
                    },
                    initiated_by: &invite.created_by,
                    // La contrainte du registre veut une confirmation, sauf pour
                    // le tout premier administrateur : la récupération se
                    // confirme elle-même, sous son nom, distinct de tout opérateur.
                    confirmed_by: recovery.then_some(RECOVERY),
                },
                now,
            )
            .await
        } else {
            let json = serde_json::to_value(&passkey).map_err(|e| sqlx::Error::Encode(e.into()))?;
            sqlx::query(
                "INSERT INTO pending_credentials
                   (credential_id, operator_id, public_key, aaguid, attestation_format,
                    attestation_object, backup_eligible, invite_id, registered_at,
                    expires_at, passkey)
                 VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8, $9, $10)",
            )
            .bind(&cred_id)
            .bind(invite.operator_id)
            .bind(json.to_string().into_bytes())
            .bind(summary.aaguid)
            .bind(summary.format)
            .bind(attestation)
            .bind(invite.id)
            .bind(now)
            .bind(now + PENDING_TTL)
            .bind(json)
            .execute(&mut *tx)
            .await
            .map(|_| ())
        };
        match stored {
            Ok(()) => {}
            Err(e) if is_unique_violation(&e) => {
                return Err(Error::Denied("cette clé est déjà enregistrée".to_string()))
            }
            Err(e) => return Err(e.into()),
        }

        // Le journal avant la validation : s'il échoue, rien n'est écrit et
        // l'invitation reste utilisable.
        self.journal
            .append(
                "operators.credential_registered",
                serde_json::json!({
                    "operateur": invite.operator,
                    "operator_id": invite.operator_id.to_string(),
                    "invite_id": invite.id.to_string(),
                    "credential_id": cred_id,
                    "statut": status.as_str(),
                    "empreinte": fingerprint,
                    "aaguid": summary.aaguid.to_string(),
                    "attestation": summary.format,
                }),
            )
            .map_err(Error::Journal)?;
        tx.commit().await?;

        Ok(Registered {
            operator: invite.operator,
            credential_id: cred_id,
            status,
            key_fingerprint: fingerprint,
            aaguid: summary.aaguid,
        })
    }
}

enum InviteKey<'a> {
    Token(&'a str),
    Id(Uuid),
}
