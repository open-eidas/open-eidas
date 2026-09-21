//! Amorçage et invitation des opérateurs (docs/WEBUI.md §10, §21).
//!
//! Le tout premier administrateur ne peut pas être créé par une action signée,
//! puisqu'aucune clé n'existe pour signer : c'est un acte d'amorçage local,
//! exécuté sur l'hôte de `ca-server`, comme la cérémonie de clé. Il crée
//! l'opérateur et une invitation à usage unique ; l'administrateur enregistre
//! ensuite sa clé avec le jeton (tranche suivante).

use crate::registry::{credential_id, Registry, Role};
use crate::Error;
use oe_raflow::Recorder;
use oe_webauthn::Uuid;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::OffsetDateTime;

/// Durée de vie d'une invitation : « courte », de la minute à la journée (§10).
pub const MIN_INVITE_TTL: time::Duration = time::Duration::minutes(1);
pub const MAX_INVITE_TTL: time::Duration = time::Duration::hours(24);

/// Sérialise les amorçages concurrents : sans cela, deux commandes lancées en
/// même temps pourraient chacune laisser une invitation vivante.
const BOOTSTRAP_LOCK: i64 = 0x0EB0_07AD;

/// Une invitation. `token` n'existe qu'ici : la base n'en garde que le haché,
/// il ne peut plus être relu après coup.
pub struct Invite {
    pub operator_id: Uuid,
    pub invite_id: Uuid,
    pub token: String,
    pub expires_at: OffsetDateTime,
}

pub(crate) fn valid_name(name: &str) -> Result<(), Error> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 || n.chars().any(char::is_control) || n != name {
        return Err(Error::BadRequest(
            "nom d'opérateur invalide (1 à 100 caractères, sans espace en bordure ni caractère de contrôle)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Un jeton de 256 bits tiré du générateur du système, en base64url.
pub(crate) fn new_token() -> String {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    credential_id(&raw)
}

/// Crée (ou ré-invite) le premier administrateur.
///
/// - Refuse s'il existe déjà un administrateur actif, c'est-à-dire non
///   désactivé et muni d'au moins une clé non révoquée : le bootstrap sert à
///   amorcer, pas à reprendre la main sur un système qui a des administrateurs.
///   Un système verrouillé (tous les administrateurs sans clé) passe par
///   `recover-admin` (§21), pas par ici.
/// - Ré-invite sans doublon un administrateur qui n'a jamais enregistré de clé
///   (invitation expirée ou perdue) et éteint alors ses invitations précédentes :
///   une seule reste vivante.
/// - Écrit au journal **avant** de valider, pour qu'une invitation générée puis
///   jamais consommée reste visible. Journal en échec : rien n'est créé.
pub async fn bootstrap_admin(
    registry: &Registry,
    journal: &dyn Recorder,
    name: &str,
    ttl: time::Duration,
    now: OffsetDateTime,
) -> Result<Invite, Error> {
    valid_name(name)?;
    if ttl < MIN_INVITE_TTL || ttl > MAX_INVITE_TTL {
        return Err(Error::BadRequest(
            "durée de l'invitation hors de 1 minute à 24 heures".to_string(),
        ));
    }

    let mut tx = registry.pool().begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(BOOTSTRAP_LOCK)
        .execute(&mut *tx)
        .await?;

    let active_admin: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM operators o
             JOIN webauthn_credentials c ON c.operator_id = o.id
             WHERE o.role = 'admin' AND o.disabled_at IS NULL AND c.revoked_at IS NULL)",
    )
    .fetch_one(&mut *tx)
    .await?;
    if active_admin {
        // Un refus est aussi un événement : quelqu'un a essayé.
        let _ = journal.append(
            "operators.bootstrap_admin_refused",
            serde_json::json!({ "nom": name, "motif": "un administrateur actif existe déjà" }),
        );
        return Err(Error::Denied(
            "un administrateur actif existe déjà : l'amorçage n'est plus possible \
             (récupération : voir « recover-admin », docs/WEBUI.md §21)"
                .to_string(),
        ));
    }

    let existing = sqlx::query("SELECT id, role, disabled_at FROM operators WHERE name = $1")
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
    let operator_id = match existing {
        Some(row) => {
            let role: String = row.get("role");
            let disabled: Option<OffsetDateTime> = row.get("disabled_at");
            if role != Role::Admin.as_str() || disabled.is_some() {
                return Err(Error::BadRequest(format!(
                    "le nom {name:?} est déjà pris par un autre opérateur"
                )));
            }
            row.get::<Uuid, _>("id")
        }
        None => {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO operators (id, name, role, created_at, created_by)
                 VALUES ($1, $2, 'admin', $3, 'bootstrap-admin')",
            )
            .bind(id)
            .bind(name)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            id
        }
    };

    // Une seule invitation vivante par opérateur.
    sqlx::query(
        "UPDATE operator_invites SET expires_at = $2
         WHERE operator_id = $1 AND consumed_at IS NULL AND expires_at > $2",
    )
    .bind(operator_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    let token = new_token();
    let invite_id = Uuid::new_v4();
    let expires_at = now + ttl;
    sqlx::query(
        "INSERT INTO operator_invites (id, operator_id, token_hash, created_by, created_at, expires_at)
         VALUES ($1, $2, $3, 'bootstrap-admin', $4, $5)",
    )
    .bind(invite_id)
    .bind(operator_id)
    .bind(Sha256::digest(token.as_bytes()).to_vec())
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    // Le jeton n'est jamais journalisé : seul l'identifiant de l'invitation.
    journal
        .append(
            "operators.bootstrap_admin_invited",
            serde_json::json!({
                "operateur": name,
                "operator_id": operator_id.to_string(),
                "invite_id": invite_id.to_string(),
                "expire_a": expires_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            }),
        )
        .map_err(Error::Journal)?;

    tx.commit().await?;
    Ok(Invite {
        operator_id,
        invite_id,
        token,
        expires_at,
    })
}
