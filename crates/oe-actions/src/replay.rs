//! Rejeu du journal contre le registre, et `operators reconcile`
//! (docs/WEBUI.md §21, « Restauration d'une sauvegarde plus ancienne que le
//! journal »).
//!
//! Le journal chaîné est un fichier répliqué hors de l'hôte : il n'est pas
//! restauré avec la base. Une clé révoquée à T réapparaît donc *active* dans une
//! base restaurée à T-1, alors que le journal atteste la révocation. Le journal
//! fait foi pour le registre, pas l'inverse.
//!
//! On rejoue les événements qui touchent le registre (enregistrement direct,
//! confirmation, révocation de clé, invitation, changement de rôle) et on compare
//! à la base :
//!
//!   * **réparable** : une révocation ou un changement de rôle du journal absent de
//!     la base. `reconcile` les ré-applique ;
//!   * **non réparable** : une clé que le journal dit active et que la base n'a
//!     plus. Le journal ne porte pas la clé publique : rien ne peut la recréer. La
//!     clé est à ré-enrôler, et `reconcile` n'en prend acte que sur demande
//!     explicite et motivée, jamais en silence.

use std::collections::{BTreeMap, BTreeSet};

use oe_raflow::Recorder;
use sqlx::Row;
use time::OffsetDateTime;

use crate::{Error, Registry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// Le journal atteste la révocation, la base garde la clé active. Réparable.
    RevokedInJournal {
        credential_id: String,
        operator: String,
    },
    /// Le rôle de la base n'est pas celui que le journal a consigné. Réparable.
    RoleDiffers {
        operator: String,
        journal_role: String,
        db_role: String,
    },
    /// Le journal dit la clé active, la base ne la connaît plus. Non réparable.
    MissingKey {
        credential_id: String,
        operator: String,
    },
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Divergence::RevokedInJournal {
                credential_id,
                operator,
            } => write!(
                f,
                "la clé {credential_id} de {operator} est révoquée au journal mais active dans la base"
            ),
            Divergence::RoleDiffers {
                operator,
                journal_role,
                db_role,
            } => write!(
                f,
                "le rôle de {operator} est {journal_role} au journal mais {db_role} dans la base"
            ),
            Divergence::MissingKey {
                credential_id,
                operator,
            } => write!(
                f,
                "la clé {credential_id} de {operator} est active au journal mais absente de la base \
                 (à ré-enrôler)"
            ),
        }
    }
}

#[derive(Debug, Default)]
struct KeyFacts {
    operator: String,
    revoked: bool,
}

/// Ce que le journal atteste du registre.
#[derive(Debug, Default)]
pub struct Replay {
    keys: BTreeMap<String, KeyFacts>,
    roles: BTreeMap<String, String>,
    acknowledged: BTreeSet<String>,
}

fn text<'a>(data: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(|v| v.as_str())
}

impl Replay {
    /// Rejoue les événements `(nom, données)` dans l'ordre du journal, dont
    /// l'appelant a déjà contrôlé la chaîne.
    pub fn from_events(events: impl IntoIterator<Item = (String, serde_json::Value)>) -> Replay {
        let mut r = Replay::default();
        for (event, data) in events {
            match event.as_str() {
                // Une clé entrée directement dans le registre (amorçage,
                // récupération) ; une clé « pending » n'y est pas.
                "operators.credential_registered" if text(&data, "statut") == Some("active") => {
                    if let (Some(id), Some(op)) =
                        (text(&data, "credential_id"), text(&data, "operateur"))
                    {
                        r.keys.entry(id.to_string()).or_default().operator = op.to_string();
                    }
                }
                "operators.key_confirmed" => {
                    if let (Some(id), Some(op)) =
                        (text(&data, "credential_id"), text(&data, "operateur"))
                    {
                        r.keys.entry(id.to_string()).or_default().operator = op.to_string();
                    }
                }
                "operators.key_revoked" => {
                    if let Some(id) = text(&data, "credential_id") {
                        let k = r.keys.entry(id.to_string()).or_default();
                        k.revoked = true;
                        if k.operator.is_empty() {
                            k.operator = text(&data, "operateur").unwrap_or_default().to_string();
                        }
                    }
                }
                // Les rôles : celui de la création, puis chaque changement.
                "operators.invited" => {
                    if let (Some(name), Some(role)) =
                        (text(&data, "operateur"), text(&data, "role"))
                    {
                        r.roles.insert(name.to_string(), role.to_string());
                    }
                }
                "operators.bootstrap_admin_invited" | "operators.admin_recovery" => {
                    if let Some(name) = text(&data, "operateur") {
                        r.roles
                            .entry(name.to_string())
                            .or_insert_with(|| "admin".to_string());
                    }
                }
                "operators.role_changed" => {
                    if let (Some(name), Some(role)) =
                        (text(&data, "operateur"), text(&data, "nouveau_role"))
                    {
                        r.roles.insert(name.to_string(), role.to_string());
                    }
                }
                // Une résolution déjà consignée : la divergence n'est pas rouverte.
                "operators.reconciled"
                    if text(&data, "resultat") == Some("acknowledged_missing") =>
                {
                    if let Some(id) = text(&data, "credential_id") {
                        r.acknowledged.insert(id.to_string());
                    }
                }
                _ => {}
            }
        }
        r
    }
}

/// Compare le journal rejoué à la base.
pub async fn find_divergences(
    registry: &Registry,
    replay: &Replay,
) -> Result<Vec<Divergence>, Error> {
    let pool = registry.pool();
    let keys: BTreeMap<String, bool> = sqlx::query(
        "SELECT credential_id, revoked_at IS NOT NULL AS revoked FROM webauthn_credentials",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| (r.get("credential_id"), r.get("revoked")))
    .collect();
    let roles: BTreeMap<String, String> = sqlx::query("SELECT name, role FROM operators")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| (r.get("name"), r.get("role")))
        .collect();

    let mut out = Vec::new();
    for (id, facts) in &replay.keys {
        match (keys.get(id), facts.revoked) {
            // Révoquée au journal, encore active en base.
            (Some(false), true) => out.push(Divergence::RevokedInJournal {
                credential_id: id.clone(),
                operator: facts.operator.clone(),
            }),
            // Active au journal, disparue de la base (et pas déjà actée).
            (None, false) if !replay.acknowledged.contains(id) => {
                out.push(Divergence::MissingKey {
                    credential_id: id.clone(),
                    operator: facts.operator.clone(),
                })
            }
            _ => {}
        }
    }
    for (name, journal_role) in &replay.roles {
        if let Some(db_role) = roles.get(name) {
            if db_role != journal_role {
                out.push(Divergence::RoleDiffers {
                    operator: name.clone(),
                    journal_role: journal_role.clone(),
                    db_role: db_role.clone(),
                });
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Default)]
pub struct ReconcileOutcome {
    /// Ce qui a été ré-appliqué ou acquitté, en clair.
    pub resolved: Vec<String>,
    /// Ce que `reconcile` ne peut pas résoudre seul.
    pub unresolved: Vec<Divergence>,
}

/// Résout les divergences (`operators reconcile`), en journalisant chacune.
///
/// - une révocation ou un rôle du journal absent de la base est **ré-appliqué** ;
/// - une clé perdue n'est **acquittée** que si elle est nommée dans
///   `acknowledge_missing` : on ne cache jamais une clé perdue.
///
/// Chaque résolution s'écrit au journal *avant* d'être validée : journal en
/// échec, rien n'est modifié. `dry_run` ne modifie ni la base ni le journal.
pub async fn reconcile(
    registry: &Registry,
    journal: &dyn Recorder,
    replay: &Replay,
    reason: &str,
    acknowledge_missing: &[String],
    dry_run: bool,
    now: OffsetDateTime,
) -> Result<ReconcileOutcome, Error> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Error::BadRequest(
            "un motif écrit est obligatoire pour résoudre une divergence".to_string(),
        ));
    }
    let divergences = find_divergences(registry, replay).await?;

    // On n'acquitte que ce qui est réellement une divergence non réparable.
    for id in acknowledge_missing {
        let is_missing = divergences.iter().any(
            |d| matches!(d, Divergence::MissingKey { credential_id, .. } if credential_id == id),
        );
        if !is_missing {
            return Err(Error::BadRequest(format!(
                "{id:?} n'est pas une clé active au journal et absente de la base : rien à acquitter"
            )));
        }
    }

    let mut out = ReconcileOutcome::default();
    for d in divergences {
        match &d {
            Divergence::RevokedInJournal {
                credential_id,
                operator,
            } => {
                if dry_run {
                    out.resolved.push(format!("(à ré-appliquer) {d}"));
                    continue;
                }
                let mut tx = registry.pool().begin().await?;
                sqlx::query(
                    "UPDATE webauthn_credentials
                     SET revoked_at = $2, revoked_by = 'reconcile', revoked_reason = $3
                     WHERE credential_id = $1 AND revoked_at IS NULL",
                )
                .bind(credential_id)
                .bind(now)
                .bind(format!("rejeu du journal : {reason}"))
                .execute(&mut *tx)
                .await?;
                journal
                    .append(
                        "operators.reconciled",
                        serde_json::json!({
                            "resultat": "reapplied_revocation",
                            "credential_id": credential_id,
                            "operateur": operator,
                            "motif": reason,
                        }),
                    )
                    .await
                    .map_err(Error::Journal)?;
                tx.commit().await?;
                out.resolved.push(format!("révocation ré-appliquée : {d}"));
            }
            Divergence::RoleDiffers {
                operator,
                journal_role,
                ..
            } => {
                if dry_run {
                    out.resolved.push(format!("(à ré-appliquer) {d}"));
                    continue;
                }
                let mut tx = registry.pool().begin().await?;
                sqlx::query("UPDATE operators SET role = $2 WHERE name = $1")
                    .bind(operator)
                    .bind(journal_role)
                    .execute(&mut *tx)
                    .await?;
                journal
                    .append(
                        "operators.reconciled",
                        serde_json::json!({
                            "resultat": "reapplied_role",
                            "operateur": operator,
                            "role": journal_role,
                            "motif": reason,
                        }),
                    )
                    .await
                    .map_err(Error::Journal)?;
                tx.commit().await?;
                out.resolved.push(format!("rôle ré-appliqué : {d}"));
            }
            Divergence::MissingKey {
                credential_id,
                operator,
            } => {
                if !acknowledge_missing.contains(credential_id) {
                    out.unresolved.push(d);
                    continue;
                }
                if dry_run {
                    out.resolved.push(format!("(à acquitter) {d}"));
                    continue;
                }
                journal
                    .append(
                        "operators.reconciled",
                        serde_json::json!({
                            "resultat": "acknowledged_missing",
                            "credential_id": credential_id,
                            "operateur": operator,
                            "motif": reason,
                        }),
                    )
                    .await
                    .map_err(Error::Journal)?;
                out.resolved.push(format!("perte acquittée : {d}"));
            }
        }
    }
    Ok(out)
}
