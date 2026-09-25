//! Purge périodique des sessions et des challenges WebAuthn expirés
//! (docs/WEBUI.md §15 étape 1c-2b) : aucune opération manuelle, une tâche de
//! fond au même schéma que `registry_check` côté `ca-server`.
//!
//! L'échéance (`expires_at`) commande seule la purge, pas l'état de la ligne :
//! une session révoquée ou un challenge consommé ne sont retirés qu'une fois
//! leur échéance dépassée, pas avant — rien ne dépend de cette purge pour être
//! correct (une session révoquée est déjà refusée, un challenge consommé
//! aussi), elle ne fait que libérer la place.

use std::time::Duration;

use sqlx::PgPool;
use time::OffsetDateTime;

/// Ce qu'une passe de purge a supprimé.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Purged {
    pub sessions: u64,
    pub challenges: u64,
}

/// Une passe de purge, appelable seule (tests, ou un futur appel manuel).
pub async fn once(pool: &PgPool) -> Result<Purged, sqlx::Error> {
    let now = OffsetDateTime::now_utc();
    let sessions = sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();
    let challenges = sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(Purged {
        sessions,
        challenges,
    })
}

/// Boucle de fond : une passe immédiate, puis toutes les `every`. S'arrête à
/// l'arrêt du service (Ctrl-C), pas avant — un échec d'une passe n'interrompt
/// pas la boucle, la suivante réessaie.
pub fn spawn_periodic(pool: PgPool, every: Duration) {
    tokio::spawn(async move {
        loop {
            match once(&pool).await {
                Ok(p) if p.sessions > 0 || p.challenges > 0 => {
                    tracing::info!(
                        sessions = p.sessions,
                        challenges = p.challenges,
                        "purge périodique"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::error!(erreur = %e, "purge périodique : échec"),
            }
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = tokio::signal::ctrl_c() => return,
            }
        }
    });
}
