//! Contrôle du registre contre le journal (docs/WEBUI.md §21) : au démarrage, puis
//! périodiquement. Une divergence ferme la garde : plus aucune action n'est
//! exécutée et `/healthz` passe en 503 avec le détail, jusqu'à
//! `ca-server operators reconcile`.
//!
//! Le journal fait foi. S'il est illisible ou rompu, on ne sait pas contre quoi
//! juger le registre : la garde se ferme aussi (échec fermé), avec cette raison.

use std::sync::Arc;
use std::time::Duration;

use oe_actions::{find_divergences, RegistryGuard, Replay};

/// Les événements du journal, sous la forme que rejoue `oe-actions`.
pub fn journal_events(path: &str) -> Result<Vec<(String, serde_json::Value)>, String> {
    let records =
        oe_audit::read(path).map_err(|e| format!("journal illisible ou rompu ({path}) : {e}"))?;
    Ok(records
        .into_iter()
        .filter_map(|r| {
            r.data
                .map(|d| (r.event, serde_json::Value::Object(d.into_iter().collect())))
        })
        .collect())
}

/// Les raisons pour lesquelles le registre ne peut pas servir ; vide s'il est sain.
pub async fn check(registry: &oe_actions::Registry, journal_path: &str) -> Vec<String> {
    let events = match journal_events(journal_path) {
        Ok(e) => e,
        Err(reason) => return vec![reason],
    };
    match find_divergences(registry, &Replay::from_events(events)).await {
        Ok(found) => found.iter().map(|d| d.to_string()).collect(),
        Err(e) => vec![format!("contrôle du registre impossible : {e}")],
    }
}

/// Un contrôle, appliqué à la garde. Une divergence doit **persister** après
/// `debounce` pour la fermer : le journal est écrit *avant* la validation en base
/// (échec fermé), et un contrôle qui tombe dans cette fenêtre de quelques
/// millisecondes verrait une divergence qui n'en est pas une.
pub async fn refresh(
    registry: &oe_actions::Registry,
    journal_path: &str,
    guard: &RegistryGuard,
    debounce: Duration,
) {
    let mut reasons = check(registry, journal_path).await;
    if !reasons.is_empty() && !debounce.is_zero() {
        tokio::time::sleep(debounce).await;
        reasons = check(registry, journal_path).await;
    }
    let was_blocked = guard.blocked().is_some();
    if reasons.is_empty() {
        guard.open();
        if was_blocked {
            tracing::info!("registre de nouveau conforme au journal : les actions reprennent");
        }
    } else {
        if !was_blocked {
            tracing::error!(?reasons, "registre divergent du journal : actions bloquées");
        }
        guard.block(reasons);
    }
}

pub fn spawn_periodic(
    registry: oe_actions::Registry,
    journal_path: String,
    guard: Arc<RegistryGuard>,
    every: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    refresh(&registry, &journal_path, &guard, Duration::from_secs(3)).await;
                }
                _ = shutdown.changed() => return,
            }
        }
    });
}
