//! Garde du registre (docs/WEBUI.md §21) : tant que le registre diverge du
//! journal, `ca-server` n'exécute aucune action. C'est un échec fermé : le
//! journal fait foi, et agir sur un registre dont on sait qu'il a pu être
//! restauré en arrière (une clé révoquée qui réapparaît active) serait faire
//! signer des décisions par des clés que le journal dit révoquées.

use std::sync::{Arc, RwLock};

/// Partagée entre le service d'actions (qui refuse d'agir) et `/healthz` (qui
/// affiche la raison).
#[derive(Debug, Default)]
pub struct RegistryGuard {
    blocked: RwLock<Option<Vec<String>>>,
}

impl RegistryGuard {
    /// Ouverte : rien ne bloque.
    pub fn new() -> Arc<RegistryGuard> {
        Arc::new(RegistryGuard::default())
    }

    /// Ferme la garde avec les raisons (jamais vides : une garde fermée sans
    /// raison serait indébogable).
    pub fn block(&self, reasons: Vec<String>) {
        let reasons = if reasons.is_empty() {
            vec!["registre bloqué, sans détail".to_string()]
        } else {
            reasons
        };
        *self.blocked.write().unwrap_or_else(|e| e.into_inner()) = Some(reasons);
    }

    pub fn open(&self) {
        *self.blocked.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Les raisons du blocage, ou `None` si la garde est ouverte.
    pub fn blocked(&self) -> Option<Vec<String>> {
        self.blocked
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
