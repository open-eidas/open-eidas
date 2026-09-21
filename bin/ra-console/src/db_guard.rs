//! Le rôle PostgreSQL de `ra-console` est en lecture seule sur les tables de
//! `ca-server` (docs/WEBUI.md §16).
//!
//! C'est la base qui l'impose (`crates/oe-castore/sql/ra_console_grants.sql`), pas
//! une convention de code : c'est ce qui ferme la faille où une console compromise
//! écrivait une approbation en base et obtenait l'émission d'un certificat. Mais un
//! déploiement qui donne à la console le DSN de `ca-server`, ou celui d'un
//! superutilisateur, contournerait la règle sans qu'aucun test le voie. Le
//! démarrage relit donc les droits **réels** du rôle connecté et refuse de servir
//! s'il peut écrire dans ces tables.

use sqlx::PgPool;

/// Ce qui appartient à `ca-server` : la console n'y a que la lecture (ou rien).
pub const CA_TABLES: &[&str] = &[
    "authorities",
    "certificates",
    "crls",
    "enrollment_requests",
    "operators",
    "webauthn_credentials",
    "pending_credentials",
    "operator_invites",
    "actions",
    "action_challenges",
    "decision_evidence",
];

const WRITE_PRIVILEGES: &[&str] = &["INSERT", "UPDATE", "DELETE", "TRUNCATE"];

/// Vérifie les droits du rôle *connecté* (`current_user`, `SET ROLE` compris).
/// Rend toutes les violations, pas seulement la première : un déploiement mal
/// configuré se corrige en une fois.
pub async fn check_read_only(pool: &PgPool) -> Result<(), String> {
    let mut violations = Vec::new();

    let superuser: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(pool)
            .await
            .map_err(|e| format!("lecture du rôle courant : {e}"))?;
    if superuser {
        violations.push("le rôle est superutilisateur".to_string());
    }

    for table in CA_TABLES {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("lecture de {table} : {e}"))?;
        if !exists {
            // Base non migrée : rien à protéger, mais rien à servir non plus. Le
            // défaut se verra à la première lecture.
            continue;
        }
        for privilege in WRITE_PRIVILEGES {
            let granted: bool =
                sqlx::query_scalar("SELECT has_table_privilege(current_user, $1, $2)")
                    .bind(table)
                    .bind(privilege)
                    .fetch_one(pool)
                    .await
                    .map_err(|e| format!("droits sur {table} : {e}"))?;
            if granted {
                violations.push(format!("{privilege} accordé sur {table}"));
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "le rôle PostgreSQL de la console peut écrire dans les tables de ca-server \
             (docs/WEBUI.md §16) : {}",
            violations.join(", ")
        ))
    }
}
