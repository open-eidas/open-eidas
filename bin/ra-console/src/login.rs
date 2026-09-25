//! Connexion par nom (docs/WEBUI.md §15 étape 1c, §16 « connexion par nom,
//! réponses uniformes »).
//!
//! `ra-console` vérifie elle-même l'assertion contre le registre en lecture
//! seule : une session n'est jamais une ancre de confiance, `ca-server`
//! re-vérifie chaque action (§16), mais la connexion elle-même n'a besoin
//! d'aucun aller-retour vers `ca-server`. `finish` prouve l'identité et met à
//! jour le compteur anti-clonage ; l'ouverture de la session elle-même (cookie,
//! `/api/v1/me`, déconnexion) est l'affaire de `crate::session`, à partir de
//! l'identité que ce module rend.
//!
//! Une seule erreur, `LoginError::Invalid`, sort de tout ce qui peut échouer
//! après `begin` : nom inconnu, clé factice, challenge périmé ou déjà
//! consommé, clé révoquée, opérateur désactivé, signature refusée, compteur en
//! régression. Les distinguer laisserait deviner lequel s'est produit.

use hmac::{Hmac, Mac};
use oe_actions::{Registry, Role};
use oe_webauthn::{
    decoy_authentication_challenge, AttestedPasskeyAuthentication, PublicKeyCredential,
    RequestChallengeResponse, Uuid, Verifier,
};
use sha2::Sha256;
use sqlx::Row;
use time::OffsetDateTime;

/// Aligné sur la contrainte SQL `challenge_short_lived` (migration 0006) : un
/// challenge de connexion ne vit pas plus longtemps qu'un challenge d'action.
pub const CHALLENGE_TTL: time::Duration = time::Duration::minutes(5);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoginError {
    /// Toute défaillance après `begin` : voir la documentation du module.
    #[error("identifiants invalides")]
    Invalid,
}

/// Ce que `login/begin` rend au navigateur.
pub struct Begun {
    pub challenge_id: Uuid,
    pub options: RequestChallengeResponse,
}

/// Identité vérifiée par `login/finish`. `operator_id` et `credential_id` :
/// de quoi ouvrir une session (1c-2, `crate::session`), sans que ce module
/// n'ait à connaître les sessions.
pub struct Verified {
    pub operator_id: Uuid,
    pub operator: String,
    pub role: Role,
    pub credential_id: String,
}

pub struct LoginService {
    registry: Registry,
    verifier: Verifier,
    decoy_secret: Vec<u8>,
}

impl LoginService {
    pub fn new(registry: Registry, verifier: Verifier, decoy_secret: Vec<u8>) -> LoginService {
        LoginService {
            registry,
            verifier,
            decoy_secret,
        }
    }

    /// Dérivé du nom et du secret du service : stable pour un même nom (une
    /// même requête reçoit toujours la même forme de réponse), imprévisible
    /// sans le secret. `HMAC-SHA256`, pas un simple hachage : le secret ne
    /// doit jouer aucun autre rôle qu'ici (pas de risque de confusion de
    /// domaine à défendre, mais c'est la construction de référence pour un
    /// MAC à clé).
    fn decoy_credential_id(&self, name: &str) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.decoy_secret)
            .expect("HMAC-SHA256 accepte une clé de taille arbitraire");
        mac.update(name.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// `login/begin {name}` : options WebAuthn de même forme que le nom
    /// existe ou non (docs/WEBUI.md §16). Un opérateur désactivé ou sans clé
    /// active reçoit lui aussi le leurre : il ne pourrait de toute façon pas
    /// se connecter, autant ne pas le distinguer d'un nom inconnu.
    pub async fn begin(&self, name: &str) -> Result<Begun, sqlx::Error> {
        let real = match self.registry.operator_by_name(name).await? {
            Some(op) if !op.disabled => {
                let keys = self.registry.active_keys(op.id).await?;
                if keys.is_empty() {
                    None
                } else {
                    Some((op.id, keys))
                }
            }
            _ => None,
        };

        let operator_id = real.as_ref().map(|(id, _)| *id);
        let (options, state) = match real {
            Some((_, keys)) => {
                let passkeys = keys.into_iter().map(|k| k.passkey).collect::<Vec<_>>();
                let (options, ast) = self
                    .verifier
                    .start_authentication(&passkeys)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                (options, Some(ast))
            }
            None => {
                let decoy_id = self.decoy_credential_id(name);
                let options = decoy_authentication_challenge(self.verifier.rp_id(), &decoy_id);
                (options, None)
            }
        };

        let challenge_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let request_body = state
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| sqlx::Error::Encode(e.into()))?;
        sqlx::query(
            "INSERT INTO webauthn_challenges
               (id, kind, challenge, operator_id, request_body, created_at, expires_at)
             VALUES ($1, 'login', $2, $3, $4, $5, $6)",
        )
        .bind(challenge_id)
        .bind(options.public_key.challenge.as_ref())
        .bind(operator_id)
        .bind(request_body)
        .bind(now)
        .bind(now + CHALLENGE_TTL)
        .execute(self.registry.pool())
        .await?;

        Ok(Begun {
            challenge_id,
            options,
        })
    }

    /// `login/finish {challenge_id, credential}` : consomme le challenge
    /// (usage unique), vérifie l'assertion et met à jour le compteur
    /// anti-clonage (`login_counters`, jamais en régression une fois positif).
    pub async fn finish(
        &self,
        challenge_id: Uuid,
        credential: &PublicKeyCredential,
    ) -> Result<Verified, LoginError> {
        let row = sqlx::query(
            "UPDATE webauthn_challenges
             SET consumed_at = $2
             WHERE id = $1 AND kind = 'login' AND consumed_at IS NULL AND expires_at > $2
             RETURNING operator_id, request_body",
        )
        .bind(challenge_id)
        .bind(OffsetDateTime::now_utc())
        .fetch_optional(self.registry.pool())
        .await
        .map_err(|_| LoginError::Invalid)?
        .ok_or(LoginError::Invalid)?;

        // Un leurre n'a rien à vérifier : aucune assertion ne peut réussir.
        let operator_id: Option<Uuid> = row.get("operator_id");
        let operator_id = operator_id.ok_or(LoginError::Invalid)?;
        let request_body: Option<serde_json::Value> = row.get("request_body");
        let state: AttestedPasskeyAuthentication = request_body
            .and_then(|v| serde_json::from_value(v).ok())
            .ok_or(LoginError::Invalid)?;

        // La clé qui a signé, lue dans le registre — jamais déclarée par
        // l'appelant (§16).
        let credential_id = oe_actions::credential_id(credential.raw_id.as_ref());
        let key = self
            .registry
            .key(&credential_id)
            .await
            .map_err(|_| LoginError::Invalid)?
            .ok_or(LoginError::Invalid)?;
        if key.revoked || key.operator_id != operator_id {
            return Err(LoginError::Invalid);
        }
        let operator = self
            .registry
            .operator(operator_id)
            .await
            .map_err(|_| LoginError::Invalid)?
            .ok_or(LoginError::Invalid)?;
        if operator.disabled {
            return Err(LoginError::Invalid);
        }

        // Son propre compteur, jamais `webauthn_credentials.sign_count` : ce
        // dernier n'est écrit que par `ca-server` (migration 0006), et
        // `ra-console` n'a que la lecture sur cette table (§16).
        let last_sign_count: Option<i64> = sqlx::query_scalar(
            "SELECT last_sign_count FROM login_counters WHERE credential_id = $1",
        )
        .bind(&credential_id)
        .fetch_optional(self.registry.pool())
        .await
        .map_err(|_| LoginError::Invalid)?;
        let last_sign_count = u32::try_from(last_sign_count.unwrap_or(0)).unwrap_or(u32::MAX);

        let assertion = self
            .verifier
            .finish_authentication(credential, &state, last_sign_count)
            .map_err(|e| {
                tracing::debug!(erreur = %e, "assertion de connexion refusée");
                LoginError::Invalid
            })?;

        sqlx::query(
            "INSERT INTO login_counters (credential_id, last_sign_count)
             VALUES ($1, $2)
             ON CONFLICT (credential_id) DO UPDATE SET last_sign_count = excluded.last_sign_count",
        )
        .bind(&credential_id)
        .bind(i64::from(assertion.counter))
        .execute(self.registry.pool())
        .await
        .map_err(|_| LoginError::Invalid)?;

        Ok(Verified {
            operator_id: operator.id,
            operator: operator.name,
            role: operator.role,
            credential_id,
        })
    }
}
