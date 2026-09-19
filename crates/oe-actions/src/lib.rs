//! Actions d'opérateur signées, vérifiées et exécutées par `ca-server`
//! (docs/WEBUI.md §4, §16).
//!
//! Le principe : `ra-console` n'est jamais une ancre de confiance. Elle relaie
//! une demande et une assertion WebAuthn ; c'est ce module, dans `ca-server`,
//! qui vérifie la signature contre son propre registre, lit le rôle dans ce
//! registre, exécute, et consigne. Approuver une demande déclenche l'émission
//! du certificat (`oe_raflow::Flow::resume`) : une console qui pouvait écrire
//! une approbation pouvait faire émettre n'importe quoi.
//!
//! Déroulement :
//!
//!   1. [`Service::issue_challenge`] fige le corps de l'action, l'écrit au
//!      journal chaîné **avant** de répondre, et émet un challenge ;
//!   2. l'opérateur signe le challenge avec sa clé ;
//!   3. [`Service::execute`] reçoit l'identifiant du challenge et l'assertion,
//!      **et aucun corps** : il exécute le corps figé à l'étape 1.
//!
//! Le challenge est tiré par la bibliothèque WebAuthn, il ne dérive pas du
//! corps (décision O7). Le lien challenge → corps est donc établi par le
//! journal et par la table `actions`, pas par la signature seule.

mod registry;

pub use registry::{credential_id, Key, NewCredential, Operator, Registry, Role};

use oe_castore::{RequestState, Store, StoreError};
use oe_raflow::Decider;
use oe_raflow::Recorder;
use oe_webauthn::{PublicKeyCredential, RequestChallengeResponse, Uuid, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// Durée de validité d'une action et de son challenge.
pub const CHALLENGE_TTL: time::Duration = time::Duration::minutes(5);

pub type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// Ce que l'opérateur demande. L'énumération est fermée : une action qui n'y
/// figure pas ne peut pas être signée, donc pas exécutée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    ApproveRequest {
        transaction_id: String,
        /// Empreinte de la CSR que l'opérateur a vérifiée avec le demandeur
        /// (§11). Si présente, elle doit correspondre à la demande.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        csr_fingerprint: Option<String>,
        comment: String,
    },
    RejectRequest {
        transaction_id: String,
        comment: String,
    },
}

impl Action {
    fn kind(&self) -> &'static str {
        match self {
            Action::ApproveRequest { .. } => "approve_request",
            Action::RejectRequest { .. } => "reject_request",
        }
    }

    /// Rôles habilités à signer cette action (§3). `admin` n'y figure pas :
    /// il gère les opérateurs, aucun droit sur les certificats.
    fn allowed_roles(&self) -> &'static [Role] {
        match self {
            Action::ApproveRequest { .. } | Action::RejectRequest { .. } => {
                &[Role::RaOperateur, Role::CaOperateur]
            }
        }
    }

    fn transaction_id(&self) -> &str {
        match self {
            Action::ApproveRequest { transaction_id, .. }
            | Action::RejectRequest { transaction_id, .. } => transaction_id,
        }
    }
}

/// Le corps figé : l'action et son échéance. Les octets de cette
/// sérialisation, dans cet ordre de champs, sont ce que couvre `body_hash`.
#[derive(Serialize, Deserialize)]
struct Body {
    #[serde(flatten)]
    action: Action,
    expires_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("action refusée : {0}")]
    Denied(String),
    #[error("requête invalide : {0}")]
    BadRequest(String),
    #[error("challenge inconnu")]
    NotFound,
    #[error("challenge expiré")]
    Expired,
    #[error("challenge déjà utilisé")]
    AlreadyUsed,
    #[error("cérémonie perdue (redémarrage) : demander un nouveau challenge")]
    StateLost,
    #[error("journal indisponible, action non émise : {0}")]
    Journal(String),
    #[error("signature refusée : {0}")]
    Verification(#[from] oe_webauthn::Error),
    #[error("base de données : {0}")]
    Db(#[from] sqlx::Error),
    #[error("exécution : {0}")]
    Effect(String),
}

/// Un challenge émis, à présenter à l'opérateur.
pub struct Issued {
    pub challenge_id: Uuid,
    pub action_id: Uuid,
    /// Le corps que `ca-server` exécutera, à afficher tel quel (WYSIWYS).
    pub body: serde_json::Value,
    /// SHA-256 hexadécimal de la sérialisation canonique du corps.
    pub body_hash: String,
    pub options: RequestChallengeResponse,
}

/// Une action exécutée.
#[derive(Debug)]
pub struct Executed {
    pub action_id: Uuid,
    pub challenge_id: Uuid,
    /// Identité lue dans le registre, jamais transmise par l'appelant.
    pub operator: String,
    pub role: Role,
}

struct Pending {
    state: oe_webauthn::AttestedPasskeyAuthentication,
}

pub struct Service {
    registry: Registry,
    verifier: Verifier,
    store: Arc<dyn Store>,
    decider: Decider,
    journal: Arc<dyn Recorder>,
    clock: Clock,
    // L'état d'une cérémonie reste en mémoire : `ca-server` n'a qu'un
    // réplica (il détient un token PKCS#11). Une cérémonie perdue à un
    // redémarrage est simplement refaite.
    pending: Mutex<HashMap<Uuid, Pending>>,
}

impl Service {
    pub fn new(
        registry: Registry,
        verifier: Verifier,
        store: Arc<dyn Store>,
        decider: Decider,
        journal: Arc<dyn Recorder>,
        clock: Clock,
    ) -> Service {
        Service {
            registry,
            verifier,
            store,
            decider,
            journal,
            clock,
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn now(&self) -> OffsetDateTime {
        (self.clock)()
    }

    /// Contrôles communs à l'émission et à l'exécution, sur l'état *actuel*
    /// de la demande visée : elle existe, est en attente, et l'empreinte de
    /// CSR annoncée est bien la sienne.
    async fn check_target(&self, action: &Action) -> Result<(), Error> {
        let request = match self
            .store
            .request_by_transaction_id(action.transaction_id())
            .await
        {
            Ok(r) => r,
            Err(StoreError::NotFound) => return Err(Error::Denied("demande inconnue".to_string())),
            Err(e) => return Err(Error::Effect(e.to_string())),
        };
        if request.state != RequestState::Pending {
            return Err(Error::Denied(format!(
                "la demande n'est pas en attente ({})",
                request.state
            )));
        }
        if let Action::ApproveRequest {
            csr_fingerprint: Some(fp),
            ..
        } = action
        {
            if *fp != request.csr_fingerprint {
                return Err(Error::Denied(
                    "l'empreinte de CSR annoncée n'est pas celle de la demande".to_string(),
                ));
            }
        }
        if let Action::RejectRequest { comment, .. } = action {
            if comment.trim().is_empty() {
                return Err(Error::BadRequest(
                    "un rejet exige un motif écrit".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Fige l'action et émet un challenge pour les clés de `operator_hint`.
    ///
    /// `operator_hint` sert seulement à choisir les clés à proposer : ce n'est
    /// jamais une décision de confiance. L'opérateur qui agit est celui dont la
    /// clé signe, lu dans le registre par [`Service::execute`].
    pub async fn issue_challenge(
        &self,
        action: Action,
        operator_hint: Uuid,
    ) -> Result<Issued, Error> {
        let operator = self
            .registry
            .operator(operator_hint)
            .await?
            .ok_or_else(|| Error::Denied("opérateur inconnu".to_string()))?;
        if operator.disabled || !action.allowed_roles().contains(&operator.role) {
            return Err(Error::Denied(format!(
                "le rôle {} ne peut pas signer {}",
                operator.role.as_str(),
                action.kind()
            )));
        }
        self.check_target(&action).await?;

        let keys = self.registry.active_keys(operator_hint).await?;
        if keys.is_empty() {
            return Err(Error::Denied("aucune clé active".to_string()));
        }
        let passkeys: Vec<_> = keys.iter().map(|k| k.passkey.clone()).collect();
        let (options, state) = self.verifier.start_authentication(&passkeys)?;

        let now = self.now();
        let expires_at = now + CHALLENGE_TTL;
        let body = Body {
            action,
            expires_at: expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| Error::BadRequest(e.to_string()))?,
        };
        // Les octets qui font foi. JSONB réordonne les clés : c'est cette
        // chaîne, écrite au journal, qu'un auditeur re-hache.
        let canonical =
            serde_json::to_string(&body).map_err(|e| Error::BadRequest(e.to_string()))?;
        let body_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
        let body_json: serde_json::Value =
            serde_json::from_str(&canonical).map_err(|e| Error::BadRequest(e.to_string()))?;

        let action_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();

        // Le journal d'abord : si l'écriture échoue, aucun challenge n'est émis.
        // Un système qui ferait signer sans pouvoir consigner perdrait la
        // propriété qui donne son sens à tout ce module (§21).
        self.journal
            .append(
                "operators.action_challenge_issued",
                serde_json::json!({
                    "action_id": action_id.to_string(),
                    "challenge_id": challenge_id.to_string(),
                    "action": body_json["action"],
                    "body": canonical,
                    "body_hash": body_hash,
                    "operator_hint": operator.name,
                }),
            )
            .map_err(Error::Journal)?;

        let challenge = options.public_key.challenge.as_ref().to_vec();
        let mut tx = self.registry.pool().begin().await?;
        sqlx::query(
            "INSERT INTO actions (id, body, body_hash, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(action_id)
        .bind(&body_json)
        .bind(Sha256::digest(canonical.as_bytes()).to_vec())
        .bind(now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO action_challenges
               (challenge_id, action_id, challenge, operator_hint, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(challenge_id)
        .bind(action_id)
        .bind(challenge)
        .bind(operator_hint)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.pending
            .lock()
            .expect("verrou des cérémonies")
            .insert(challenge_id, Pending { state });

        Ok(Issued {
            challenge_id,
            action_id,
            body: body_json,
            body_hash,
            options,
        })
    }

    /// Vérifie l'assertion et exécute **le corps figé à l'émission**.
    ///
    /// La signature est consommée dès qu'elle est reconnue valide, avant
    /// l'effet : si l'effet échoue ensuite, l'opérateur devra signer de
    /// nouveau. On préfère ne jamais exécuter deux fois, et ne jamais exécuter
    /// sans une signature valide et neuve, à « réessayer » sur une signature
    /// déjà utilisée.
    pub async fn execute(
        &self,
        challenge_id: Uuid,
        assertion: &PublicKeyCredential,
    ) -> Result<Executed, Error> {
        let now = self.now();

        let row = sqlx::query(
            "SELECT c.action_id, c.consumed_at, c.expires_at, a.body, a.body_hash, a.executed_at
             FROM action_challenges c JOIN actions a ON a.id = c.action_id
             WHERE c.challenge_id = $1",
        )
        .bind(challenge_id)
        .fetch_optional(self.registry.pool())
        .await?
        .ok_or(Error::NotFound)?;
        use sqlx::Row;
        let action_id: Uuid = row.get("action_id");
        let consumed: Option<OffsetDateTime> = row.get("consumed_at");
        let executed: Option<OffsetDateTime> = row.get("executed_at");
        let expires_at: OffsetDateTime = row.get("expires_at");
        let body: serde_json::Value = row.get("body");
        let body_hash: Vec<u8> = row.get("body_hash");
        if consumed.is_some() || executed.is_some() {
            return Err(Error::AlreadyUsed);
        }
        if now > expires_at {
            return Err(Error::Expired);
        }

        // Une seule tentative par cérémonie : l'état sort de la mémoire quoi
        // qu'il arrive ensuite.
        let pending = self
            .pending
            .lock()
            .expect("verrou des cérémonies")
            .remove(&challenge_id)
            .ok_or(Error::StateLost)?;

        // L'opérateur est celui dont la clé a signé, lu dans le registre.
        let key = self
            .registry
            .key(&credential_id(assertion.raw_id.as_ref()))
            .await?
            .ok_or_else(|| Error::Denied("clé inconnue du registre".to_string()))?;
        if key.revoked {
            return Err(Error::Denied("clé révoquée".to_string()));
        }
        let operator = self
            .registry
            .operator(key.operator_id)
            .await?
            .ok_or_else(|| Error::Denied("opérateur inconnu".to_string()))?;
        let stored: Body =
            serde_json::from_value(body).map_err(|e| Error::BadRequest(e.to_string()))?;
        if operator.disabled || !stored.action.allowed_roles().contains(&operator.role) {
            return Err(Error::Denied(format!(
                "le rôle {} ne peut pas signer {}",
                operator.role.as_str(),
                stored.action.kind()
            )));
        }

        let verified =
            self.verifier
                .finish_authentication(assertion, &pending.state, key.sign_count)?;

        // Le corps figé peut avoir vieilli depuis l'émission (demande décidée
        // entre-temps) : on le recontrôle avant d'engager la signature.
        self.check_target(&stored.action).await?;

        // Consommation : conditionnelle, donc sûre sous concurrence. Une
        // exécution simultanée du même challenge n'en laisse passer qu'une.
        let mut tx = self.registry.pool().begin().await?;
        let a = sqlx::query(
            "UPDATE action_challenges SET consumed_at = $2
             WHERE challenge_id = $1 AND consumed_at IS NULL",
        )
        .bind(challenge_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let b = sqlx::query(
            "UPDATE actions SET executed_at = $2 WHERE id = $1 AND executed_at IS NULL",
        )
        .bind(action_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if a.rows_affected() != 1 || b.rows_affected() != 1 {
            return Err(Error::AlreadyUsed);
        }
        sqlx::query(
            "UPDATE webauthn_credentials SET sign_count = $2, last_used_at = $3
             WHERE credential_id = $1",
        )
        .bind(&key.credential_id)
        .bind(i64::from(verified.counter))
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO decision_evidence
               (id, challenge_id, action_id, operator_id, credential_id,
                authenticator_data, client_data_json, signature, verified_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(Uuid::new_v4())
        .bind(challenge_id)
        .bind(action_id)
        .bind(operator.id)
        .bind(&key.credential_id)
        .bind(assertion.response.authenticator_data.as_ref())
        .bind(assertion.response.client_data_json.as_ref())
        .bind(assertion.response.signature.as_ref())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // Journal avant l'effet : s'il échoue, rien n'est appliqué et la
        // signature reste consommée (échec fermé).
        self.journal
            .append(
                "operators.action_executed",
                serde_json::json!({
                    "action_id": action_id.to_string(),
                    "challenge_id": challenge_id.to_string(),
                    "action": stored.action.kind(),
                    "body_hash": hex::encode(&body_hash),
                    "operateur": operator.name,
                    "role": operator.role.as_str(),
                    "credential_id": key.credential_id,
                }),
            )
            .map_err(Error::Journal)?;

        match &stored.action {
            Action::ApproveRequest {
                transaction_id,
                comment,
                ..
            } => {
                self.decider
                    .approve(transaction_id, &operator.name, comment)
                    .await
            }
            Action::RejectRequest {
                transaction_id,
                comment,
            } => {
                self.decider
                    .reject(transaction_id, &operator.name, comment)
                    .await
            }
        }
        .map_err(|e| Error::Effect(e.to_string()))?;

        Ok(Executed {
            action_id,
            challenge_id,
            operator: operator.name,
            role: operator.role,
        })
    }
}
