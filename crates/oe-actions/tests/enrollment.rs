//! Enregistrement d'une clé avec un jeton d'invitation (docs/WEBUI.md §5, §10)
//! contre un vrai PostgreSQL et un authentificateur logiciel. Chaque test crée
//! sa propre base : la règle « pas d'administrateur actif » est globale.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use oe_actions::{bootstrap_admin, Error, KeyStatus, Registry, Service};
use oe_castore::{Postgres, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, TrustedModel, Url, Uuid, Verifier};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::WebauthnAuthenticator;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn origin() -> Url {
    Url::parse("https://console.example.com").unwrap()
}

#[derive(Default)]
struct MemJournal {
    events: Mutex<Vec<(String, serde_json::Value)>>,
    fail: AtomicBool,
}

impl Recorder for MemJournal {
    fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("disque plein".to_string());
        }
        self.events.lock().unwrap().push((event.to_string(), data));
        Ok(())
    }
}

struct Env {
    svc: Service,
    registry: Registry,
    journal: Arc<MemJournal>,
    authn: WebauthnAuthenticator<SoftToken>,
    /// Un authentificateur dont le modèle n'est pas dans la liste blanche.
    rogue: WebauthnAuthenticator<SoftToken>,
    now: Arc<Mutex<OffsetDateTime>>,
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let (head, _) = base.rsplit_once('/').expect("DSN sans base");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("enr_{nanos}_{}", SEQ.fetch_add(1, Ordering::Relaxed));
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base)
            .await
            .unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let dsn = format!("{head}/{name}");
        let store: Arc<dyn Store> = Arc::new(Postgres::open(&dsn).await.unwrap());
        let registry = Registry::connect(&dsn).await.unwrap();

        let (token, root) = SoftToken::new(true).unwrap();
        let (rogue_token, _) = SoftToken::new(true).unwrap();
        let root_pem = root.to_pem().unwrap();
        let verifier = Verifier::new(
            "console.example.com",
            &origin(),
            "test",
            trusted_models(&[TrustedModel {
                root_pem: &root_pem,
                aaguid: AAGUID,
                description: "SoftToken (test)",
            }])
            .unwrap(),
        )
        .unwrap();
        let journal = Arc::new(MemJournal::default());
        let now = Arc::new(Mutex::new(OffsetDateTime::now_utc()));
        let clock = now.clone();
        let svc = Service::new(
            registry.clone(),
            verifier,
            store.clone(),
            Decider::new(DeciderOptions {
                store,
                recorder: None,
                clock: None,
            }),
            journal.clone() as Arc<dyn Recorder>,
            Arc::new(move || *clock.lock().unwrap()),
        );
        Some(Env {
            svc,
            registry,
            journal,
            authn: WebauthnAuthenticator::new(token),
            rogue: WebauthnAuthenticator::new(rogue_token),
            now,
        })
    }

    fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap()
    }

    async fn bootstrap(&self, name: &str) -> String {
        bootstrap_admin(
            &self.registry,
            self.journal.as_ref(),
            name,
            time::Duration::minutes(15),
            self.now(),
        )
        .await
        .unwrap()
        .token
    }

    /// Une invitation ordinaire, comme en créera l'action signée « inviter ».
    async fn invite(&self, name: &str, created_by: &str) -> String {
        let id = self
            .registry
            .add_operator(name, oe_actions::Role::RaOperateur, created_by, self.now())
            .await
            .unwrap();
        let token = format!("jeton-{name}-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO operator_invites (id, operator_id, token_hash, created_by, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(Sha256::digest(token.as_bytes()).to_vec())
        .bind(created_by)
        .bind(self.now())
        .bind(self.now() + time::Duration::minutes(15))
        .execute(self.registry.pool())
        .await
        .unwrap();
        token
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(self.registry.pool())
            .await
            .unwrap()
    }
}

macro_rules! env {
    () => {
        match Env::new().await {
            Some(e) => e,
            None => {
                eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
                return;
            }
        }
    };
}

#[tokio::test]
async fn the_bootstrap_admin_registers_a_key_that_goes_straight_to_the_registry() {
    let mut env = env!();
    let token = env.bootstrap("alice").await;

    let begun = env.svc.begin_registration(&token).await.unwrap();
    assert_eq!(begun.operator, "alice");
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();
    let done = env
        .svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();

    assert_eq!(done.status, KeyStatus::Active);
    assert_eq!(done.aaguid, AAGUID);
    // Une empreinte lisible : huit groupes de quatre, deux fois.
    assert_eq!(done.key_fingerprint.split(' ').count(), 16);
    assert!(done
        .key_fingerprint
        .chars()
        .all(|c| c == ' ' || c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));

    let key = env
        .registry
        .key(&done.credential_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!key.revoked);
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT initiated_by, confirmed_by FROM webauthn_credentials WHERE credential_id = $1",
    )
    .bind(&done.credential_id)
    .fetch_one(env.registry.pool())
    .await
    .unwrap();
    assert_eq!(row, ("bootstrap-admin".to_string(), None));
    assert_eq!(
        env.count("SELECT count(*) FROM pending_credentials").await,
        0
    );

    // L'événement porte l'empreinte, jamais le jeton.
    let events = env.journal.events.lock().unwrap();
    let (_, data) = events
        .iter()
        .find(|(n, _)| n == "operators.credential_registered")
        .expect("enregistrement journalisé");
    assert_eq!(data["empreinte"], done.key_fingerprint);
    assert_eq!(data["statut"], "active");
    assert!(!format!("{events:?}").contains(&token));
}

#[tokio::test]
async fn an_invitation_serves_once() {
    let mut env = env!();
    let token = env.bootstrap("alice").await;
    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();
    env.svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();

    // Consommée : ni nouvelle cérémonie, ni rejeu de l'ancienne.
    assert!(matches!(
        env.svc.begin_registration(&token).await,
        Err(Error::Denied(_))
    ));
    assert!(matches!(
        env.svc.finish_registration(begun.ceremony_id, &reg).await,
        Err(Error::StateLost)
    ));
}

#[tokio::test]
async fn unknown_and_expired_invitations_look_the_same() {
    let env = env!();
    let token = env.bootstrap("alice").await;

    let unknown = env
        .svc
        .begin_registration("pas-un-jeton")
        .await
        .err()
        .unwrap();
    let later = env.now() + time::Duration::minutes(16);
    *env.now.lock().unwrap() = later;
    let expired = env.svc.begin_registration(&token).await.err().unwrap();
    assert_eq!(unknown.to_string(), expired.to_string());
    assert!(matches!(unknown, Error::Denied(_)));
}

#[tokio::test]
async fn a_ceremony_cannot_outlive_its_invitation() {
    let mut env = env!();
    let token = env.bootstrap("alice").await;
    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();

    // L'invitation expire entre begin et finish.
    let later = env.now() + time::Duration::minutes(16);
    *env.now.lock().unwrap() = later;
    assert!(env
        .svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .is_err());
    assert_eq!(
        env.count("SELECT count(*) FROM webauthn_credentials").await,
        0
    );
}

#[tokio::test]
async fn a_key_of_a_model_outside_the_whitelist_is_refused_and_leaves_the_invitation_alive() {
    let mut env = env!();
    let token = env.bootstrap("alice").await;

    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.rogue.do_registration(origin(), begun.options).unwrap();
    let err = env
        .svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .expect_err("modèle hors liste blanche");
    assert!(matches!(err, Error::Verification(_)), "{err}");
    assert_eq!(
        env.count("SELECT count(*) FROM webauthn_credentials").await,
        0
    );
    assert_eq!(
        env.count("SELECT count(*) FROM operator_invites WHERE consumed_at IS NOT NULL")
            .await,
        0
    );

    // L'invité peut recommencer avec la bonne clé.
    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();
    env.svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_ordinary_invitation_only_reaches_the_pending_table() {
    let mut env = env!();
    // Un admin actif existe déjà : c'est le cas normal d'un onboarding.
    let admin = env.bootstrap("alice").await;
    let begun = env.svc.begin_registration(&admin).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();
    env.svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();

    let token = env.invite("bob", "alice").await;
    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();
    let done = env
        .svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();

    assert_eq!(done.status, KeyStatus::PendingConfirmation);
    // Hors du registre : la clé ne permet ni de se connecter ni d'agir.
    assert!(env
        .registry
        .key(&done.credential_id)
        .await
        .unwrap()
        .is_none());
    let bob: Uuid = sqlx::query_scalar("SELECT id FROM operators WHERE name = 'bob'")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert!(env.registry.active_keys(bob).await.unwrap().is_empty());
    assert_eq!(
        env.count("SELECT count(*) FROM pending_credentials").await,
        1
    );
}

#[tokio::test]
async fn a_bootstrap_invitation_is_useless_once_an_admin_is_active() {
    let mut env = env!();
    // Deux administrateurs invités par l'amorçage n'est pas possible : on
    // simule l'invitation d'amorçage restée vivante d'un autre opérateur.
    let first = env.bootstrap("alice").await;
    let stale = env.invite("mallory", "bootstrap-admin").await;
    sqlx::query("UPDATE operators SET role = 'admin' WHERE name = 'mallory'")
        .execute(env.registry.pool())
        .await
        .unwrap();

    // mallory a ouvert sa cérémonie avant que alice ne devienne active.
    let begun_m = env.svc.begin_registration(&stale).await.unwrap();
    let reg_m = env
        .authn
        .do_registration(origin(), begun_m.options)
        .unwrap();

    let begun = env.svc.begin_registration(&first).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();
    env.svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();

    let err = env
        .svc
        .finish_registration(begun_m.ceremony_id, &reg_m)
        .await
        .expect_err("un admin est déjà actif");
    assert!(matches!(err, Error::Denied(_)), "{err}");
    assert_eq!(
        env.count("SELECT count(*) FROM webauthn_credentials").await,
        1
    );
}

#[tokio::test]
async fn a_failing_journal_stores_nothing_and_keeps_the_invitation() {
    let mut env = env!();
    let token = env.bootstrap("alice").await;
    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();

    env.journal.fail.store(true, Ordering::SeqCst);
    let err = env
        .svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .expect_err("journal en panne");
    assert!(matches!(err, Error::Journal(_)), "{err}");
    assert_eq!(
        env.count("SELECT count(*) FROM webauthn_credentials").await,
        0
    );

    env.journal.fail.store(false, Ordering::SeqCst);
    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();
    env.svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();
}
