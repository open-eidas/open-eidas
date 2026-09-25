//! Récupération d'un système verrouillé (docs/WEBUI.md §21) : `recover_admin`
//! rend la main quand les administrateurs « actifs » ont perdu leurs clés, sans
//! rien désactiver et en laissant une trace distincte. PostgreSQL réel,
//! authentificateur logiciel, une base neuve par test.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use oe_actions::{
    bootstrap_admin, recover_admin, Action, Error, KeyStatus, Registry, Role, Service,
};
use oe_castore::{Postgres, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, TrustedModel, Url, Uuid, Verifier};
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
}

const TTL: time::Duration = time::Duration::minutes(15);

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let (head, _) = base.rsplit_once('/').expect("DSN sans base");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("rec_{nanos}_{}", SEQ.fetch_add(1, Ordering::Relaxed));
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
            Arc::new(OffsetDateTime::now_utc),
        );
        Some(Env {
            svc,
            registry,
            journal,
            authn: WebauthnAuthenticator::new(token),
        })
    }

    async fn register(&mut self, token: &str) -> oe_actions::Registered {
        let begun = self.svc.begin_registration(token).await.unwrap();
        let reg = self.authn.do_registration(origin(), begun.options).unwrap();
        self.svc
            .finish_registration(begun.ceremony_id, &reg)
            .await
            .unwrap()
    }

    /// Le premier administrateur, amorcé comme au Jour 0.
    async fn bootstrapped(&mut self, name: &str) -> Uuid {
        let invite = bootstrap_admin(
            &self.registry,
            self.journal.as_ref(),
            name,
            TTL,
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        self.register(&invite.token).await;
        invite.operator_id
    }

    async fn recover(&self, name: &str, reason: &str) -> Result<oe_actions::Invite, Error> {
        recover_admin(
            &self.registry,
            self.journal.as_ref(),
            name,
            reason,
            TTL,
            OffsetDateTime::now_utc(),
        )
        .await
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(self.registry.pool())
            .await
            .unwrap()
    }

    fn events(&self, name: &str) -> Vec<serde_json::Value> {
        self.journal
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, d)| d.clone())
            .collect()
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
async fn recovery_gives_back_control_when_the_active_admin_lost_their_key() {
    let mut env = env!();
    let alice = env.bootstrapped("alice").await;
    let alice_key: String = sqlx::query_scalar("SELECT credential_id FROM webauthn_credentials")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();

    // alice est active (sa clé n'est pas révoquée) mais perdue : `bootstrap-admin`
    // refuse, et personne ne peut révoquer sa clé. Le système est verrouillé.
    let refused = bootstrap_admin(
        &env.registry,
        env.journal.as_ref(),
        "bob",
        TTL,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("un administrateur actif existe");
    assert!(matches!(refused, Error::Denied(_)), "{refused}");

    let invite = env.recover("bob", "clé de alice perdue").await.unwrap();
    let done = env.register(&invite.token).await;
    // La récupération active la clé directement : personne ne pourrait la confirmer.
    assert_eq!(done.status, KeyStatus::Active);
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT initiated_by, confirmed_by FROM webauthn_credentials WHERE credential_id = $1",
    )
    .bind(&done.credential_id)
    .fetch_one(env.registry.pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            "recover-admin".to_string(),
            Some("recover-admin".to_string())
        )
    );

    // Rien du registre existant n'a été désactivé.
    assert!(!env.registry.key(&alice_key).await.unwrap().unwrap().revoked);
    assert!(
        !env.registry
            .operator(alice)
            .await
            .unwrap()
            .unwrap()
            .disabled
    );

    // Un événement distinct, avec le motif et l'état du système, sans le jeton.
    let events = env.events("operators.admin_recovery");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["motif"], "clé de alice perdue");
    assert_eq!(events[0]["administrateurs_actifs"], 1);
    assert!(!format!("{events:?}").contains(&invite.token));

    // Et bob peut maintenant révoquer la clé perdue de alice, par une action signée.
    let bob = env
        .registry
        .key(&done.credential_id)
        .await
        .unwrap()
        .unwrap();
    let issued = env
        .svc
        .issue_challenge(
            Action::RevokeKey {
                credential_id: alice_key.clone(),
                reason: "perdue".into(),
            },
            bob.operator_id,
        )
        .await
        .unwrap();
    let assertion = env
        .authn
        .do_authentication(origin(), issued.options.clone())
        .unwrap();
    assert!(
        env.svc
            .execute(issued.challenge_id, &assertion)
            .await
            .unwrap()
            .executed
    );
    assert!(env.registry.key(&alice_key).await.unwrap().unwrap().revoked);
}

#[tokio::test]
async fn an_existing_admin_who_lost_their_key_can_be_re_invited() {
    let mut env = env!();
    let alice = env.bootstrapped("alice").await;

    let invite = env.recover("alice", "clé cassée").await.unwrap();
    assert_eq!(invite.operator_id, alice);
    env.register(&invite.token).await;
    assert_eq!(env.registry.active_keys(alice).await.unwrap().len(), 2);
    // Un seul opérateur, pas de doublon.
    assert_eq!(env.count("SELECT count(*) FROM operators").await, 1);
}

#[tokio::test]
async fn an_invitation_of_recovery_serves_once() {
    let mut env = env!();
    env.bootstrapped("alice").await;
    let invite = env.recover("bob", "test").await.unwrap();
    env.register(&invite.token).await;
    assert!(matches!(
        env.svc.begin_registration(&invite.token).await,
        Err(Error::Denied(_))
    ));
}

#[tokio::test]
async fn refused_recoveries_create_nothing() {
    let mut env = env!();
    env.bootstrapped("alice").await;
    // Un opérateur d'un autre rôle et un administrateur désactivé.
    env.registry
        .add_operator("rita", Role::RaOperateur, "test", OffsetDateTime::now_utc())
        .await
        .unwrap();
    env.registry
        .add_operator("zed", Role::Admin, "test", OffsetDateTime::now_utc())
        .await
        .unwrap();
    sqlx::query("UPDATE operators SET disabled_at = now() WHERE name = 'zed'")
        .execute(env.registry.pool())
        .await
        .unwrap();
    let before = env.count("SELECT count(*) FROM operator_invites").await;

    let long = "x".repeat(1001);
    for (name, reason) in [
        ("bob", ""),
        ("bob", "   "),
        ("bob", long.as_str()),
        ("rita", "motif"),
        ("zed", "motif"),
        (" mauvais", "motif"),
    ] {
        let err = env
            .recover(name, reason)
            .await
            .expect_err("récupération refusée");
        assert!(
            matches!(err, Error::BadRequest(_)),
            "{name}/{reason}: {err}"
        );
    }
    let err = recover_admin(
        &env.registry,
        env.journal.as_ref(),
        "bob",
        "motif",
        time::Duration::days(2),
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("durée abusive");
    assert!(matches!(err, Error::BadRequest(_)), "{err}");

    assert_eq!(
        env.count("SELECT count(*) FROM operator_invites").await,
        before
    );
    assert_eq!(
        env.count("SELECT count(*) FROM operators WHERE name = 'bob'")
            .await,
        0
    );
    assert!(env.events("operators.admin_recovery").is_empty());
}

#[tokio::test]
async fn a_failing_journal_creates_nothing() {
    let mut env = env!();
    env.bootstrapped("alice").await;
    env.journal.fail.store(true, Ordering::SeqCst);
    let err = env
        .recover("bob", "motif")
        .await
        .expect_err("journal en panne");
    assert!(matches!(err, Error::Journal(_)), "{err}");
    assert_eq!(
        env.count("SELECT count(*) FROM operators WHERE name = 'bob'")
            .await,
        0
    );
}
