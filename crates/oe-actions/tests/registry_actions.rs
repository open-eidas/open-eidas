//! Actions signées sur le registre (docs/WEBUI.md §10) : inviter, confirmer une
//! clé, révoquer une clé, changer un rôle. PostgreSQL réel, authentificateur
//! logiciel, une base neuve par test (la règle « dernier administrateur » est
//! globale).
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use oe_actions::{Action, Error, Issued, KeyStatus, NewCredential, Registry, Role, Service};
use oe_castore::{Postgres, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, PublicKeyCredential, TrustedModel, Url, Uuid, Verifier};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicU64, Ordering};
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
}

impl Recorder for MemJournal {
    fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        self.events.lock().unwrap().push((event.to_string(), data));
        Ok(())
    }
}

struct Env {
    svc: Service,
    registry: Registry,
    journal: Arc<MemJournal>,
    authn: WebauthnAuthenticator<SoftToken>,
    verifier: Verifier,
}

struct Op {
    id: Uuid,
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let (head, _) = base.rsplit_once('/').expect("DSN sans base");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("ract_{nanos}_{}", SEQ.fetch_add(1, Ordering::Relaxed));
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
        let make_verifier = || {
            Verifier::new(
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
            .unwrap()
        };
        let journal = Arc::new(MemJournal::default());
        let svc = Service::new(
            registry.clone(),
            make_verifier(),
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
            verifier: make_verifier(),
        })
    }

    /// Un opérateur avec une clé active, comme après une confirmation.
    async fn operator(&mut self, name: &str, role: Role) -> Op {
        let now = OffsetDateTime::now_utc();
        let id = self
            .registry
            .add_operator(name, role, "test", now)
            .await
            .unwrap();
        let (options, state) = self.verifier.start_registration(id, name, None).unwrap();
        let reg = self.authn.do_registration(origin(), options).unwrap();
        let key = self.verifier.finish_registration(&reg, &state).unwrap();
        self.registry
            .add_credential(
                NewCredential {
                    operator_id: id,
                    passkey: &key,
                    aaguid: AAGUID,
                    attestation_format: "basic",
                    attestation_object: reg.response.attestation_object.as_ref(),
                    label: "test",
                    initiated_by: "test",
                    confirmed_by: Some("test"),
                },
                now,
            )
            .await
            .unwrap();
        Op { id }
    }

    fn sign(&mut self, issued: &Issued) -> PublicKeyCredential {
        self.authn
            .do_authentication(origin(), issued.options.clone())
            .unwrap()
    }

    /// Émet, signe et exécute.
    async fn run(&mut self, signer: &Op, action: Action) -> Result<oe_actions::Executed, Error> {
        let issued = self.svc.issue_challenge(action, signer.id).await?;
        let assertion = self.sign(&issued);
        self.svc.execute(issued.challenge_id, &assertion).await
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(self.registry.pool())
            .await
            .unwrap()
    }

    /// Invite `name` (rôle ra_operateur) et enregistre sa clé : elle reste en attente.
    async fn invited_with_pending_key(&mut self, by: &Op, name: &str) -> (String, String) {
        let done = self
            .run(
                by,
                Action::InviteOperator {
                    name: name.to_string(),
                    role: Role::RaOperateur,
                    ttl_minutes: 60,
                },
            )
            .await
            .unwrap();
        let token = done.result.unwrap()["invite_token"]
            .as_str()
            .unwrap()
            .to_string();
        self.register(&token).await
    }

    async fn register(&mut self, token: &str) -> (String, String) {
        let begun = self.svc.begin_registration(token).await.unwrap();
        let reg = self.authn.do_registration(origin(), begun.options).unwrap();
        let done = self
            .svc
            .finish_registration(begun.ceremony_id, &reg)
            .await
            .unwrap();
        assert_eq!(done.status, KeyStatus::PendingConfirmation);
        (done.credential_id, done.key_fingerprint)
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
async fn an_admin_invites_and_confirms_the_invitee_key() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;

    let done = env
        .run(
            &alice,
            Action::InviteOperator {
                name: "bob".into(),
                role: Role::RaOperateur,
                ttl_minutes: 60,
            },
        )
        .await
        .unwrap();
    let result = done.result.expect("le jeton est rendu à l'appelant");
    let token = result["invite_token"].as_str().unwrap().to_string();
    assert_eq!(result["operator"], "bob");

    // Le jeton n'est conservé nulle part en clair.
    let hash: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM operator_invites WHERE created_by = 'alice'")
            .fetch_one(env.registry.pool())
            .await
            .unwrap();
    assert_eq!(hash, Sha256::digest(token.as_bytes()).to_vec());
    assert!(!format!("{:?}", env.journal.events.lock().unwrap()).contains(&token));
    let body: String = sqlx::query_scalar("SELECT body::text FROM actions LIMIT 1")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert!(!body.contains(&token));

    // L'invité enregistre sa clé : en attente, sans droit.
    let (credential_id, fingerprint) = env.register(&token).await;
    let bob: Uuid = sqlx::query_scalar("SELECT id FROM operators WHERE name = 'bob'")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert!(env.registry.active_keys(bob).await.unwrap().is_empty());

    // L'empreinte fausse est refusée dès l'émission, la clé reste en attente.
    let wrong = env
        .svc
        .issue_challenge(
            Action::ConfirmKey {
                credential_id: credential_id.clone(),
                key_fingerprint: "0000 0000".into(),
            },
            alice.id,
        )
        .await
        .err()
        .expect("empreinte fausse");
    assert!(matches!(wrong, Error::Denied(_)), "{wrong}");
    assert_eq!(
        env.count("SELECT count(*) FROM pending_credentials").await,
        1
    );

    // La bonne empreinte active la clé.
    env.run(
        &alice,
        Action::ConfirmKey {
            credential_id: credential_id.clone(),
            key_fingerprint: fingerprint,
        },
    )
    .await
    .unwrap();
    assert_eq!(env.registry.active_keys(bob).await.unwrap().len(), 1);
    assert_eq!(
        env.count("SELECT count(*) FROM pending_credentials").await,
        0
    );
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT initiated_by, confirmed_by FROM webauthn_credentials WHERE operator_id = $1",
    )
    .bind(bob)
    .fetch_one(env.registry.pool())
    .await
    .unwrap();
    assert_eq!(row, ("alice".to_string(), Some("alice".to_string())));
}

#[tokio::test]
async fn only_an_admin_may_touch_the_registry() {
    let mut env = env!();
    let _alice = env.operator("alice", Role::Admin).await;
    let ra = env.operator("rita", Role::RaOperateur).await;
    let err = env
        .svc
        .issue_challenge(
            Action::InviteOperator {
                name: "eve".into(),
                role: Role::Auditeur,
                ttl_minutes: 60,
            },
            ra.id,
        )
        .await
        .err()
        .expect("un ra_operateur n'invite pas");
    assert!(matches!(err, Error::Denied(_)), "{err}");
    assert_eq!(
        env.count("SELECT count(*) FROM operators WHERE name = 'eve'")
            .await,
        0
    );
}

#[tokio::test]
async fn nobody_confirms_their_own_key() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    let (k1, fp1) = env.invited_with_pending_key(&alice, "bob").await;
    env.run(
        &alice,
        Action::ConfirmKey {
            credential_id: k1,
            key_fingerprint: fp1,
        },
    )
    .await
    .unwrap();

    // bob devient admin (par le SQL : le quorum n'existe pas encore), puis
    // enregistre une seconde clé avec une nouvelle invitation.
    sqlx::query("UPDATE operators SET role = 'admin' WHERE name = 'bob'")
        .execute(env.registry.pool())
        .await
        .unwrap();
    let bob_id: Uuid = sqlx::query_scalar("SELECT id FROM operators WHERE name = 'bob'")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    let bob = Op { id: bob_id };
    let token = "second-jeton-de-bob";
    sqlx::query(
        "INSERT INTO operator_invites (id, operator_id, token_hash, created_by, created_at, expires_at)
         VALUES (gen_random_uuid(), $1, $2, 'alice', now(), now() + interval '15 minutes')",
    )
    .bind(bob.id)
    .bind(Sha256::digest(token.as_bytes()).to_vec())
    .execute(env.registry.pool())
    .await
    .unwrap();
    let (k2, fp2) = env.register(token).await;

    let err = env
        .svc
        .issue_challenge(
            Action::ConfirmKey {
                credential_id: k2,
                key_fingerprint: fp2,
            },
            bob.id,
        )
        .await
        .err()
        .expect("auto-confirmation");
    assert!(matches!(err, Error::Denied(_)), "{err}");
    assert_eq!(
        env.count("SELECT count(*) FROM pending_credentials").await,
        1
    );
}

#[tokio::test]
async fn the_admin_role_cannot_be_granted_or_removed_by_a_single_admin() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    let _bob = env.operator("bob", Role::RaOperateur).await;
    let _carol = env.operator("carol", Role::Admin).await;

    for action in [
        Action::InviteOperator {
            name: "dave".into(),
            role: Role::Admin,
            ttl_minutes: 60,
        },
        Action::SetRole {
            operator: "bob".into(),
            role: Role::Admin,
        },
        // Retirer le rôle à un autre admin : même règle, dans l'autre sens.
        Action::SetRole {
            operator: "carol".into(),
            role: Role::Auditeur,
        },
        // Et jamais son propre rôle.
        Action::SetRole {
            operator: "alice".into(),
            role: Role::Auditeur,
        },
    ] {
        let err = env
            .svc
            .issue_challenge(action.clone(), alice.id)
            .await
            .err()
            .unwrap_or_else(|| panic!("{action:?} aurait dû être refusée"));
        assert!(matches!(err, Error::Denied(_)), "{action:?} : {err}");
    }
}

#[tokio::test]
async fn a_role_change_is_executed_and_journaled() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    let bob = env.operator("bob", Role::RaOperateur).await;
    env.run(
        &alice,
        Action::SetRole {
            operator: "bob".into(),
            role: Role::CaOperateur,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        env.registry.operator(bob.id).await.unwrap().unwrap().role,
        Role::CaOperateur
    );
    let events = env.journal.events.lock().unwrap();
    let (_, data) = events
        .iter()
        .find(|(n, _)| n == "operators.role_changed")
        .unwrap();
    assert_eq!(data["ancien_role"], "ra_operateur");
    assert_eq!(data["par"], "alice");
}

#[tokio::test]
async fn invitations_reject_a_taken_name_and_an_absurd_lifetime() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    for (name, ttl) in [("alice", 60), ("zoé", 0), ("zoé", 24 * 60 + 1)] {
        let err = env
            .svc
            .issue_challenge(
                Action::InviteOperator {
                    name: name.into(),
                    role: Role::Auditeur,
                    ttl_minutes: ttl,
                },
                alice.id,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("{name} / {ttl} min aurait dû être refusée"));
        assert!(matches!(err, Error::BadRequest(_)), "{err}");
    }
}

#[tokio::test]
async fn a_key_revocation_needs_a_reason_and_never_removes_the_last_admin() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    let bob = env.operator("bob", Role::RaOperateur).await;
    let alice_key: String =
        sqlx::query_scalar("SELECT credential_id FROM webauthn_credentials WHERE operator_id = $1")
            .bind(alice.id)
            .fetch_one(env.registry.pool())
            .await
            .unwrap();
    let bob_key: String =
        sqlx::query_scalar("SELECT credential_id FROM webauthn_credentials WHERE operator_id = $1")
            .bind(bob.id)
            .fetch_one(env.registry.pool())
            .await
            .unwrap();

    // Sans motif.
    let err = env
        .svc
        .issue_challenge(
            Action::RevokeKey {
                credential_id: bob_key.clone(),
                reason: "  ".into(),
            },
            alice.id,
        )
        .await
        .err()
        .expect("motif obligatoire");
    assert!(matches!(err, Error::BadRequest(_)), "{err}");

    // La clé du seul administrateur.
    let err = env
        .svc
        .issue_challenge(
            Action::RevokeKey {
                credential_id: alice_key.clone(),
                reason: "test".into(),
            },
            alice.id,
        )
        .await
        .err()
        .expect("dernier administrateur");
    assert!(matches!(err, Error::Denied(_)), "{err}");

    // La clé d'un autre opérateur, elle, se révoque.
    env.run(
        &alice,
        Action::RevokeKey {
            credential_id: bob_key.clone(),
            reason: "clé perdue".into(),
        },
    )
    .await
    .unwrap();
    assert!(env.registry.key(&bob_key).await.unwrap().unwrap().revoked);

    // Une seconde révocation de la même clé est refusée.
    let err = env
        .svc
        .issue_challenge(
            Action::RevokeKey {
                credential_id: bob_key,
                reason: "encore".into(),
            },
            alice.id,
        )
        .await
        .err()
        .expect("déjà révoquée");
    assert!(matches!(err, Error::Denied(_)), "{err}");
}
