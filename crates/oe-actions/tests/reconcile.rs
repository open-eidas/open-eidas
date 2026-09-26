//! Rejeu du journal et `reconcile` (docs/WEBUI.md §21) : une base restaurée en
//! arrière est détectée, bloque les actions, et se répare depuis le journal.
//! PostgreSQL réel, authentificateur logiciel, une base neuve par test.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use oe_actions::{
    bootstrap_admin, find_divergences, reconcile, Action, Divergence, Error, Registry,
    RegistryGuard, Replay, Role, Service,
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

#[async_trait::async_trait]
impl Recorder for MemJournal {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("disque plein".to_string());
        }
        self.events.lock().unwrap().push((event.to_string(), data));
        Ok(())
    }
}

struct Env {
    svc: Service,
    guard: Arc<RegistryGuard>,
    registry: Registry,
    journal: Arc<MemJournal>,
    authn: WebauthnAuthenticator<SoftToken>,
}

impl Env {
    async fn new() -> Option<Env> {
        let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
        let (head, _) = base.rsplit_once('/').expect("DSN sans base");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("aud_{nanos}_{}", SEQ.fetch_add(1, Ordering::Relaxed));
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
        let guard = RegistryGuard::new();
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
        )
        .with_guard(guard.clone());
        Some(Env {
            svc,
            guard,
            registry,
            journal,
            authn: WebauthnAuthenticator::new(token),
        })
    }

    fn replay(&self) -> Replay {
        Replay::from_events(self.journal.events.lock().unwrap().iter().cloned())
    }

    async fn divergences(&self) -> Vec<Divergence> {
        find_divergences(&self.registry, &self.replay())
            .await
            .unwrap()
    }

    async fn run(&mut self, signer: Uuid, action: Action) -> oe_actions::Executed {
        let issued = self.svc.issue_challenge(action, signer).await.unwrap();
        let a = self
            .authn
            .do_authentication(origin(), issued.options.clone())
            .unwrap();
        self.svc.execute(issued.challenge_id, &a).await.unwrap()
    }

    async fn register(&mut self, token: &str) -> oe_actions::Registered {
        let begun = self.svc.begin_registration(token).await.unwrap();
        let reg = self.authn.do_registration(origin(), begun.options).unwrap();
        self.svc
            .finish_registration(begun.ceremony_id, &reg)
            .await
            .unwrap()
    }

    /// Une chaîne réelle : alice (ancre) invite bob, qui enregistre sa clé,
    /// qu'alice confirme. Rend (id d'alice, clé d'alice, clé de bob).
    async fn genuine_chain(&mut self) -> (Uuid, String, String) {
        let invite = bootstrap_admin(
            &self.registry,
            self.journal.as_ref(),
            "alice",
            time::Duration::minutes(15),
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        let alice_key = self.register(&invite.token).await.credential_id;
        let alice = invite.operator_id;
        let done = self
            .run(
                alice,
                Action::InviteOperator {
                    name: "bob".into(),
                    role: Role::RaOperateur,
                    ttl_minutes: 60,
                },
            )
            .await;
        let token = done.result.unwrap()["invite_token"]
            .as_str()
            .unwrap()
            .to_string();
        let pending = self.register(&token).await;
        self.run(
            alice,
            Action::ConfirmKey {
                credential_id: pending.credential_id.clone(),
                key_fingerprint: pending.key_fingerprint,
            },
        )
        .await;
        (alice, alice_key, pending.credential_id)
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

impl Env {
    /// Le contrôle que fait `ca-server` : compare, et ferme la garde s'il y a lieu.
    async fn check(&self) -> Vec<Divergence> {
        let found = self.divergences().await;
        if found.is_empty() {
            self.guard.open();
        } else {
            self.guard
                .block(found.iter().map(|d| d.to_string()).collect());
        }
        found
    }

    async fn reconcile(
        &self,
        ack: &[&str],
        dry_run: bool,
    ) -> Result<oe_actions::ReconcileOutcome, Error> {
        reconcile(
            &self.registry,
            self.journal.as_ref(),
            &self.replay(),
            "base restaurée",
            &ack.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            dry_run,
            OffsetDateTime::now_utc(),
        )
        .await
    }

    async fn key_revoked(&self, id: &str) -> bool {
        self.registry.key(id).await.unwrap().unwrap().revoked
    }
}

#[tokio::test]
async fn a_registry_consistent_with_its_journal_has_no_divergence() {
    let mut env = env!();
    let (alice, _, bob_key) = env.genuine_chain().await;
    env.run(
        alice,
        Action::SetRole {
            operator: "bob".into(),
            role: Role::CaOperateur,
        },
    )
    .await;
    env.run(
        alice,
        Action::RevokeKey {
            credential_id: bob_key,
            reason: "perdue".into(),
        },
    )
    .await;
    assert!(env.check().await.is_empty());
    assert!(env.guard.blocked().is_none());
}

#[tokio::test]
async fn a_restored_older_database_is_detected_blocks_actions_and_is_repaired() {
    let mut env = env!();
    let (alice, _, bob_key) = env.genuine_chain().await;
    env.run(
        alice,
        Action::RevokeKey {
            credential_id: bob_key.clone(),
            reason: "perdue".into(),
        },
    )
    .await;

    // La base est restaurée à un état antérieur à la révocation ; le journal,
    // lui, n'est pas restauré.
    sqlx::query("UPDATE webauthn_credentials SET revoked_at = NULL, revoked_by = NULL, revoked_reason = NULL WHERE credential_id = $1")
        .bind(&bob_key)
        .execute(env.registry.pool())
        .await
        .unwrap();
    assert!(!env.key_revoked(&bob_key).await);

    let found = env.check().await;
    assert_eq!(
        found,
        vec![Divergence::RevokedInJournal {
            credential_id: bob_key.clone(),
            operator: "bob".into()
        }]
    );

    // Échec fermé : plus rien ne s'exécute, ne s'émet, ne s'enregistre.
    let blocked = env
        .svc
        .issue_challenge(
            Action::SetRole {
                operator: "bob".into(),
                role: Role::Auditeur,
            },
            alice,
        )
        .await
        .expect_err("registre bloqué");
    assert!(matches!(blocked, Error::Blocked(_)), "{blocked}");
    assert!(blocked.to_string().contains(&bob_key));
    assert!(matches!(
        env.svc.begin_registration("jeton").await,
        Err(Error::Blocked(_))
    ));
    assert!(matches!(
        env.svc.issue_challenge_for(Uuid::new_v4(), alice).await,
        Err(Error::Blocked(_))
    ));

    // Un essai à blanc ne change rien.
    let dry = env.reconcile(&[], true).await.unwrap();
    assert_eq!(dry.resolved.len(), 1);
    assert!(!env.key_revoked(&bob_key).await);

    // La résolution ré-applique la révocation, et le journal en garde la trace.
    let done = env.reconcile(&[], false).await.unwrap();
    assert_eq!(done.resolved.len(), 1);
    assert!(done.unresolved.is_empty());
    assert!(env.key_revoked(&bob_key).await);
    let events = env.journal.events.lock().unwrap().clone();
    let reconciled = events
        .iter()
        .find(|(n, _)| n == "operators.reconciled")
        .expect("résolution consignée");
    assert_eq!(reconciled.1["resultat"], "reapplied_revocation");
    assert_eq!(reconciled.1["motif"], "base restaurée");
    drop(events);

    // Le contrôle suivant rouvre la garde : les actions reprennent.
    assert!(env.check().await.is_empty());
    assert!(env
        .svc
        .issue_challenge(
            Action::SetRole {
                operator: "bob".into(),
                role: Role::Auditeur,
            },
            alice,
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn a_role_restored_backwards_is_reapplied_from_the_journal() {
    let mut env = env!();
    let (alice, _, _) = env.genuine_chain().await;
    env.run(
        alice,
        Action::SetRole {
            operator: "bob".into(),
            role: Role::CaOperateur,
        },
    )
    .await;
    sqlx::query("UPDATE operators SET role = 'ra_operateur' WHERE name = 'bob'")
        .execute(env.registry.pool())
        .await
        .unwrap();

    assert_eq!(
        env.check().await,
        vec![Divergence::RoleDiffers {
            operator: "bob".into(),
            journal_role: "ca_operateur".into(),
            db_role: "ra_operateur".into()
        }]
    );
    env.reconcile(&[], false).await.unwrap();
    let role: String = sqlx::query_scalar("SELECT role FROM operators WHERE name = 'bob'")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert_eq!(role, "ca_operateur");
    assert!(env.check().await.is_empty());
}

#[tokio::test]
async fn a_lost_key_is_never_hidden_and_needs_an_explicit_acknowledgement() {
    let mut env = env!();
    let (_, _, bob_key) = env.genuine_chain().await;
    // La base restaurée n'a jamais connu la clé de bob (ni son opérateur, sans
    // quoi la contrainte étrangère la retiendrait) ; le journal, si.
    sqlx::query("DELETE FROM webauthn_credentials WHERE credential_id = $1")
        .bind(&bob_key)
        .execute(env.registry.pool())
        .await
        .unwrap();

    let expected = Divergence::MissingKey {
        credential_id: bob_key.clone(),
        operator: "bob".into(),
    };
    assert_eq!(env.check().await, vec![expected.clone()]);

    // `reconcile` ne peut pas la recréer : il la laisse en suspens, actions bloquées.
    let out = env.reconcile(&[], false).await.unwrap();
    assert_eq!(out.unresolved, vec![expected]);
    assert!(out.resolved.is_empty());
    assert!(!env.check().await.is_empty());
    assert!(env.guard.blocked().is_some());

    // Acquitter autre chose qu'une vraie perte est refusé.
    assert!(matches!(
        env.reconcile(&["n-importe-quoi"], false).await,
        Err(Error::BadRequest(_))
    ));

    // L'acquittement explicite est consigné, et le rejeu en tient compte.
    let out = env.reconcile(&[&bob_key], false).await.unwrap();
    assert_eq!(out.resolved.len(), 1);
    assert!(out.unresolved.is_empty());
    assert!(env.check().await.is_empty());
    assert!(env.guard.blocked().is_none());
    let events = env.journal.events.lock().unwrap().clone();
    assert!(events.iter().any(|(n, d)| n == "operators.reconciled"
        && d["resultat"] == "acknowledged_missing"
        && d["credential_id"] == bob_key.as_str()));
}

#[tokio::test]
async fn a_failing_journal_or_a_missing_reason_changes_nothing() {
    let mut env = env!();
    let (alice, _, bob_key) = env.genuine_chain().await;
    env.run(
        alice,
        Action::RevokeKey {
            credential_id: bob_key.clone(),
            reason: "perdue".into(),
        },
    )
    .await;
    sqlx::query("UPDATE webauthn_credentials SET revoked_at = NULL WHERE credential_id = $1")
        .bind(&bob_key)
        .execute(env.registry.pool())
        .await
        .unwrap();

    // Journal en échec : la résolution s'écrit avant d'être validée, donc rien.
    env.journal.fail.store(true, Ordering::SeqCst);
    let err = env
        .reconcile(&[], false)
        .await
        .expect_err("journal en panne");
    assert!(matches!(err, Error::Journal(_)), "{err}");
    assert!(!env.key_revoked(&bob_key).await);
    env.journal.fail.store(false, Ordering::SeqCst);

    // Sans motif écrit.
    let err = reconcile(
        &env.registry,
        env.journal.as_ref(),
        &env.replay(),
        "  ",
        &[],
        false,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("motif obligatoire");
    assert!(matches!(err, Error::BadRequest(_)), "{err}");
    assert!(!env.key_revoked(&bob_key).await);
}

#[tokio::test]
async fn a_key_still_pending_confirmation_is_not_expected_in_the_registry() {
    let mut env = env!();
    let (alice, _, _) = env.genuine_chain().await;
    let done = env
        .run(
            alice,
            Action::InviteOperator {
                name: "carol".into(),
                role: Role::Auditeur,
                ttl_minutes: 60,
            },
        )
        .await;
    let token = done.result.unwrap()["invite_token"]
        .as_str()
        .unwrap()
        .to_string();
    let pending = env.register(&token).await;

    // Enregistrée mais pas confirmée : le journal ne l'attend pas dans le registre.
    assert!(env.check().await.is_empty());
    // Et sa perte (base restaurée avant) n'est pas une divergence du registre.
    sqlx::query("DELETE FROM pending_credentials WHERE credential_id = $1")
        .bind(&pending.credential_id)
        .execute(env.registry.pool())
        .await
        .unwrap();
    assert!(env.check().await.is_empty());
}

#[tokio::test]
async fn a_signature_obtained_before_the_block_cannot_be_executed_after_it() {
    let mut env = env!();
    let (alice, _, _) = env.genuine_chain().await;

    // Une inscription de clé en cours (l'invitation passe par une action signée,
    // faite avant : le compteur de la clé d'alice ne doit plus bouger ensuite).
    let done = env
        .run(
            alice,
            Action::InviteOperator {
                name: "erin".into(),
                role: Role::Auditeur,
                ttl_minutes: 60,
            },
        )
        .await;
    let token = done.result.unwrap()["invite_token"]
        .as_str()
        .unwrap()
        .to_string();
    let begun = env.svc.begin_registration(&token).await.unwrap();
    let reg = env.authn.do_registration(origin(), begun.options).unwrap();

    // Une action signée, prête à s'exécuter.
    let issued = env
        .svc
        .issue_challenge(
            Action::SetRole {
                operator: "bob".into(),
                role: Role::CaOperateur,
            },
            alice,
        )
        .await
        .unwrap();
    let assertion = env
        .authn
        .do_authentication(origin(), issued.options.clone())
        .unwrap();

    // Le registre se met à diverger du journal : tout s'arrête, même ce qui est prêt.
    env.guard.block(vec!["divergence".to_string()]);
    assert!(matches!(
        env.svc.execute(issued.challenge_id, &assertion).await,
        Err(Error::Blocked(_))
    ));
    assert!(matches!(
        env.svc.finish_registration(begun.ceremony_id, &reg).await,
        Err(Error::Blocked(_))
    ));

    // Rien n'a été consommé : une fois la garde rouverte, tout reprend.
    env.guard.open();
    assert!(
        env.svc
            .execute(issued.challenge_id, &assertion)
            .await
            .unwrap()
            .executed
    );
    env.svc
        .finish_registration(begun.ceremony_id, &reg)
        .await
        .unwrap();
}
