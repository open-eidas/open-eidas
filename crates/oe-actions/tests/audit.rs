//! Audit de la chaîne du registre (docs/WEBUI.md §21) : chaque clé active se
//! remonte, signature re-vérifiée, jusqu'à une ancre attestée par le journal.
//! PostgreSQL réel, authentificateur logiciel, une base neuve par test.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use base64::Engine;
use oe_actions::{
    audit_registry, bootstrap_admin, key_fingerprint, Action, AuditReport, JournalView,
    NewCredential, Registry, Role, Service, Verdict,
};
use oe_castore::{Postgres, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, AttestedPasskey, TrustedModel, Url, Uuid, Verifier};
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

#[async_trait::async_trait]
impl Recorder for MemJournal {
    async fn append(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
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

    /// Ce que le journal atteste, éventuellement amputé de certains événements.
    fn view(&self, keep: impl Fn(&str) -> bool) -> JournalView {
        JournalView::from_events(
            self.journal
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|(n, _)| keep(n))
                .cloned(),
        )
    }

    async fn audit(&self) -> AuditReport {
        audit_registry(&self.registry, &self.view(|_| true))
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

    /// Ce que ferait quelqu'un qui écrit en base : une clé attestée réelle,
    /// insérée à la main.
    async fn forge(
        &mut self,
        name: &str,
        initiated_by: &str,
        confirmed_by: Option<&str>,
    ) -> (Uuid, String, AttestedPasskey) {
        let now = OffsetDateTime::now_utc();
        let id = self
            .registry
            .add_operator(name, Role::RaOperateur, "intrus", now)
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
                    label: "forgée",
                    initiated_by,
                    confirmed_by,
                },
                now,
            )
            .await
            .unwrap();
        let cred = oe_actions::credential_id(key.cred_id().as_ref());
        (id, cred, key)
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

fn finding<'a>(report: &'a AuditReport, credential: &str) -> &'a str {
    report
        .keys
        .iter()
        .find(|k| k.credential_id == credential)
        .unwrap_or_else(|| panic!("clé {credential} absente du rapport"))
        .verdict
        .as_ref()
        .expect_err("un constat était attendu")
}

#[tokio::test]
async fn a_genuine_chain_is_clean() {
    let mut env = env!();
    let (_, alice_key, bob_key) = env.genuine_chain().await;

    let report = env.audit().await;
    assert!(report.is_clean(), "{:?}", report.findings());
    let verdict = |id: &str| {
        report
            .keys
            .iter()
            .find(|k| k.credential_id == id)
            .unwrap()
            .verdict
            .clone()
            .unwrap()
    };
    assert_eq!(verdict(&alice_key), Verdict::Anchor);
    assert_eq!(verdict(&bob_key), Verdict::Chained { depth: 1 });
}

#[tokio::test]
async fn a_key_inserted_in_sql_has_no_chain() {
    let mut env = env!();
    env.genuine_chain().await;
    // L'intrus se fait passer pour confirmé par alice.
    let (_, forged, _) = env.forge("mallory", "intrus", Some("alice")).await;

    let report = env.audit().await;
    assert!(finding(&report, &forged).contains("aucune confirmation signée"));
    assert_eq!(report.findings().len(), 1);
}

#[tokio::test]
async fn a_forged_anchor_is_caught_by_the_journal() {
    let mut env = env!();
    env.genuine_chain().await;
    // La contrainte du registre admet `initiated_by = 'bootstrap-admin'` sans
    // confirmation : seule l'absence au journal trahit la ligne.
    let (_, forged, _) = env.forge("mallory", "bootstrap-admin", None).await;
    let (_, forged_recovery, _) = env
        .forge("mallet", "recover-admin", Some("recover-admin"))
        .await;

    let report = env.audit().await;
    assert!(finding(&report, &forged).contains("absente du journal"));
    assert!(finding(&report, &forged_recovery).contains("absente du journal"));
}

#[tokio::test]
async fn forged_evidence_without_a_real_signature_is_rejected() {
    let mut env = env!();
    let (alice, alice_key, _) = env.genuine_chain().await;
    let (mallory, forged, passkey) = env.forge("mallory", "intrus", Some("alice")).await;

    // L'intrus fabrique tout ce qu'il peut : l'action exécutée, son challenge, une
    // « preuve » au nom d'alice, avec une empreinte correcte. Il ne peut pas
    // fabriquer la signature.
    let expires = "2099-01-01T00:00:00Z";
    let fp = key_fingerprint(&passkey).unwrap();
    let canonical = format!(
        r#"{{"action":"confirm_key","credential_id":"{forged}","key_fingerprint":"{fp}","expires_at":"{expires}"}}"#
    );
    let action_id = Uuid::new_v4();
    let challenge_id = Uuid::new_v4();
    let challenge = vec![7u8; 32];
    sqlx::query(
        "INSERT INTO actions (id, body, body_hash, created_at, expires_at, executed_at, required_signatures)
         VALUES ($1, $2::jsonb, $3, now(), now() + interval '1 hour', now(), 1)",
    )
    .bind(action_id)
    .bind(&canonical)
    .bind(Sha256::digest(canonical.as_bytes()).to_vec())
    .execute(env.registry.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO action_challenges (challenge_id, action_id, challenge, operator_hint, issued_at, expires_at, consumed_at)
         VALUES ($1, $2, $3, $4, now(), now() + interval '5 minutes', now())",
    )
    .bind(challenge_id)
    .bind(action_id)
    .bind(&challenge)
    .bind(alice)
    .execute(env.registry.pool())
    .await
    .unwrap();
    let client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://console.example.com"}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge)
    );
    let insert_evidence = |signer_key: String, signer_op: Uuid, sig: Vec<u8>| {
        let (pool, client_data) = (env.registry.pool().clone(), client_data.clone());
        async move {
            sqlx::query("DELETE FROM decision_evidence WHERE action_id = $1")
                .bind(action_id)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO decision_evidence
                   (id, challenge_id, action_id, operator_id, credential_id,
                    authenticator_data, client_data_json, signature, verified_at)
                 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, now())",
            )
            .bind(challenge_id)
            .bind(action_id)
            .bind(signer_op)
            .bind(signer_key)
            .bind(vec![1u8; 37])
            .bind(client_data.into_bytes())
            .bind(sig)
            .execute(&pool)
            .await
            .unwrap();
        }
    };

    // Au nom d'alice, avec une signature inventée.
    insert_evidence(alice_key.clone(), alice, vec![9u8; 70]).await;
    let report = env.audit().await;
    assert!(
        finding(&report, &forged).contains("signature de alice refusée"),
        "{}",
        finding(&report, &forged)
    );

    // Au nom de l'intrus lui-même : refusé avant même de regarder la signature.
    insert_evidence(forged.clone(), mallory, vec![9u8; 70]).await;
    let report = env.audit().await;
    assert!(
        finding(&report, &forged).contains("ne se confirme pas elle-même"),
        "{}",
        finding(&report, &forged)
    );
}

#[tokio::test]
async fn a_tampered_signature_or_body_is_reported() {
    let mut env = env!();
    let (_, _, bob_key) = env.genuine_chain().await;
    assert!(env.audit().await.is_clean());

    // Un bit de la signature retourné.
    sqlx::query(
        "UPDATE decision_evidence SET signature = set_byte(signature, 10, get_byte(signature, 10) # 1)
         WHERE action_id = (SELECT id FROM actions WHERE body->>'action' = 'confirm_key')",
    )
    .execute(env.registry.pool())
    .await
    .unwrap();
    let report = env.audit().await;
    assert!(
        finding(&report, &bob_key).contains("signature de alice refusée"),
        "{}",
        finding(&report, &bob_key)
    );

    // Le corps modifié après coup (ici la date d'expiration).
    sqlx::query(
        "UPDATE decision_evidence SET signature = set_byte(signature, 10, get_byte(signature, 10) # 1)
         WHERE action_id = (SELECT id FROM actions WHERE body->>'action' = 'confirm_key')",
    )
    .execute(env.registry.pool())
    .await
    .unwrap();
    assert!(env.audit().await.is_clean(), "la signature est rétablie");
    sqlx::query(
        "UPDATE actions SET body = jsonb_set(body, '{expires_at}', '\"2099-01-01T00:00:00Z\"')
         WHERE body->>'action' = 'confirm_key'",
    )
    .execute(env.registry.pool())
    .await
    .unwrap();
    let report = env.audit().await;
    assert!(
        finding(&report, &bob_key).contains("ne correspond plus à son empreinte"),
        "{}",
        finding(&report, &bob_key)
    );
}

#[tokio::test]
async fn a_body_rewritten_together_with_its_hash_is_caught_by_the_journal() {
    let mut env = env!();
    let (_, _, bob_key) = env.genuine_chain().await;

    // La signature porte sur le challenge, pas sur le corps : un attaquant qui
    // réécrit le corps ET son empreinte, cohérents entre eux, passe la
    // cryptographie. Seul le journal, écrit avant la signature, le trahit.
    let row: (String, serde_json::Value) =
        sqlx::query_as("SELECT id::text, body FROM actions WHERE body->>'action' = 'confirm_key'")
            .fetch_one(env.registry.pool())
            .await
            .unwrap();
    let canonical = format!(
        r#"{{"action":"confirm_key","credential_id":"{bob_key}","key_fingerprint":"{}","expires_at":"2099-01-01T00:00:00Z"}}"#,
        row.1["key_fingerprint"].as_str().unwrap()
    );
    sqlx::query("UPDATE actions SET body = $2::jsonb, body_hash = $3 WHERE id = $1::uuid")
        .bind(&row.0)
        .bind(&canonical)
        .bind(Sha256::digest(canonical.as_bytes()).to_vec())
        .execute(env.registry.pool())
        .await
        .unwrap();

    let report = env.audit().await;
    assert!(
        finding(&report, &bob_key).contains("diffère de celui que le journal a consigné"),
        "{}",
        finding(&report, &bob_key)
    );

    // Et une action que le journal ne connaît pas du tout.
    let report = audit_registry(
        &env.registry,
        &env.view(|n| n != "operators.action_challenge_issued"),
    )
    .await
    .unwrap();
    assert!(finding(&report, &bob_key).contains("action absente du journal"));
}

#[tokio::test]
async fn the_journal_is_the_reference_for_confirmations_and_anchors() {
    let mut env = env!();
    let (_, alice_key, bob_key) = env.genuine_chain().await;

    // La confirmation de bob manque au journal, alors que sa signature est bonne.
    let report = audit_registry(&env.registry, &env.view(|n| n != "operators.key_confirmed"))
        .await
        .unwrap();
    assert!(finding(&report, &bob_key).contains("absente du journal chaîné"));
    assert!(report
        .keys
        .iter()
        .any(|k| k.credential_id == alice_key && k.verdict.is_ok()));

    // L'ancre manque au journal : alice est signalée, et bob avec elle, puisque sa
    // chaîne ne remonte plus à rien d'attesté.
    let report = audit_registry(
        &env.registry,
        &env.view(|n| n != "operators.credential_registered"),
    )
    .await
    .unwrap();
    assert!(finding(&report, &alice_key).contains("absente du journal"));
    assert!(finding(&report, &bob_key).contains("n'a pas de chaîne valide"));
}

#[tokio::test]
async fn revoked_keys_are_not_audited() {
    let mut env = env!();
    env.genuine_chain().await;
    let (_, forged, _) = env.forge("mallory", "intrus", Some("alice")).await;
    assert_eq!(env.audit().await.findings().len(), 1);

    env.registry
        .revoke_key(&forged, "test", "révoquée", OffsetDateTime::now_utc())
        .await
        .unwrap();
    assert!(env.audit().await.is_clean());
}

#[tokio::test]
async fn a_signature_bound_to_another_challenge_is_rejected() {
    let mut env = env!();
    let (_, _, bob_key) = env.genuine_chain().await;

    // La signature est bonne mais ne porte pas le challenge que `ca-server` avait
    // émis pour elle : une preuve rejouée depuis une autre cérémonie.
    sqlx::query(
        "UPDATE action_challenges SET challenge = set_byte(challenge, 0, get_byte(challenge, 0) # 1)
         WHERE action_id = (SELECT id FROM actions WHERE body->>'action' = 'confirm_key')",
    )
    .execute(env.registry.pool())
    .await
    .unwrap();
    let report = env.audit().await;
    assert!(
        finding(&report, &bob_key).contains("challenge signé n'est pas celui"),
        "{}",
        finding(&report, &bob_key)
    );
}

#[tokio::test]
async fn a_confirmation_that_signs_another_key_is_rejected() {
    let mut env = env!();
    let (_, _, bob_key) = env.genuine_chain().await;

    // Corps et empreinte réécrits ensemble pour engager une autre clé.
    let expires: String = sqlx::query_scalar(
        "SELECT body->>'expires_at' FROM actions WHERE body->>'action' = 'confirm_key'",
    )
    .fetch_one(env.registry.pool())
    .await
    .unwrap();
    let canonical = format!(
        r#"{{"action":"confirm_key","credential_id":"{bob_key}","key_fingerprint":"AAAA BBBB","expires_at":"{expires}"}}"#
    );
    sqlx::query(
        "UPDATE actions SET body = $1::jsonb, body_hash = $2 WHERE body->>'action' = 'confirm_key'",
    )
    .bind(&canonical)
    .bind(Sha256::digest(canonical.as_bytes()).to_vec())
    .execute(env.registry.pool())
    .await
    .unwrap();
    let report = env.audit().await;
    assert!(
        finding(&report, &bob_key).contains("empreinte signée n'est pas celle"),
        "{}",
        finding(&report, &bob_key)
    );
}

#[tokio::test]
async fn a_confirmation_with_too_few_signers_is_rejected() {
    let mut env = env!();
    let (_, _, bob_key) = env.genuine_chain().await;

    // La ligne prétend que l'action exigeait deux signatures : une seule existe.
    sqlx::query("UPDATE actions SET required_signatures = 2 WHERE body->>'action' = 'confirm_key'")
        .execute(env.registry.pool())
        .await
        .unwrap();
    let report = env.audit().await;
    assert!(
        finding(&report, &bob_key).contains("signataire(s) distinct(s) sur 2 exigés"),
        "{}",
        finding(&report, &bob_key)
    );
}
