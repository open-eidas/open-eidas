//! Double contrôle (docs/WEBUI.md §8) : une action à deux signatures ne
//! s'exécute qu'avec deux opérateurs distincts et habilités, sur le même corps
//! figé, et une seule fois. PostgreSQL réel, authentificateur logiciel, une base
//! neuve par test.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use async_trait::async_trait;
use oe_actions::{
    Action, Error, Executed, Issued, NewCredential, Registry, Revoker, Role, Service, QUORUM_WINDOW,
};
use oe_castore::{Certificate, CertificateStatus, Postgres, Store};
use oe_raflow::{Decider, DeciderOptions, Recorder};
use oe_webauthn::{trusted_models, TrustedModel, Url, Uuid, Verifier};
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

/// Une autorité factice : elle marque le certificat révoqué dans le magasin et
/// retient qui a été imputé.
struct MockRevoker {
    store: Arc<dyn Store>,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl Revoker for MockRevoker {
    async fn revoke(
        &self,
        serial: &[u8],
        reason: i32,
        operator: &str,
        _comment: &str,
    ) -> Result<(), String> {
        self.calls.lock().unwrap().push(operator.to_string());
        self.store
            .revoke(&serial.to_vec(), OffsetDateTime::now_utc(), reason)
            .await
            .map_err(|e| e.to_string())
    }
    async fn publish_crl(&self) -> Result<i64, String> {
        Ok(1)
    }
}

struct Env {
    svc: Service,
    registry: Registry,
    store: Arc<dyn Store>,
    revoker: Arc<MockRevoker>,
    journal: Arc<MemJournal>,
    authn: WebauthnAuthenticator<SoftToken>,
    verifier: Verifier,
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
        let name = format!("quo_{nanos}_{}", SEQ.fetch_add(1, Ordering::Relaxed));
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
        let now = Arc::new(Mutex::new(OffsetDateTime::now_utc()));
        let clock = now.clone();
        let revoker = Arc::new(MockRevoker {
            store: store.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let svc = Service::new(
            registry.clone(),
            make_verifier(),
            store.clone(),
            Decider::new(DeciderOptions {
                store: store.clone(),
                recorder: None,
                clock: None,
            }),
            journal.clone() as Arc<dyn Recorder>,
            Arc::new(move || *clock.lock().unwrap()),
        )
        .with_revoker(revoker.clone());
        Some(Env {
            svc,
            registry,
            store,
            revoker,
            journal,
            authn: WebauthnAuthenticator::new(token),
            verifier: make_verifier(),
            now,
        })
    }

    async fn operator(&mut self, name: &str, role: Role) -> Uuid {
        let now = *self.now.lock().unwrap();
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
        id
    }

    /// Un certificat émis (ligne de la table), et son numéro de série en hexadécimal.
    async fn certificate(&self) -> String {
        let serial = vec![
            0x42,
            0x10,
            (SEQ.fetch_add(1, Ordering::Relaxed) & 0x7f) as u8,
            0x01,
        ];
        let now = OffsetDateTime::now_utc();
        self.store
            .reserve_serial(&serial, "tsa_signer")
            .await
            .unwrap();
        self.store
            .save_certificate(Certificate {
                serial: serial.clone(),
                profile: "tsa_signer".into(),
                subject_dn: "CN=tsu".into(),
                issuer_dn: "CN=ca".into(),
                not_before: now,
                not_after: now + time::Duration::days(365),
                der: vec![1],
                status: CertificateStatus::Issued,
                revoked_at: None,
                revocation_reason: 0,
                request_transaction_id: String::new(),
            })
            .await
            .unwrap();
        hex::encode(serial)
    }

    async fn revoked(&self, serial: &str) -> bool {
        self.store
            .certificate(&hex::decode(serial).unwrap())
            .await
            .unwrap()
            .status
            == CertificateStatus::Revoked
    }

    fn advance(&self, by: time::Duration) {
        let mut now = self.now.lock().unwrap();
        *now += by;
    }

    fn sign(&mut self, issued: &Issued) -> oe_webauthn::PublicKeyCredential {
        self.authn
            .do_authentication(origin(), issued.options.clone())
            .unwrap()
    }

    /// Émet un challenge pour une nouvelle action, signe, exécute.
    async fn first(&mut self, signer: Uuid, action: Action) -> (Uuid, Executed) {
        let issued = self.svc.issue_challenge(action, signer).await.unwrap();
        let a = self.sign(&issued);
        (
            issued.action_id,
            self.svc.execute(issued.challenge_id, &a).await.unwrap(),
        )
    }

    /// Un signataire de plus sur une action déjà figée.
    async fn join(&mut self, action: Uuid, signer: Uuid) -> Result<Executed, Error> {
        let issued = self.svc.issue_challenge_for(action, signer).await?;
        let a = self.sign(&issued);
        self.svc.execute(issued.challenge_id, &a).await
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

fn revoke(serial: &str) -> Action {
    Action::RevokeCertificate {
        serial: serial.to_string(),
        reason: 1,
        comment: "clé compromise".to_string(),
    }
}

#[tokio::test]
async fn two_distinct_ca_operators_revoke_once_and_both_are_attributed() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    let dave = env.operator("dave", Role::CaOperateur).await;
    let serial = env.certificate().await;

    let (action, first) = env.first(carla, revoke(&serial)).await;
    assert!(!first.executed);
    assert_eq!((first.signatures, first.required), (1, 2));
    assert!(first.result.is_none());
    assert!(!env.revoked(&serial).await);
    // Le seuil vient de la politique de ca-server, figé sur la ligne de l'action.
    let stored: i32 = sqlx::query_scalar("SELECT required_signatures FROM actions WHERE id = $1")
        .bind(action)
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert_eq!(stored, 2);
    assert_eq!(env.events("operators.action_signed").len(), 1);

    let done = env.join(action, dave).await.unwrap();
    assert!(done.executed);
    assert_eq!((done.signatures, done.required), (2, 2));
    assert!(env.revoked(&serial).await);

    // Une seule révocation, imputée aux deux signataires.
    let calls = env.revoker.calls.lock().unwrap().clone();
    assert_eq!(calls, vec!["carla, dave".to_string()]);
    let executed = env.events("operators.action_executed");
    assert_eq!(executed.len(), 1);
    assert_eq!(
        executed[0]["signataires"],
        serde_json::json!(["carla", "dave"])
    );

    // Une action exécutée ne reçoit plus de signature.
    let erin = env.operator("erin", Role::CaOperateur).await;
    assert!(matches!(
        env.svc.issue_challenge_for(action, erin).await,
        Err(Error::AlreadyUsed)
    ));
}

#[tokio::test]
async fn one_operator_counts_once_even_with_two_challenges() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    // Un second titulaire existe (sinon l'action ne serait pas créée) mais ne signe pas.
    env.operator("dave", Role::CaOperateur).await;
    let serial = env.certificate().await;

    // Deux challenges obtenus avant toute signature : l'astuce évidente.
    let c1 = env
        .svc
        .issue_challenge(revoke(&serial), carla)
        .await
        .unwrap();
    let c2 = env
        .svc
        .issue_challenge_for(c1.action_id, carla)
        .await
        .unwrap();
    let a1 = env.sign(&c1);
    let a2 = env.sign(&c2);
    let done = env.svc.execute(c1.challenge_id, &a1).await.unwrap();
    assert!(!done.executed);
    let err = env
        .svc
        .execute(c2.challenge_id, &a2)
        .await
        .expect_err("la même personne ne signe pas deux fois");
    assert!(matches!(err, Error::Denied(_)), "{err}");
    assert!(!env.revoked(&serial).await);
    assert!(env.revoker.calls.lock().unwrap().is_empty());

    // Et, une fois la première signature enregistrée, plus de challenge du tout.
    assert!(matches!(
        env.svc.issue_challenge_for(c1.action_id, carla).await,
        Err(Error::Denied(_))
    ));
}

#[tokio::test]
async fn a_second_signer_must_have_the_required_role() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    // Un second titulaire existe (sinon l'action ne serait pas créée) mais ne signe pas.
    env.operator("dave", Role::CaOperateur).await;
    let rita = env.operator("rita", Role::RaOperateur).await;
    let alice = env.operator("alice", Role::Admin).await;
    let serial = env.certificate().await;
    let (action, _) = env.first(carla, revoke(&serial)).await;

    for outsider in [rita, alice] {
        assert!(matches!(
            env.svc.issue_challenge_for(action, outsider).await,
            Err(Error::Denied(_))
        ));
    }
    assert!(!env.revoked(&serial).await);
}

#[tokio::test]
async fn the_action_stays_signable_for_the_window_and_each_challenge_stays_short() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    let dave = env.operator("dave", Role::CaOperateur).await;
    let serial = env.certificate().await;
    let (action, _) = env.first(carla, revoke(&serial)).await;

    // Un challenge oublié expire au bout de 5 minutes...
    let issued = env.svc.issue_challenge_for(action, dave).await.unwrap();
    let a = env.sign(&issued);
    env.advance(time::Duration::minutes(6));
    assert!(matches!(
        env.svc.execute(issued.challenge_id, &a).await,
        Err(Error::Expired)
    ));
    // ...mais l'action, elle, attend encore : on en redemande un.
    env.advance(time::Duration::hours(12));
    assert!(env.join(action, dave).await.unwrap().executed);
    assert!(env.revoked(&serial).await);
}

#[tokio::test]
async fn an_action_expires_after_the_window() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    let dave = env.operator("dave", Role::CaOperateur).await;
    let serial = env.certificate().await;
    let (action, _) = env.first(carla, revoke(&serial)).await;

    env.advance(QUORUM_WINDOW + time::Duration::minutes(1));
    assert!(matches!(
        env.svc.issue_challenge_for(action, dave).await,
        Err(Error::Expired)
    ));
    assert!(!env.revoked(&serial).await);
}

#[tokio::test]
async fn a_signer_who_lost_authority_in_between_blocks_the_execution() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    let dave = env.operator("dave", Role::CaOperateur).await;
    let serial = env.certificate().await;
    let (action, _) = env.first(carla, revoke(&serial)).await;

    // carla est désactivée entre les deux signatures.
    sqlx::query("UPDATE operators SET disabled_at = now() WHERE id = $1")
        .bind(carla)
        .execute(env.registry.pool())
        .await
        .unwrap();
    let err = env.join(action, dave).await.expect_err("signataire retiré");
    assert!(matches!(err, Error::Denied(_)), "{err}");
    assert!(!env.revoked(&serial).await);
    assert!(env.revoker.calls.lock().unwrap().is_empty());
}

// Multi-thread, et plusieurs manches. Deux signatures qui arrivent ensemble
// doivent produire exactement une exécution. Sans verrou sur l'action, chacune
// ne voit que « 1 signature sur 2 » (l'autre n'est pas encore validée) : les deux
// attendent, et la révocation n'a jamais lieu. Le `UPDATE` conditionnel, lui,
// garantit déjà qu'on n'exécute jamais deux fois.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_signatures_execute_exactly_once() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    let dave = env.operator("dave", Role::CaOperateur).await;

    for round in 0..15 {
        let serial = env.certificate().await;
        let cc = env
            .svc
            .issue_challenge(revoke(&serial), carla)
            .await
            .unwrap();
        let cd = env
            .svc
            .issue_challenge_for(cc.action_id, dave)
            .await
            .unwrap();
        let ac = env.sign(&cc);
        let ad = env.sign(&cd);
        let (svc_c, svc_d) = (&env.svc, &env.svc);
        let (rc, rd) = tokio::join!(async { svc_c.execute(cc.challenge_id, &ac).await }, async {
            svc_d.execute(cd.challenge_id, &ad).await
        },);
        let executed = [&rc, &rd]
            .iter()
            .filter(|r| matches!(r, Ok(e) if e.executed))
            .count();
        assert_eq!(executed, 1, "manche {round} : {rc:?} / {rd:?}");
        assert!(env.revoked(&serial).await);
        assert_eq!(env.revoker.calls.lock().unwrap().len(), round + 1);
    }
}

#[tokio::test]
async fn two_admins_create_an_admin() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    let bob = env.operator("bob", Role::Admin).await;

    let (action, first) = env
        .first(
            alice,
            Action::InviteOperator {
                name: "dave".into(),
                role: Role::Admin,
                ttl_minutes: 60,
            },
        )
        .await;
    assert!(!first.executed);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM operators WHERE name = 'dave'")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);

    let done = env.join(action, bob).await.unwrap();
    assert!(done.executed);
    let role: String = sqlx::query_scalar("SELECT role FROM operators WHERE name = 'dave'")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert_eq!(role, "admin");
    assert!(done.result.unwrap()["invite_token"].is_string());
}

#[tokio::test]
async fn ordinary_actions_still_need_one_signature() {
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    env.operator("bob", Role::RaOperateur).await;
    let (_, done) = env
        .first(
            alice,
            Action::SetRole {
                operator: "bob".into(),
                role: Role::CaOperateur,
            },
        )
        .await;
    assert!(done.executed);
    assert_eq!((done.signatures, done.required), (1, 1));
}

#[tokio::test]
async fn an_action_that_could_never_reach_its_threshold_is_not_created() {
    let mut env = env!();
    let carla = env.operator("carla", Role::CaOperateur).await;
    let serial = env.certificate().await;

    // Un seul titulaire du rôle : la laisser en attente ferait croire qu'un
    // second signataire va venir.
    let err = env
        .svc
        .issue_challenge(revoke(&serial), carla)
        .await
        .expect_err("un seul ca_operateur");
    assert!(matches!(err, Error::Denied(_)), "{err}");
    let actions: i64 = sqlx::query_scalar("SELECT count(*) FROM actions")
        .fetch_one(env.registry.pool())
        .await
        .unwrap();
    assert_eq!(actions, 0, "aucune action ne doit rester en attente");

    // Un second titulaire dont la clé est révoquée ne compte pas.
    let dave = env.operator("dave", Role::CaOperateur).await;
    sqlx::query(
        "UPDATE webauthn_credentials SET revoked_at = now(), revoked_by = 't', revoked_reason = 't' WHERE operator_id = $1",
    )
    .bind(dave)
    .execute(env.registry.pool())
    .await
    .unwrap();
    assert!(matches!(
        env.svc.issue_challenge(revoke(&serial), carla).await,
        Err(Error::Denied(_))
    ));

    // Avec un vrai second titulaire, l'action est créée.
    env.operator("erin", Role::CaOperateur).await;
    assert!(env
        .svc
        .issue_challenge(revoke(&serial), carla)
        .await
        .is_ok());

    // Idem pour l'élévation au rôle admin : un seul admin ne peut pas la lancer.
    let mut env = env!();
    let alice = env.operator("alice", Role::Admin).await;
    let err = env
        .svc
        .issue_challenge(
            Action::InviteOperator {
                name: "dave".into(),
                role: Role::Admin,
                ttl_minutes: 60,
            },
            alice,
        )
        .await
        .expect_err("un seul admin");
    assert!(matches!(err, Error::Denied(_)), "{err}");
}
