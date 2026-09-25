//! Vérifie l'amorçage du premier administrateur (docs/WEBUI.md §10) contre un
//! vrai PostgreSQL. La règle « refuser s'il existe un administrateur actif »
//! est globale : chaque test crée donc **sa propre base**, pour ne pas dépendre
//! des administrateurs que d'autres tests, en parallèle, ont créés.
//!
//! DSN dans `OE_CASTORE_TEST_DSN` ; test ignoré si elle n'est pas définie.

use oe_actions::{bootstrap_admin, Error, Registry, MAX_INVITE_TTL};
use oe_castore::Postgres;
use oe_raflow::Recorder;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

static SEQ: AtomicU64 = AtomicU64::new(0);

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

impl MemJournal {
    fn events(&self, name: &str) -> Vec<serde_json::Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, d)| d.clone())
            .collect()
    }

    fn dump(&self) -> String {
        format!("{:?}", self.events.lock().unwrap())
    }
}

/// Une base neuve, migrée, rien que pour ce test.
async fn fresh() -> Option<Registry> {
    let base = std::env::var("OE_CASTORE_TEST_DSN").ok()?;
    let (head, _) = base.rsplit_once('/').expect("DSN sans base");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("boot_{nanos}_{}", SEQ.fetch_add(1, Ordering::Relaxed));

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base)
        .await
        .expect("connexion d'administration");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .expect("création de la base de test");

    let dsn = format!("{head}/{name}");
    Postgres::open(&dsn).await.expect("migrations");
    Some(Registry::connect(&dsn).await.expect("pool"))
}

macro_rules! fresh {
    () => {
        match fresh().await {
            Some(r) => r,
            None => {
                eprintln!("OE_CASTORE_TEST_DSN non définie : test PostgreSQL ignoré");
                return;
            }
        }
    };
}

fn ttl() -> time::Duration {
    time::Duration::minutes(15)
}

/// Un administrateur qui a déjà une clé active (ligne insérée à la main :
/// l'amorçage compte les clés, il ne les déchiffre pas).
async fn seed_admin_with_key(r: &Registry, name: &str) {
    let id: String = sqlx::query_scalar(
        "INSERT INTO operators (id, name, role, created_at, created_by)
         VALUES (gen_random_uuid(), $1, 'admin', now(), 'test') RETURNING id::text",
    )
    .bind(name)
    .fetch_one(r.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO webauthn_credentials
           (credential_id, operator_id, public_key, aaguid, attestation_format,
            attestation_object, backup_eligible, initiated_by, initiated_at,
            confirmed_by, confirmed_at, passkey)
         VALUES ('cred-' || $1, $1::uuid, '\\x00', gen_random_uuid(), 'packed',
                 '\\x00', false, 'test', now(), 'test', now(), '{}'::jsonb)",
    )
    .bind(&id)
    .execute(r.pool())
    .await
    .unwrap();
}

async fn count(r: &Registry, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(r.pool()).await.unwrap()
}

#[tokio::test]
async fn it_creates_the_admin_and_keeps_only_a_hash_of_the_token() {
    let r = fresh!();
    let journal = MemJournal::default();
    let now = OffsetDateTime::now_utc();

    let invite = bootstrap_admin(&r, &journal, "alice", ttl(), now)
        .await
        .expect("amorçage");

    // 256 bits en base64url sans remplissage : 43 caractères.
    assert_eq!(invite.token.len(), 43);
    assert_eq!(invite.expires_at, now + ttl());

    let role: String = sqlx::query_scalar("SELECT role FROM operators WHERE name = 'alice'")
        .fetch_one(r.pool())
        .await
        .unwrap();
    assert_eq!(role, "admin");

    let row = sqlx::query("SELECT token_hash, created_by, consumed_at FROM operator_invites")
        .fetch_one(r.pool())
        .await
        .unwrap();
    let stored: Vec<u8> = row.get("token_hash");
    assert_eq!(stored, Sha256::digest(invite.token.as_bytes()).to_vec());
    assert_eq!(row.get::<String, _>("created_by"), "bootstrap-admin");
    assert!(row
        .get::<Option<OffsetDateTime>, _>("consumed_at")
        .is_none());

    // Le jeton lui-même n'est nulle part en base…
    let leaked = count(
        &r,
        &format!(
            "SELECT count(*) FROM operator_invites WHERE encode(token_hash, 'escape') LIKE '%{}%'",
            invite.token
        ),
    )
    .await;
    assert_eq!(leaked, 0);
    // …ni au journal, qui ne porte que l'identifiant de l'invitation.
    assert!(!journal.dump().contains(&invite.token));
    let logged = journal.events("operators.bootstrap_admin_invited");
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0]["invite_id"], invite.invite_id.to_string());
}

#[tokio::test]
async fn it_refuses_once_an_admin_has_an_active_key_and_says_so() {
    let r = fresh!();
    seed_admin_with_key(&r, "premier").await;
    let journal = MemJournal::default();

    let err = bootstrap_admin(&r, &journal, "pirate", ttl(), OffsetDateTime::now_utc())
        .await
        .expect_err("refusé");
    assert!(matches!(err, Error::Denied(_)), "{err}");

    // Rien n'a été créé, et la tentative est au journal.
    assert_eq!(
        count(&r, "SELECT count(*) FROM operators WHERE name = 'pirate'").await,
        0
    );
    assert_eq!(count(&r, "SELECT count(*) FROM operator_invites").await, 0);
    assert_eq!(journal.events("operators.bootstrap_admin_refused").len(), 1);
}

#[tokio::test]
async fn an_admin_without_a_key_can_be_reinvited_and_the_old_invite_dies() {
    let r = fresh!();
    let journal = MemJournal::default();
    let t0 = OffsetDateTime::now_utc();

    let first = bootstrap_admin(&r, &journal, "alice", ttl(), t0)
        .await
        .unwrap();
    // Invitation perdue : on relance, plus tard.
    let t1 = t0 + time::Duration::minutes(5);
    let second = bootstrap_admin(&r, &journal, "alice", ttl(), t1)
        .await
        .unwrap();

    assert_ne!(first.token, second.token);
    assert_eq!(
        first.operator_id, second.operator_id,
        "pas de doublon d'opérateur"
    );
    assert_eq!(count(&r, "SELECT count(*) FROM operators").await, 1);

    // Une seule invitation reste vivante à t1 : la seconde.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM operator_invites WHERE consumed_at IS NULL AND expires_at > $1",
    )
    .bind(t1)
    .fetch_one(r.pool())
    .await
    .unwrap();
    assert_eq!(live, 1);
}

#[tokio::test]
async fn concurrent_bootstraps_leave_a_single_live_invite() {
    let r = fresh!();
    let journal = Arc::new(MemJournal::default());
    let now = OffsetDateTime::now_utc();

    let mut tasks = Vec::new();
    for _ in 0..6 {
        let (r, j) = (r.clone(), journal.clone());
        tasks.push(tokio::spawn(async move {
            bootstrap_admin(&r, j.as_ref(), "alice", ttl(), now).await
        }));
    }
    for t in tasks {
        t.await.unwrap().expect("chaque amorçage aboutit, en série");
    }

    assert_eq!(count(&r, "SELECT count(*) FROM operators").await, 1);
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM operator_invites WHERE consumed_at IS NULL AND expires_at > $1",
    )
    .bind(now)
    .fetch_one(r.pool())
    .await
    .unwrap();
    assert_eq!(
        live, 1,
        "les amorçages concurrents ne doivent laisser qu'une invitation"
    );
}

#[tokio::test]
async fn a_journal_failure_creates_nothing() {
    let r = fresh!();
    let journal = MemJournal::default();
    journal.fail.store(true, Ordering::SeqCst);

    let res = bootstrap_admin(&r, &journal, "alice", ttl(), OffsetDateTime::now_utc()).await;
    assert!(matches!(res, Err(Error::Journal(_))));

    assert_eq!(count(&r, "SELECT count(*) FROM operators").await, 0);
    assert_eq!(count(&r, "SELECT count(*) FROM operator_invites").await, 0);
}

#[tokio::test]
async fn a_name_already_taken_by_another_operator_is_refused() {
    let r = fresh!();
    let journal = MemJournal::default();
    sqlx::query(
        "INSERT INTO operators (id, name, role, created_at, created_by)
         VALUES (gen_random_uuid(), 'bob', 'auditeur', now(), 'test')",
    )
    .execute(r.pool())
    .await
    .unwrap();

    let res = bootstrap_admin(&r, &journal, "bob", ttl(), OffsetDateTime::now_utc()).await;
    assert!(matches!(res, Err(Error::BadRequest(_))));
    assert_eq!(count(&r, "SELECT count(*) FROM operator_invites").await, 0);
}

#[tokio::test]
async fn names_and_durations_are_validated() {
    let r = fresh!();
    let journal = MemJournal::default();
    let now = OffsetDateTime::now_utc();

    for bad in ["", "   ", " alice", "alice ", "a\nb", &"x".repeat(101)] {
        let res = bootstrap_admin(&r, &journal, bad, ttl(), now).await;
        assert!(matches!(res, Err(Error::BadRequest(_))), "{bad:?}");
    }
    for bad in [
        time::Duration::seconds(30),
        MAX_INVITE_TTL + time::Duration::seconds(1),
        time::Duration::ZERO,
        time::Duration::minutes(-5),
    ] {
        let res = bootstrap_admin(&r, &journal, "alice", bad, now).await;
        assert!(matches!(res, Err(Error::BadRequest(_))), "{bad}");
    }
    assert_eq!(count(&r, "SELECT count(*) FROM operators").await, 0);
}
