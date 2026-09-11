//! Génère tests/fixtures/audit/rust-produced.log avec oe-audit, pour prouver
//! la compatibilité Rust -> Go (jalon J5) : ce fichier doit être vérifiable
//! par `go run ./scripts/verify-audit-fixture`.
//!
//! `cargo run -p oe-audit --example gen_fixture`

use oe_audit::{Data, Log};

fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/audit/rust-produced.log"
    );
    let _ = std::fs::remove_file(path);
    let log = Log::open(path).expect("ouverture du journal");

    log.append(oe_audit::EVENT_OPENED, None).expect("append 1");

    let mut data = Data::new();
    data.insert("serial_number".to_string(), serde_json::json!(42));
    data.insert("message_imprint".to_string(), serde_json::json!("a1b2c3"));
    data.insert(
        "reason".to_string(),
        serde_json::json!("valeur <sensible> & \"citée\" avec accents éàî"),
    );
    log.append(oe_audit::EVENT_TIMESTAMP_GRANTED, Some(data))
        .expect("append 2");

    let mut sources = Data::new();
    sources.insert("ntp.obspm.fr".to_string(), serde_json::json!("12ms"));
    sources.insert("ptbtime1.ptb.de".to_string(), serde_json::json!("-8ms"));
    let mut data2 = Data::new();
    data2.insert("traceable".to_string(), serde_json::json!(true));
    data2.insert(
        "sources".to_string(),
        serde_json::Value::Object(sources.into_iter().collect()),
    );
    log.append(oe_audit::EVENT_TIME_MEASUREMENT, Some(data2))
        .expect("append 3");

    log.append(oe_audit::EVENT_SEALED, None).expect("append 4");

    println!("écrit: {path}");
}
