//! Preuve de compatibilité Go ↔ Rust du format de journal d'audit (jalon
//! critique J5 du plan de migration). La fixture est produite par le binaire
//! Go de référence (`scripts/gen-audit-fixture`, régénérable via
//! `go run ./scripts/gen-audit-fixture`) — ce test ne doit jamais la
//! régénérer lui-même : il vérifie que le format Rust interopère avec ce que
//! le service Go écrit réellement aujourd'hui.

use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/audit/go-produced.log"
    ))
}

#[test]
fn verifies_a_journal_produced_by_the_go_binary() {
    let report = oe_audit::verify(fixture_path())
        .expect("un journal produit par le binaire Go doit être vérifiable par oe-audit");
    assert_eq!(report.records, 4);
    assert_eq!(report.first, 1);
    assert_eq!(report.last, 4);
    assert_eq!(report.seals, 1);
}
