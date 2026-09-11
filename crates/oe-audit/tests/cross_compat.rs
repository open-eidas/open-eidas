//! Preuve de compatibilité Go ↔ Rust du format de journal d'audit (jalon
//! critique J5 du plan de migration, aujourd'hui achevé — le binaire Go est
//! déprécié). La fixture (`tests/fixtures/audit/go-produced.log`) a été
//! produite une fois pour toutes par le binaire Go de référence, avant sa
//! dépréciation, via l'outil `scripts/gen-audit-fixture` (supprimé avec le
//! reste du code Go) ; ce test ne doit jamais la régénérer : il vérifie
//! que le format Rust interopère avec ce que le service Go écrivait
//! réellement, à titre de preuve historique de compatibilité.

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
