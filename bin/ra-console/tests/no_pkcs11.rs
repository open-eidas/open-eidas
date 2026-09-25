//! `ra-console` n'ouvre jamais de session PKCS#11 et ne lie pas `cryptoki`
//! (docs/WEBUI.md §16 « Surface d'attaque du binaire »).
//!
//! Ce n'est pas qu'une propriété du code : c'est le profil de dépendances du
//! binaire, donc de `cargo audit`, et de son image (aucun module PKCS#11,
//! aucune variable de PIN). Une dépendance transitive suffit à le défaire sans que
//! rien ne le dise : `oe-enroll` tirait `oe-hsm` pour un simple trait, et avec lui
//! `cryptoki`. On lit donc le graphe réel des dépendances du binaire.

use std::process::Command;

#[test]
fn the_console_binary_does_not_link_cryptoki() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("racine du workspace");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .current_dir(root)
        // Dépendances de production du binaire : ni les tests, ni les outils.
        .args([
            "tree",
            "-p",
            "ra-console",
            "-e",
            "normal",
            "--prefix",
            "none",
        ])
        .args(["--offline", "--locked"])
        .output()
        .expect("lancement de cargo tree");
    assert!(
        out.status.success(),
        "cargo tree : {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8_lossy(&out.stdout);
    let linked: Vec<&str> = tree
        .lines()
        .map(|l| l.split_whitespace().next().unwrap_or(""))
        .filter(|name| name.starts_with("cryptoki"))
        .collect();
    assert!(
        linked.is_empty(),
        "ra-console lie {linked:?} : elle ne doit jamais ouvrir de session PKCS#11 (§16). \
         Une dépendance active la feature `pkcs11` d'oe-hsm ?"
    );
}
