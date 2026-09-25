// `sqlx::migrate!` embarque les fichiers de `migrations/` à la compilation, mais
// cargo ne recompile pas la crate quand on y *ajoute* un fichier : une nouvelle
// migration serait alors silencieusement absente du binaire, et les tests
// passeraient ou échoueraient selon l'état du cache de compilation.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
