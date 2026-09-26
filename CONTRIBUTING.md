# Contribuer à Open eIDAS

Merci de l'intérêt porté à ce projet. Open eIDAS vise une infrastructure de
confiance ouverte et auditable : les contributions techniques comme la
relecture critique de l'architecture ont de la valeur.

## Avant d'écrire du code

Pour tout changement non trivial (nouvelle fonctionnalité, changement de
comportement cryptographique ou protocolaire, dépendance ajoutée), ouvrez une
*issue* décrivant le problème avant d'envoyer une pull request. Ce projet
touche à de la cryptographie et à de la conformité réglementaire : discuter
l'approche en amont évite du travail jeté.

## Domaines où l'aide est particulièrement utile

Voir la section « Écarts assumés » de [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
pour le détail de chaque point :

- intégration de HSM certifiés (au-delà de SoftHSM2) ;
- redondance du service et procédure de bascule ;
- conformité fine à ETSI EN 319 421 / 319 422 ;
- durcissement de la configuration OpenXPKI de démonstration.

## Workflow git (gitflow)

- **`dev`** est la branche de développement : toute contribution y arrive
  par pull request depuis une branche de fonctionnalité (`feat/...`,
  `fix/...`...), jamais par push direct. Une CI verte et au moins une
  approbation sont exigées.
- **`main`** ne suit que la production certifiée. Elle n'avance que par
  pull request **depuis `dev`**, avec deux approbations de l'équipe
  `maintainers` — sans possibilité de contournement, y compris pour les
  administrateurs du dépôt. N'ouvrez jamais de PR directement vers `main`.
- Les titres de commit/PR suivent
  [Conventional Commits](https://www.conventionalcommits.org/fr/)
  (`feat: ...`, `fix: ...`, `docs: ...`, `feat!: ...` pour un changement
  incompatible, etc.) : c'est ce qui alimente le calcul automatique du
  numéro de version ([SemVer](https://semver.org/lang/fr/)) par
  `release-please` sur `dev`.

```bash
git clone https://github.com/otspi/open-eidas.git
cd open-eidas
git checkout dev
git checkout -b feat/ma-contribution
```

## Mettre en place l'environnement de développement

```bash
make up      # amorce la pile complète (PKI + TSA) via docker compose
make demo    # vérifie qu'un jeton s'émet et se valide
```

Le code est en Rust (édition 2021+, workspace Cargo) ; `rustup` avec les
composants `clippy` et `rustfmt` suffit pour développer localement.

## Avant d'envoyer une pull request

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check licenses   # compatibilité des dépendances avec la double licence (make licenses)
make demo   # bout en bout, si le changement touche à l'horodatage, l'enrôlement
            # ou la PKI
```

La CI (déclenchée sur `dev` et sur toute pull request) exécute les mêmes
vérifications, plus la matrice de conformité ETSI, un scan de
vulnérabilités des images (Trivy) et un amorçage complet de la pile
(`docker compose` et Helm sur `kind`).

## Assistance par IA et provenance

L'usage d'un outil d'IA générative (Claude Code notamment) est admis, à
condition d'être déclaré et que la revue reste humaine :

- chaque commit produit avec assistance se termine par la remorque
  `Co-authored-by: Claude <noreply@anthropic.com>` ;
- `Author` et `Committer` restent le contributeur humain qui valide la
  modification, jamais l'outil ;
- la liste de contrôle du modèle de pull request est cochée par ce
  contributeur, après une revue et des tests qu'il a faits lui-même ;
- les transcriptions des sessions sont conservées et archivées localement
  (`scripts/provenance.py archive`), jamais commitées.

Le détail, et la manière de justifier la provenance d'un commit, sont dans
[PROVENANCE.md](PROVENANCE.md).

## Style de code

- Pas de commentaire qui répète ce que fait le code ; un commentaire n'existe
  que pour expliquer un choix non évident (contrainte cryptographique,
  exigence normative, contournement documenté).
- Pas d'abstraction ni de configuration pour un besoin hypothétique : ce
  dépôt est un prototype, pas un framework.
- Toute nouvelle vérification de conformité (algorithme accepté, usage de
  certificat requis, etc.) doit citer la norme dont elle découle, en
  commentaire ou dans le message de commit.

## Sécurité

Ne pas ouvrir d'*issue* publique pour une vulnérabilité. Voir
[SECURITY.md](SECURITY.md).

## Licence

En contribuant, vous acceptez que vos changements soient publiés sous les
deux licences du projet, au choix du réutilisateur : la licence publique de
l'Union européenne EUPL-1.2 (voir [LICENSE](LICENSE)) ou la GNU AGPL v3 ou
ultérieure (voir [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0)).
