# Provenance du code et gouvernance de la contribution

Ce document décrit comment le code d'Open eIDAS est conçu, écrit, revu et
validé, et comment cette provenance peut être justifiée après coup. Il
complète [CONTRIBUTING.md](CONTRIBUTING.md) et s'applique à tout le dépôt,
publié sous double licence [EUPL-1.2](LICENSE) ou
[AGPL-3.0-or-later](LICENSE-AGPL-3.0), au choix du réutilisateur.

## 1. Déclaration d'assistance par IA générative

Une partie du code, des tests et de la documentation de ce dépôt est saisie
ou générée avec l'assistance de **Claude Code** (Anthropic), un outil d'IA
générative utilisé dans le terminal. Claude Code n'a pas d'accès en écriture
au dépôt distant : il travaille sur le poste du contributeur, sous son
contrôle, et chaque commit est créé sous l'identité de ce contributeur.

L'assistance est déclarée, commit par commit, par la remorque Git standard :

```
Co-authored-by: Claude <noreply@anthropic.com>
```

Les champs `Author` et `Committer` restent **toujours** au nom du
contributeur humain qui a validé la modification. Un commit sans cette
remorque est un commit écrit sans assistance, ou antérieur à l'adoption de
la règle (voir §4).

## 2. Rôle du contributeur humain

L'outil est un moyen de saisie et de génération. Les décisions qui
déterminent l'œuvre restent humaines :

- **spécification fonctionnelle** : ce que le service doit faire, les
  exigences eIDAS et ETSI retenues, les écarts assumés ;
- **architecture logicielle** : découpage en crates, frontières de confiance
  (`ca-server`, `ra-console`, HSM), choix cryptographiques et protocolaires ;
- **conduite de la génération** : découpage du travail en tranches, consignes
  et contraintes données à l'outil, arbitrage entre les propositions ;
- **revue systématique** : chaque modification est relue avant commit, puis
  à nouveau dans la pull request, avec la liste de contrôle du modèle de PR ;
- **validation** : exécution locale des tests, contrôles par mutation des
  gardes de sécurité, vérification de la CI ; la décision de fusionner
  appartient au contributeur.

Le code retenu dans le dépôt est le résultat de cette sélection, de ces
corrections et de cette validation humaines. Les contributeurs estiment que
cet apport intellectuel fonde leur qualité d'auteurs de l'œuvre publiée
sous ces licences. Ce document décrit des faits et un processus. Il ne constitue
pas un avis juridique : l'appréciation de la protection par le droit
d'auteur relève, le cas échéant, du juge.

## 3. Traçabilité : ce qui peut être produit

| Élément | Où | Ce qu'il établit |
|---|---|---|
| Historique Git | dépôt public | auteur, committer, date, remorque d'assistance, contenu de chaque modification |
| Pull requests | GitHub | description, liste de contrôle cochée par un humain, CI, approbation |
| Transcriptions des sessions Claude Code | poste du contributeur (`~/.claude/projects/`) | consignes données, propositions, corrections, commandes exécutées, résultats des tests |
| Archive de provenance | poste du contributeur, hors dépôt | copie immuable des transcriptions, manifestes chaînés, horodatés en RFC 3161 par une TSA tierce |

Les transcriptions et l'archive **ne sont jamais commitées ni publiées** :
elles contiennent tout ce que les sessions ont lu ou affiché, secrets de
développement compris. Elles restent privées (droits `0700`/`0600`) et ne
sont produites qu'à la demande (litige, audit, contestation de paternité).

### Outil : `scripts/provenance.py`

```bash
# Quelles sessions ont produit ce commit ?
scripts/provenance.py trace <commit>

# Tableau pour toute une plage (défaut : dev)
scripts/provenance.py report > provenance-dev.md     # ou : make provenance

# Archiver les transcriptions et horodater le manifeste (à faire régulièrement)
scripts/provenance.py archive

# Revérifier l'archive : objets, chaîne des manifestes, jetons
curl -sO https://freetsa.org/files/cacert.pem
scripts/provenance.py verify --tsa-ca cacert.pem
```

`trace` et `report` classent les preuves par force :

1. **créé** : le commit, ou le commit de branche dont la PR a été fusionnée,
   a été produit par une commande `git commit` réussie de la session (sortie
   `[branche hash]`, ou message rédigé dans la commande) ;
2. **PR ouverte** / **PR fusionnée** : la session a exécuté `gh pr create`
   ou `gh pr merge` pour la pull request citée dans l'objet du commit ;
3. **mentionné** : le hash apparaît seulement dans la session (lecture de
   l'historique, par exemple). Ce n'est pas une preuve de production.

`archive` copie chaque transcription sous une forme adressée par son
empreinte SHA-256 (jamais écrasée), écrit un manifeste qui cite l'empreinte
du précédent, et le fait horodater par une TSA RFC 3161 tierce (FreeTSA puis
DigiCert par défaut, `OPENEIDAS_PROVENANCE_TSA` pour en choisir d'autres). Le
jeton obtenu prouve que les transcriptions existaient, dans cet état, à la
date attestée, sans dépendre de la confiance accordée au contributeur. Une
transcription que Claude Code aurait purgée reste dans l'archive.

Emplacement par défaut : `~/archives/open-eidas/provenance`
(`OPENEIDAS_PROVENANCE_DIR` pour le changer). Cette archive doit être
sauvegardée comme le reste des documents probants du contributeur.

### Conservation des transcriptions

Claude Code supprime par défaut les transcriptions de plus de 30 jours. Tout
contributeur qui utilise l'outil sur ce dépôt règle `cleanupPeriodDays` à une
valeur longue dans `~/.claude/settings.json`, par exemple `36500`, et lance
`scripts/provenance.py archive` régulièrement, au minimum avant chaque
fusion de PR.

## 4. État au 2026-09-25

- La remorque `Co-authored-by: Claude <noreply@anthropic.com>` est exigée à
  partir de cette date. Les commits antérieurs n'en portent pas, y compris
  ceux qui ont été produits avec l'assistance de Claude Code.
- Pour ces commits antérieurs, la provenance repose sur les transcriptions
  locales. Au 2026-09-25, `scripts/provenance.py report` rattache **76 des
  102 commits** de `dev` à une session qui les a créés ou qui a ouvert ou
  fusionné leur PR. Les 26 autres ne sont que mentionnés dans des sessions
  conservées. Ce sont pour l'essentiel les commits du 2026-09-06, dont aucune
  transcription n'a été retrouvée dans les archives locales : leur provenance
  ne peut pas être établie par cet outil.
- Les commits créés sur GitHub (fusion en squash, `release-please`) portent
  `GitHub` comme committer. La session qui a ouvert ou fusionné la PR en
  témoigne.

## 5. Licences des dépendances

Une dépendance n'entre dans le dépôt que si le binaire qui l'embarque peut
rester distribué sous la licence du projet (`EUPL-1.2 OR AGPL-3.0-or-later`).
La politique est
dans [deny.toml](deny.toml) et vérifiée par la CI (`cargo deny check
licenses`, ou `make licenses` en local) :

- **admises** : licences permissives (MIT, Apache-2.0, BSD, ISC, Zlib,
  Unicode, BSL-1.0, Unlicense, CC0, CDLA-Permissive), MPL-2.0, qui figure
  dans l'annexe des licences compatibles de l'EUPL-1.2, et AGPL-3.0, seconde
  licence du projet (un binaire qui en embarque une n'est plus distribuable
  que sous AGPL-3.0) ;
- **refusées sauf exception humaine consignée** : les autres copyleft de
  l'annexe (GPL, LGPL, OSL, EPL, CeCILL, CC-BY-SA, LiLiQ). Ils feraient
  basculer la licence du binaire vers une troisième licence : c'est une
  décision à prendre au cas par cas, jamais un automatisme.
