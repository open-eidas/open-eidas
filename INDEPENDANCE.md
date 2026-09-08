# Indépendance vis-à-vis d'OpenXPKI

Document d'arbitrage, puis **compte rendu de réalisation** : la décision de
remplacer OpenXPKI par un moteur de CA/RA maison en Go a été prise, puis
exécutée. Ce document conserve l'argumentaire d'origine — un arbitrage se juge
sur ce qui l'a motivé, pas seulement sur son résultat — et rend compte de ce
qui a été livré et de ce qui reste ouvert.

## Contexte (à la date de l'arbitrage)

Le MVP utilisait OpenXPKI Community comme moteur de CA (hiérarchie de test,
profils de certificat, workflow d'enrôlement) derrière la TSA et le répondeur
OCSP, tous deux entièrement custom (Go). Au fil de deux sous-tâches — l'ajout
du répondeur OCSP et l'activation réelle de l'approbation RA — plusieurs
comportements internes non documentés d'OpenXPKI ont dû être découverts par
rétro-ingénierie :

- un profil de certificat mal formé (`crl_distribution_points.uri` scalaire
  au lieu d'une liste, format de durée relative invalide) échoue
  silencieusement côté moteur NICE plutôt que de rejeter la configuration
  au chargement ;
- le point d'approbation RA (`approval_points`) était intégralement
  contourné par la règle d'éligibilité (`eligible.value: 1`), qui
  déclenche une auto-approbation interne (`EvaluateEligibility` →
  `approve_by_eligiblity`) sans qu'aucune erreur ne le signale ;
- la clé CLI privilégiée (`system/cli.yaml`) ne porte aucun rôle
  exploitable par le moteur de workflow lors d'un appel réalisé dans un
  contexte de royaume (`--realm`) — seule une session authentifiée
  normalement (mot de passe) obtient le rôle attendu, une distinction non
  documentée qui a fait échouer plusieurs tentatives avant d'être
  comprise.

Ce type d'opacité est précisément ce qu'un audit eIDAS (ETSI EN 319 401 /
421 / 422, évaluation par un organisme accrédité type LSTI ou Apave) va
chercher à mettre en défaut, puisqu'il touche à des contrôles documentés
(validité du profil de certificat émis, effectivité réelle de
l'approbation RA).

## Argument central retenu

Un moteur de CA/RA entièrement maison, aussi étroit soit-il, élimine
cette catégorie de risque : plus de comportement caché qu'on n'a pas vu
venir en l'intégrant. Il est aussi objectivement plus petit et plus
simple à revoir dans son intégralité qu'une suite PKI généraliste, ce qui
peut rendre un audit externe plus rapide et moins coûteux, pas plus.

Le bénéfice le plus fort se situe sur l'axe de l'entretien d'audit et de
la traçabilité : une équipe qui a écrit le code peut l'expliquer ligne par
ligne à l'auditeur et démontrer, test à l'appui, que chaque exigence est
appliquée — une équipe qui a déployé un logiciel tiers ne peut que citer
sa documentation et espérer que le comportement réel y correspond. Pour
une association dont la mission repose sur la transparence, c'est un
atout de fond, pas seulement technique.

Ce que ça ne supprime pas :

- la nécessité d'un audit de sécurité/pentest externe et indépendant
  (l'auto-justification ne remplace jamais la vérification tierce — un
  auditeur scrutera probablement du code maison *plus* attentivement,
  faute d'antécédent, pas moins) ;
- la cérémonie de clé de la CA racine/émettrice, les contrôles
  organisationnels, le CP/CPS — identiques quel que soit le moteur choisi.

## Ce qui a été livré

| Fonction | OpenXPKI auparavant | Réalisation |
|---|---|---|
| Émission depuis une CSR | Profil YAML + moteur NICE (Perl) | `internal/ca` — `x509.CreateCertificate`, profils en structures Go testables unitairement |
| Génération de CRL | Workflow `crl_issuance` + connecteur `cdp` | `internal/ca` — `x509.CreateRevocationList`, `CRLNumber` monotone servi par la base |
| Stockage des clés de CA | Datavault chiffré en base (MariaDB) | PKCS#11 (`internal/hsm`), un token par autorité — un seul mécanisme de gestion de clé pour toute la pile |
| Enrôlement + approbation RA | Workflow générique `certificate_enroll` | `internal/raflow` — une machine à états dédiée (HMAC → PENDING → APPROVED → ISSUED), sans aucun chemin d'auto-approbation |
| Publication du certificat de CA et de la CRL | Connecteurs `cacert-der`/`cacert-pem`, contournés par la hiérarchie jetable | Servies par `cmd/ca-server` aux mêmes chemins `/download/<CN>.cer` et `.crl` |
| Répondeur OCSP | — | Déjà fait avant ce chantier (`cmd/ocsp-responder`) |
| Interface opérateur RA | WebUI OpenXPKI | CLI `ca-server ra list|approve|reject`, cohérente avec `tsa-server enroll`/`verify-audit` |
| Registre (certificats, demandes, CRL) | MariaDB, schéma OpenXPKI | PostgreSQL, schéma écrit et commenté par ce dépôt (`internal/castore`) |

**Au-delà du périmètre initialement envisagé**, le chantier a produit
`internal/conformance` : les exigences ETSI applicables rendues exécutables,
définies une seule fois et utilisées à trois endroits qui ne peuvent pas
diverger — les tests unitaires, les gardes d'exécution (le certificat produit
est relu depuis son DER et re-contrôlé avant d'être délivré), et la matrice
publiée dans [`docs/CONFORMITE-ETSI.md`](docs/CONFORMITE-ETSI.md), générée
depuis le code et vérifiée en CI.

Conséquence pour le packaging : le Pod OpenXPKI à 4 conteneurs
(`server`/`client`/`web`/`bootstrap`), ses contournements de permissions
Kubernetes (`fsGroup`, vhost Apache recopié, groupe forcé des workers Apache)
et la dépendance Perl/MariaDB ont disparu du chart Helm comme du
docker-compose. La pile ne contient plus que du Go et PostgreSQL.

## Risques du chantier, et où ils en sont

- **Correction cryptographique d'une CA** — unicité et aléa des numéros de
  série, encodage correct des extensions, absence de collision de sujet.
  Traité par : numéros de série de 128 bits sur `crypto/rand` dont l'unicité
  est portée par la clé primaire du registre ; relecture systématique du DER
  produit avant délivrance ; et **vérification croisée avec `openssl`**
  (`verify`, `crl -verify`, `ts -verify`, `ocsp`) dans `scripts/demo.sh` et en
  CI — un moteur maison ne se valide pas avec ses seuls outils. Le risque
  résiduel n'est pas nul : il justifie l'audit externe ci-dessous.
- **Aucun antécédent d'audit externe** pour ce code précis — inchangé, et
  déjà vrai pour la TSA elle-même. La matrice de conformité est conçue comme
  le point d'entrée d'un tel audit.

## Ce qui reste ouvert

Les écarts subsistants sont ceux que le remplacement du moteur ne pouvait pas
lever, et qui figurent comme tels dans la matrice :

- **SoftHSM2** en lieu d'un HSM certifié (le code applicatif est déjà
  compatible : seul `OPENEIDAS_PKCS11_MODULE` change) ;
- **cérémonie de clé** sans double contrôle ni témoin indépendant ;
- **approbation RA automatisée** sous un compte technique en démonstration et
  en CI — le point d'approbation est réellement actif, mais la décision n'est
  pas encore prise par un opérateur humain nominatif ;
- **CP/CPS** non publiés, OID de politique encore de test ;
- **audit par un organisme accrédité** non engagé ;
- **continuité** : instance unique, sauvegarde et restauration non encore
  testées de bout en bout.

Procédures et cibles correspondantes : [`docs/CA.md`](docs/CA.md).

## Suite

1. Sauvegarde et restauration du registre et des tokens, testées.
2. Cérémonie de clé rejouée sur HSM certifié, sous double contrôle.
3. Substitution d'un opérateur RA nominatif à l'approbation automatisée.
4. Rédaction du CP/CPS et obtention d'un arc OID propre.
5. Audit externe, en s'appuyant sur `docs/CONFORMITE-ETSI.md`.
