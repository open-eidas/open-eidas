# Indépendance vis-à-vis d'OpenXPKI

Document d'arbitrage : décision de principe et plan envisagé pour
remplacer OpenXPKI par un moteur de CA/RA maison en Go. **Non engagé à
la date de rédaction** — la conception détaillée et l'implémentation
sont volontairement reportées à une session dédiée.

## Contexte

Le MVP utilise OpenXPKI Community comme moteur de CA (hiérarchie de test,
profils de certificat, workflow d'enrôlement) derrière la TSA et le
répondeur OCSP, tous deux entièrement custom (Go). Au fil de deux
sous-tâches de cette session — l'ajout du répondeur OCSP et l'activation
réelle de l'approbation RA — plusieurs comportements internes non
documentés d'OpenXPKI ont dû être découverts par rétro-ingénierie :

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
l'approbation RA). Voir aussi `docs/ARCHITECTURE.md` §8.

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

## Périmètre à reprendre

Ce qu'OpenXPKI rend concrètement à ce projet, et son équivalent envisagé :

| Fonction | OpenXPKI aujourd'hui | Équivalent maison envisagé |
|---|---|---|
| Émission depuis une CSR | Profil YAML + moteur NICE (Perl) | `x509.CreateCertificate` (stdlib), profil = struct Go testable unitairement |
| Génération de CRL | `crl_issuance` workflow + connecteur `cdp` | `x509.CreateRevocationList` (stdlib) — symétrique du code déjà écrit côté `internal/ocspresponder` pour le *parsing* |
| Stockage de la clé de CA | Datavault chiffré en base (MariaDB) | PKCS#11 (`internal/hsm`), même paradigme que TSU et OCSP — un seul mécanisme de gestion de clé au lieu de deux |
| Enrôlement + approbation RA | Workflow générique `certificate_enroll` (état PENDING, `approval_points`, éligibilité) | Petite machine à états dédiée (HMAC → PENDING → approuvé → émis), un seul workflow au lieu d'un moteur générique |
| Publication du certificat de CA | Connecteur `cacert-der`/`cacert-pem` (déclenché par le workflow normal, contourné par la hiérarchie jetable — voir `docs/ARCHITECTURE.md`) | Fichier statique servi par un petit handler HTTP |
| Répondeur OCSP | — | **Déjà fait** (`cmd/ocsp-responder`), aucune dépendance OpenXPKI ici |
| Interface opérateur RA | WebUI OpenXPKI | CLI d'abord (cohérent avec `tsa-server enroll`/`verify-audit`), UI web si besoin plus tard |

Conséquence pour le packaging : le Pod OpenXPKI à 4 conteneurs
(`server`/`client`/`web`/`bootstrap`) et ses contournements de permissions
Kubernetes (`fsGroup`, vhost Apache recopié, groupe forcé des workers
Apache — voir `deploy/helm/open-eidas/README.md`) disparaîtraient
entièrement du chart Helm, de même que la dépendance Perl/MariaDB-comme-
base-de-CA.

## Risques du chantier

- **Correction cryptographique d'une CA** : unicité et aléa des numéros de
  série, encodage correct des extensions, absence de collision de sujet —
  des exigences que des années d'usage ont déjà éprouvées côté OpenXPKI
  et qu'il faudra revalider soi-même avec la même rigueur (tests,
  vérification croisée avec des outils tiers comme `openssl`/`certutil`,
  a minima).
- **Aucun antécédent d'audit externe** pour ce code précis — déjà vrai
  pour la TSA elle-même (évaluée selon ETSI EN 319 421), donc pas une
  nouvelle catégorie de charge pour le projet, mais un axe d'attention
  supplémentaire pour l'auditeur.

## Effort estimé (ordre de grandeur)

- `internal/ca` (émission, profil, numérotation de série) : 1 à 2 semaines
- Machine à états d'enrôlement/approbation + endpoint RPC/HTTP : ~1 semaine
- Service de génération de CRL : 2 à 3 jours (mirroir du travail OCSP)
- Interface CLI d'approbation RA : 2 à 3 jours
- Outillage de cérémonie de clé racine/émettrice + procédure documentée : 3 à 5 jours
- Migration du docker-compose et du chart Helm (suppression des 4 conteneurs OpenXPKI) : quelques jours
- Vérification de bout en bout avec la même rigueur que le reste de ce dépôt (docker-compose + kind, CI)

Total approximatif : 4 à 6 semaines de travail concentré — du même ordre
que le temps déjà investi cette session à percer les internals
d'OpenXPKI, mais qui élimine la classe de problème plutôt que de la
documenter comme écart permanent.

## Prochaine étape

Session dédiée pour :
1. Concevoir en détail `internal/ca` (structures, API, choix de
   persistance pour l'état du workflow d'enrôlement).
2. Valider ce plan avant tout code (mode Plan).
3. Implémenter, tester (docker-compose + kind, comme pour la TSA et
   l'OCSP), migrer le packaging, documenter.
