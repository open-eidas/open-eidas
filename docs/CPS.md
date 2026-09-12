# Politique et Déclaration des Pratiques — Open eIDAS

> **Statut : brouillon de travail, non adopté.** Ce document contient des
> emplacements réservés marqués `[À COMPLÉTER — ...]` partout où le contenu
> relève d'une décision organisationnelle ou juridique de l'association, et
> non d'un fait technique. Rien de ce qui suit ne doit être cité comme
> politique en vigueur, ni gravé dans un OID de certificat, tant que :
>
> 1. chaque emplacement réservé n'a pas été rempli par une décision actée du
>    conseil d'administration de l'association ;
> 2. le document qui en résulte n'a pas été formellement adopté et versionné ;
> 3. l'OID de politique correspondant n'a pas été obtenu et substitué à l'OID
>    de test actuel (`1.3.6.1.4.1.99999.1.1.1`).
>
> Le contenu technique (profils, algorithmes, durées de vie, journalisation)
> est en revanche tiré du code réellement en service — `internal/ca`,
> `internal/tsa`, `internal/conformance` — et non inventé. Voir
> [ARCHITECTURE.md](ARCHITECTURE.md) pour le fonctionnement, [CA.md](CA.md)
> pour les procédures d'exploitation, et
> [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md) pour l'état exigence par exigence.
>
> Structure : RFC 3647 (neuf sections), telle que reprise par ETSI
> EN 319 411-1 Annexe A pour la CA et adaptée aux exigences propres à la TSA
> d'ETSI EN 319 421 dans la Partie B.

| Champ | Valeur |
|---|---|
| Titre | `[À COMPLÉTER — nom définitif du document]` |
| Version | 0.1 (brouillon) |
| Statut | Brouillon — non adopté |
| Date | `[À COMPLÉTER]` |
| OID de ce document | `[À COMPLÉTER — sous l'arc PEN de l'association]` |
| Approuvé par | `[À COMPLÉTER — organe de gouvernance de l'association]` |

---

## Partie A — Politique de Certification et Déclaration des Pratiques (CA)

Couvre l'autorité de certification et d'enregistrement d'Open eIDAS
(`cmd/ca-server`), racine et CA émettrice, telle que documentée dans
[CA.md](CA.md).

### A.1 Introduction

#### A.1.1 Vue d'ensemble

`[À COMPLÉTER]` — présentation de l'association, de sa mission et du rôle de
cette CA dans l'écosystème eIDAS (voir README.md pour la matière existante à
reprendre).

#### A.1.2 Nom et identification du document

| | |
|---|---|
| Nom du document | `[À COMPLÉTER]` |
| OID de politique de certification | `[À COMPLÉTER — un OID par type de certificat émis (TSU, répondeur OCSP), sous l'arc PEN de l'association]` |
| Version | 0.1 (brouillon) |

#### A.1.3 Acteurs de la PKI

| Rôle | Qui | Référence technique |
|---|---|---|
| Autorité de certification racine | `[À COMPLÉTER — nom légal de l'association]` | `internal/ca.RunCeremony`, autorité `root` |
| Autorité de certification émettrice | `[À COMPLÉTER]` | autorité `issuing` |
| Autorité d'enregistrement (RA) | `[À COMPLÉTER — désignation du ou des opérateurs RA nominatifs]` | `internal/raflow`, `ca-server ra` |
| Porteurs de certificat | Les services d'Open eIDAS opérés par l'association (unité d'horodatage, répondeur OCSP) — pas de tiers externes à ce jour | `internal/ca/profile.go` |
| Parties utilisatrices | Quiconque vérifie un jeton d'horodatage ou interroge le statut de révocation | — |

#### A.1.4 Usage des certificats

Deux profils, aucun autre :

| Profil | Usage | Interdictions explicites |
|---|---|---|
| `tsa_signer` | Signature de jetons d'horodatage RFC 3161 exclusivement | `extendedKeyUsage` limité à `id-kp-timeStamping`, marqué critique — aucun autre usage n'est techniquement possible avec ce certificat |
| `ocsp_responder` | Signature de réponses OCSP RFC 6960 exclusivement | `extendedKeyUsage` limité à `id-kp-OCSPSigning` |

Cette CA n'émet **pas** de certificats pour des tiers externes à l'association
à la date de rédaction. `[À COMPLÉTER — si cela devait changer, cette section
doit être révisée avant toute émission hors des deux profils ci-dessus]`.

#### A.1.5 Gestion de la politique

| | |
|---|---|
| Organisation responsable | `[À COMPLÉTER]` |
| Contact | `[À COMPLÉTER — adresse e-mail dédiée, distincte du contact commercial]` |
| Procédure d'approbation des modifications | `[À COMPLÉTER]` |

### A.2 Publication et responsabilités liées au dépôt

| Ce qui est publié | Où | Mécanisme |
|---|---|---|
| Ce document (CP/CPS) | `[À COMPLÉTER — URL de publication définitive]` | — |
| Certificat de la CA émettrice | `GET /download/<CN>.cer` (DER) | `cmd/ca-server`, voir CA.md §6 |
| CRL de la CA émettrice | `GET /download/<CN>.crl` | Republiée toutes les heures, fenêtre de validité 24 h |
| Matrice de conformité ETSI | `GET /api/v1/conformance` et [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md) | Générée depuis `internal/conformance`, ne peut pas diverger du code |
| Code source complet | `[À COMPLÉTER — URL du dépôt public]` | Dépôt public par principe (voir README.md, gouvernance de transparence) |

Fréquence de publication de la CRL, délai de republication après révocation,
et conservation des CRL historiques : voir [CA.md](CA.md) §6.

### A.3 Identification et authentification

#### A.3.1 Nommage

Le sujet d'un certificat émis est composé pour partie de la demande, pour
partie imposé par le profil (voir `internal/ca/profile.go`) :

- `CN` : nom courant du service, fourni par la demande d'enrôlement ;
- `OU`, `O`, `C` : imposés par le profil, non modifiables par le demandeur.

Un demandeur ne peut donc jamais se réclamer d'une organisation qui n'est pas
la sienne.

#### A.3.2 Validation initiale de l'identité

Les porteurs de certificat sont exclusivement les services internes
d'Open eIDAS (TSA, répondeur OCSP). L'authentification de la demande repose
sur un secret HMAC-SHA256 partagé, provisionné hors bande à chaque service au
déploiement (voir `internal/raflow`, `docker-compose.yml`).

`[À COMPLÉTER — si des porteurs externes à l'association devaient un jour être
admis, cette section doit décrire une procédure de vérification d'identité
réelle, distincte du secret partagé actuel]`.

#### A.3.3 Identification pour une demande de renouvellement

Automatique : une nouvelle CSR pour le même sujet suit le même circuit
qu'une demande initiale (authentification HMAC, approbation RA). Le
certificat précédent est révoqué avec le motif `superseded` (4) une fois le
nouveau émis — voir [CA.md](CA.md) §4.

#### A.3.4 Identification pour une demande de révocation

Toute révocation exige l'identité d'un opérateur, consignée en base et au
journal d'audit (`ca-server revoke`, voir [CA.md](CA.md) §5). Aucune
révocation anonyme ou automatique par un tiers n'est possible.

### A.4 Exigences opérationnelles sur le cycle de vie du certificat

#### A.4.1 Demande de certificat

Décrit intégralement par la machine à états `internal/raflow` :
authentification HMAC → état `PENDING` → décision d'un opérateur RA → état
`APPROVED` → émission par le service détenant la clé → état `ISSUED`. Aucun
chemin du code ne permet de sauter la décision de l'opérateur.

#### A.4.2 Traitement de la demande

Voir [CA.md](CA.md) §4. Délai cible entre soumission et décision :
`[À COMPLÉTER — engagement de délai de traitement par un opérateur RA
nominatif ; la démonstration l'approuve automatiquement sous quelques
secondes, ce qui n'est pas représentatif d'un délai humain réel]`.

#### A.4.3 Émission du certificat

Automatique dès approbation, par le processus qui détient la clé de
l'autorité émettrice (`cmd/ca-server serve`). Le certificat produit est relu
depuis son DER et soumis aux règles d'`internal/conformance` avant d'être
délivré : un certificat non conforme n'est jamais enregistré ni rendu.

#### A.4.4 Acceptation du certificat

Implicite : le service demandeur récupère son certificat via l'API
d'enrôlement et l'utilise directement.

#### A.4.5 Usage de la paire de clés et du certificat

Voir A.1.4. La clé privée ne quitte jamais le module PKCS#11
(`internal/hsm`).

#### A.4.6 Renouvellement de certificat

Voir A.3.3. Déclenché automatiquement dans les 30 jours précédant
l'expiration (`OPENEIDAS_RENEW_BEFORE`).

#### A.4.7 Révocation et suspension du certificat

| | |
|---|---|
| Motifs admis | Codes RFC 5280 §5.3.1 (voir [CA.md](CA.md) §5) |
| Délai de publication après révocation | Immédiat : `ca-server revoke` republie la CRL dans le même appel |
| Fréquence de publication de la CRL | Toutes les heures, fenêtre de validité 24 h (`OPENEIDAS_CRL_REFRESH`, `OPENEIDAS_CRL_VALIDITY`) |
| Suspension | Non implémentée : un certificat est actif ou révoqué, pas d'état intermédiaire |
| Vérification du statut en ligne | OCSP (RFC 6960), `internal/ocspresponder`, refuse de répondre plutôt que de garantir un statut obsolète |

#### A.4.8 Services d'état de certificat

CRL et OCSP, tous deux couverts ci-dessus.

#### A.4.9 Fin de la relation d'abonnement

`[À COMPLÉTER — sans objet tant que les porteurs sont uniquement les services
internes de l'association]`.

#### A.4.10 Séquestre de clé et recouvrement

Non applicable : les clés privées ne sont jamais exportées du module
cryptographique, à aucun moment de leur cycle de vie.

### A.5 Contrôles de sécurité physiques, organisationnels et humains

`[À COMPLÉTER intégralement — cette section est presque entièrement
organisationnelle : localisation des systèmes, contrôle d'accès physique aux
hôtes exécutant les tokens PKCS#11, vérifications appliquées au personnel
ayant accès aux clés d'autorité ou au rôle d'opérateur RA, formation, plan de
continuité d'activité opérationnel. Le squelette technique correspondant
existe dans docs/CA.md §7-8, mais les engagements organisationnels (qui a
accès, sous quel contrôle, avec quelle vérification préalable) restent à
décider par l'association.]`

### A.6 Contrôles techniques de sécurité

Section presque entièrement factuelle — reprise directement de ce que le
code applique et vérifie automatiquement (`internal/conformance`) :

| Contrôle | Valeur appliquée | Mécanisme |
|---|---|---|
| Génération de la paire de clés | Dans le module PKCS#11, jamais exportée | `internal/hsm`, `ca-server ceremony` |
| Taille de clé — autorités | RSA ≥ 3072 bits (4096 par défaut) | `OPENEIDAS_CA_KEY_BITS`, `internal/conformance.CheckPublicKey` |
| Taille de clé — TSU / OCSP | RSA ≥ 3072 bits | `internal/conformance.CheckPublicKey` |
| Algorithmes de signature admis | SHA-256/384/512 avec RSA ou ECDSA ; SHA-1 et MD5 explicitement refusés | `internal/conformance.CheckSignatureAlgorithm` |
| Protection de l'activation de la clé | PIN du token PKCS#11 | `internal/hsm` |
| Durée de vie — racine | ~20 ans | `OPENEIDAS_ROOT_VALIDITY` |
| Durée de vie — CA émettrice | ~10 ans, jamais au-delà de l'expiration de la racine | `OPENEIDAS_ISSUING_VALIDITY` |
| Durée de vie — TSU | 1 an | `internal/ca/profile.go` |
| Durée de vie — répondeur OCSP | 3 mois | `internal/ca/profile.go` |
| Module cryptographique | SoftHSM2 (démonstration) | `[À COMPLÉTER — HSM certifié FIPS 140-2 niv. 3 / CC EAL4+ retenu pour la production]` |

### A.7 Profils de certificat, CRL et OCSP

Renvoi direct au code, qui en est la source unique :

- profils de certificat : `internal/ca/profile.go`, vérifiés par
  `internal/conformance.CheckTSUCertificate` et
  `CheckOCSPResponderCertificate` ;
- profil de CRL : `internal/ca.PublishCRL`, vérifié par
  `internal/conformance.CheckCRL` ;
- profil de réponse OCSP : `internal/ocspresponder`.

### A.8 Audit de conformité et autres évaluations

| | |
|---|---|
| Fréquence | `[À COMPLÉTER]` |
| Identité de l'auditeur | `[À COMPLÉTER — organisme accrédité, ex. LSTI, Apave]` |
| Portée | L'intégralité du dépôt, point d'entrée : [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md) |
| Actions en cas de non-conformité constatée | `[À COMPLÉTER]` |

### A.9 Autres questions commerciales et juridiques

`[À COMPLÉTER intégralement — tarification (voir README.md : gratuit ou à
prix coûtant par principe de gouvernance), confidentialité, propriété
intellectuelle (code sous licence `[À COMPLÉTER]`), limitation de
responsabilité, durée et résiliation de cette politique, résolution des
litiges, droit applicable, juridiction compétente.]`

---

## Partie B — Politique de l'Autorité d'Horodatage (TSA)

Complète la Partie A pour les exigences propres à ETSI EN 319 421, non
couvertes par une CP/CPS générique de CA.

### B.1 Politique d'horodatage

| | |
|---|---|
| OID de politique d'horodatage | `1.3.6.1.4.1.99999.1.1.1` — **OID de test**, `[À COMPLÉTER — OID définitif sous l'arc PEN de l'association avant toute émission destinée à être invoquée devant un tiers]` |
| Exactitude annoncée (`accuracy`) | 1 seconde (`OPENEIDAS_ACCURACY`) |
| Algorithmes d'empreinte acceptés | SHA-256, SHA-384, SHA-512 — SHA-1 refusé (`badAlg`) |
| Ordonnancement (`ordering`) | Non garanti entre jetons |

### B.2 Traçabilité de l'heure (ETSI EN 319 421 §7.6)

| | |
|---|---|
| Sources actuelles | NTP, deux laboratoires de métrologie (UTC(OP), UTC(PTB)) |
| Quorum minimal | 2 sources concordantes |
| Seuil de dérive tolérée | 500 ms |
| Comportement en cas de perte de traçabilité | Refus de signer (`failureInfo: timeNotAvailable`), politique `enforce` |
| Cible de qualification | `[À COMPLÉTER — réception de temps redondante et indépendante du réseau (ex. réception GNSS avec source de secours), calibration documentée par un laboratoire accrédité]` |

### B.3 Journal d'audit et conservation

| | |
|---|---|
| Chaînage | SHA-256, vérifié intégralement à l'ouverture (`internal/audit`) |
| Scellement | Périodique (`OPENEIDAS_AUDIT_SEAL_INTERVAL`), horodaté par la TSU elle-même |
| Contreseing tiers | TSA publiques indépendantes (`OPENEIDAS_CROSS_TSA_URLS`) |
| Réplication | Hors site à chaque scellement (WebDAV) |
| Durée de conservation **technique actuelle** | 1 an minimum imposé au démarrage (`OPENEIDAS_AUDIT_RETENTION`) |
| Durée de conservation **engagée** | `[À COMPLÉTER — durée contractuelle publiée, qui peut légitimement excéder le minimum technique ci-dessus ; vérifier les obligations eIDAS applicables aux journaux d'une TSA qualifiée]` |

### B.4 Cessation de service de la TSA

Renvoi à [CA.md](CA.md) §8 pour la procédure technique. Engagement formel :
`[À COMPLÉTER — préavis minimal aux utilisateurs, autorité destinataire des
journaux et du registre en cas de cessation]`.

---

## Journal des versions

| Version | Date | Modification |
|---|---|---|
| 0.1 | `[À COMPLÉTER]` | Brouillon initial, structure RFC 3647 / EN 319 411-1 Annexe A, contenu technique aligné sur le code à cette date |
