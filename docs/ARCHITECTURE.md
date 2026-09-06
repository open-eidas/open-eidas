# Architecture technique — MVP

## 1. Objectif du prototype

Démontrer qu'une autorité d'horodatage (TSA) conforme à la RFC 3161, adossée à
une PKI et à un module cryptographique, tient dans une pile reproductible que
l'on démarre en une commande. Le prototype vise la crédibilité technique
auprès de financeurs, pas encore la qualification eIDAS : les écarts au
référentiel sont listés en section 6.

## 2. Vue d'ensemble

```
                  ┌──────────────────────────────────────────────┐
   client         │                  Open eIDAS                  │
   (curl,         │                                              │
    openssl ts,   │   ┌───────────────┐        ┌──────────────┐  │
    Sign*)        │   │  tsa-server   │  PKCS#11│   SoftHSM2   │  │
      │ RFC 3161  │   │     (Go)      ├────────▶│  (→ HSM FIPS │  │
      ├──────────▶│   │               │        │   en prod)   │  │
      │  :8318    │   └───────┬───────┘        └──────────────┘  │
      │           │           │ RPC /rpc/tsa/RequestCertificate  │
      │           │           ▼                                  │
      │           │   ┌───────────────┐        ┌──────────────┐  │
      │           │   │   OpenXPKI    │────────│   MariaDB    │  │
      │           │   │ (root + issu- │        │              │  │
      │           │   │  ing CA)      │        └──────────────┘  │
      │           │   └───────────────┘                          │
                  └──────────────────────────────────────────────┘
```

Quatre responsabilités séparées :

| Composant | Rôle | Image / langage |
|---|---|---|
| `tsa-server` | Service RFC 3161, signature des jetons | Go 1.25, binaire unique |
| SoftHSM2 | Conservation de la clé privée de la TSU | `softhsm2` (Debian), PKCS#11 |
| OpenXPKI | Hiérarchie de CA, émission et révocation du certificat TSU | `whiterabbitsecurity/openxpki3:3.34` |
| MariaDB | Persistance des workflows et du registre de certificats OpenXPKI | `mariadb:11.4` |

## 3. Choix techniques et justification

**Go pour le service d'horodatage.** Binaire unique sans runtime, surface
d'attaque réduite, bibliothèque standard solide en ASN.1/X.509, et bindings
PKCS#11 matures. Un service d'horodatage est un composant synchrone, court, à
forte contrainte de disponibilité : c'est le profil pour lequel Go est le plus
prévisible en latence et en empreinte mémoire.

**PKCS#11 dès le prototype.** La clé privée de la TSU ne quitte jamais le
module cryptographique : `tsa-server` ne manipule qu'un `crypto.Signer` dont
chaque signature est déléguée au token. SoftHSM2 parle exactement le même
protocole qu'un HSM certifié FIPS 140-2 niveau 3 ou Critères Communs. Le
passage en production se fait en changeant `OPENEIDAS_PKCS11_MODULE` et le
label du token — aucune ligne de code applicatif à modifier.

**OpenXPKI comme autorité de certification.** Le certificat de la TSU doit
être émis par une CA distincte, avec un profil contraint et un cycle de vie
auditable (émission, révocation, publication de CRL). OpenXPKI apporte ces
workflows sans développement spécifique, et son endpoint RPC permet un
enrôlement entièrement automatisé.

**Séparation enrôlement / service.** Le binaire expose deux sous-commandes :
`enroll` obtient le certificat, `serve` signe les jetons. Le service refuse de
démarrer si le certificat ne correspond pas à la clé du HSM ou ne porte pas
l'usage étendu `id-kp-timeStamping`. Cette séparation permet, en production, de
confier l'enrôlement à un opérateur habilité et de ne donner au service qu'un
accès en lecture au certificat.

## 4. Séquence de démarrage

1. `scripts/bootstrap.sh` clone la configuration OpenXPKI amont, y applique
   l'overlay Open eIDAS (profil `tsa_signer`, endpoint RPC `tsa`), génère la
   clé du coffre de données et la clé d'administration CLI.
2. La pile PKI démarre ; `sampleconfig.sh` crée une hiérarchie à deux niveaux
   (racine hors ligne + CA émettrice).
3. Le conteneur TSA initialise son token SoftHSM au premier lancement.
4. `tsa-server enroll` génère une bi-clé RSA-3072 **dans le token**, produit une
   CSR signée par cette clé et la soumet à `POST /rpc/tsa/RequestCertificate`.
   OpenXPKI applique le profil `tsa_signer` et retourne le certificat et sa
   chaîne, écrits sur le volume d'état.
5. `tsa-server serve` charge le certificat, vérifie sa cohérence avec la clé du
   token, puis écoute sur le port 8318.

L'enrôlement est idempotent : au redémarrage, un certificat encore valide et
apparié à la clé du HSM est conservé. Le renouvellement se déclenche
automatiquement dans les 30 jours précédant l'expiration
(`OPENEIDAS_RENEW_BEFORE`).

## 5. Structure du jeton produit

Le jeton est une `TimeStampResp` DER contenant un CMS `SignedData` :

- `TSTInfo` porte la politique d'horodatage, le `messageImprint` soumis, un
  numéro de série unique, `genTime` en UTC et la précision annoncée ;
- l'attribut signé `signingCertificateV2` (RFC 5035) lie le jeton au
  certificat exact de la TSU, comme l'exige ETSI EN 319 422 ;
- le nonce du client est repris tel quel lorsqu'il est présent ;
- le certificat de la TSU et sa chaîne sont inclus si le client les demande
  (`certReq`).

Empreintes acceptées : SHA-256, SHA-384, SHA-512. SHA-1 est refusé avec
`badAlg`, conformément à ETSI TS 119 312.

## 6. Écarts assumés du prototype vis-à-vis d'une TSA qualifiée

Ces points sont volontairement hors périmètre du MVP et constituent la
feuille de route de qualification :

| Exigence | État du prototype | Cible |
|---|---|---|
| Module cryptographique | SoftHSM2 (logiciel) | HSM certifié FIPS 140-2 niv. 3 / CC EAL4+ |
| Source de temps | Horloge du conteneur | Deux sources UTC(k) traçables, surveillance de dérive, calibration documentée |
| Enrôlement de la TSU | Anonyme et auto-approuvé | Authentification du demandeur et approbation par un opérateur RA |
| Journalisation | Journaux applicatifs | Journal d'audit inaltérable et horodaté, conservé selon la politique |
| Politique d'horodatage | OID de test `1.3.6.1.4.1.99999.1.1.1` | OID sous l'arc PEN de l'association, TSA Policy et Practice Statement publiés |
| Extensions du certificat TSU | Points CRL/OCSP et OID de politique hérités de la configuration de démonstration amont (`pki.example.com`) | Points de distribution réellement publiés et politique de certification propre |
| Continuité | Instance unique | Redondance active/active, plan de cessation d'activité, séquestre des clés |
| Audit | Aucun | Évaluation par un organisme accrédité (LSTI, Apave), inscription à la liste de confiance |

Le prototype refuse de démarrer sur les écarts qui rendraient les jetons
invalides (clé et certificat désaccordés, usage étendu absent, certificat
expiré) et journalise un avertissement sur les écarts de profil non bloquants.

## 7. Trajectoire vers la production

1. **Temps.** Ajouter un service de surveillance NTP/PTP et refuser de signer
   si la dérive dépasse la précision annoncée dans le `TSTInfo`.
2. **HSM.** Remplacer SoftHSM par un module certifié ; le code applicatif est
   déjà compatible.
3. **Politique.** Publier la TSA Policy et la Practice Statement, obtenir un
   arc OID propre.
4. **Exploitation.** Journal d'audit chaîné, supervision, deux instances
   derrière un répartiteur, procédure de révocation testée.
5. **Qualification.** Constituer le dossier ANSSI et engager l'audit d'un
   organisme accrédité.
