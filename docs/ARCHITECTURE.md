# Architecture technique — MVP

## 1. Objectif du prototype

Démontrer qu'une autorité d'horodatage (TSA) conforme à la RFC 3161, adossée à
une PKI et à un module cryptographique, tient dans une pile reproductible que
l'on démarre en une commande. Le prototype vise la crédibilité technique
auprès de financeurs, pas encore la qualification eIDAS : les écarts au
référentiel sont listés en section 8.

## 2. Vue d'ensemble

```
                 ┌───────────────────────────────────────────────┐
  client         │                  Open eIDAS                   │
  (curl,         │                                               │
   openssl ts,   │   ┌───────────────┐  PKCS#11 ┌─────────────┐  │
   Sign*)        │   │  tsa-server   │─────────▶│  SoftHSM2   │  │
     │ RFC 3161  │   │     (Go)      │          │ (→ HSM FIPS │  │
     ├──────────▶│   │               │          │   en prod)  │  │
     │  :8318    │   └──┬─────────┬──┘          └─────────────┘  │
     │           │      │         │ RPC /rpc/tsa/RequestCertificate
     │           │      │         ▼                              │
     │           │      │  ┌───────────────┐   ┌─────────────┐   │
     │           │      │  │   OpenXPKI    │───│   MariaDB   │   │
     │           │      │  │ (root + issu- │   │             │   │
     │           │      │  │  ing CA)      │   └─────────────┘   │
     │           │      │  └───────────────┘                     │
                 └──────┼────────────────────────────────────────┘
                        │ NTP
                        ▼
              UTC(OP) · UTC(PTB)   sources de temps de référence
```

Cinq responsabilités séparées :

| Composant | Rôle | Image / langage |
|---|---|---|
| `tsa-server` | Service RFC 3161, signature des jetons | Go 1.25, binaire unique |
| `ocsp-responder` | Répondeur OCSP (RFC 6960) pour la CA émettrice ; OpenXPKI Community n'en embarque aucun, voir §8 | Go 1.25, binaire unique |
| SoftHSM2 | Conservation des clés privées de la TSU et du répondeur OCSP (une par service) | `softhsm2` (Debian), PKCS#11 |
| OpenXPKI | Hiérarchie de CA, émission et révocation des certificats TSU et OCSP | `whiterabbitsecurity/openxpki3:3.34` |
| MariaDB | Persistance des workflows et du registre de certificats OpenXPKI | `mariadb:11.4` |

`ocsp-responder` s'enrôle lui-même auprès d'OpenXPKI exactement comme
`tsa-server` (RPC `/rpc/ocsp/RequestCertificate`, même secret HMAC partagé),
puis répond aux requêtes OCSP en consultant un instantané de la CRL déjà
publiée par OpenXPKI (`/download`), rafraîchi périodiquement — plutôt qu'un
accès direct, plus complexe, à la base OpenXPKI. Voir
`internal/ocspresponder`.

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

## 6. Traçabilité de l'heure

Un jeton d'horodatage ne vaut que ce que vaut l'horloge qui l'a produit. ETSI
EN 319 421 impose que l'heure soit traçable jusqu'à UTC et que la TSA **cesse
d'émettre** dès qu'elle ne peut plus garantir la précision qu'elle annonce.

Le service interroge donc périodiquement plusieurs serveurs NTP de
laboratoires de métrologie — par défaut l'Observatoire de Paris (UTC(OP)) et
la PTB (UTC(PTB)) — et recoupe leurs réponses. L'heure est jugée traçable
lorsque les quatre conditions suivantes sont réunies :

1. le quorum de sources est joignable (`OPENEIDAS_TIME_MIN_SOURCES`, 2 par défaut) ;
2. la dérive mesurée reste sous le seuil (`OPENEIDAS_TIME_MAX_OFFSET`, 500 ms) ;
3. les sources s'accordent entre elles à l'intérieur du même seuil ;
4. la dernière mesure n'est pas périmée (`OPENEIDAS_TIME_MAX_AGE`, 1 h).

Dès qu'une condition tombe, la politique `enforce` fait refuser chaque
demande avec le `failureInfo` **`timeNotAvailable`** — une réponse RFC 3161
parfaitement valide — et `/healthz` bascule en `503`. Le service ne produit
jamais de jeton dont il ne peut pas défendre la date, ce qui est précisément
ce qu'un auditeur vient vérifier.

L'état complet des mesures (écart par source, dispersion, strate, temps
d'aller-retour, horodatage de la dernière synchronisation) est publié sur
`/healthz` et `/api/v1/policy`, et journalisé à chaque cycle.

Deux politiques dégradées existent pour le développement : `monitor`
journalise l'écart sans bloquer l'émission, `disabled` désactive la
surveillance. Aucune des deux n'est admissible en production.

## 7. Journal d'audit inaltérable

Un auditeur ne vérifie pas seulement qu'un jeton est correct : il vérifie que
le service *était sous contrôle* au moment où il l'a émis, et que la trace de
cet instant n'a pas été retouchée depuis.

Le service tient donc un journal en JSON Lines dont chaque enregistrement
porte l'empreinte SHA-256 du précédent. Modifier une ligne, en supprimer une
ou en intercaler une rompt la chaîne, et la rupture est détectable par
quiconque relit le fichier — y compris sans accès au service :

```bash
docker compose exec tsa tsa-server verify-audit
```

Y sont consignés l'ouverture du journal, chaque jeton émis (numéro de série,
`genTime`, politique, empreinte soumise, présence d'un nonce), chaque refus
avec son `failureInfo`, chaque mesure de temps avec l'écart par source, et
chaque enrôlement de certificat. Le jeton émis est **relu avant d'être
consigné** : le journal enregistre ce que contient réellement le jeton, pas ce
que le service croit y avoir mis.

Deux propriétés rendent le dispositif exploitable :

- **Une écriture ratée annule l'émission.** Si le journal ne peut pas être
  écrit, la requête échoue. Un jeton non tracé ne sort jamais du service.
- **Un journal altéré empêche le démarrage.** La chaîne est vérifiée
  intégralement à l'ouverture.

La tête de chaîne est **scellée périodiquement**
(`OPENEIDAS_AUDIT_SEAL_INTERVAL`, une heure par défaut) : la TSU horodate sa
propre empreinte de tête et le jeton obtenu est inscrit au journal, ce qui
date son contenu.

### Contreseing par des TSA tierces

Le scellement ci-dessus reste auto-référentiel : il ne prouve l'antériorité à
un tiers que si l'on fait déjà confiance à la TSU elle-même. Le service
soumet donc la même tête de chaîne à une ou plusieurs **TSA publiques
indépendantes** (`OPENEIDAS_CROSS_TSA_URLS`, par défaut FreeTSA.org et
DigiCert), via le protocole RFC 3161 standard, et consigne chaque attestation
obtenue (`log.cross_sealed`) : émetteur, date, numéro de série et jeton
complet en base64.

Un auditeur n'a besoin de rien d'Open eIDAS pour vérifier une attestation : le
certificat de la TSA tierce est public, et les outils standards suffisent —
```bash
openssl ts -query -digest <tête-de-chaîne> -sha256 -no_nonce -out head.tsq
openssl ts -verify -in <jeton-décodé> -queryfile head.tsq \
    -CAfile <CA-de-la-TSA-tierce> -untrusted <certificat-de-la-TSA-tierce>
```
— une réponse `Verification: OK` établit que la tête de chaîne, donc tout le
journal qu'elle couvre par construction, existait à la date attestée par une
autorité qui n'a aucun lien avec Open eIDAS.

L'indisponibilité d'une TSA tierce est journalisée mais non bloquante : le
scellement propre au service continue, et les autres TSA configurées
prennent le relais.

### Réplication hors site

Un journal chaîné et contresigné ne protège que contre l'altération — pas
contre la perte de l'instance elle-même (panne disque, compromission,
suppression accidentelle). À chaque scellement, le service dépose donc une
copie complète et datée du journal (`audit-<horodatage>-seq<n>.log`) sur un
serveur **WebDAV** distant (`OPENEIDAS_AUDIT_REPLICA_URL`) : Nextcloud, un
stockage d'objets exposé en WebDAV, ou tout hébergeur souverain qui l'offre —
aucun fournisseur particulier n'est imposé.

Chaque copie est un journal complet et vérifiable indépendamment :
```bash
tsa-server verify-audit audit-20260906T145600Z-seq000030.log
```
retrouve exactement la même chaîne de hachage que sur l'instance d'origine,
jusqu'au numéro de séquence capturé. L'échec de la réplication est
journalisé mais non bloquant, comme pour le contreseing tiers.

## 8. Écarts assumés du prototype vis-à-vis d'une TSA qualifiée

Ces points sont volontairement hors périmètre du MVP et constituent la
feuille de route de qualification :

| Exigence | État du prototype | Cible |
|---|---|---|
| Module cryptographique | SoftHSM2 (logiciel) | HSM certifié FIPS 140-2 niv. 3 / CC EAL4+ |
| Source de temps | Surveillance NTP de deux sources UTC(k) avec suspension automatique de l'émission | Réception redondante et indépendante, calibration documentée, journal des mesures conservé et audité |
| Enrôlement de la TSU | Authentifié par secret HMAC partagé, auto-approuvé | Approbation par un opérateur RA en plus de l'authentification |
| Journalisation | Journal chaîné par hachage, contresigné par des TSA tierces publiques et répliqué hors site à chaque scellement | Politique de conservation formalisée, réplication multi-région |
| Politique d'horodatage | OID de test `1.3.6.1.4.1.99999.1.1.1` | OID sous l'arc PEN de l'association, TSA Policy et Practice Statement publiés |
| Extensions du certificat TSU | Point de distribution de CRL réellement publié et vérifié (`/download`, servi par OpenXPKI) ; répondeur OCSP fonctionnel (`cmd/ocsp-responder`, OpenXPKI Community n'en embarque aucun) ; `ca_issuers` (AIA) toujours supprimé, faute de publication du certificat de CA dans ce bootstrap de démonstration | Publication du certificat de CA, OID de politique de certification propre |
| Continuité | Instance unique | Redondance active/active, plan de cessation d'activité, séquestre des clés |
| Audit | Aucun | Évaluation par un organisme accrédité (LSTI, Apave), inscription à la liste de confiance |

Le prototype refuse de démarrer sur les écarts qui rendraient les jetons
invalides (clé et certificat désaccordés, usage étendu absent, certificat
expiré) et journalise un avertissement sur les écarts de profil non bloquants.

## 9. Trajectoire vers la production

1. **Temps.** Passer d'une synchronisation réseau à une réception redondante
   et indépendante, conserver le journal des mesures et faire calibrer la
   chaîne de temps.
2. **HSM.** Remplacer SoftHSM par un module certifié ; le code applicatif est
   déjà compatible.
3. **Politique.** Publier la TSA Policy et la Practice Statement, obtenir un
   arc OID propre.
4. **Exploitation.** Supervision, deux instances derrière un répartiteur,
   procédure de révocation testée.
5. **Qualification.** Constituer le dossier ANSSI et engager l'audit d'un
   organisme accrédité.
