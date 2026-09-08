# Matrice de conformité ETSI

<!-- Document généré par `ca-server conformance --markdown` depuis
     internal/conformance/matrix.go. Ne pas modifier à la main : toute
     correction se fait dans le code, pour que la matrice publiée reste
     celle que le système applique réellement. -->

**28 exigences** — 20 couvertes, 6 écarts documentés, 2 hors périmètre logiciel.

Trois statuts seulement, pour qu'aucune zone grise ne puisse s'y loger :

- **couvert** — l'exigence est appliquée par du code de ce dépôt et vérifiée par un test nommé ci-dessous ;
- **écart documenté** — l'exigence n'est pas satisfaite en l'état ; la mesure compensatoire en place et la cible sont indiquées ;
- **hors périmètre logiciel** — exigence organisationnelle, qu'aucun code ne peut établir seul.

Aucune ligne ne peut être « partiellement conforme » : `ca-server conformance`
échoue si une exigence déclarée couverte ne nomme pas son mécanisme et son
test, ou si un écart ne nomme pas sa cible.

## ETSI EN 319 401

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §7.4 | Gestion des clés du prestataire dans un module cryptographique | écart documenté | Toutes les clés (racine, émettrice, TSU, répondeur OCSP) vivent dans un token PKCS#11 et n'en sortent jamais : internal/hsm. SoftHSM2 parle le même protocole qu'un module certifié. | **Cible :** Remplacer SoftHSM2 par un HSM certifié FIPS 140-2 niv. 3 ou CC EAL4+ ; seule la variable OPENEIDAS_PKCS11_MODULE change. |
| §7.10 | Journalisation des événements et durée de conservation | couvert | Journal JSON Lines chaîné par SHA-256, scellé périodiquement, contresigné par des TSA tierces et répliqué hors site : internal/audit, internal/crosstsa, internal/replicate. Durée de conservation contrôlée par CheckAuditRetention. | internal/audit/audit_test.go, internal/conformance/crl_test.go (TestCheckAuditRetention) |
| §7.9 | Intégrité démontrable des enregistrements d'audit | couvert | Chaînage par hachage vérifié intégralement à l'ouverture ; une écriture ratée annule l'opération, un journal altéré empêche le démarrage. Le service et les commandes d'exploitation partagent une seule chaîne, sous verrou de fichier : internal/audit + sous-commandes `verify-audit`. | internal/audit/audit_test.go (TestDeuxEcrivainsPartagentLaMemeChaine) |
| §7.11 | Continuité d'activité et reprise après sinistre | écart documenté | Réplication hors site du journal à chaque scellement (internal/replicate) ; état de la CA en base PostgreSQL sauvegardable. | **Cible :** Redondance active/active des services, sauvegarde et restauration testées, plan de continuité formalisé — voir docs/CA.md. |
| §7.12 | Plan de cessation d'activité | hors périmètre logiciel | Procédure décrite dans docs/CA.md (révocation en masse, publication d'une dernière CRL longue, remise des journaux). | **Cible :** Engagement juridique de l'association, dépôt auprès de l'organe de contrôle, séquestre des journaux. |
| §6.1 | Politique de service et déclaration des pratiques publiées | écart documenté | docs/ARCHITECTURE.md et docs/CA.md décrivent les pratiques réellement mises en œuvre. | **Cible :** TSA Policy et Practice Statement formels publiés, sous un OID de politique de l'arc PEN de l'association (l'OID actuel 1.3.6.1.4.1.99999.1.1.1 est un OID de test). |

## ETSI EN 319 403-1

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §7 | Évaluation par un organisme d'évaluation de la conformité accrédité | hors périmètre logiciel | Le dépôt est intégralement public et la présente matrice fournit le point d'entrée d'un audit. | **Cible :** Audit par un organisme accrédité (LSTI, Apave), puis inscription à la liste de confiance nationale. |

## ETSI EN 319 411-1

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §6.6.1 | Profil du certificat d'autorité de certification | couvert | Cérémonie de clé produisant une racine et une CA émettrice au profil contrôlé (CA:TRUE critique, keyCertSign+cRLSign, SKI/AKI) : internal/ca.Ceremony, vérifié par CheckCACertificate. | internal/conformance/certificate_test.go, internal/ca/ca_test.go |
| §6.2.1 | Enregistrement et responsabilité de la décision d'émission | écart documenté | Aucune transition vers APPROVED n'existe sans identité d'opérateur : internal/raflow. L'identité est consignée en base et au journal d'audit. | **Cible :** Remplacer l'opérateur technique `ci-bootstrap` de la démonstration par un opérateur RA humain nominatif authentifié. |
| §6.3.1 | Authentification de la demande de certificat | couvert | HMAC-SHA256 sur la CSR DER, comparé en temps constant, et vérification de l'auto-signature de la CSR (preuve de possession) : internal/raflow, internal/ca. | internal/raflow/raflow_test.go, internal/ca/ca_test.go (TestIssueRefuseCSRNonSignee) |
| §6.3.2 | Durée de vie du certificat plafonnée | couvert | Durées de vie fixées par profil Go et plafonnées à l'émission ; le certificat émis est relu et re-contrôlé avant d'être délivré : internal/ca. | internal/conformance/certificate_test.go (TestCheckLifetime), internal/ca/ca_test.go |
| §6.3.9 | Motif de révocation consigné | couvert | Motif RFC 5280 obligatoire à la révocation, persisté et repris dans chaque entrée de CRL : internal/castore, internal/ca. | internal/conformance/crl_test.go, internal/ca/ca_test.go (TestCRLPorteLesMotifs) |
| §6.3.10 | Publication régulière de l'état de révocation | couvert | CRL régénérée périodiquement et republiée même vide, nextUpdate borné, servie depuis le registre pour qu'une révocation décidée par une commande d'exploitation soit visible aussitôt, /healthz en 503 si la CRL est périmée : internal/ca, cmd/ca-server. | internal/conformance/crl_test.go, internal/ca/ca_test.go (TestCRLPublieeMemeVide), cmd/ca-server/server_test.go (TestCRLServieDepuisLeRegistreEtNonDuCache) |
| §6.5.1 | Cérémonie de génération des clés d'autorité | écart documenté | Cérémonie scriptée et idempotente, produisant un procès-verbal consigné au journal d'audit (empreintes de clés, horodatage, opérateur) : `ca-server ceremony`, docs/CA.md. | **Cible :** Cérémonie en double contrôle, sous témoin indépendant, sur HSM certifié, avec procès-verbal contresigné. |

## ETSI EN 319 412-1

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §4 | Structures communes du profil de certificat | couvert | Profils définis en structures Go, pas en configuration interprétée : internal/ca/profile.go. Contrôle de criticité de basicConstraints et keyUsage par CheckCommonCertificate. | internal/conformance/certificate_test.go |
| §4.1 | Numéro de série positif et imprévisible | couvert | Numéro de série de 128 bits tiré sur crypto/rand et réservé de façon atomique (contrainte d'unicité en base) : internal/ca, internal/castore. | internal/conformance/certificate_test.go, internal/ca/ca_test.go (TestSeriesUniquesEtAleatoires) |

## ETSI EN 319 421

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §7.6 | Traçabilité de l'heure jusqu'à UTC et suspension en cas de dérive | écart documenté | Surveillance NTP multi-sources (UTC(OP), UTC(PTB)) avec quorum, seuil de dérive et péremption ; la politique `enforce` fait refuser chaque demande avec failureInfo timeNotAvailable : internal/timesource. | **Cible :** Réception de temps redondante et indépendante du réseau, calibration documentée et journal des mesures audité. |
| §7.7.2 | Profil du certificat de l'unité d'horodatage | couvert | Profil tsa_signer : id-kp-timeStamping seul et critique, CA:FALSE, keyUsage restreint à la signature. Appliqué à l'émission et re-contrôlé au démarrage de la TSA : internal/ca/profile.go, internal/tsa. | internal/conformance/certificate_test.go (TestCheckTSUCertificate), internal/tsa/authority_test.go |
| §7.7.1 | Génération de la clé TSU dans le module cryptographique | couvert | La bi-clé est générée dans le token et ne manipule qu'un crypto.Signer ; le service refuse de démarrer si la clé du token ne correspond pas au certificat : internal/hsm, internal/tsa. | internal/tsa/authority_test.go |

## ETSI EN 319 422

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §5 | Profil du jeton d'horodatage | couvert | TSTInfo complet (politique, imprint, série, genTime UTC, précision), attribut signé signingCertificateV2 (RFC 5035), nonce repris ; le jeton est relu avant d'être consigné : internal/tsa. | internal/tsa/authority_test.go |
| §7 | Protocole d'horodatage RFC 3161 sur HTTP | couvert | Endpoint /tsa acceptant application/timestamp-query, refus protocolaires rendus en TimeStampResp valides : internal/httpapi, internal/tsa. | internal/tsa/authority_test.go, vérification croisée `openssl ts -verify` en CI |

## ETSI TS 119 312

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §6.2 | Longueur de clé suffisante pour la durée de vie visée | couvert | RSA ≥ 3072 bits ou courbe NIST ≥ P-256, imposé à la CSR reçue comme au certificat émis : CheckPublicKey, appelé par internal/ca et la configuration des services. | internal/conformance/crypto_test.go (TestCheckPublicKey) |
| §6.1 | Algorithme de signature et fonction de hachage admis | couvert | Liste blanche d'algorithmes de signature ; SHA-1 et MD5 sont refusés explicitement, jamais par omission : CheckSignatureAlgorithm. | internal/conformance/crypto_test.go (TestCheckSignatureAlgorithm) |
| §5.1 | Fonction de hachage admise pour l'empreinte soumise | couvert | messageImprint restreint à SHA-256/384/512 ; SHA-1 est rejeté avec badAlg : HashAdmitted, internal/tsa. | internal/conformance/crypto_test.go, internal/tsa/authority_test.go |

## RFC 5280

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §4.2.1.1-4.2.1.2 | Identifiants de clé de sujet et d'autorité présents | couvert | SKI dérivé de la clé publique et AKI hérité de l'émettrice, posés systématiquement à l'émission : internal/ca. | internal/conformance/certificate_test.go |
| §5.1 | Liste de révocation signée, numérotée et datée | couvert | CRLNumber monotone servi par la base, thisUpdate/nextUpdate cohérents, signature vérifiée par l'émettrice avant publication : internal/ca, CheckCRL. | internal/conformance/crl_test.go (TestCheckCRL), vérification croisée `openssl crl -verify` en CI |

## RFC 6960

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §2.1 | Service d'état de révocation interrogeable en ligne | couvert | Répondeur OCSP RFC 6960 autonome adossé à la CRL, refusant de répondre plutôt que de garantir un statut obsolète : internal/ocspresponder. | job kind et compose (openssl ocsp), .github/workflows/ci.yml |
| §4.2.2.2 | Profil du certificat de signature du répondeur OCSP | couvert | Profil ocsp_responder : id-kp-OCSPSigning, id-pkix-ocsp-nocheck, durée de vie courte : internal/ca/profile.go. | internal/conformance/certificate_test.go (TestCheckOCSPResponderCertificate) |

