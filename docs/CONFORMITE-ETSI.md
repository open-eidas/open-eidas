# Matrice de conformité ETSI

<!-- Document généré par `ca-server conformance --markdown` depuis
     oe-conformance::system_matrix. Ne pas modifier à la main : toute
     correction se fait dans le code, pour que la matrice publiée reste
     celle que le système applique réellement. -->

**28 exigences** — 17 couvertes, 9 écarts documentés, 2 hors périmètre logiciel.

Trois statuts seulement, pour qu'aucune zone grise ne puisse s'y loger :

- **couvert** — l'exigence est appliquée par du code de ce dépôt et vérifiée par un test nommé ci-dessous ;
- **écart documenté** — l'exigence n'est pas satisfaite en l'état ; la mesure compensatoire en place et la cible sont indiquées ;
- **hors périmètre logiciel** — exigence organisationnelle, qu'aucun code ne peut établir seul.

## ETSI EN 319 401

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §7.4 | Gestion des clés du prestataire dans un module cryptographique | couvert | Toutes les clés vivent dans un token PKCS#11 et n'en sortent jamais : oe-hsm::Pkcs11Token, validé contre un vrai token SoftHSM2 (crates/oe-hsm/tests/pkcs11_integration.rs). | crates/oe-hsm/tests/pkcs11_integration.rs |
| §7.10 | Journalisation des événements et durée de conservation | écart documenté | Le journal JSON Lines chaîné par SHA-256 est porté et testé (oe-audit) ; la vérification de la durée de conservation configurée (équivalent de CheckAuditRetention, Go) ne l'est pas encore. | **Cible :** Porter l'équivalent de conformance.CheckAuditRetention et le brancher au démarrage de bin/ca-server, comme le fait cmd/ca-server (Go). |
| §7.9 | Intégrité démontrable des enregistrements d'audit | couvert | Chaînage par hachage vérifié intégralement à l'ouverture ; verrou de fichier partagé entre plusieurs écrivains d'un même processus : oe-audit::Log. | crates/oe-audit/src/lib.rs (deux_ecrivains_partagent_la_meme_chaine, verify_detects_modified_record, verify_detects_truncated_and_rewritten_tail) |
| §7.11 | Continuité d'activité et reprise après sinistre | couvert | Contreseing du journal par une TSA tierce (oe-crosstsa) et réplication WebDAV hors site (oe-replicate), validés contre un vrai serveur. | crates/oe-crosstsa/tests/against_local_server.rs (seals_a_digest_against_a_real_rfc3161_server), crates/oe-replicate/tests/against_local_server.rs (replicates_content_via_webdav_put) |
| §7.12 | Plan de cessation d'activité | hors périmètre logiciel | Procédure organisationnelle décrite dans docs/CA.md, indépendante du langage d'implémentation. | **Cible :** Engagement juridique de l'association, dépôt auprès de l'organe de contrôle, séquestre des journaux. |
| §6.1 | Politique de service et déclaration des pratiques publiées | écart documenté | docs/CPS.md porte un brouillon structuré, déjà indépendant du langage d'implémentation du service. | **Cible :** Adoption formelle de docs/CPS.md par l'association (organisationnel, non affecté par le portage Rust). |

## ETSI EN 319 403-1

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §7 | Évaluation par un organisme d'évaluation de la conformité accrédité | hors périmètre logiciel | Le dépôt est intégralement public ; cette matrice fournit le point d'entrée d'un audit, indépendamment du langage d'implémentation. | **Cible :** Audit par un organisme accrédité (LSTI, Apave), puis inscription à la liste de confiance nationale. |

## ETSI EN 319 411-1

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §6.6.1 | Profil du certificat d'autorité de certification | couvert | Cérémonie produisant une racine et une CA émettrice au profil contrôlé (CA:TRUE critique, keyCertSign+cRLSign, SKI/AKI) : oe_ca_core::ceremony::run_ceremony, chaîne revérifiée par openssl. | crates/oe-ca-core/tests/issuance.rs (ceremony_is_idempotent, ceremony_rejects_mismatched_signer_on_replay, openssl_accepts_the_chain_and_honors_revocation) |
| §6.2.1 | Enregistrement et responsabilité de la décision d'émission | couvert | Aucune transition vers Approved n'existe sans identité d'opérateur : oe_raflow::Decider::approve/reject. L'identité est consignée en base et au journal d'audit. | crates/oe-raflow/tests/flow.rs (decide_without_operator_identity_is_refused, approve_then_resubmit_issues_a_certificate_signed_by_the_issuing_key) |
| §6.3.1 | Authentification de la demande de certificat | couvert | HMAC-SHA256 sur la CSR DER, vérifié en temps constant, et vérification de l'auto-signature de la CSR (preuve de possession) : oe_raflow::Flow::submit. | crates/oe-raflow/tests/flow.rs (submit_without_valid_hmac_is_unauthenticated, submit_opens_a_pending_request_idempotently) |
| §6.3.2 | Durée de vie du certificat plafonnée | écart documenté | La durée de vie est bornée par le profil au moment de la construction (oe_ca_core::Issuer::issue), mais rien ne relit ni ne re-contrôle le certificat produit après signature — contrairement au binaire Go (findings := profile.Check(...)). | **Cible :** Porter l'équivalent de profile.Check/CheckLifetime (oe-conformance) et l'appliquer après signature, avant l'enregistrement en base. |
| §6.3.9 | Motif de révocation consigné | couvert | Motif RFC 5280 obligatoire à la révocation (Issuer::revoke), persisté et repris dans chaque entrée de CRL avec son extension cRLReason. | crates/oe-ca-core/tests/issuance.rs (revoke_is_idempotent_and_keeps_first_reason, revoke_then_publish_crl_lists_the_certificate) |
| §6.3.10 | Publication régulière de l'état de révocation | écart documenté | oe_ca_core::Issuer::publish_crl produit une CRL signée, republiable même vide, et testée ; la republication périodique et le repli sur le registre plutôt que le cache (bin/ca-server::http::Server) n'ont pas encore de test automatisé propre au binaire, contrairement à cmd/ca-server/server_test.go (Go). | **Cible :** Écrire un test d'intégration pour bin/ca-server couvrant la republication périodique et la dégradation de /healthz sur CRL périmée. |
| §6.5.1 | Cérémonie de génération des clés d'autorité | écart documenté | Cérémonie scriptée et idempotente (`ca-server ceremony`), produisant un procès-verbal consigné au journal d'audit (empreintes de clés, opérateur, date) : oe_ca_core::ceremony. | **Cible :** Cérémonie en double contrôle, sous témoin indépendant, sur HSM certifié, avec procès-verbal contresigné — écart organisationnel, pas seulement logiciel. |

## ETSI EN 319 412-1

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §4 | Structures communes du profil de certificat | couvert | Profils définis en structures Rust compilées, pas en configuration interprétée : oe_ca_core::profile. Contrôle de criticité (basicConstraints, keyUsage, EKU) posé à la main, vérifié par openssl. | crates/oe-ca-core/tests/issuance.rs (openssl_accepts_the_chain_and_honors_revocation) |
| §4.1 | Numéro de série positif et imprévisible | couvert | Numéro de série de 128 bits tiré sur rand::thread_rng et réservé de façon atomique (contrainte d'unicité en base) : oe_ca_core::Issuer::reserve_serial, oe_castore::Store::reserve_serial. | crates/oe-castore/src/lib.rs (reserve_serial_twice_conflicts), crates/oe-castore/tests/postgres.rs (reserve_serial_twice_conflicts) |

## ETSI EN 319 421

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §7.6 | Traçabilité de l'heure jusqu'à UTC et suspension en cas de dérive | couvert | Surveillance NTP multi-sources avec quorum, seuil de dérive (MaxOffset) et péremption (MaxAge) ; la politique enforce fait refuser chaque demande avec timeNotAvailable : oe_timesource::Monitor. | crates/oe-timesource/src/lib.rs (now_refuses_untraceable_time_in_enforce_mode, now_allows_untraceable_time_in_monitor_mode, new_rejects_quorum_larger_than_source_count), crates/oe-tsa-core/src/lib.rs (test_timestamp_refuses_when_time_is_not_traceable) |
| §7.7.2 | Profil du certificat de l'unité d'horodatage | écart documenté | Le profil tsa_signer (id-kp-timeStamping seul et critique, CA:FALSE, keyUsage restreint) est appliqué à l'émission (oe_ca_core::profile) ; contrairement au binaire Go, rien ne re-contrôle ce profil au démarrage de tsa-server (équivalent de CheckTSUCertificate absent). | **Cible :** Porter l'équivalent de CheckTSUCertificate et le brancher à oe_tsa_core::Authority::new, comme le fait cmd/tsa-server (Go) au démarrage. |
| §7.7.1 | Génération de la clé TSU dans le module cryptographique | couvert | La bi-clé est générée dans le token PKCS#11 (oe_hsm::Pkcs11Token::generate_rsa_key) et ne manipule qu'un SigningToken ; la clé privée n'est jamais extraite. | crates/oe-hsm/tests/pkcs11_integration.rs |

## ETSI EN 319 422

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §5 | Profil du jeton d'horodatage | couvert | TSTInfo complet (politique, imprint, série, genTime UTC, précision), assemblé en CMS SignedData signé par le token ; le jeton est relu avant d'être consigné : oe_rfc3161_asn1, oe_tsa_core::Authority::timestamp. | crates/oe-tsa-core/tests/end_to_end.rs (produces_tokens_accepted_by_openssl_for_every_granted_case_in_the_corpus) |
| §7 | Protocole d'horodatage RFC 3161 sur HTTP | couvert | Endpoint /tsa acceptant application/timestamp-query, refus protocolaires rendus en TimeStampResp valides : oe_httpapi, bin/tsa-server. | crates/oe-httpapi/tests/end_to_end.rs (serves_a_verifiable_token_over_http, vérification croisée openssl ts -verify) |

## ETSI TS 119 312

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §6.2 | Longueur de clé suffisante pour la durée de vie visée | écart documenté | oe-config et bin/ca-server/src/config.rs imposent OPENEIDAS_KEY_BITS >= 3072 à la configuration (clé de l'autorité elle-même), mais rien ne contrôle la longueur de la clé publique portée par une CSR soumise à l'enrôlement. | **Cible :** Porter l'équivalent de CheckPublicKey et l'appliquer à oe_raflow::parse_and_verify_csr. |
| §6.1 | Algorithme de signature et fonction de hachage admis | écart documenté | Le système n'implémente que RSA/SHA-256 de bout en bout (aucune négociation d'algorithme), ce qui exclut structurellement les algorithmes faibles sans qu'un contrôle explicite et nommé ne le vérifie sur une entrée arbitraire, contrairement à conformance.CheckSignatureAlgorithm (Go). | **Cible :** Porter l'équivalent de CheckSignatureAlgorithm si le système vient à accepter plus d'un algorithme. |
| §5.1 | Fonction de hachage admise pour l'empreinte soumise | couvert | oe_hsm::DigestAlg restreint la signature à SHA-256/384/512 ; une empreinte SHA-1 est refusée avec le failureInfo RFC 3161 badAlg : oe_tsa_core::Authority::timestamp. | crates/oe-tsa-core/src/lib.rs (test_timestamp_rejects_sha1) |

## RFC 5280

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §4.2.1.1-4.2.1.2 | Identifiants de clé de sujet et d'autorité présents | écart documenté | subjectKeyIdentifier et authorityKeyIdentifier sont posés sans condition à l'émission et dans la cérémonie (oe_ca_core::extensions, oe_ca_core::signing::subject_key_id), mais aucun test n'affirme spécifiquement leur présence/valeur — seule la CRL (dont l'AKI a un bug corrigé en pratique) l'est indirectement via `openssl verify -crl_check`. | **Cible :** Ajouter un test qui décode le certificat émis et vérifie explicitement la présence et la valeur de ces deux extensions. |
| §5.1 | Liste de révocation signée, numérotée et datée | couvert | CRL régénérée avec cRLNumber, thisUpdate/nextUpdate et signature, republiée même vide : oe_ca_core::Issuer::publish_crl. La signature et le motif de révocation sont revérifiés par openssl. | crates/oe-ca-core/tests/issuance.rs (revoke_then_publish_crl_lists_the_certificate, openssl_accepts_the_chain_and_honors_revocation) |

## RFC 6960

| Clause | Exigence | Statut | Mécanisme | Vérification / cible |
|---|---|---|---|---|
| §2.1 | Service d'état de révocation interrogeable en ligne | couvert | Répondeur OCSP RFC 6960 s'appuyant sur la CRL publiée par la CA : oe_ocsp_core::Responder. | crates/oe-ocsp-core/tests/against_real_crl.rs (reports_good_status_for_a_non_revoked_certificate, reports_revoked_status_for_a_revoked_certificate) |
| §4.2.2.2 | Profil du certificat de signature du répondeur OCSP | couvert | Profil ocsp_responder (id-pkix-ocsp-nocheck, pas de CDP/AIA, durée de vie courte) appliqué à l'émission : oe_ca_core::profile::ocsp_responder. | crates/oe-ca-core/tests/issuance.rs (revoke_then_publish_crl_lists_the_certificate, qui émet avec ce profil) |

