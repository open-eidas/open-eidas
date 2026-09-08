package conformance

import (
	"fmt"
	"strings"
)

// SystemMatrix est la matrice de conformité complète d'Open eIDAS : chaque
// exigence normative applicable, le mécanisme qui la porte, le test qui le
// vérifie, et son statut.
//
// Elle est la source unique de docs/CONFORMITE-ETSI.md, régénéré depuis ce
// code afin que la documentation ne puisse pas dériver de l'implémentation.
// `ca-server conformance` échoue si Validate() la juge incohérente.
//
// Les trois statuts sont volontairement les seuls disponibles : une exigence
// est appliquée et testée, ou c'est un écart avec sa cible, ou elle relève
// d'une mesure organisationnelle qu'aucun logiciel ne peut établir seul. Rien
// ne peut y être « partiellement conforme ».
func SystemMatrix() Matrix {
	return Matrix{
		// ── ETSI EN 319 401 — exigences générales aux prestataires ────────
		{
			Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§7.4",
				Title: "Gestion des clés du prestataire dans un module cryptographique"},
			Status:    StatusGap,
			Mechanism: "Toutes les clés (racine, émettrice, TSU, répondeur OCSP) vivent dans un token PKCS#11 et n'en sortent jamais : internal/hsm. SoftHSM2 parle le même protocole qu'un module certifié.",
			Test:      "internal/hsm — exercé de bout en bout par scripts/bootstrap.sh et le job kind",
			Target:    "Remplacer SoftHSM2 par un HSM certifié FIPS 140-2 niv. 3 ou CC EAL4+ ; seule la variable OPENEIDAS_PKCS11_MODULE change.",
		},
		{
			Requirement: ReqAuditLogging,
			Status:      StatusCovered,
			Mechanism:   "Journal JSON Lines chaîné par SHA-256, scellé périodiquement, contresigné par des TSA tierces et répliqué hors site : internal/audit, internal/crosstsa, internal/replicate. Durée de conservation contrôlée par CheckAuditRetention.",
			Test:        "internal/audit/audit_test.go, internal/conformance/crl_test.go (TestCheckAuditRetention)",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§7.9",
				Title: "Intégrité démontrable des enregistrements d'audit"},
			Status:    StatusCovered,
			Mechanism: "Chaînage par hachage vérifié intégralement à l'ouverture ; une écriture ratée annule l'opération, un journal altéré empêche le démarrage. Le service et les commandes d'exploitation partagent une seule chaîne, sous verrou de fichier : internal/audit + sous-commandes `verify-audit`.",
			Test:      "internal/audit/audit_test.go (TestDeuxEcrivainsPartagentLaMemeChaine)",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§7.11",
				Title: "Continuité d'activité et reprise après sinistre"},
			Status:    StatusGap,
			Mechanism: "Réplication hors site du journal à chaque scellement (internal/replicate) ; état de la CA en base PostgreSQL sauvegardable.",
			Target:    "Redondance active/active des services, sauvegarde et restauration testées, plan de continuité formalisé — voir docs/CA.md.",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§7.12",
				Title: "Plan de cessation d'activité"},
			Status:    StatusOutOfScope,
			Mechanism: "Procédure décrite dans docs/CA.md (révocation en masse, publication d'une dernière CRL longue, remise des journaux).",
			Target:    "Engagement juridique de l'association, dépôt auprès de l'organe de contrôle, séquestre des journaux.",
		},

		// ── ETSI EN 319 411-1 — cycle de vie de l'autorité ────────────────
		{
			Requirement: ReqCACertificate,
			Status:      StatusCovered,
			Mechanism:   "Cérémonie de clé produisant une racine et une CA émettrice au profil contrôlé (CA:TRUE critique, keyCertSign+cRLSign, SKI/AKI) : internal/ca.Ceremony, vérifié par CheckCACertificate.",
			Test:        "internal/conformance/certificate_test.go, internal/ca/ca_test.go",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 411-1", Clause: "§6.2.1",
				Title: "Enregistrement et responsabilité de la décision d'émission"},
			Status:    StatusGap,
			Mechanism: "Aucune transition vers APPROVED n'existe sans identité d'opérateur : internal/raflow. L'identité est consignée en base et au journal d'audit.",
			Test:      "internal/raflow/raflow_test.go (TestApprobationExigeUnOperateur, TestAucunCheminVersIssuedSansApprobation)",
			Target:    "Remplacer l'opérateur technique `ci-bootstrap` de la démonstration par un opérateur RA humain nominatif authentifié.",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 411-1", Clause: "§6.3.1",
				Title: "Authentification de la demande de certificat"},
			Status:    StatusCovered,
			Mechanism: "HMAC-SHA256 sur la CSR DER, comparé en temps constant, et vérification de l'auto-signature de la CSR (preuve de possession) : internal/raflow, internal/ca.",
			Test:      "internal/raflow/raflow_test.go, internal/ca/ca_test.go (TestIssueRefuseCSRNonSignee)",
		},
		{
			Requirement: ReqCertificateLifetime,
			Status:      StatusCovered,
			Mechanism:   "Durées de vie fixées par profil Go et plafonnées à l'émission ; le certificat émis est relu et re-contrôlé avant d'être délivré : internal/ca.",
			Test:        "internal/conformance/certificate_test.go (TestCheckLifetime), internal/ca/ca_test.go",
		},
		{
			Requirement: ReqRevocationReason,
			Status:      StatusCovered,
			Mechanism:   "Motif RFC 5280 obligatoire à la révocation, persisté et repris dans chaque entrée de CRL : internal/castore, internal/ca.",
			Test:        "internal/conformance/crl_test.go, internal/ca/ca_test.go (TestCRLPorteLesMotifs)",
		},
		{
			Requirement: ReqCRLPublication,
			Status:      StatusCovered,
			Mechanism:   "CRL régénérée périodiquement et republiée même vide, nextUpdate borné, servie depuis le registre pour qu'une révocation décidée par une commande d'exploitation soit visible aussitôt, /healthz en 503 si la CRL est périmée : internal/ca, cmd/ca-server.",
			Test:        "internal/conformance/crl_test.go, internal/ca/ca_test.go (TestCRLPublieeMemeVide), cmd/ca-server/server_test.go (TestCRLServieDepuisLeRegistreEtNonDuCache)",
		},
		{
			Requirement: Requirement{Standard: "RFC 6960", Clause: "§2.1",
				Title: "Service d'état de révocation interrogeable en ligne"},
			Status:    StatusCovered,
			Mechanism: "Répondeur OCSP RFC 6960 autonome adossé à la CRL, refusant de répondre plutôt que de garantir un statut obsolète : internal/ocspresponder.",
			Test:      "job kind et compose (openssl ocsp), .github/workflows/ci.yml",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 411-1", Clause: "§6.5.1",
				Title: "Cérémonie de génération des clés d'autorité"},
			Status:    StatusGap,
			Mechanism: "Cérémonie scriptée et idempotente, produisant un procès-verbal consigné au journal d'audit (empreintes de clés, horodatage, opérateur) : `ca-server ceremony`, docs/CA.md.",
			Test:      "internal/ca/ca_test.go (TestCeremonieProduitUneHierarchieConforme)",
			Target:    "Cérémonie en double contrôle, sous témoin indépendant, sur HSM certifié, avec procès-verbal contresigné.",
		},

		// ── ETSI EN 319 412 — profils de certificat ───────────────────────
		{
			Requirement: ReqCertificateStructure,
			Status:      StatusCovered,
			Mechanism:   "Profils définis en structures Go, pas en configuration interprétée : internal/ca/profile.go. Contrôle de criticité de basicConstraints et keyUsage par CheckCommonCertificate.",
			Test:        "internal/conformance/certificate_test.go",
		},
		{
			Requirement: ReqSerialNumber,
			Status:      StatusCovered,
			Mechanism:   "Numéro de série de 128 bits tiré sur crypto/rand et réservé de façon atomique (contrainte d'unicité en base) : internal/ca, internal/castore.",
			Test:        "internal/conformance/certificate_test.go, internal/ca/ca_test.go (TestSeriesUniquesEtAleatoires)",
		},
		{
			Requirement: ReqKeyIdentifiers,
			Status:      StatusCovered,
			Mechanism:   "SKI dérivé de la clé publique et AKI hérité de l'émettrice, posés systématiquement à l'émission : internal/ca.",
			Test:        "internal/conformance/certificate_test.go",
		},

		// ── ETSI EN 319 421 / 422 — horodatage ────────────────────────────
		{
			Requirement: Requirement{Standard: "ETSI EN 319 421", Clause: "§7.6",
				Title: "Traçabilité de l'heure jusqu'à UTC et suspension en cas de dérive"},
			Status:    StatusGap,
			Mechanism: "Surveillance NTP multi-sources (UTC(OP), UTC(PTB)) avec quorum, seuil de dérive et péremption ; la politique `enforce` fait refuser chaque demande avec failureInfo timeNotAvailable : internal/timesource.",
			Test:      "internal/timesource/timesource_test.go",
			Target:    "Réception de temps redondante et indépendante du réseau, calibration documentée et journal des mesures audité.",
		},
		{
			Requirement: ReqTSUCertificate,
			Status:      StatusCovered,
			Mechanism:   "Profil tsa_signer : id-kp-timeStamping seul et critique, CA:FALSE, keyUsage restreint à la signature. Appliqué à l'émission et re-contrôlé au démarrage de la TSA : internal/ca/profile.go, internal/tsa.",
			Test:        "internal/conformance/certificate_test.go (TestCheckTSUCertificate), internal/tsa/authority_test.go",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 421", Clause: "§7.7.1",
				Title: "Génération de la clé TSU dans le module cryptographique"},
			Status:    StatusCovered,
			Mechanism: "La bi-clé est générée dans le token et ne manipule qu'un crypto.Signer ; le service refuse de démarrer si la clé du token ne correspond pas au certificat : internal/hsm, internal/tsa.",
			Test:      "internal/tsa/authority_test.go",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 422", Clause: "§5",
				Title: "Profil du jeton d'horodatage"},
			Status:    StatusCovered,
			Mechanism: "TSTInfo complet (politique, imprint, série, genTime UTC, précision), attribut signé signingCertificateV2 (RFC 5035), nonce repris ; le jeton est relu avant d'être consigné : internal/tsa.",
			Test:      "internal/tsa/authority_test.go",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 422", Clause: "§7",
				Title: "Protocole d'horodatage RFC 3161 sur HTTP"},
			Status:    StatusCovered,
			Mechanism: "Endpoint /tsa acceptant application/timestamp-query, refus protocolaires rendus en TimeStampResp valides : internal/httpapi, internal/tsa.",
			Test:      "internal/tsa/authority_test.go, vérification croisée `openssl ts -verify` en CI",
		},

		// ── ETSI TS 119 312 — suites cryptographiques ─────────────────────
		{
			Requirement: ReqKeyLength,
			Status:      StatusCovered,
			Mechanism:   "RSA ≥ 3072 bits ou courbe NIST ≥ P-256, imposé à la CSR reçue comme au certificat émis : CheckPublicKey, appelé par internal/ca et la configuration des services.",
			Test:        "internal/conformance/crypto_test.go (TestCheckPublicKey)",
		},
		{
			Requirement: ReqSignatureAlgorithm,
			Status:      StatusCovered,
			Mechanism:   "Liste blanche d'algorithmes de signature ; SHA-1 et MD5 sont refusés explicitement, jamais par omission : CheckSignatureAlgorithm.",
			Test:        "internal/conformance/crypto_test.go (TestCheckSignatureAlgorithm)",
		},
		{
			Requirement: ReqHashAlgorithm,
			Status:      StatusCovered,
			Mechanism:   "messageImprint restreint à SHA-256/384/512 ; SHA-1 est rejeté avec badAlg : HashAdmitted, internal/tsa.",
			Test:        "internal/conformance/crypto_test.go, internal/tsa/authority_test.go",
		},

		// ── RFC — encodages et protocoles ─────────────────────────────────
		{
			Requirement: ReqCRLIntegrity,
			Status:      StatusCovered,
			Mechanism:   "CRLNumber monotone servi par la base, thisUpdate/nextUpdate cohérents, signature vérifiée par l'émettrice avant publication : internal/ca, CheckCRL.",
			Test:        "internal/conformance/crl_test.go (TestCheckCRL), vérification croisée `openssl crl -verify` en CI",
		},
		{
			Requirement: ReqOCSPResponderCertificate,
			Status:      StatusCovered,
			Mechanism:   "Profil ocsp_responder : id-kp-OCSPSigning, id-pkix-ocsp-nocheck, durée de vie courte : internal/ca/profile.go.",
			Test:        "internal/conformance/certificate_test.go (TestCheckOCSPResponderCertificate)",
		},

		// ── Exigences qu'aucun logiciel ne peut établir seul ──────────────
		{
			Requirement: Requirement{Standard: "ETSI EN 319 403-1", Clause: "§7",
				Title: "Évaluation par un organisme d'évaluation de la conformité accrédité"},
			Status:    StatusOutOfScope,
			Mechanism: "Le dépôt est intégralement public et la présente matrice fournit le point d'entrée d'un audit.",
			Target:    "Audit par un organisme accrédité (LSTI, Apave), puis inscription à la liste de confiance nationale.",
		},
		{
			Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§6.1",
				Title: "Politique de service et déclaration des pratiques publiées"},
			Status:    StatusGap,
			Mechanism: "docs/ARCHITECTURE.md et docs/CA.md décrivent les pratiques réellement mises en œuvre.",
			Target:    "TSA Policy et Practice Statement formels publiés, sous un OID de politique de l'arc PEN de l'association (l'OID actuel 1.3.6.1.4.1.99999.1.1.1 est un OID de test).",
		},
	}
}

// RenderMarkdown produit le contenu de docs/CONFORMITE-ETSI.md à partir de la
// matrice, pour que le document publié soit toujours celui que le code
// applique.
func RenderMarkdown(m Matrix) string {
	var b strings.Builder
	b.WriteString("# Matrice de conformité ETSI\n\n")
	b.WriteString("<!-- Document généré par `ca-server conformance --markdown` depuis\n")
	b.WriteString("     internal/conformance/matrix.go. Ne pas modifier à la main : toute\n")
	b.WriteString("     correction se fait dans le code, pour que la matrice publiée reste\n")
	b.WriteString("     celle que le système applique réellement. -->\n\n")

	counts := m.Counts()
	b.WriteString(fmt.Sprintf(
		"**%d exigences** — %d couvertes, %d écarts documentés, %d hors périmètre logiciel.\n\n",
		len(m), counts[StatusCovered], counts[StatusGap], counts[StatusOutOfScope]))

	b.WriteString("Trois statuts seulement, pour qu'aucune zone grise ne puisse s'y loger :\n\n")
	b.WriteString("- **couvert** — l'exigence est appliquée par du code de ce dépôt et vérifiée par un test nommé ci-dessous ;\n")
	b.WriteString("- **écart documenté** — l'exigence n'est pas satisfaite en l'état ; la mesure compensatoire en place et la cible sont indiquées ;\n")
	b.WriteString("- **hors périmètre logiciel** — exigence organisationnelle, qu'aucun code ne peut établir seul.\n\n")
	b.WriteString("Aucune ligne ne peut être « partiellement conforme » : `ca-server conformance`\n")
	b.WriteString("échoue si une exigence déclarée couverte ne nomme pas son mécanisme et son\n")
	b.WriteString("test, ou si un écart ne nomme pas sa cible.\n\n")

	for _, standard := range m.Standards() {
		b.WriteString("## " + standard + "\n\n")
		b.WriteString("| Clause | Exigence | Statut | Mécanisme | Vérification / cible |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, e := range m {
			if e.Requirement.Standard != standard {
				continue
			}
			last := e.Test
			if e.Status != StatusCovered {
				last = "**Cible :** " + e.Target
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				cell(e.Requirement.Clause), cell(e.Requirement.Title), cell(string(e.Status)),
				cell(e.Mechanism), cell(last)))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// cell neutralise les caractères qui casseraient une cellule de tableau
// Markdown.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.Join(strings.Fields(s), " ")
}
