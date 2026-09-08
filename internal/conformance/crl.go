package conformance

import (
	"crypto/x509"
	"time"
)

var (
	ReqCRLPublication = Requirement{
		Standard: "ETSI EN 319 411-1",
		Clause:   "§6.3.10",
		Title:    "Publication régulière de l'état de révocation",
	}
	ReqCRLIntegrity = Requirement{
		Standard: "RFC 5280",
		Clause:   "§5.1",
		Title:    "Liste de révocation signée, numérotée et datée",
	}
	ReqRevocationReason = Requirement{
		Standard: "ETSI EN 319 411-1",
		Clause:   "§6.3.9",
		Title:    "Motif de révocation consigné",
	}
	ReqAuditLogging = Requirement{
		Standard: "ETSI EN 319 401",
		Clause:   "§7.10",
		Title:    "Journalisation des événements et durée de conservation",
	}
)

// MaxCRLValidity plafonne l'écart entre thisUpdate et nextUpdate. Une CRL dont
// la fenêtre est trop large laisse une révocation invisible trop longtemps ;
// EN 319 411-1 §6.3.10 exige une publication régulière sans fixer la valeur,
// posée ici à 7 jours et resserrée par la configuration du service.
const MaxCRLValidity = 7 * 24 * time.Hour

// MinAuditRetention est la durée de conservation minimale du journal. Le
// règlement eIDAS impose de pouvoir justifier a posteriori des opérations du
// service ; une conservation nulle ou dérisoire vide la journalisation de son
// objet.
const MinAuditRetention = 365 * 24 * time.Hour

// CheckCRL contrôle une liste de révocation avant sa publication : elle doit
// être datée, bornée dans le temps, numérotée, et vérifiable par l'autorité
// qui prétend l'avoir signée.
//
// `previousNumber` est le numéro de la CRL publiée précédemment, ou nil s'il
// s'agit de la première : la monotonie du CRLNumber est ce qui empêche un
// attaquant de rejouer une CRL ancienne, donc plus courte.
func CheckCRL(subject string, crl *x509.RevocationList, issuer *x509.Certificate, previousNumber *int64) Findings {
	var out Findings
	out = append(out, CheckSignatureAlgorithm(subject, crl.SignatureAlgorithm)...)

	if crl.ThisUpdate.IsZero() {
		out = append(out, fail(ReqCRLIntegrity, "%s: thisUpdate absent", subject))
	}
	if crl.NextUpdate.IsZero() {
		out = append(out, fail(ReqCRLPublication, "%s: nextUpdate absent", subject))
	} else {
		if !crl.ThisUpdate.Before(crl.NextUpdate) {
			out = append(out, fail(ReqCRLPublication,
				"%s: nextUpdate (%s) n'est pas postérieur à thisUpdate (%s)",
				subject, crl.NextUpdate.UTC().Format(time.RFC3339), crl.ThisUpdate.UTC().Format(time.RFC3339)))
		} else if window := crl.NextUpdate.Sub(crl.ThisUpdate); window > MaxCRLValidity {
			out = append(out, fail(ReqCRLPublication,
				"%s: fenêtre de validité de %s, plafond %s", subject, window, MaxCRLValidity))
		}
	}

	if crl.Number == nil || crl.Number.Sign() < 0 {
		out = append(out, fail(ReqCRLIntegrity, "%s: CRLNumber absent ou négatif", subject))
	} else if previousNumber != nil && crl.Number.Int64() <= *previousNumber {
		out = append(out, fail(ReqCRLIntegrity,
			"%s: CRLNumber %s n'est pas strictement supérieur au précédent (%d)",
			subject, crl.Number, *previousNumber))
	}

	if issuer != nil {
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			out = append(out, fail(ReqCRLIntegrity,
				"%s: signature non vérifiable par l'émettrice annoncée: %v", subject, err))
		}
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 {
			out = append(out, fail(ReqCRLIntegrity, "%s: entrée sans numéro de série exploitable", subject))
			continue
		}
		if entry.RevocationTime.IsZero() {
			out = append(out, fail(ReqCRLIntegrity,
				"%s: entrée %s sans date de révocation", subject, entry.SerialNumber))
		}
		if entry.ReasonCode == 0 {
			// reasonCode 0 est « unspecified » : accepté par RFC 5280 mais
			// insuffisant pour justifier une décision devant un auditeur.
			out = append(out, warn(ReqRevocationReason,
				"%s: entrée %s révoquée sans motif explicite", subject, entry.SerialNumber))
		}
	}
	return out
}

// CheckAuditRetention vérifie que la durée de conservation du journal est
// configurée et suffisante.
func CheckAuditRetention(retention time.Duration) Findings {
	if retention <= 0 {
		return Findings{fail(ReqAuditLogging, "durée de conservation du journal d'audit non configurée")}
	}
	if retention < MinAuditRetention {
		return Findings{fail(ReqAuditLogging,
			"durée de conservation du journal de %s, minimum requis %s",
			retention.Round(24*time.Hour), MinAuditRetention.Round(24*time.Hour))}
	}
	return nil
}
