package conformance

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"time"
)

// OID des extensions contrôlées ici. Elles sont nommées explicitement parce
// que crypto/x509 expose la valeur analysée mais pas toujours la criticité,
// qui est justement ce que plusieurs exigences ETSI portent.
var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	// OIDOCSPNoCheck est id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1).
	OIDOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
)

var (
	ReqCertificateStructure = Requirement{
		Standard: "ETSI EN 319 412-1",
		Clause:   "§4",
		Title:    "Structures communes du profil de certificat",
	}
	ReqSerialNumber = Requirement{
		Standard: "ETSI EN 319 412-1",
		Clause:   "§4.1",
		Title:    "Numéro de série positif et imprévisible",
	}
	ReqKeyIdentifiers = Requirement{
		Standard: "RFC 5280",
		Clause:   "§4.2.1.1-4.2.1.2",
		Title:    "Identifiants de clé de sujet et d'autorité présents",
	}
	ReqTSUCertificate = Requirement{
		Standard: "ETSI EN 319 421",
		Clause:   "§7.7.2",
		Title:    "Profil du certificat de l'unité d'horodatage",
	}
	ReqOCSPResponderCertificate = Requirement{
		Standard: "RFC 6960",
		Clause:   "§4.2.2.2",
		Title:    "Profil du certificat de signature du répondeur OCSP",
	}
	ReqCACertificate = Requirement{
		Standard: "ETSI EN 319 411-1",
		Clause:   "§6.6.1",
		Title:    "Profil du certificat d'autorité de certification",
	}
	ReqCertificateLifetime = Requirement{
		Standard: "ETSI EN 319 411-1",
		Clause:   "§6.3.2",
		Title:    "Durée de vie du certificat plafonnée",
	}
)

// Plafonds de durée de vie appliqués par le moteur d'émission. Aucune norme ne
// fixe ces valeurs au jour près pour une TSU ; elles sont posées ici de façon
// explicite et conservatrice, afin qu'un certificat à durée aberrante soit
// refusé plutôt que produit.
const (
	MaxEndEntityLifetime = 39 * 30 * 24 * time.Hour  // ~39 mois
	MaxOCSPLifetime      = 6 * 30 * 24 * time.Hour   // ~6 mois (ocsp-nocheck)
	MaxIssuingCALifetime = 15 * 365 * 24 * time.Hour // ~15 ans
	MaxRootCALifetime    = 25 * 365 * 24 * time.Hour // ~25 ans
	// MinSerialEntropyBits est le minimum d'aléa exigé sur un numéro de série.
	// Le moteur en tire 128 ; en deçà de 64, la prévisibilité redevient une
	// voie d'attaque sur les collisions de signature.
	MinSerialEntropyBits = 64
)

func extension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkixExt, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return pkixExt{Critical: ext.Critical, Present: true}, true
		}
	}
	return pkixExt{}, false
}

type pkixExt struct {
	Critical bool
	Present  bool
}

// CheckCommonCertificate applique les règles valables pour tout certificat
// émis par cette PKI, quel que soit son profil. `selfSigned` dispense de
// l'identifiant de clé d'autorité, qu'une racine auto-signée n'a pas à porter
// distinctement.
func CheckCommonCertificate(subject string, cert *x509.Certificate, selfSigned bool) Findings {
	var out Findings
	out = append(out, CheckSignatureAlgorithm(subject, cert.SignatureAlgorithm)...)
	out = append(out, CheckPublicKey(subject, cert.PublicKey)...)

	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		out = append(out, fail(ReqSerialNumber, "%s: numéro de série absent, nul ou négatif", subject))
	} else if cert.SerialNumber.BitLen() < MinSerialEntropyBits {
		out = append(out, fail(ReqSerialNumber,
			"%s: numéro de série de %d bits, minimum requis %d",
			subject, cert.SerialNumber.BitLen(), MinSerialEntropyBits))
	}

	if !cert.NotBefore.Before(cert.NotAfter) {
		out = append(out, fail(ReqCertificateStructure,
			"%s: période de validité incohérente (notBefore %s, notAfter %s)",
			subject, cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339)))
	}

	if len(cert.SubjectKeyId) == 0 {
		out = append(out, fail(ReqKeyIdentifiers, "%s: extension subjectKeyIdentifier absente", subject))
	}
	if !selfSigned && len(cert.AuthorityKeyId) == 0 {
		out = append(out, fail(ReqKeyIdentifiers, "%s: extension authorityKeyIdentifier absente", subject))
	}
	if _, ok := extension(cert, oidSubjectKeyID); !ok && len(cert.SubjectKeyId) > 0 {
		out = append(out, warn(ReqKeyIdentifiers, "%s: subjectKeyIdentifier non encodé comme extension", subject))
	}

	if bc, ok := extension(cert, oidBasicConstraints); !ok {
		out = append(out, fail(ReqCertificateStructure, "%s: extension basicConstraints absente", subject))
	} else if !bc.Critical {
		out = append(out, fail(ReqCertificateStructure,
			"%s: extension basicConstraints non marquée critique", subject))
	}

	if ku, ok := extension(cert, oidKeyUsage); !ok {
		out = append(out, fail(ReqCertificateStructure, "%s: extension keyUsage absente", subject))
	} else if !ku.Critical {
		out = append(out, fail(ReqCertificateStructure,
			"%s: extension keyUsage non marquée critique", subject))
	}

	return out
}

func checkLifetime(subject string, cert *x509.Certificate, max time.Duration) Findings {
	if life := cert.NotAfter.Sub(cert.NotBefore); life > max {
		return Findings{fail(ReqCertificateLifetime,
			"%s: durée de vie de %s, plafond %s",
			subject, life.Round(24*time.Hour), max.Round(24*time.Hour))}
	}
	return nil
}

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}

// CheckTSUCertificate applique le profil du certificat de l'unité
// d'horodatage : ETSI EN 319 421 §7.7.2 impose que extendedKeyUsage soit
// marqué critique et ne contienne QUE id-kp-timeStamping — un certificat qui
// servirait aussi à autre chose ne peut pas garantir que la signature relève
// bien de l'horodatage.
func CheckTSUCertificate(subject string, cert *x509.Certificate) Findings {
	out := CheckCommonCertificate(subject, cert, false)
	out = append(out, checkLifetime(subject, cert, MaxEndEntityLifetime)...)

	if cert.IsCA {
		out = append(out, fail(ReqTSUCertificate, "%s: le certificat TSU porte basicConstraints CA:TRUE", subject))
	}
	if !hasExtKeyUsage(cert, x509.ExtKeyUsageTimeStamping) {
		out = append(out, fail(ReqTSUCertificate,
			"%s: extendedKeyUsage id-kp-timeStamping absent", subject))
	}
	if len(cert.ExtKeyUsage) > 1 || len(cert.UnknownExtKeyUsage) > 0 {
		out = append(out, fail(ReqTSUCertificate,
			"%s: extendedKeyUsage porte %d usages en plus de id-kp-timeStamping",
			subject, len(cert.ExtKeyUsage)-1+len(cert.UnknownExtKeyUsage)))
	}
	if eku, ok := extension(cert, oidExtKeyUsage); !ok {
		out = append(out, fail(ReqTSUCertificate, "%s: extension extendedKeyUsage absente", subject))
	} else if !eku.Critical {
		out = append(out, fail(ReqTSUCertificate,
			"%s: extension extendedKeyUsage non marquée critique", subject))
	}

	const allowed = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	if cert.KeyUsage == 0 {
		out = append(out, fail(ReqTSUCertificate, "%s: keyUsage vide", subject))
	}
	if cert.KeyUsage&^allowed != 0 {
		out = append(out, fail(ReqTSUCertificate,
			"%s: keyUsage déborde de digitalSignature/contentCommitment", subject))
	}
	return out
}

// CheckOCSPResponderCertificate applique le profil du certificat de signature
// du répondeur OCSP. id-pkix-ocsp-nocheck lève la dépendance circulaire (un
// répondeur ne peut pas attester de sa propre révocation) ; en contrepartie,
// RFC 6960 §4.2.2.2.1 impose que sa durée de vie reste courte.
func CheckOCSPResponderCertificate(subject string, cert *x509.Certificate) Findings {
	out := CheckCommonCertificate(subject, cert, false)
	out = append(out, checkLifetime(subject, cert, MaxOCSPLifetime)...)

	if cert.IsCA {
		out = append(out, fail(ReqOCSPResponderCertificate,
			"%s: le certificat du répondeur porte basicConstraints CA:TRUE", subject))
	}
	if !hasExtKeyUsage(cert, x509.ExtKeyUsageOCSPSigning) {
		out = append(out, fail(ReqOCSPResponderCertificate,
			"%s: extendedKeyUsage id-kp-OCSPSigning absent", subject))
	}
	if len(cert.ExtKeyUsage) > 1 || len(cert.UnknownExtKeyUsage) > 0 {
		out = append(out, fail(ReqOCSPResponderCertificate,
			"%s: extendedKeyUsage porte des usages en plus de id-kp-OCSPSigning", subject))
	}
	if _, ok := extension(cert, OIDOCSPNoCheck); !ok {
		out = append(out, fail(ReqOCSPResponderCertificate,
			"%s: extension id-pkix-ocsp-nocheck absente", subject))
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		out = append(out, fail(ReqOCSPResponderCertificate,
			"%s: keyUsage ne porte pas digitalSignature", subject))
	}
	return out
}

// CheckCACertificate applique le profil d'un certificat d'autorité, racine ou
// émettrice. Une CA doit pouvoir signer des certificats ET des CRL : sans
// cRLSign, le service de statut de révocation devient invérifiable.
func CheckCACertificate(subject string, cert *x509.Certificate, root bool) Findings {
	out := CheckCommonCertificate(subject, cert, root)
	max := MaxIssuingCALifetime
	if root {
		max = MaxRootCALifetime
	}
	out = append(out, checkLifetime(subject, cert, max)...)

	if !cert.IsCA {
		out = append(out, fail(ReqCACertificate, "%s: basicConstraints CA:FALSE sur une autorité", subject))
	}
	if !cert.BasicConstraintsValid {
		out = append(out, fail(ReqCACertificate, "%s: basicConstraints non exploitable", subject))
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		out = append(out, fail(ReqCACertificate, "%s: keyUsage ne porte pas keyCertSign", subject))
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		out = append(out, fail(ReqCACertificate, "%s: keyUsage ne porte pas cRLSign", subject))
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, warn(ReqCACertificate,
			"%s: keyUsage porte digitalSignature, inutile pour une autorité", subject))
	}
	if root && cert.MaxPathLenZero {
		out = append(out, warn(ReqCACertificate,
			"%s: pathLenConstraint à 0 sur la racine interdit toute CA émettrice sous-jacente", subject))
	}
	return out
}

// SerialEntropyBits expose la taille effective d'un numéro de série, pour le
// rapport de conformité.
func SerialEntropyBits(serial *big.Int) int {
	if serial == nil {
		return 0
	}
	return serial.BitLen()
}
