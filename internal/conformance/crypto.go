package conformance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
)

// Exigences de suites cryptographiques. ETSI TS 119 312 fixe les algorithmes
// et paramètres admissibles pour les services de confiance ; les tailles
// retenues ici sont celles annoncées comme utilisables au-delà de 2030.
var (
	ReqKeyLength = Requirement{
		Standard: "ETSI TS 119 312",
		Clause:   "§6.2",
		Title:    "Longueur de clé suffisante pour la durée de vie visée",
	}
	ReqSignatureAlgorithm = Requirement{
		Standard: "ETSI TS 119 312",
		Clause:   "§6.1",
		Title:    "Algorithme de signature et fonction de hachage admis",
	}
	ReqHashAlgorithm = Requirement{
		Standard: "ETSI TS 119 312",
		Clause:   "§5.1",
		Title:    "Fonction de hachage admise pour l'empreinte soumise",
	}
)

const (
	// MinRSABits est le minimum imposé aux clés RSA. TS 119 312 ne retient
	// plus 2048 bits au-delà de 2029 : le projet impose 3072 dès maintenant,
	// pour ne pas avoir à réémettre toute la hiérarchie en cours de route.
	MinRSABits = 3072
	// MinECDSABits est le minimum imposé aux clés sur courbe elliptique.
	MinECDSABits = 256
)

// CheckPublicKey vérifie qu'une clé publique — celle d'une CSR reçue, d'un
// certificat émis ou d'une autorité — relève d'un algorithme et d'une taille
// admis. `subject` nomme l'objet contrôlé pour que le constat soit lisible.
func CheckPublicKey(subject string, pub crypto.PublicKey) Findings {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits < MinRSABits {
			return Findings{fail(ReqKeyLength,
				"%s: clé RSA de %d bits, minimum requis %d", subject, bits, MinRSABits)}
		}
		return nil
	case *ecdsa.PublicKey:
		if key.Curve == nil {
			return Findings{fail(ReqKeyLength, "%s: courbe elliptique indéterminée", subject)}
		}
		switch key.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return Findings{fail(ReqKeyLength,
				"%s: courbe %s hors des courbes NIST admises (P-256, P-384, P-521)",
				subject, key.Curve.Params().Name)}
		}
		if bits := key.Curve.Params().BitSize; bits < MinECDSABits {
			return Findings{fail(ReqKeyLength,
				"%s: courbe de %d bits, minimum requis %d", subject, bits, MinECDSABits)}
		}
		return nil
	case ed25519.PublicKey:
		// Ed25519 n'est pas retenu par TS 119 312 pour les certificats de ces
		// services : refusé explicitement plutôt que toléré par omission.
		return Findings{fail(ReqSignatureAlgorithm,
			"%s: Ed25519 n'est pas une suite admise par ETSI TS 119 312 pour ce service", subject)}
	default:
		return Findings{fail(ReqSignatureAlgorithm,
			"%s: algorithme de clé publique non reconnu (%T)", subject, pub)}
	}
}

// admittedSignatureAlgorithms énumère les algorithmes de signature acceptés
// sur un certificat, une CSR ou une CRL. Tout ce qui repose sur SHA-1 ou MD5
// en est absent : le refus est explicite, jamais implicite.
var admittedSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.SHA256WithRSA:    true,
	x509.SHA384WithRSA:    true,
	x509.SHA512WithRSA:    true,
	x509.SHA256WithRSAPSS: true,
	x509.SHA384WithRSAPSS: true,
	x509.SHA512WithRSAPSS: true,
	x509.ECDSAWithSHA256:  true,
	x509.ECDSAWithSHA384:  true,
	x509.ECDSAWithSHA512:  true,
}

// CheckSignatureAlgorithm vérifie l'algorithme dont un objet signé est revêtu.
func CheckSignatureAlgorithm(subject string, algo x509.SignatureAlgorithm) Findings {
	if !admittedSignatureAlgorithms[algo] {
		return Findings{fail(ReqSignatureAlgorithm,
			"%s: algorithme de signature %s refusé (SHA-1 et MD5 sont proscrits par ETSI TS 119 312)",
			subject, algo)}
	}
	return nil
}

// admittedHashes énumère les fonctions de hachage acceptées, notamment pour
// le messageImprint d'une requête RFC 3161. SHA-1 en est volontairement
// absent.
var admittedHashes = map[crypto.Hash]bool{
	crypto.SHA256: true,
	crypto.SHA384: true,
	crypto.SHA512: true,
}

// AdmittedHashes retourne les fonctions de hachage acceptées, dans un ordre
// stable, pour publication sur l'API de politique du service.
func AdmittedHashes() []crypto.Hash {
	return []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
}

// HashAdmitted indique si une fonction de hachage est acceptée. Utilisé sur le
// chemin chaud d'une requête d'horodatage, où seule la décision compte.
func HashAdmitted(h crypto.Hash) bool { return admittedHashes[h] }

// CheckHashAlgorithm produit un constat exploitable pour un rapport.
func CheckHashAlgorithm(subject string, h crypto.Hash) Findings {
	if !HashAdmitted(h) {
		return Findings{fail(ReqHashAlgorithm,
			"%s: fonction de hachage %s refusée par la politique", subject, h)}
	}
	return nil
}
