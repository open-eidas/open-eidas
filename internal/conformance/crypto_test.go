package conformance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestCheckPublicKey(t *testing.T) {
	// Une clé RSA de 3072 bits est coûteuse à générer : une seule est
	// produite ici, pour le cas passant.
	rsaOK, err := rsa.GenerateKey(rand.Reader, MinRSABits)
	if err != nil {
		t.Fatalf("génération RSA-%d: %v", MinRSABits, err)
	}
	rsaTropCourte, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("génération RSA-2048: %v", err)
	}
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("génération Ed25519: %v", err)
	}

	cas := []struct {
		nom      string
		clé      crypto.PublicKey
		exigence *Requirement
	}{
		{"RSA-3072 admise", rsaOK.Public(), nil},
		{"P-256 admise", testKey(t).Public(), nil},
		{"RSA-2048 refusée", rsaTropCourte.Public(), &ReqKeyLength},
		{"Ed25519 refusée", ed, &ReqSignatureAlgorithm},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			got := CheckPublicKey("sujet de test", c.clé)
			if c.exigence == nil {
				assertConforme(t, got)
				return
			}
			assertBlocking(t, got, *c.exigence)
		})
	}
}

// P-224 est une courbe NIST valide pour crypto/elliptic mais hors des courbes
// admises : le refus doit être explicite, pas un effet de bord de la taille.
func TestCheckPublicKeyRefuseCourbeHorsListe(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("génération P-224: %v", err)
	}
	assertBlocking(t, CheckPublicKey("sujet de test", key.Public()), ReqKeyLength)
}

func TestCheckSignatureAlgorithm(t *testing.T) {
	admis := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256, x509.ECDSAWithSHA512,
	}
	for _, algo := range admis {
		if err := CheckSignatureAlgorithm("sujet", algo).Err(); err != nil {
			t.Errorf("%s devrait être admis: %v", algo, err)
		}
	}

	// Le refus de SHA-1 et MD5 est le point de contrôle : il doit être
	// explicite, y compris pour un algorithme que Go sait encore encoder.
	refusés := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.PureEd25519,
	}
	for _, algo := range refusés {
		assertBlocking(t, CheckSignatureAlgorithm("sujet", algo), ReqSignatureAlgorithm)
	}
}

func TestHashAdmitted(t *testing.T) {
	for _, h := range AdmittedHashes() {
		if !HashAdmitted(h) {
			t.Errorf("%s devrait être admise", h)
		}
	}
	// SHA-1 doit être refusée : c'est ce qui fait répondre badAlg à une
	// requête RFC 3161 qui la demanderait.
	if HashAdmitted(crypto.SHA1) {
		t.Error("SHA-1 ne doit jamais être admise (ETSI TS 119 312)")
	}
	assertBlocking(t, CheckHashAlgorithm("imprint", crypto.SHA1), ReqHashAlgorithm)
}
