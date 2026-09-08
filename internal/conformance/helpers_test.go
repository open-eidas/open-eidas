package conformance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// Les tests de ce paquet fabriquent de vrais certificats plutôt que des
// structures x509.Certificate remplies à la main : c'est le DER réellement
// encodé, avec ses criticités, qui doit satisfaire les règles — c'est aussi
// ainsi que le moteur d'émission les appellera.

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("génération de clé de test: %v", err)
	}
	return key
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("tirage du numéro de série: %v", err)
	}
	return n.Add(n, big.NewInt(1))
}

func skiOf(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	// Un identifiant arbitraire mais stable suffit aux tests : la dérivation
	// réelle (SHA-1 de la BIT STRING, RFC 5280 §4.2.1.2 méthode 1) est celle
	// d'internal/ca, contrôlée là-bas.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("sérialisation de la clé publique: %v", err)
	}
	return der[:20]
}

// signCert encode le modèle avec l'émetteur donné et relit le résultat, de
// sorte que les tests portent sur le certificat tel qu'il existera réellement.
func signCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("création du certificat de test: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("relecture du certificat de test: %v", err)
	}
	return cert
}

// rootCA fabrique une racine auto-signée conforme, et retourne sa clé.
func rootCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := testKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "Open eIDAS Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skiOf(t, key.Public()),
	}
	return signCert(t, tmpl, tmpl, key.Public(), key), key
}

// leafTemplate produit un modèle d'entité finale valide, que chaque test
// dégrade sur le seul point qu'il vérifie.
func leafTemplate(t *testing.T, issuer *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "unité de test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          skiOf(t, pub),
		AuthorityKeyId:        issuer.SubjectKeyId,
		ExtraExtensions: []pkix.Extension{{
			Id:       oidExtKeyUsage,
			Critical: true,
			Value:    mustMarshalEKU(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}),
		}},
	}
}

func mustMarshalEKU(t *testing.T, oids []asn1.ObjectIdentifier) []byte {
	t.Helper()
	der, err := asn1.Marshal(oids)
	if err != nil {
		t.Fatalf("encodage de l'extendedKeyUsage: %v", err)
	}
	return der
}

// assertBlocking exige qu'au moins un constat bloquant cite l'exigence
// attendue, et rien d'autre de bloquant : un test qui laisse passer un second
// écart ne prouve pas ce qu'il croit prouver.
func assertBlocking(t *testing.T, got Findings, want Requirement) {
	t.Helper()
	blocking := got.Blocking()
	if len(blocking) == 0 {
		t.Fatalf("aucun constat bloquant, attendu %s", want)
	}
	for _, f := range blocking {
		if f.Requirement != want {
			t.Errorf("constat bloquant inattendu: %s", f)
		}
	}
}

func assertConforme(t *testing.T, got Findings) {
	t.Helper()
	if err := got.Err(); err != nil {
		t.Fatalf("certificat attendu conforme: %v", err)
	}
}
