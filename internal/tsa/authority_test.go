package tsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

var testPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}

// testKey est générée une seule fois pour tout le paquet : RSA-3072 est le
// minimum admis par ETSI TS 119 312, et son coût de génération n'a pas à être
// payé à chaque test.
var (
	testKeyOnce sync.Once
	testKeyRSA  *rsa.PrivateKey
)

func sharedKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		testKeyRSA = key
	})
	return testKeyRSA
}

// testCertificate produit un certificat TSU réellement conforme au profil
// ETSI EN 319 421 §7.7.2 : c'est ce que la CA du projet émet, et c'est donc
// sur ce matériel que la TSA doit être exercée.
func testCertificate(t *testing.T, key *rsa.PrivateKey, eku ...asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	if len(eku) == 0 {
		eku = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}} // id-kp-timeStamping
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	serial.SetBit(serial, 127, 1)

	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)

	ekuValue, err := asn1.Marshal(eku)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test TSU"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
		SubjectKeyId:          sum[:20],
		AuthorityKeyId:        sum[:20],
		// extendedKeyUsage doit être marqué critique : crypto/x509 ne le
		// permet pas via le champ ExtKeyUsage, d'où l'extension explicite.
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
			Critical: true,
			Value:    ekuValue,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newTestAuthority(t *testing.T) *Authority {
	t.Helper()
	key := sharedKey(t)
	cert := testCertificate(t, key)
	authority, _, err := New(Options{
		Signer:        key,
		Certificate:   cert,
		Policy:        testPolicy,
		Accuracy:      time.Second,
		SigningDigest: crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func mustRequest(t *testing.T, req timestamp.Request) []byte {
	t.Helper()
	der, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestTimestampGranted(t *testing.T) {
	authority := newTestAuthority(t)
	digest := sha256.Sum256([]byte("facture-2026-001.pdf"))
	nonce := big.NewInt(424242)

	respDER, err := authority.Timestamp(mustRequest(t, timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: digest[:],
		Certificates:  true,
		Nonce:         nonce,
	}))
	if err != nil {
		t.Fatalf("horodatage refusé: %v", err)
	}

	token, err := timestamp.ParseResponse(respDER)
	if err != nil {
		t.Fatalf("réponse illisible: %v", err)
	}
	if string(token.HashedMessage) != string(digest[:]) {
		t.Error("le messageImprint du jeton ne correspond pas à l'empreinte soumise")
	}
	if token.Nonce == nil || token.Nonce.Cmp(nonce) != 0 {
		t.Error("le nonce n'a pas été repris dans le jeton")
	}
	if !token.Policy.Equal(testPolicy) {
		t.Errorf("politique inattendue: %s", token.Policy)
	}
	if len(token.Certificates) == 0 {
		t.Error("le certificat TSU était demandé mais absent du jeton")
	}
	if token.Time.IsZero() {
		t.Error("genTime absent du jeton")
	}
}

func TestTimestampRejectsSHA1(t *testing.T) {
	authority := newTestAuthority(t)
	digest := make([]byte, 20)

	_, err := authority.Timestamp(mustRequest(t, timestamp.Request{
		HashAlgorithm: crypto.SHA1,
		HashedMessage: digest,
	}))

	var rejection *Rejection
	if !errors.As(err, &rejection) {
		t.Fatalf("un refus était attendu, obtenu: %v", err)
	}
	if rejection.Failure != timestamp.BadAlgorithm {
		t.Errorf("failureInfo attendu badAlg, obtenu %v", rejection.Failure)
	}
}

func TestTimestampRejectsForeignPolicy(t *testing.T) {
	authority := newTestAuthority(t)
	digest := sha256.Sum256([]byte("x"))

	_, err := authority.Timestamp(mustRequest(t, timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: digest[:],
		TSAPolicyOID:  asn1.ObjectIdentifier{1, 2, 3, 4},
	}))

	var rejection *Rejection
	if !errors.As(err, &rejection) {
		t.Fatalf("un refus était attendu, obtenu: %v", err)
	}
	if rejection.Failure != timestamp.UnacceptedPolicy {
		t.Errorf("failureInfo attendu unacceptedPolicy, obtenu %v", rejection.Failure)
	}
}

// Le certificat de test est par ailleurs entièrement conforme : seul l'usage
// étendu diffère, de sorte que le refus prouve bien la règle visée et non un
// autre écart au passage.
func TestNewRejectsCertificateWithoutTimeStampingEKU(t *testing.T) {
	key := sharedKey(t)
	serverAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	cert := testCertificate(t, key, serverAuth)

	if _, _, err := New(Options{
		Signer:        key,
		Certificate:   cert,
		Policy:        testPolicy,
		SigningDigest: crypto.SHA256,
	}); err == nil {
		t.Fatal("un certificat sans id-kp-timeStamping doit être refusé au démarrage")
	}
}

type brokenClock struct{}

func (brokenClock) Now() (time.Time, error) {
	return time.Time{}, errors.New("aucune source de temps jointe")
}

func TestTimestampRefusesWhenTimeIsNotTraceable(t *testing.T) {
	authority := newTestAuthority(t)
	authority.opts.Clock = brokenClock{}
	digest := sha256.Sum256([]byte("x"))

	_, err := authority.Timestamp(mustRequest(t, timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: digest[:],
	}))

	var rejection *Rejection
	if !errors.As(err, &rejection) {
		t.Fatalf("un refus était attendu, obtenu: %v", err)
	}
	if rejection.Failure != timestamp.TimeNotAvailable {
		t.Errorf("failureInfo attendu timeNotAvailable, obtenu %v", rejection.Failure)
	}
}
