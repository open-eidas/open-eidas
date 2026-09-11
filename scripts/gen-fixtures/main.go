// Commande gen-fixtures régénère le corpus de non-régression Go↔Rust
// (tests/fixtures/rfc3161/) à partir du code Go de référence, conformément au
// jalon J0 du plan de migration
// (/home/philippe/.claude/plans/witty-hopping-nest.md).
//
// La bi-clé RSA et le certificat TSU de test sont dérivés d'une graine fixe :
// ils ne sont PAS des secrets, uniquement du matériel de test committé pour
// que le portage Rust dispose d'un jeu de données reproductible. Ne jamais
// réutiliser cette clé en dehors de ce corpus de tests.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/open-eidas/open-eidas/internal/tsa"
)

const fixturesDir = "tests/fixtures/rfc3161"

var testPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}

// fixedGenTime est l'horloge injectée pour toutes les fixtures : figée pour
// que le champ genTime des jetons générés soit reproductible.
var fixedGenTime = time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() (time.Time, error) { return fixedGenTime, nil }

type brokenClock struct{}

func (brokenClock) Now() (time.Time, error) {
	return time.Time{}, errors.New("aucune source de temps jointe")
}

// deterministicRand fournit un flux d'octets reproductible d'une exécution à
// l'autre : la clé de test est ainsi identique à chaque régénération du
// corpus, ce qui simplifie les diffs de revue.
func deterministicRand(seed int64) *mrand.Rand {
	return mrand.New(mrand.NewSource(seed))
}

func generateTestKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(deterministicRand(42), 3072)
}

// generateTestCertificate reproduit le profil de testCertificate
// (internal/tsa/authority_test.go), seul gabarit déjà connu pour satisfaire
// internal/conformance.CheckTSUCertificate. La fenêtre de validité est
// relative à l'instant de génération (et non figée) : ETSI EN 319 411-1
// §6.3.2 plafonne la durée de vie d'un certificat TSU à 28080h (~3,2 ans),
// donc une date fixe finirait par expirer et casser une régénération future.
func generateTestCertificate(key *rsa.PrivateKey) (*x509.Certificate, error) {
	serialBytes := make([]byte, 16)
	deterministicRand(44).Read(serialBytes)
	serialNum := new(big.Int).SetBytes(serialBytes)
	serialNum.SetBit(serialNum, 127, 1) // garantit un nombre positif de 128 bits

	eku := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}} // id-kp-timeStamping
	ekuValue, err := asn1.Marshal(eku)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serialNum,
		Subject:               pkix.Name{CommonName: "Open eIDAS Time-Stamping Unit (fixture de test)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(28000 * time.Hour), // < plafond ETSI de 28080h
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
		SubjectKeyId:          sum[:20],
		AuthorityKeyId:        sum[:20],
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // extendedKeyUsage
			Critical: true,
			Value:    ekuValue,
		}},
	}
	der, err := x509.CreateCertificate(deterministicRand(43), tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

type fixtureCase struct {
	name        string
	request     timestamp.Request
	clock       tsa.Clock // nil => fixedClock
	wantGranted bool
	wantFailure timestamp.FailureInfo
	notes       string
}

type meta struct {
	Name          string `json:"name"`
	Notes         string `json:"notes"`
	WantGranted   bool   `json:"want_granted"`
	WantFailure   string `json:"want_failure,omitempty"`
	HasResponse   bool   `json:"has_response"`
	HashAlgorithm string `json:"hash_algorithm"`
}

func digestOf(alg crypto.Hash, msg string) []byte {
	h := alg.New()
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixtures:", err)
		os.Exit(1)
	}
}

func run() error {
	key, err := generateTestKey()
	if err != nil {
		return fmt.Errorf("génération de la clé de test: %w", err)
	}
	cert, err := generateTestCertificate(key)
	if err != nil {
		return fmt.Errorf("génération du certificat de test: %w", err)
	}

	keysDir := filepath.Join(fixturesDir, "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		return err
	}
	if err := writeKeyAndCert(keysDir, key, cert); err != nil {
		return err
	}

	nonce := big.NewInt(424242)
	cases := []fixtureCase{
		{
			name: "granted-sha256-with-cert",
			request: timestamp.Request{
				HashAlgorithm: crypto.SHA256,
				HashedMessage: digestOf(crypto.SHA256, "facture-2026-001.pdf"),
				Certificates:  true,
				Nonce:         nonce,
			},
			wantGranted: true,
			notes:       "cas nominal : demande de chaîne, nonce fourni, SHA-256.",
		},
		{
			name: "granted-sha256-no-cert-no-nonce",
			request: timestamp.Request{
				HashAlgorithm: crypto.SHA256,
				HashedMessage: digestOf(crypto.SHA256, "contrat-signe.pdf"),
				Certificates:  false,
			},
			wantGranted: true,
			notes:       "cas nominal sans demande de certificat ni nonce.",
		},
		{
			name: "granted-sha512",
			request: timestamp.Request{
				HashAlgorithm: crypto.SHA512,
				HashedMessage: digestOf(crypto.SHA512, "livrable-v2.zip"),
				Certificates:  true,
			},
			wantGranted: true,
			notes:       "algorithme de hachage alternatif accepté (SHA-512).",
		},
		{
			name: "rejects-sha1",
			request: timestamp.Request{
				HashAlgorithm: crypto.SHA1,
				HashedMessage: make([]byte, 20),
			},
			wantGranted: false,
			wantFailure: timestamp.BadAlgorithm,
			notes:       "SHA-1 est refusé par la politique (ETSI TS 119 312).",
		},
		{
			name: "rejects-foreign-policy",
			request: timestamp.Request{
				HashAlgorithm: crypto.SHA256,
				HashedMessage: digestOf(crypto.SHA256, "x"),
				TSAPolicyOID:  asn1.ObjectIdentifier{1, 2, 3, 4},
			},
			wantGranted: false,
			wantFailure: timestamp.UnacceptedPolicy,
			notes:       "politique demandée différente de celle servie par cette TSA.",
		},
		{
			name: "rejects-time-not-traceable",
			request: timestamp.Request{
				HashAlgorithm: crypto.SHA256,
				HashedMessage: digestOf(crypto.SHA256, "x"),
			},
			clock:       brokenClock{},
			wantGranted: false,
			wantFailure: timestamp.TimeNotAvailable,
			notes:       "l'horloge injectée signale l'absence de traçabilité UTC.",
		},
	}

	for _, c := range cases {
		if err := generateCase(cert, key, c); err != nil {
			return fmt.Errorf("cas %q: %w", c.name, err)
		}
		fmt.Println("généré:", c.name)
	}
	return nil
}

func generateCase(cert *x509.Certificate, key *rsa.PrivateKey, c fixtureCase) error {
	clock := c.clock
	if clock == nil {
		clock = fixedClock{}
	}
	authority, _, err := tsa.New(tsa.Options{
		Signer:        key,
		Certificate:   cert,
		Policy:        testPolicy,
		Accuracy:      time.Second,
		SigningDigest: crypto.SHA256,
		Clock:         clock,
	})
	if err != nil {
		return fmt.Errorf("construction de l'autorité: %w", err)
	}

	reqDER, err := c.request.Marshal()
	if err != nil {
		return fmt.Errorf("encodage de la requête: %w", err)
	}

	dir := filepath.Join(fixturesDir, c.name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "request.der"), reqDER, 0o644); err != nil {
		return err
	}

	m := meta{
		Name:          c.name,
		Notes:         c.notes,
		WantGranted:   c.wantGranted,
		HashAlgorithm: c.request.HashAlgorithm.String(),
	}

	respDER, tsErr := authority.Timestamp(reqDER)
	if c.wantGranted {
		if tsErr != nil {
			return fmt.Errorf("horodatage refusé alors qu'il devait être accordé: %w", tsErr)
		}
		if err := os.WriteFile(filepath.Join(dir, "response.der"), respDER, 0o644); err != nil {
			return err
		}
		m.HasResponse = true
	} else {
		var rejection *tsa.Rejection
		if !errors.As(tsErr, &rejection) {
			return fmt.Errorf("un refus était attendu, obtenu: %v", tsErr)
		}
		if rejection.Failure != c.wantFailure {
			return fmt.Errorf("failureInfo attendu %v, obtenu %v", c.wantFailure, rejection.Failure)
		}
		m.WantFailure = rejection.Failure.String()
	}

	metaBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	metaBytes = append(metaBytes, '\n')
	return os.WriteFile(filepath.Join(dir, "meta.json"), metaBytes, 0o644)
}

func writeKeyAndCert(dir string, key *rsa.PrivateKey, cert *x509.Certificate) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "tsu-test-key.pem"), "PRIVATE KEY", keyDER); err != nil {
		return err
	}
	return writePEM(filepath.Join(dir, "tsu-test-cert.pem"), "CERTIFICATE", cert.Raw)
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
