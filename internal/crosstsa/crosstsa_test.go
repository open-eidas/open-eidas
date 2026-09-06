package crosstsa

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// fakeTSA sert de TSA tierce de test : elle rejoue exactement le protocole
// RFC 3161, avec sa propre clé, indépendante du service sous test.
func fakeTSA(t *testing.T) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Third-Party TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tok := timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              time.Now(),
			Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
			Nonce:             req.Nonce,
			AddTSACertificate: true,
		}
		resp, err := tok.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			t.Logf("échec de la TSA de test: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	}))
	return srv, cert
}

func TestSealAttestsAgainstThirdPartyTSA(t *testing.T) {
	srv, cert := fakeTSA(t)
	defer srv.Close()

	digest := sha256.Sum256([]byte("tête de chaîne de test"))
	client := New(Options{URLs: []string{srv.URL}, Timeout: 5 * time.Second})

	attestations := client.Seal(context.Background(), digest[:], crypto.SHA256)
	if len(attestations) != 1 {
		t.Fatalf("une attestation attendue, %d obtenue(s)", len(attestations))
	}
	att := attestations[0]
	if att.TSA != cert.Subject.String() {
		t.Errorf("TSA attendue %q, obtenue %q", cert.Subject.String(), att.TSA)
	}
	if att.GenTime == "" || att.Serial == "" || att.Token == "" {
		t.Errorf("attestation incomplète: %+v", att)
	}
}

func TestSealSkipsUnreachableTSAWithoutFailing(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	client := New(Options{URLs: []string{"http://127.0.0.1:1"}, Timeout: 500 * time.Millisecond})

	if got := client.Seal(context.Background(), digest[:], crypto.SHA256); len(got) != 0 {
		t.Errorf("une TSA injoignable ne doit produire aucune attestation, obtenu %+v", got)
	}
}

func TestSealContinuesPastOneFailingTSA(t *testing.T) {
	srv, cert := fakeTSA(t)
	defer srv.Close()

	digest := sha256.Sum256([]byte("x"))
	client := New(Options{
		URLs:    []string{"http://127.0.0.1:1", srv.URL},
		Timeout: 2 * time.Second,
	})

	attestations := client.Seal(context.Background(), digest[:], crypto.SHA256)
	if len(attestations) != 1 || attestations[0].TSA != cert.Subject.String() {
		t.Fatalf("l'échec d'une TSA ne doit pas empêcher les autres de répondre: %+v", attestations)
	}
}
