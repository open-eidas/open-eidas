package enroll

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-eidas/open-eidas/internal/raflow"
)

const secret = "secret-partagé-de-test"

func testSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// selfSigned fabrique un certificat que le serveur de test rendra comme s'il
// venait de la CA : le client n'a pas à en vérifier la chaîne, c'est le
// service appelant qui le fera contre sa propre clé.
func selfSigned(t *testing.T, cn string) string {
	t.Helper()
	key := testSigner(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	c, err := NewClient(Options{
		Endpoint: endpoint, Profile: "tsa_signer", HMACSecret: secret,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// La signature transmise doit être exactement celle que la machine à états
// recalcule côté serveur : client et serveur partagent la même fonction, il
// n'y a rien à deviner.
func TestSignatureTransmiseCorrespondACelleAttendueParLaCA(t *testing.T) {
	var vue string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		block, _ := pem.Decode([]byte(req.PKCS10))
		if block == nil {
			t.Error("la CSR doit être transmise en PEM")
			return
		}
		if attendu := raflow.Signature(block.Bytes, secret); req.Signature != attendu {
			t.Errorf("signature %q, attendu %q", req.Signature, attendu)
		}
		vue = req.Profile
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(response{State: "PENDING", TransactionID: "tx", RetryAfter: 60})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := newClient(t, srv.URL)
	c.opts.Timeout = time.Second
	if _, err := c.Request(ctx, testSigner(t), Subject{CommonName: "tsa.test"}); err == nil {
		t.Fatal("une demande restée en attente doit finir par expirer")
	}
	if vue != "tsa_signer" {
		t.Errorf("profil transmis %q", vue)
	}
}

// Le client doit revenir tant que la demande attend une décision : c'est ce
// qui permet à un opérateur RA humain de prendre son temps.
func TestBoucleDeScrutationJusquALApprobation(t *testing.T) {
	var appels atomic.Int32
	cert := selfSigned(t, "tsa.test")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if appels.Add(1) < 3 {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(response{State: "PENDING", TransactionID: "tx", RetryAfter: 1})
			return
		}
		_ = json.NewEncoder(w).Encode(response{
			State: "ISSUED", TransactionID: "tx",
			Certificate: cert, Chain: []string{selfSigned(t, "Issuing CA")},
		})
	}))
	defer srv.Close()

	res, err := newClient(t, srv.URL).Request(context.Background(), testSigner(t), Subject{CommonName: "tsa.test"})
	if err != nil {
		t.Fatalf("enrôlement: %v", err)
	}
	if res.Certificate.Subject.CommonName != "tsa.test" {
		t.Errorf("certificat inattendu: %s", res.Certificate.Subject)
	}
	if len(res.Chain) != 1 {
		t.Errorf("chaîne d'émission attendue, obtenu %d certificats", len(res.Chain))
	}
	if appels.Load() != 3 {
		t.Errorf("%d appels, attendu 3", appels.Load())
	}
}

// Un refus de la RA doit remonter tel quel : le service appelant doit pouvoir
// afficher qui a refusé et pourquoi, pas un « erreur 403 » opaque.
func TestRefusDeLaRARemonteLeMotif(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(response{Error: "demande rejetée (opérateur ra-1 : sujet non reconnu)"})
	}))
	defer srv.Close()

	_, err := newClient(t, srv.URL).Request(context.Background(), testSigner(t), Subject{CommonName: "tsa.test"})
	if err == nil {
		t.Fatal("un refus doit produire une erreur")
	}
	if !strings.Contains(err.Error(), "sujet non reconnu") {
		t.Errorf("le motif du refus doit remonter: %v", err)
	}
}

func TestNewClientRefuseUneConfigurationIncomplete(t *testing.T) {
	cas := []struct {
		nom  string
		opts Options
	}{
		{"sans endpoint", Options{Profile: "tsa_signer", HMACSecret: secret}},
		{"sans profil", Options{Endpoint: "http://ca:8320/api/v1/enroll", HMACSecret: secret}},
		// Un enrôlement sans secret serait anonyme : refusé côté client aussi,
		// pour que l'erreur soit lisible avant l'appel réseau.
		{"sans secret", Options{Endpoint: "http://ca:8320/api/v1/enroll", Profile: "tsa_signer"}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if _, err := NewClient(c.opts); err == nil {
				t.Fatal("configuration incomplète acceptée")
			}
		})
	}
}

// La CSR produite doit être signée en SHA-256 : SHA-1 serait refusé par la CA
// (ETSI TS 119 312), autant ne jamais le produire.
func TestCSRSigneeEnSHA256(t *testing.T) {
	der, _, err := buildCSR(testSigner(t), Subject{CommonName: "tsa.test"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("algorithme de signature %s", csr.SignatureAlgorithm)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("la CSR doit être auto-signée valide: %v", err)
	}
}
