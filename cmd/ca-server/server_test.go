package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-eidas/open-eidas/internal/ca"
	"github.com/open-eidas/open-eidas/internal/castore"
	"github.com/open-eidas/open-eidas/internal/raflow"
)

func testSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newTestServer(t *testing.T) (*Server, *ca.Issuer, castore.Store, crypto.Signer) {
	t.Helper()
	ctx := context.Background()
	store := castore.NewMemory()
	issuingSigner := testSigner(t)

	h, err := ca.RunCeremony(ctx, ca.CeremonyOptions{
		RootSigner: testSigner(t), IssuingSigner: issuingSigner,
		Store: store, Operator: "opératrice-de-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ca.New(ca.Options{
		Signer: issuingSigner, Certificate: h.Issuing,
		Chain: []*x509.Certificate{h.Root}, Store: store,
		PublicURL: "https://pki.open-eidas.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := raflow.New(raflow.Options{
		Store: store, Issuer: issuer, HMACSecret: "secret-de-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(issuer, flow, logger, "test", 64*1024), issuer, store, issuingSigner
}

func get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// Une CRL publiée par un AUTRE processus — c'est ce que fait
// `ca-server revoke`, lancé à côté du service — doit être servie
// immédiatement. Servir un instantané mémoire reviendrait à publier une
// révocation que personne ne voit : elle ne protégerait personne.
func TestCRLServieDepuisLeRegistreEtNonDuCache(t *testing.T) {
	ctx := context.Background()
	s, issuer, store, issuingSigner := newTestServer(t)

	if err := s.StartCRLPublication(ctx, time.Hour); err != nil {
		t.Fatalf("publication initiale: %v", err)
	}
	premiere := servedCRLNumber(t, s)

	// Un second émetteur, adossé au même registre, publie une CRL — comme le
	// ferait la commande `revoke` dans son propre processus.
	autre, err := ca.New(ca.Options{
		Signer: issuingSigner, Certificate: issuer.Certificate(),
		Chain: issuer.Chain(), Store: store, PublicURL: "https://pki.open-eidas.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	publiee, err := autre.PublishCRL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if publiee.Number <= premiere {
		t.Fatalf("la seconde CRL (%d) devrait succéder à la première (%d)", publiee.Number, premiere)
	}

	if servie := servedCRLNumber(t, s); servie != publiee.Number {
		t.Fatalf("CRL servie n° %d, attendu %d : le service sert son cache au lieu du registre",
			servie, publiee.Number)
	}
}

func servedCRLNumber(t *testing.T, s *Server) int64 {
	t.Helper()
	rec := get(t, s, s.crlName)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s : code %d", s.crlName, rec.Code)
	}
	crl, err := x509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("CRL servie illisible: %v", err)
	}
	return crl.Number.Int64()
}

// Le certificat de la CA est servi au format DER à l'adresse exacte que porte
// l'extension AIA ca_issuers des certificats émis : un vérificateur tiers doit
// pouvoir le récupérer tel quel.
func TestCertificatDeCAServiEnDER(t *testing.T) {
	s, issuer, _, _ := newTestServer(t)

	rec := get(t, s, s.caName)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	cert, err := x509.ParseCertificate(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("certificat servi illisible: %v", err)
	}
	if cert.Subject.String() != issuer.Certificate().Subject.String() {
		t.Errorf("certificat servi : %s", cert.Subject)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/pkix-cert" {
		t.Errorf("Content-Type %q", got)
	}
}

// Sans CRL servable, le service ne doit pas se déclarer sain : il ne peut
// plus dire ce qui est révoqué (ETSI EN 319 411-1 §6.3.10).
func TestHealthzDegradeSansCRL(t *testing.T) {
	s, _, _, _ := newTestServer(t)

	if rec := get(t, s, "/healthz"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d, attendu 503 tant qu'aucune CRL n'est publiée", rec.Code)
	}
	if err := s.StartCRLPublication(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if rec := get(t, s, "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("code %d, attendu 200 une fois la CRL publiée", rec.Code)
	}
}
