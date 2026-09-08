package raflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"

	"github.com/open-eidas/open-eidas/internal/ca"
	"github.com/open-eidas/open-eidas/internal/castore"
)

const secret = "secret-partagé-de-test"

type recorder struct{ events []string }

func (r *recorder) Append(event string, _ map[string]any) error {
	r.events = append(r.events, event)
	return nil
}

func (r *recorder) has(event string) bool {
	for _, e := range r.events {
		if e == event {
			return true
		}
	}
	return false
}

func testSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newFlow(t *testing.T) (*Flow, castore.Store, *recorder) {
	t.Helper()
	ctx := context.Background()
	store := castore.NewMemory()
	rec := &recorder{}
	issuingSigner := testSigner(t)

	h, err := ca.RunCeremony(ctx, ca.CeremonyOptions{
		RootSigner: testSigner(t), IssuingSigner: issuingSigner,
		Store: store, Recorder: rec, Operator: "opératrice-de-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ca.New(ca.Options{
		Signer: issuingSigner, Certificate: h.Issuing,
		Chain: []*x509.Certificate{h.Root}, Store: store, Recorder: rec,
		PublicURL: "https://pki.open-eidas.test", OCSPURL: "http://ocsp.open-eidas.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := New(Options{Store: store, Issuer: issuer, Recorder: rec, HMACSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	return flow, store, rec
}

func csrDER(t *testing.T, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, testSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func submit(t *testing.T, f *Flow, der []byte) *Result {
	t.Helper()
	res, err := f.Submit(context.Background(), der, ca.ProfileTSASigner, Signature(der, secret))
	if err != nil {
		t.Fatalf("soumission: %v", err)
	}
	return res
}

// Le test le plus important du paquet : il n'existe aucun chemin par lequel
// une demande atteint ISSUED sans qu'un opérateur nommé l'ait approuvée. C'est
// exactement ce qu'OpenXPKI contournait silencieusement par sa règle
// d'éligibilité (voir INDEPENDANCE.md).
func TestAucunCheminVersIssuedSansApprobation(t *testing.T) {
	f, store, _ := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")

	// Autant de soumissions que l'on veut : l'état ne bouge pas.
	for i := 0; i < 5; i++ {
		res := submit(t, f, der)
		if res.State != castore.StatePending {
			t.Fatalf("soumission %d: état %s au lieu de PENDING", i, res.State)
		}
		if res.Certificate != nil {
			t.Fatal("un certificat a été délivré sans approbation")
		}
	}

	r, err := store.RequestByTransactionID(ctx, TransactionID(der))
	if err != nil {
		t.Fatal(err)
	}
	if r.State != castore.StatePending || r.Operator != "" {
		t.Fatalf("la demande a changé d'état sans décision: %s / %q", r.State, r.Operator)
	}
}

func TestApprobationExigeUnOperateur(t *testing.T) {
	f, _, _ := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")
	submit(t, f, der)

	if _, err := f.Approve(ctx, TransactionID(der), "", "approuvé"); err == nil {
		t.Fatal("une approbation anonyme doit être refusée")
	}
	if _, err := f.Reject(ctx, TransactionID(der), "", "refusé"); err == nil {
		t.Fatal("un rejet anonyme doit être refusé")
	}
}

func TestCycleCompletJusquAuCertificat(t *testing.T) {
	f, store, rec := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")

	if res := submit(t, f, der); res.State != castore.StatePending {
		t.Fatalf("état initial %s", res.State)
	}
	if _, err := f.Approve(ctx, TransactionID(der), "opératrice-ra", "identité vérifiée"); err != nil {
		t.Fatalf("approbation: %v", err)
	}

	res := submit(t, f, der)
	if res.State != castore.StateIssued || res.Certificate == nil {
		t.Fatalf("après approbation, attendu ISSUED avec certificat, obtenu %s", res.State)
	}
	if len(res.Chain) == 0 {
		t.Error("la chaîne d'émission doit accompagner le certificat")
	}

	// L'identité de l'opérateur doit rester consignée : c'est elle qu'un
	// auditeur vient chercher.
	r, err := store.RequestByTransactionID(ctx, TransactionID(der))
	if err != nil {
		t.Fatal(err)
	}
	if r.Operator != "opératrice-ra" || r.State != castore.StateIssued {
		t.Fatalf("décision perdue: %q / %s", r.Operator, r.State)
	}
	if !rec.has("ca.request_approved") || !rec.has("ca.certificate_issued") {
		t.Errorf("journal d'audit incomplet: %v", rec.events)
	}
}

// La ré-émission après émission doit rendre le même certificat, pas en signer
// un second : c'est ce qui rend la boucle de scrutation du client inoffensive.
func TestSoumissionApresEmissionRendLeMemeCertificat(t *testing.T) {
	f, _, _ := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")

	submit(t, f, der)
	if _, err := f.Approve(ctx, TransactionID(der), "opératrice-ra", ""); err != nil {
		t.Fatal(err)
	}
	first := submit(t, f, der)
	second := submit(t, f, der)

	if first.Certificate.SerialNumber.Cmp(second.Certificate.SerialNumber) != 0 {
		t.Fatal("une seconde soumission a produit un nouveau certificat")
	}
}

func TestIdempotenceSurCSRIdentique(t *testing.T) {
	f, store, _ := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")

	submit(t, f, der)
	submit(t, f, der)

	demandes, err := store.Requests(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(demandes) != 1 {
		t.Fatalf("attendu une seule demande pour une CSR re-soumise, obtenu %d", len(demandes))
	}
}

func TestRejetEstDefinitifEtExplique(t *testing.T) {
	f, _, rec := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")
	submit(t, f, der)

	if _, err := f.Reject(ctx, TransactionID(der), "opérateur-ra", "sujet non reconnu"); err != nil {
		t.Fatalf("rejet: %v", err)
	}
	_, err := f.Submit(ctx, der, ca.ProfileTSASigner, Signature(der, secret))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("attendu ErrRejected, obtenu %v", err)
	}
	// Le demandeur doit savoir qui a refusé et pourquoi.
	if !strings.Contains(err.Error(), "opérateur-ra") || !strings.Contains(err.Error(), "sujet non reconnu") {
		t.Errorf("le refus doit nommer l'opérateur et son motif: %v", err)
	}
	if !rec.has("ca.request_rejected") {
		t.Error("le rejet doit être consigné au journal d'audit")
	}
	// Une demande rejetée ne peut plus être approuvée après coup.
	if _, err := f.Approve(ctx, TransactionID(der), "opératrice-ra", ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("attendu ErrNotPending, obtenu %v", err)
	}
}

func TestSignatureHMACInvalideRefusee(t *testing.T) {
	f, _, _ := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")

	_, err := f.Submit(ctx, der, ca.ProfileTSASigner, Signature(der, "mauvais-secret"))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("attendu ErrUnauthenticated, obtenu %v", err)
	}
	_, err = f.Submit(ctx, der, ca.ProfileTSASigner, "")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("une signature vide doit être refusée, obtenu %v", err)
	}
}

// Une PKI qui délivre à quiconque le demande n'a pas de valeur : le refus doit
// être explicite à la construction, pas un défaut silencieux.
func TestEnrolementAnonymeRefuseALaConstruction(t *testing.T) {
	store := castore.NewMemory()
	if _, err := New(Options{Store: store, Issuer: &ca.Issuer{}}); err == nil {
		t.Fatal("un secret HMAC vide doit être refusé")
	}
}

// Politique « une seule unité active par sujet » : le renouvellement révoque
// le certificat précédent, avec le motif « superseded » et non « unspecified ».
func TestRenouvellementRevoqueLePrecedent(t *testing.T) {
	f, store, _ := newFlow(t)
	ctx := context.Background()

	premier := csrDER(t, "tsa.open-eidas.test")
	submit(t, f, premier)
	if _, err := f.Approve(ctx, TransactionID(premier), "opératrice-ra", ""); err != nil {
		t.Fatal(err)
	}
	ancien := submit(t, f, premier).Certificate

	// Nouvelle bi-clé, même sujet : c'est un renouvellement.
	second := csrDER(t, "tsa.open-eidas.test")
	submit(t, f, second)
	if _, err := f.Approve(ctx, TransactionID(second), "opératrice-ra", ""); err != nil {
		t.Fatal(err)
	}
	nouveau := submit(t, f, second).Certificate

	if ancien.SerialNumber.Cmp(nouveau.SerialNumber) == 0 {
		t.Fatal("le renouvellement doit produire un nouveau certificat")
	}
	rec, err := store.Certificate(ctx, ancien.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != castore.StatusRevoked {
		t.Fatalf("l'ancien certificat devrait être révoqué, statut %s", rec.Status)
	}
	const superseded = 4
	if rec.RevocationReason != superseded {
		t.Errorf("motif de révocation %d, attendu superseded (%d)", rec.RevocationReason, superseded)
	}
	// Le nouveau, lui, doit rester actif.
	if actifs, err := store.ActiveBySubject(ctx, nouveau.Subject.String(), nouveau.NotBefore.Add(1)); err != nil {
		t.Fatal(err)
	} else if len(actifs) != 1 {
		t.Fatalf("attendu un seul certificat actif pour ce sujet, obtenu %d", len(actifs))
	}
}

func TestApprobationDUneDemandeInconnue(t *testing.T) {
	f, _, _ := newFlow(t)
	if _, err := f.Approve(context.Background(), "inexistante", "opératrice-ra", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attendu ErrNotFound, obtenu %v", err)
	}
}

func TestProfilIncoherentEntreDeuxSoumissions(t *testing.T) {
	f, _, _ := newFlow(t)
	ctx := context.Background()
	der := csrDER(t, "tsa.open-eidas.test")
	submit(t, f, der)

	// La même CSR resoumise pour un autre profil : accepter reviendrait à
	// laisser le demandeur choisir ses usages après coup.
	_, err := f.Submit(ctx, der, ca.ProfileOCSPResponder, Signature(der, secret))
	if err == nil {
		t.Fatal("un changement de profil sur une demande existante doit être refusé")
	}
}
