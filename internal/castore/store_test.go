package castore

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"
)

// Les tests portent sur l'implémentation mémoire, qui reproduit les mêmes
// contraintes que le schéma PostgreSQL (unicité du numéro de série, unicité de
// l'empreinte de CSR, transition conditionnée par l'état de départ). Le
// magasin PostgreSQL est exercé par les tests de bout en bout, où il tourne
// réellement.

func newStore() (Store, context.Context) { return NewMemory(), context.Background() }

func TestReserveSerialRefuseUnDoublon(t *testing.T) {
	s, ctx := newStore()
	serial := big.NewInt(0).SetBytes([]byte{0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})

	if err := s.ReserveSerial(ctx, serial, "tsa_signer"); err != nil {
		t.Fatalf("première réservation: %v", err)
	}
	// C'est cette contrainte qui garantit qu'un numéro de série ne peut pas
	// être émis deux fois, même si deux instances signent en parallèle.
	if err := s.ReserveSerial(ctx, serial, "tsa_signer"); !errors.Is(err, ErrSerialTaken) {
		t.Fatalf("seconde réservation: attendu ErrSerialTaken, obtenu %v", err)
	}
}

// Un numéro réservé mais non signé ne doit pas être visible : il ne correspond
// à aucun certificat existant.
func TestReservationNonSigneeInvisible(t *testing.T) {
	s, ctx := newStore()
	serial := big.NewInt(1234567890123)
	if err := s.ReserveSerial(ctx, serial, "tsa_signer"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Certificate(ctx, serial); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attendu ErrNotFound, obtenu %v", err)
	}
}

func TestSaveCertificateExigeUneReservation(t *testing.T) {
	s, ctx := newStore()
	c := Certificate{Serial: big.NewInt(42), Profile: "tsa_signer", Status: StatusIssued}
	if err := s.SaveCertificate(ctx, c); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attendu ErrNotFound sans réservation préalable, obtenu %v", err)
	}
}

func issued(t *testing.T, s Store, ctx context.Context, serial *big.Int, subject string, notAfter time.Time) {
	t.Helper()
	if err := s.ReserveSerial(ctx, serial, "tsa_signer"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertificate(ctx, Certificate{
		Serial: serial, Profile: "tsa_signer", SubjectDN: subject,
		IssuerDN: "CN=Open eIDAS Issuing CA", NotBefore: time.Now().Add(-time.Hour),
		NotAfter: notAfter, DER: []byte{0x30}, Status: StatusIssued,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestActiveBySubjectIgnoreExpiresEtRevoques(t *testing.T) {
	s, ctx := newStore()
	now := time.Now()
	const sujet = "CN=tsa.example,O=Open eIDAS"

	actif := big.NewInt(0).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	expiré := big.NewInt(0).SetBytes([]byte{2, 2, 3, 4, 5, 6, 7, 8, 9})
	révoqué := big.NewInt(0).SetBytes([]byte{3, 2, 3, 4, 5, 6, 7, 8, 9})

	issued(t, s, ctx, actif, sujet, now.Add(365*24*time.Hour))
	issued(t, s, ctx, expiré, sujet, now.Add(-time.Hour))
	issued(t, s, ctx, révoqué, sujet, now.Add(365*24*time.Hour))
	if err := s.Revoke(ctx, révoqué, now, 4); err != nil {
		t.Fatal(err)
	}

	got, err := s.ActiveBySubject(ctx, sujet, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Serial.Cmp(actif) != 0 {
		t.Fatalf("attendu le seul certificat actif, obtenu %d entrées", len(got))
	}
}

// Repousser la date de première révocation reviendrait à réduire après coup la
// fenêtre pendant laquelle le certificat est réputé non fiable.
func TestRevokeConserveLaPremiereDate(t *testing.T) {
	s, ctx := newStore()
	serial := big.NewInt(0).SetBytes([]byte{9, 8, 7, 6, 5, 4, 3, 2, 1})
	issued(t, s, ctx, serial, "CN=test", time.Now().Add(365*24*time.Hour))

	première := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := s.Revoke(ctx, serial, première, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, serial, time.Now(), 4); err != nil {
		t.Fatalf("une seconde révocation doit être sans effet et sans erreur: %v", err)
	}
	c, err := s.Certificate(ctx, serial)
	if err != nil {
		t.Fatal(err)
	}
	if !c.RevokedAt.Equal(première) || c.RevocationReason != 1 {
		t.Fatalf("révocation réécrite: %s / motif %d", c.RevokedAt, c.RevocationReason)
	}
}

// RFC 5280 §5 autorise à ne plus lister un certificat expiré : sans cela la
// CRL croît indéfiniment.
func TestRevokedRetireLesExpiresApresDelai(t *testing.T) {
	s, ctx := newStore()
	now := time.Now()
	ancien := big.NewInt(0).SetBytes([]byte{4, 4, 4, 4, 4, 4, 4, 4, 4})
	récent := big.NewInt(0).SetBytes([]byte{5, 5, 5, 5, 5, 5, 5, 5, 5})

	issued(t, s, ctx, ancien, "CN=ancien", now.Add(-90*24*time.Hour))
	issued(t, s, ctx, récent, "CN=récent", now.Add(24*time.Hour))
	if err := s.Revoke(ctx, ancien, now.Add(-100*24*time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, récent, now.Add(-time.Hour), 1); err != nil {
		t.Fatal(err)
	}

	got, err := s.Revoked(ctx, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Serial.Cmp(récent) != 0 {
		t.Fatalf("attendu la seule révocation encore pertinente, obtenu %d entrées", len(got))
	}
}

func TestCreateRequestRefuseUneCSRDejaSoumise(t *testing.T) {
	s, ctx := newStore()
	r := Request{
		TransactionID: "tx-1", CSRFingerprint: "abcdef", CSRDER: []byte{0x30},
		Profile: "tsa_signer", State: StatePending, CreatedAt: time.Now(),
	}
	if err := s.CreateRequest(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.TransactionID = "tx-2"
	if err := s.CreateRequest(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("attendu ErrConflict sur empreinte de CSR identique, obtenu %v", err)
	}
}

// Le verrou optimiste est ce qui empêche deux opérateurs de décider
// simultanément de la même demande.
func TestUpdateRequestRefuseUneTransitionDepuisLeMauvaisEtat(t *testing.T) {
	s, ctx := newStore()
	r := Request{
		TransactionID: "tx-1", CSRFingerprint: "abcdef", CSRDER: []byte{0x30},
		Profile: "tsa_signer", State: StatePending, CreatedAt: time.Now(),
	}
	if err := s.CreateRequest(ctx, r); err != nil {
		t.Fatal(err)
	}

	approuvée := r
	approuvée.State = StateApproved
	approuvée.Operator = "opératrice-1"
	approuvée.DecidedAt = time.Now()
	if err := s.UpdateRequest(ctx, approuvée, StatePending); err != nil {
		t.Fatal(err)
	}

	rejetée := r
	rejetée.State = StateRejected
	rejetée.Operator = "opérateur-2"
	rejetée.DecidedAt = time.Now()
	if err := s.UpdateRequest(ctx, rejetée, StatePending); !errors.Is(err, ErrConflict) {
		t.Fatalf("attendu ErrConflict sur transition concurrente, obtenu %v", err)
	}
}

func TestNextCRLNumberEstStrictementCroissant(t *testing.T) {
	s, ctx := newStore()
	var précédent int64
	for i := 0; i < 5; i++ {
		n, err := s.NextCRLNumber(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n <= précédent {
			t.Fatalf("CRLNumber %d n'est pas supérieur au précédent %d", n, précédent)
		}
		précédent = n
	}
}

func TestLatestCRL(t *testing.T) {
	s, ctx := newStore()
	if _, err := s.LatestCRL(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attendu ErrNotFound sans CRL publiée, obtenu %v", err)
	}
	now := time.Now()
	for _, n := range []int64{1, 3, 2} {
		if err := s.SaveCRL(ctx, CRL{
			Number: n, DER: []byte{0x30}, ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	latest, err := s.LatestCRL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Number != 3 {
		t.Fatalf("attendu la CRL 3, obtenu %d", latest.Number)
	}
}
