package conformance

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func buildCRL(t *testing.T, issuer *x509.Certificate, key crypto.Signer, tmpl *x509.RevocationList) *x509.RevocationList {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		t.Fatalf("création de la CRL de test: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("relecture de la CRL de test: %v", err)
	}
	return crl
}

func TestCheckCRL(t *testing.T) {
	root, rootKey := rootCA(t)
	now := time.Now()

	t.Run("CRL vide conforme", func(t *testing.T) {
		// Une CRL sans aucune révocation doit rester publiable : c'est ce qui
		// prouve que le service de statut est vivant (EN 319 411-1 §6.3.10).
		crl := buildCRL(t, root, rootKey, &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(24 * time.Hour),
		})
		assertConforme(t, CheckCRL("CRL", crl, root, nil))
	})

	t.Run("fenêtre de validité trop large", func(t *testing.T) {
		crl := buildCRL(t, root, rootKey, &x509.RevocationList{
			Number:     big.NewInt(2),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(MaxCRLValidity + 24*time.Hour),
		})
		assertBlocking(t, CheckCRL("CRL", crl, root, nil), ReqCRLPublication)
	})

	// Un CRLNumber qui n'augmente pas permet de rejouer une CRL ancienne,
	// donc plus courte, pour masquer une révocation.
	t.Run("CRLNumber non monotone", func(t *testing.T) {
		crl := buildCRL(t, root, rootKey, &x509.RevocationList{
			Number:     big.NewInt(5),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(24 * time.Hour),
		})
		previous := int64(5)
		assertBlocking(t, CheckCRL("CRL", crl, root, &previous), ReqCRLIntegrity)
	})

	t.Run("signature d'une autre autorité", func(t *testing.T) {
		autre, _ := rootCA(t)
		crl := buildCRL(t, root, rootKey, &x509.RevocationList{
			Number:     big.NewInt(3),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(24 * time.Hour),
		})
		assertBlocking(t, CheckCRL("CRL", crl, autre, nil), ReqCRLIntegrity)
	})

	// Un motif « unspecified » est accepté par RFC 5280 mais ne justifie pas
	// une décision devant un auditeur : signalé, non bloquant.
	t.Run("entrée sans motif", func(t *testing.T) {
		crl := buildCRL(t, root, rootKey, &x509.RevocationList{
			Number:     big.NewInt(4),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(24 * time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{{
				SerialNumber:   serial(t),
				RevocationTime: now.Add(-time.Hour),
			}},
		})
		got := CheckCRL("CRL", crl, root, nil)
		assertConforme(t, got)
		if len(got.Advisories()) == 0 {
			t.Fatal("une entrée sans motif doit produire un avertissement")
		}
		if got.Advisories()[0].Requirement != ReqRevocationReason {
			t.Errorf("avertissement inattendu: %s", got.Advisories()[0])
		}
	})
}

func TestCheckAuditRetention(t *testing.T) {
	if err := CheckAuditRetention(MinAuditRetention).Err(); err != nil {
		t.Fatalf("la durée minimale devrait être acceptée: %v", err)
	}
	assertBlocking(t, CheckAuditRetention(0), ReqAuditLogging)
	assertBlocking(t, CheckAuditRetention(24*time.Hour), ReqAuditLogging)
}
