package conformance

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestCheckTSUCertificate(t *testing.T) {
	root, rootKey := rootCA(t)
	leafKey := testKey(t)

	t.Run("profil conforme", func(t *testing.T) {
		cert := signCert(t, leafTemplate(t, root, leafKey.Public()), root, leafKey.Public(), rootKey)
		assertConforme(t, CheckTSUCertificate("TSU", cert))
	})

	// EN 319 421 §7.7.2 : extendedKeyUsage doit être marqué critique. Sans
	// cela, un vérificateur peut ignorer la restriction d'usage — c'est
	// exactement l'écart qu'un auditeur cherche.
	t.Run("extendedKeyUsage non critique", func(t *testing.T) {
		tmpl := leafTemplate(t, root, leafKey.Public())
		tmpl.ExtraExtensions[0].Critical = false
		cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
		assertBlocking(t, CheckTSUCertificate("TSU", cert), ReqTSUCertificate)
	})

	// Un certificat qui sert aussi à l'authentification TLS ne garantit plus
	// qu'une signature relève de l'horodatage.
	t.Run("usage étendu surnuméraire", func(t *testing.T) {
		tmpl := leafTemplate(t, root, leafKey.Public())
		tmpl.ExtraExtensions[0].Value = mustMarshalEKU(t, []asn1.ObjectIdentifier{
			{1, 3, 6, 1, 5, 5, 7, 3, 8}, // id-kp-timeStamping
			{1, 3, 6, 1, 5, 5, 7, 3, 1}, // id-kp-serverAuth
		})
		cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
		assertBlocking(t, CheckTSUCertificate("TSU", cert), ReqTSUCertificate)
	})

	t.Run("keyUsage débordant", func(t *testing.T) {
		tmpl := leafTemplate(t, root, leafKey.Public())
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
		cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
		assertBlocking(t, CheckTSUCertificate("TSU", cert), ReqTSUCertificate)
	})

	t.Run("certificat marqué autorité", func(t *testing.T) {
		tmpl := leafTemplate(t, root, leafKey.Public())
		tmpl.IsCA = true
		cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
		assertBlocking(t, CheckTSUCertificate("TSU", cert), ReqTSUCertificate)
	})
}

func TestCheckLifetime(t *testing.T) {
	root, rootKey := rootCA(t)
	leafKey := testKey(t)
	tmpl := leafTemplate(t, root, leafKey.Public())
	tmpl.NotAfter = tmpl.NotBefore.Add(MaxEndEntityLifetime + 24*time.Hour)
	cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
	assertBlocking(t, CheckTSUCertificate("TSU", cert), ReqCertificateLifetime)
}

func TestCheckCommonCertificateSerie(t *testing.T) {
	root, rootKey := rootCA(t)
	leafKey := testKey(t)

	// Un numéro de série court est prévisible : RFC 5280 l'autorise, ETSI
	// EN 319 412-1 non, et c'est une voie d'attaque sur les collisions.
	tmpl := leafTemplate(t, root, leafKey.Public())
	tmpl.SerialNumber = big.NewInt(42)
	cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
	assertBlocking(t, CheckTSUCertificate("TSU", cert), ReqSerialNumber)
}

func TestCheckCommonCertificateIdentifiantsDeCle(t *testing.T) {
	root, rootKey := rootCA(t)
	leafKey := testKey(t)

	tmpl := leafTemplate(t, root, leafKey.Public())
	tmpl.AuthorityKeyId = nil
	// Go dérive l'AKI du parent lorsqu'il est absent : le retirer suppose de
	// neutraliser aussi le SKI de la racine pour ce certificat de test.
	parent := *root
	parent.SubjectKeyId = nil
	cert := signCert(t, tmpl, &parent, leafKey.Public(), rootKey)
	assertBlocking(t, CheckTSUCertificate("TSU", cert), ReqKeyIdentifiers)
}

func TestCheckOCSPResponderCertificate(t *testing.T) {
	root, rootKey := rootCA(t)
	leafKey := testKey(t)

	base := func() *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          serial(t),
			Subject:               pkix.Name{CommonName: "Open eIDAS OCSP Responder de test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			BasicConstraintsValid: true,
			SubjectKeyId:          skiOf(t, leafKey.Public()),
			AuthorityKeyId:        root.SubjectKeyId,
			ExtraExtensions: []pkix.Extension{{
				Id: OIDOCSPNoCheck, Critical: false, Value: []byte{0x05, 0x00},
			}},
		}
	}

	t.Run("profil conforme", func(t *testing.T) {
		cert := signCert(t, base(), root, leafKey.Public(), rootKey)
		assertConforme(t, CheckOCSPResponderCertificate("OCSP", cert))
	})

	// Sans ocsp-nocheck, le vérificateur doit contrôler la révocation du
	// certificat du répondeur… auprès du répondeur lui-même.
	t.Run("ocsp-nocheck absent", func(t *testing.T) {
		tmpl := base()
		tmpl.ExtraExtensions = nil
		cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
		assertBlocking(t, CheckOCSPResponderCertificate("OCSP", cert), ReqOCSPResponderCertificate)
	})

	// ocsp-nocheck sans durée de vie courte revient à rendre le certificat
	// irrévocable pendant des années (RFC 6960 §4.2.2.2.1).
	t.Run("durée de vie trop longue", func(t *testing.T) {
		tmpl := base()
		tmpl.NotAfter = tmpl.NotBefore.Add(MaxOCSPLifetime + 30*24*time.Hour)
		cert := signCert(t, tmpl, root, leafKey.Public(), rootKey)
		assertBlocking(t, CheckOCSPResponderCertificate("OCSP", cert), ReqCertificateLifetime)
	})
}

func TestCheckCACertificate(t *testing.T) {
	root, rootKey := rootCA(t)

	t.Run("racine conforme", func(t *testing.T) {
		assertConforme(t, CheckCACertificate("racine", root, true))
	})

	// Une CA sans cRLSign ne peut pas publier l'état de révocation de ce
	// qu'elle émet : le service de statut devient invérifiable.
	t.Run("cRLSign absent", func(t *testing.T) {
		key := testKey(t)
		tmpl := &x509.Certificate{
			SerialNumber:          serial(t),
			Subject:               pkix.Name{CommonName: "CA sans cRLSign"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			SubjectKeyId:          skiOf(t, key.Public()),
			AuthorityKeyId:        root.SubjectKeyId,
		}
		cert := signCert(t, tmpl, root, key.Public(), rootKey)
		assertBlocking(t, CheckCACertificate("émettrice", cert, false), ReqCACertificate)
	})
}
