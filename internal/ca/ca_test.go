package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"github.com/open-eidas/open-eidas/internal/castore"
	"github.com/open-eidas/open-eidas/internal/conformance"
)

// recorder capture le journal d'audit pour vérifier que chaque décision y est
// bien consignée.
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
		t.Fatalf("génération de clé de test: %v", err)
	}
	return key
}

// authority monte une hiérarchie complète en mémoire puis l'autorité
// émettrice qui en découle : c'est la cérémonie réelle qui est exercée, pas un
// raccourci de test.
func authority(t *testing.T) (*Issuer, *Hierarchy, *castore.Memory, *recorder) {
	t.Helper()
	store := castore.NewMemory()
	rec := &recorder{}
	issuingSigner := testSigner(t)
	h, err := RunCeremony(context.Background(), CeremonyOptions{
		RootSigner:        testSigner(t),
		IssuingSigner:     issuingSigner,
		Store:             store,
		Recorder:          rec,
		Operator:          "opératrice-de-test",
		RootTokenLabel:    "open-eidas-root",
		IssuingTokenLabel: "open-eidas-issuing",
	})
	if err != nil {
		t.Fatalf("cérémonie: %v", err)
	}
	issuer, err := New(Options{
		Signer:      issuingSigner,
		Certificate: h.Issuing,
		Chain:       []*x509.Certificate{h.Root},
		Store:       store,
		Recorder:    rec,
		PublicURL:   "https://pki.open-eidas.test",
		OCSPURL:     "http://ocsp.open-eidas.test",
	})
	if err != nil {
		t.Fatalf("construction de l'autorité émettrice: %v", err)
	}
	return issuer, h, store, rec
}

func csrFor(t *testing.T, cn string, signer crypto.Signer) (*x509.CertificateRequest, []byte) {
	t.Helper()
	algo := x509.ECDSAWithSHA256
	if _, ok := signer.Public().(*rsa.PublicKey); ok {
		algo = x509.SHA256WithRSA
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		SignatureAlgorithm: algo,
	}, signer)
	if err != nil {
		t.Fatalf("création de la CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("relecture de la CSR: %v", err)
	}
	return csr, der
}

func mustProfile(t *testing.T, name string) *Profile {
	t.Helper()
	p, err := ProfileByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCeremonieProduitUneHierarchieConforme(t *testing.T) {
	ctx := context.Background()
	store := castore.NewMemory()
	rec := &recorder{}
	rootSigner, issuingSigner := testSigner(t), testSigner(t)

	opts := CeremonyOptions{
		RootSigner: rootSigner, IssuingSigner: issuingSigner,
		Store: store, Recorder: rec, Operator: "opératrice-de-test",
	}
	h, err := RunCeremony(ctx, opts)
	if err != nil {
		t.Fatalf("cérémonie: %v", err)
	}
	if !h.Created {
		t.Fatal("la première cérémonie doit créer la hiérarchie")
	}
	if err := conformance.CheckCACertificate("racine", h.Root, true).Err(); err != nil {
		t.Errorf("racine non conforme: %v", err)
	}
	if err := conformance.CheckCACertificate("émettrice", h.Issuing, false).Err(); err != nil {
		t.Errorf("émettrice non conforme: %v", err)
	}
	// La chaîne doit être vérifiable telle quelle par un tiers.
	if err := h.Issuing.CheckSignatureFrom(h.Root); err != nil {
		t.Errorf("l'émettrice n'est pas signée par la racine: %v", err)
	}
	if !rec.has("ca.ceremony") {
		t.Error("la cérémonie doit produire un procès-verbal au journal d'audit")
	}

	// Relancée, elle ne doit surtout pas produire une seconde racine : cela
	// invaliderait tous les certificats déjà émis.
	again, err := RunCeremony(ctx, opts)
	if err != nil {
		t.Fatalf("seconde cérémonie: %v", err)
	}
	if again.Created {
		t.Fatal("la cérémonie doit être idempotente")
	}
	if again.Root.SerialNumber.Cmp(h.Root.SerialNumber) != 0 {
		t.Fatal("la seconde cérémonie a produit une racine différente")
	}
}

// Un token remplacé (clé perdue, volume effacé) doit être détecté, pas
// produire des signatures invérifiables par les certificats déjà émis.
func TestCeremonieDetecteUnTokenRemplace(t *testing.T) {
	ctx := context.Background()
	store := castore.NewMemory()
	rootSigner, issuingSigner := testSigner(t), testSigner(t)
	base := CeremonyOptions{
		RootSigner: rootSigner, IssuingSigner: issuingSigner,
		Store: store, Operator: "opératrice-de-test",
	}
	if _, err := RunCeremony(ctx, base); err != nil {
		t.Fatal(err)
	}

	remplacé := base
	remplacé.IssuingSigner = testSigner(t)
	if _, err := RunCeremony(ctx, remplacé); err == nil {
		t.Fatal("une clé d'émettrice différente doit être refusée")
	}
}

func TestIssueProduitUnCertificatConforme(t *testing.T) {
	ctx := context.Background()
	issuer, h, _, rec := authority(t)

	csr, _ := csrFor(t, "tsa.open-eidas.test", testSigner(t))
	cert, err := issuer.Issue(ctx, csr, mustProfile(t, ProfileTSASigner), "tx-1")
	if err != nil {
		t.Fatalf("émission: %v", err)
	}

	if err := conformance.CheckTSUCertificate("TSU", cert).Err(); err != nil {
		t.Errorf("certificat émis non conforme: %v", err)
	}
	if err := cert.CheckSignatureFrom(h.Issuing); err != nil {
		t.Errorf("le certificat n'est pas signé par l'émettrice: %v", err)
	}
	// Le sujet vient pour partie de la demande (CN) et pour partie du profil :
	// un demandeur ne doit pas pouvoir se déclarer d'une autre organisation.
	if cert.Subject.CommonName != "tsa.open-eidas.test" {
		t.Errorf("CN inattendu: %s", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Open eIDAS" {
		t.Errorf("organisation non imposée par le profil: %v", cert.Subject.Organization)
	}
	if len(cert.CRLDistributionPoints) != 1 || !strings.HasSuffix(cert.CRLDistributionPoints[0], ".crl") {
		t.Errorf("point de distribution de CRL absent: %v", cert.CRLDistributionPoints)
	}
	if len(cert.IssuingCertificateURL) != 1 {
		t.Errorf("AIA ca_issuers absent: %v", cert.IssuingCertificateURL)
	}
	if !rec.has("ca.certificate_issued") {
		t.Error("l'émission doit être consignée au journal d'audit")
	}
}

func TestIssueOCSPPorteOcspNocheckEtAucunCDP(t *testing.T) {
	ctx := context.Background()
	issuer, _, _, _ := authority(t)

	csr, _ := csrFor(t, "ocsp.open-eidas.test", testSigner(t))
	cert, err := issuer.Issue(ctx, csr, mustProfile(t, ProfileOCSPResponder), "tx-ocsp")
	if err != nil {
		t.Fatalf("émission: %v", err)
	}
	if err := conformance.CheckOCSPResponderCertificate("OCSP", cert).Err(); err != nil {
		t.Errorf("certificat de répondeur non conforme: %v", err)
	}
	// ocsp-nocheck dispense de vérifier la révocation de ce certificat : un
	// point de distribution de CRL y serait au mieux inutile, au pire une
	// dépendance circulaire.
	if len(cert.CRLDistributionPoints) != 0 || len(cert.OCSPServer) != 0 {
		t.Errorf("le profil du répondeur ne doit porter ni CDP ni AIA OCSP: %v %v",
			cert.CRLDistributionPoints, cert.OCSPServer)
	}
}

// La signature de la CSR est la preuve que le demandeur détient la clé privée.
// Sans ce contrôle, n'importe qui pourrait faire certifier la clé d'un autre.
func TestIssueRefuseCSRNonSignee(t *testing.T) {
	ctx := context.Background()
	issuer, _, _, _ := authority(t)

	_, der := csrFor(t, "tsa.open-eidas.test", testSigner(t))
	// Altère un octet du corps de la CSR : la signature ne correspond plus.
	der[len(der)/2] ^= 0xFF
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Skipf("la CSR altérée n'est plus analysable, ce qui suffit au refus: %v", err)
	}
	if _, err := issuer.Issue(ctx, csr, mustProfile(t, ProfileTSASigner), "tx"); err == nil {
		t.Fatal("une CSR dont la signature ne correspond pas doit être refusée")
	}
}

func TestIssueRefuseUneCleTropCourte(t *testing.T) {
	ctx := context.Background()
	issuer, _, _, _ := authority(t)

	faible, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(t, "tsa.open-eidas.test", faible)
	_, err = issuer.Issue(ctx, csr, mustProfile(t, ProfileTSASigner), "tx")
	if err == nil {
		t.Fatal("une clé RSA de 2048 bits doit être refusée (ETSI TS 119 312)")
	}
	if !strings.Contains(err.Error(), "3072") {
		t.Errorf("le refus doit nommer la taille exigée: %v", err)
	}
}

func TestSeriesUniquesEtAleatoires(t *testing.T) {
	ctx := context.Background()
	issuer, _, _, _ := authority(t)
	profile := mustProfile(t, ProfileTSASigner)

	vus := map[string]bool{}
	for n := 0; n < 8; n++ {
		csr, _ := csrFor(t, "tsa.open-eidas.test", testSigner(t))
		cert, err := issuer.Issue(ctx, csr, profile, "tx")
		if err != nil {
			t.Fatalf("émission %d: %v", n, err)
		}
		key := cert.SerialNumber.String()
		if vus[key] {
			t.Fatalf("numéro de série réémis: %s", key)
		}
		vus[key] = true
		if bits := cert.SerialNumber.BitLen(); bits != serialBits {
			t.Fatalf("numéro de série de %d bits, attendu %d", bits, serialBits)
		}
	}
}

// Le certificat produit est relu depuis son DER et re-contrôlé : un profil
// qui produirait un certificat non conforme doit faire échouer l'émission, et
// non délivrer le certificat en signalant l'écart.
func TestIssueAnnuleSurCertificatNonConforme(t *testing.T) {
	ctx := context.Background()
	issuer, _, store, rec := authority(t)

	// Un profil volontairement fautif : extendedKeyUsage non critique, ce
	// qu'ETSI EN 319 421 §7.7.2 interdit pour une TSU.
	fautif := *tsaSigner
	fautif.EKUCritical = false

	csr, _ := csrFor(t, "tsa.open-eidas.test", testSigner(t))
	if _, err := issuer.Issue(ctx, csr, &fautif, "tx"); err == nil {
		t.Fatal("un certificat non conforme ne doit jamais être délivré")
	}
	if !rec.has("ca.issuance_refused") {
		t.Error("le refus doit être consigné au journal d'audit")
	}
	// Rien ne doit avoir été inscrit au registre : le numéro de série reste
	// réservé — donc jamais réutilisé — mais aucun certificat n'existe.
	sujet := fautif.Subject("tsa.open-eidas.test").String()
	actifs, err := store.ActiveBySubject(ctx, sujet, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(actifs) != 0 {
		t.Fatalf("un certificat non conforme a été inscrit au registre: %d entrées", len(actifs))
	}
}

func TestCRLPublieeMemeVide(t *testing.T) {
	ctx := context.Background()
	issuer, h, _, rec := authority(t)

	crl, err := issuer.PublishCRL(ctx)
	if err != nil {
		t.Fatalf("publication de la CRL: %v", err)
	}
	parsed, err := x509.ParseRevocationList(crl.DER)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 {
		t.Fatal("la première CRL doit être vide")
	}
	// Une CRL récente et vide prouve que le service de statut fonctionne ;
	// l'absence de CRL ne prouve rien.
	if err := parsed.CheckSignatureFrom(h.Issuing); err != nil {
		t.Errorf("CRL non vérifiable par l'émettrice: %v", err)
	}
	if !rec.has("ca.crl_published") {
		t.Error("la publication doit être consignée au journal d'audit")
	}
}

func TestCRLNumberEstStrictementCroissant(t *testing.T) {
	ctx := context.Background()
	issuer, _, _, _ := authority(t)

	first, err := issuer.PublishCRL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.PublishCRL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Number <= first.Number {
		t.Fatalf("CRLNumber %d n'est pas supérieur à %d", second.Number, first.Number)
	}
}

func TestCRLPorteLesMotifs(t *testing.T) {
	ctx := context.Background()
	issuer, _, _, rec := authority(t)

	csr, _ := csrFor(t, "tsa.open-eidas.test", testSigner(t))
	cert, err := issuer.Issue(ctx, csr, mustProfile(t, ProfileTSASigner), "tx")
	if err != nil {
		t.Fatal(err)
	}
	const keyCompromise = 1
	if err := issuer.Revoke(ctx, cert.SerialNumber, keyCompromise, "opérateur-de-test", "clé exposée"); err != nil {
		t.Fatalf("révocation: %v", err)
	}
	if !rec.has("ca.certificate_revoked") {
		t.Error("la révocation doit être consignée au journal d'audit")
	}

	crl, err := issuer.PublishCRL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(crl.DER)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.RevokedCertificateEntries) != 1 {
		t.Fatalf("attendu une entrée révoquée, obtenu %d", len(parsed.RevokedCertificateEntries))
	}
	entry := parsed.RevokedCertificateEntries[0]
	if entry.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("mauvais numéro de série en CRL: %s", entry.SerialNumber)
	}
	// Le motif exact est ce qu'un auditeur vient lire : « unspecified » ne
	// justifierait pas la décision.
	if entry.ReasonCode != keyCompromise {
		t.Errorf("motif de révocation perdu: %d", entry.ReasonCode)
	}
}

// La révocation engage l'autorité : elle doit être imputable, comme
// l'approbation d'une demande.
func TestRevokeExigeUnOperateur(t *testing.T) {
	ctx := context.Background()
	issuer, _, _, _ := authority(t)

	csr, _ := csrFor(t, "tsa.open-eidas.test", testSigner(t))
	cert, err := issuer.Issue(ctx, csr, mustProfile(t, ProfileTSASigner), "tx")
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Revoke(ctx, cert.SerialNumber, 1, "", ""); err == nil {
		t.Fatal("une révocation sans opérateur doit être refusée")
	}
}

func TestProfileByNameRefuseUnProfilInconnu(t *testing.T) {
	// Aucun profil par défaut n'est appliqué en silence : c'est exactement
	// l'héritage implicite qui piégeait la configuration OpenXPKI.
	if _, err := ProfileByName("web_server"); err == nil {
		t.Fatal("un profil inconnu doit être refusé explicitement")
	}
}

func TestSubjectKeyIDSuitRFC5280(t *testing.T) {
	signer := testSigner(t)
	ski, err := subjectKeyID(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(ski) != 20 {
		t.Fatalf("SubjectKeyIdentifier de %d octets, attendu 20 (SHA-1)", len(ski))
	}
	// La dérivation porte sur la seule BIT STRING, sans l'identifiant
	// d'algorithme qui l'accompagne dans SubjectPublicKeyInfo.
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatal(err)
	}
	if len(info.PublicKey.RightAlign()) == 0 {
		t.Fatal("clé publique vide")
	}
}

func TestNewRefuseUneEmettriceNonConforme(t *testing.T) {
	// Une « CA » sans cRLSign ne peut pas publier son état de révocation :
	// l'autorité doit refuser de démarrer plutôt que d'émettre à l'aveugle.
	signer := testSigner(t)
	ski, err := subjectKeyID(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "CA incomplète"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Options{
		Signer: signer, Certificate: cert,
		Store: castore.NewMemory(), PublicURL: "https://pki.test",
	})
	if err == nil {
		t.Fatal("une émettrice non conforme ne doit pas pouvoir démarrer")
	}
}
