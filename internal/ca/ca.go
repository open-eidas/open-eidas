// Package ca est le moteur d'émission et de révocation de l'autorité de
// certification d'Open eIDAS : il produit les certificats de l'unité
// d'horodatage et du répondeur OCSP, et publie l'état de révocation.
//
// Il remplace OpenXPKI (voir INDEPENDANCE.md). Le périmètre est étroit et
// assumé comme tel : émettre depuis une CSR selon un profil compilé, publier
// une CRL, révoquer. Tout ce qu'il produit est relu depuis son DER et soumis
// aux règles d'internal/conformance avant de sortir du service — le moteur ne
// délivre jamais un certificat qu'il n'a pas vérifié après coup.
package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/open-eidas/open-eidas/internal/audit"
	"github.com/open-eidas/open-eidas/internal/castore"
	"github.com/open-eidas/open-eidas/internal/certs"
	"github.com/open-eidas/open-eidas/internal/conformance"
)

// serialBits est la taille du numéro de série tiré à chaque émission. ETSI
// EN 319 412-1 exige de l'imprévisibilité ; 128 bits rendent une collision et
// une prédiction également hors d'atteinte.
const serialBits = 128

// serialAttempts borne les tentatives en cas de collision avec un numéro déjà
// réservé. Sur 128 bits, une seule collision serait déjà un signe de
// défaillance du générateur : la boucle sert à ne pas planter, pas à absorber
// un aléa faible.
const serialAttempts = 5

// Recorder consigne les décisions de l'autorité au journal d'audit. Comme
// pour la TSA, une écriture ratée annule l'opération : un certificat dont
// l'émission n'est pas tracée ne doit pas exister.
type Recorder interface {
	Append(event string, data map[string]any) error
}

// Options configure l'autorité émettrice.
type Options struct {
	// Signer et Certificate sont la clé (PKCS#11) et le certificat de la CA
	// émettrice ; Chain porte la racine.
	Signer      crypto.Signer
	Certificate *x509.Certificate
	Chain       []*x509.Certificate

	Store    castore.Store
	Recorder Recorder

	// PublicURL est l'adresse à laquelle cette CA est joignable par qui
	// vérifie un certificat : elle est gravée dans les extensions CDP et AIA
	// et doit donc être l'adresse publique, pas l'adresse interne du service.
	PublicURL string
	// OCSPURL est l'adresse publique du répondeur OCSP.
	OCSPURL string

	// CRLValidity est l'écart entre thisUpdate et nextUpdate des CRL émises.
	CRLValidity time.Duration
	// CRLGrace est le délai après expiration pendant lequel un certificat
	// révoqué reste listé (RFC 5280 §5 autorise à l'en retirer ensuite).
	CRLGrace time.Duration

	// Clock est injectable pour les tests ; time.Now par défaut.
	Clock func() time.Time
}

// Issuer est l'autorité émettrice en fonctionnement.
type Issuer struct {
	opts Options
}

// New valide la cohérence du matériel de l'autorité et la construit. Le
// certificat de l'émettrice est lui-même soumis aux règles ETSI : une CA non
// conforme ne doit pas pouvoir émettre.
func New(o Options) (*Issuer, error) {
	if o.Signer == nil {
		return nil, errors.New("ca: clé de signature de l'autorité manquante")
	}
	if o.Certificate == nil {
		return nil, errors.New("ca: certificat de l'autorité émettrice manquant")
	}
	if o.Store == nil {
		return nil, errors.New("ca: magasin de persistance manquant")
	}
	if o.PublicURL == "" {
		return nil, errors.New("ca: adresse publique de la PKI manquante (extensions CDP/AIA)")
	}
	if o.CRLValidity <= 0 {
		o.CRLValidity = 24 * time.Hour
	}
	if o.CRLGrace <= 0 {
		o.CRLGrace = 30 * 24 * time.Hour
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}

	if err := matchesSigner(o.Certificate, o.Signer); err != nil {
		return nil, err
	}
	if err := conformance.CheckCACertificate("CA émettrice", o.Certificate, false).Err(); err != nil {
		return nil, fmt.Errorf("ca: l'autorité émettrice elle-même n'est pas conforme: %w", err)
	}
	return &Issuer{opts: o}, nil
}

func matchesSigner(cert *x509.Certificate, signer crypto.Signer) error {
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("ca: clé publique du certificat illisible: %w", err)
	}
	signerPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("ca: clé publique du signataire illisible: %w", err)
	}
	if string(certPub) != string(signerPub) {
		return errors.New("ca: la clé du token PKCS#11 ne correspond pas au certificat de l'autorité")
	}
	return nil
}

// Certificate retourne le certificat de la CA émettrice.
func (i *Issuer) Certificate() *x509.Certificate { return i.opts.Certificate }

// Chain retourne la chaîne d'émission (racine incluse).
func (i *Issuer) Chain() []*x509.Certificate { return i.opts.Chain }

// FullChain retourne l'émettrice suivie de sa chaîne, dans l'ordre attendu
// par un client qui joindra le tout à un jeton.
func (i *Issuer) FullChain() []*x509.Certificate {
	return append([]*x509.Certificate{i.opts.Certificate}, i.opts.Chain...)
}

// CRLURL est l'adresse à laquelle cette autorité publie sa CRL.
func (i *Issuer) CRLURL() string {
	return fmt.Sprintf("%s/download/%s.crl", i.opts.PublicURL,
		certs.FileName(i.opts.Certificate.Subject.CommonName))
}

// CACertificateURL est l'adresse à laquelle cette autorité publie son propre
// certificat, au format DER (extension AIA ca_issuers).
func (i *Issuer) CACertificateURL() string {
	return fmt.Sprintf("%s/download/%s.cer", i.opts.PublicURL,
		certs.FileName(i.opts.Certificate.Subject.CommonName))
}

func (i *Issuer) now() time.Time { return i.opts.Clock() }

func (i *Issuer) record(event string, data map[string]any) error {
	if i.opts.Recorder == nil {
		return nil
	}
	if err := i.opts.Recorder.Append(event, data); err != nil {
		return fmt.Errorf("ca: journal d'audit: %w", err)
	}
	return nil
}

// subjectKeyID applique la méthode 1 de RFC 5280 §4.2.1.2 : SHA-1 de la BIT
// STRING de la clé publique. SHA-1 n'intervient ici que comme identifiant
// d'appariement, jamais comme preuve d'intégrité — sa faiblesse aux collisions
// est sans effet sur cet usage, et c'est la dérivation que les vérificateurs
// attendent.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, fmt.Errorf("ca: SubjectPublicKeyInfo illisible: %w", err)
	}
	sum := sha1.Sum(info.PublicKey.RightAlign())
	return sum[:], nil
}

// Issue produit un certificat pour la CSR donnée selon le profil demandé.
//
// La séquence est volontairement rigide : vérifier la demande, réserver le
// numéro de série AVANT de signer, signer, relire le DER produit, le soumettre
// aux règles ETSI, et seulement alors l'inscrire au registre. Un certificat
// qui échoue le contrôle final n'est jamais enregistré ni retourné.
func (i *Issuer) Issue(ctx context.Context, csr *x509.CertificateRequest, profile *Profile, transactionID string) (*x509.Certificate, error) {
	if profile == nil {
		return nil, errors.New("ca: profil de certificat manquant")
	}
	if err := ValidateCSR(csr); err != nil {
		return nil, err
	}

	serial, err := i.reserveSerial(ctx, profile.Name)
	if err != nil {
		return nil, err
	}

	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	now := i.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               profile.Subject(csr.Subject.CommonName),
		NotBefore:             now.Add(-5 * time.Minute).Truncate(time.Second),
		NotAfter:              now.Add(profile.Validity).Truncate(time.Second),
		KeyUsage:              profile.KeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		ExtraExtensions:       []pkix.Extension{},
	}
	// extendedKeyUsage est posé à la main plutôt que par le champ ExtKeyUsage
	// de crypto/x509 : celui-ci ne permet pas de marquer l'extension
	// critique, ce qu'ETSI EN 319 421 §7.7.2 exige pour la TSU.
	if len(profile.ExtKeyUsage) > 0 {
		value, err := asn1.Marshal(profile.ExtKeyUsage)
		if err != nil {
			return nil, fmt.Errorf("ca: encodage de l'extendedKeyUsage: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: profile.EKUCritical, Value: value,
		})
	}
	if profile.OCSPNoCheck {
		// La valeur est un NULL DER : l'extension vaut par sa seule présence.
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: conformance.OIDOCSPNoCheck, Critical: false, Value: []byte{0x05, 0x00},
		})
	}
	if profile.IncludeCRLDistributionPoint {
		tmpl.CRLDistributionPoints = []string{i.CRLURL()}
	}
	if profile.IncludeCAIssuers {
		tmpl.IssuingCertificateURL = []string{i.CACertificateURL()}
	}
	if profile.IncludeOCSPResponder && i.opts.OCSPURL != "" {
		tmpl.OCSPServer = []string{i.opts.OCSPURL + "/ocsp"}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.opts.Certificate, csr.PublicKey, i.opts.Signer)
	if err != nil {
		return nil, fmt.Errorf("ca: signature du certificat: %w", err)
	}
	// Le certificat est relu depuis son DER : le contrôle porte sur ce qui a
	// réellement été encodé, pas sur le modèle qu'on croit avoir rempli.
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: relecture du certificat émis: %w", err)
	}
	sujet := fmt.Sprintf("certificat %s émis pour %s", profile.Name, cert.Subject.CommonName)
	findings := profile.Check(sujet, cert)
	if err := findings.Err(); err != nil {
		if recErr := i.record(audit.EventCAIssuanceRefused, map[string]any{
			"profil":  profile.Name,
			"sujet":   cert.Subject.String(),
			"serie":   cert.SerialNumber.String(),
			"motif":   err.Error(),
			"demande": transactionID,
		}); recErr != nil {
			return nil, recErr
		}
		return nil, fmt.Errorf("ca: le certificat produit n'est pas conforme, émission annulée: %w", err)
	}

	if err := i.opts.Store.SaveCertificate(ctx, castore.Certificate{
		Serial:               cert.SerialNumber,
		Profile:              profile.Name,
		SubjectDN:            cert.Subject.String(),
		IssuerDN:             cert.Issuer.String(),
		NotBefore:            cert.NotBefore,
		NotAfter:             cert.NotAfter,
		DER:                  cert.Raw,
		Status:               castore.StatusIssued,
		RequestTransactionID: transactionID,
	}); err != nil {
		return nil, err
	}
	if err := i.record(audit.EventCACertificateIssued, map[string]any{
		"profil":     profile.Name,
		"sujet":      cert.Subject.String(),
		"emetteur":   cert.Issuer.String(),
		"serie":      cert.SerialNumber.String(),
		"not_after":  cert.NotAfter.UTC().Format(time.RFC3339),
		"demande":    transactionID,
		"empreintes": len(findings.Advisories()),
	}); err != nil {
		return nil, err
	}
	return cert, nil
}

// randomSerial tire un numéro de série de serialBits bits. Le bit de poids
// fort est forcé, ce qui garantit d'un seul geste les deux propriétés
// attendues : strictement positif (RFC 5280 §4.1.2.2) et portant réellement
// l'entropie annoncée, sans qu'un tirage à zéros de tête ne la réduise.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: tirage du numéro de série: %w", err)
	}
	n.SetBit(n, serialBits-1, 1)
	return n, nil
}

func (i *Issuer) reserveSerial(ctx context.Context, profile string) (*big.Int, error) {
	for attempt := 0; attempt < serialAttempts; attempt++ {
		n, err := randomSerial()
		if err != nil {
			return nil, err
		}
		err = i.opts.Store.ReserveSerial(ctx, n, profile)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, castore.ErrSerialTaken) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("ca: %d collisions successives de numéro de série sur %d bits — générateur d'aléa suspect",
		serialAttempts, serialBits)
}

// ValidateCSR contrôle une demande avant tout traitement : la signature de la
// CSR est la preuve que le demandeur détient bien la clé privée
// correspondante, et la clé publique doit relever d'une suite admise.
func ValidateCSR(csr *x509.CertificateRequest) error {
	if csr == nil {
		return errors.New("ca: demande de certificat manquante")
	}
	if csr.Subject.CommonName == "" {
		return errors.New("ca: la demande ne porte pas de nom courant (CN)")
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("ca: la demande n'est pas signée par la clé qu'elle présente: %w", err)
	}
	if err := conformance.CheckSignatureAlgorithm("demande de certificat", csr.SignatureAlgorithm).Err(); err != nil {
		return err
	}
	if err := conformance.CheckPublicKey("clé de la demande", csr.PublicKey).Err(); err != nil {
		return err
	}
	return nil
}

// Revoke révoque un certificat émis par cette autorité et consigne la
// décision. La CRL n'est pas republiée ici : c'est le cycle de publication
// (PublishCRL) qui la reprend, afin qu'une révocation en masse ne produise pas
// autant de CRL que de certificats.
func (i *Issuer) Revoke(ctx context.Context, serial *big.Int, reason int, operator, comment string) error {
	if operator == "" {
		return errors.New("ca: la révocation exige l'identité de l'opérateur qui la décide")
	}
	cert, err := i.opts.Store.Certificate(ctx, serial)
	if err != nil {
		return err
	}
	at := i.now()
	if err := i.opts.Store.Revoke(ctx, serial, at, reason); err != nil {
		return err
	}
	return i.record(audit.EventCACertificateRevoked, map[string]any{
		"serie":       serial.String(),
		"sujet":       cert.SubjectDN,
		"motif":       reason,
		"operateur":   operator,
		"commentaire": comment,
		"date":        at.UTC().Format(time.RFC3339),
	})
}

// PublishCRL produit et enregistre une nouvelle liste de révocation.
//
// Elle est publiée même vide : une CRL récente sans aucune entrée est ce qui
// prouve que le service de statut fonctionne, là où l'absence de CRL ne
// prouve rien (ETSI EN 319 411-1 §6.3.10).
func (i *Issuer) PublishCRL(ctx context.Context) (*castore.CRL, error) {
	now := i.now()
	revoked, err := i.opts.Store.Revoked(ctx, now, i.opts.CRLGrace)
	if err != nil {
		return nil, err
	}
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   c.Serial,
			RevocationTime: c.RevokedAt.UTC(),
			ReasonCode:     c.RevocationReason,
		})
	}

	number, err := i.opts.Store.NextCRLNumber(ctx)
	if err != nil {
		return nil, err
	}
	var previous *int64
	if latest, err := i.opts.Store.LatestCRL(ctx); err == nil {
		previous = &latest.Number
	} else if !errors.Is(err, castore.ErrNotFound) {
		return nil, err
	}

	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now.Add(-time.Minute).Truncate(time.Second),
		NextUpdate:                now.Add(i.opts.CRLValidity).Truncate(time.Second),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, i.opts.Certificate, i.opts.Signer)
	if err != nil {
		return nil, fmt.Errorf("ca: signature de la CRL: %w", err)
	}
	// Comme pour un certificat, la CRL est relue depuis son DER avant d'être
	// publiée : c'est ce qui sera servi qui doit être conforme.
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("ca: relecture de la CRL produite: %w", err)
	}
	if err := conformance.CheckCRL("CRL de la CA émettrice", parsed, i.opts.Certificate, previous).Err(); err != nil {
		return nil, fmt.Errorf("ca: la CRL produite n'est pas conforme, publication annulée: %w", err)
	}

	record := castore.CRL{
		Number:     number,
		DER:        der,
		ThisUpdate: parsed.ThisUpdate,
		NextUpdate: parsed.NextUpdate,
	}
	if err := i.opts.Store.SaveCRL(ctx, record); err != nil {
		return nil, err
	}
	if err := i.record(audit.EventCACRLPublished, map[string]any{
		"numero":      number,
		"revoques":    len(entries),
		"this_update": parsed.ThisUpdate.UTC().Format(time.RFC3339),
		"next_update": parsed.NextUpdate.UTC().Format(time.RFC3339),
	}); err != nil {
		return nil, err
	}
	return &record, nil
}

// CurrentCRL retourne la dernière CRL publiée, ou ErrNotFound si aucune ne
// l'a encore été.
func (i *Issuer) CurrentCRL(ctx context.Context) (*castore.CRL, error) {
	return i.opts.Store.LatestCRL(ctx)
}
