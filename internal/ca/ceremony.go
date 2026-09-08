package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/open-eidas/open-eidas/internal/audit"
	"github.com/open-eidas/open-eidas/internal/castore"
	"github.com/open-eidas/open-eidas/internal/conformance"
)

// Noms des autorités au registre.
const (
	AuthorityRoot    = "root"
	AuthorityIssuing = "issuing"
)

// CeremonyOptions décrit la hiérarchie à créer. Les deux clés vivent dans des
// tokens PKCS#11 distincts : la racine ne sert qu'à signer la CA émettrice et
// n'a aucune raison d'être accessible au service en fonctionnement.
type CeremonyOptions struct {
	RootSigner    crypto.Signer
	IssuingSigner crypto.Signer

	RootCN    string
	IssuingCN string
	// Organization et Country sont communs aux deux autorités.
	Organization string
	Country      string

	RootValidity    time.Duration
	IssuingValidity time.Duration

	// Labels d'accès aux tokens, consignés au registre pour qu'un opérateur
	// sache où retrouver chaque clé — la clé elle-même n'est jamais stockée.
	RootTokenLabel    string
	RootKeyLabel      string
	IssuingTokenLabel string
	IssuingKeyLabel   string

	Store    castore.Store
	Recorder Recorder
	// Operator identifie qui conduit la cérémonie ; consigné au procès-verbal.
	Operator string

	Clock func() time.Time
}

// Hierarchy est le résultat d'une cérémonie : les deux certificats
// d'autorité, tels qu'ils existent au registre.
type Hierarchy struct {
	Root    *x509.Certificate
	Issuing *x509.Certificate
	// Created vaut faux lorsque la hiérarchie existait déjà et a simplement
	// été relue : la cérémonie est idempotente.
	Created bool
}

func (o *CeremonyOptions) applyDefaults() error {
	if o.RootSigner == nil || o.IssuingSigner == nil {
		return errors.New("ca: la cérémonie exige les clés de la racine et de l'émettrice")
	}
	if o.Store == nil {
		return errors.New("ca: magasin de persistance manquant")
	}
	if o.Operator == "" {
		return errors.New("ca: la cérémonie exige l'identité de l'opérateur qui la conduit")
	}
	if o.RootCN == "" {
		o.RootCN = "Open eIDAS Root CA"
	}
	if o.IssuingCN == "" {
		o.IssuingCN = "Open eIDAS Issuing CA"
	}
	if o.Organization == "" {
		o.Organization = "Open eIDAS"
	}
	if o.Country == "" {
		o.Country = "FR"
	}
	if o.RootValidity <= 0 {
		o.RootValidity = 20 * 365 * 24 * time.Hour
	}
	if o.IssuingValidity <= 0 {
		o.IssuingValidity = 10 * 365 * 24 * time.Hour
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return nil
}

// RunCeremony crée la hiérarchie racine + émettrice si elle n'existe pas
// encore, et se contente de la relire sinon.
//
// L'idempotence est délibérée : la cérémonie est exécutée à chaque démarrage
// du service en démonstration, et ne doit surtout pas produire une seconde
// racine — ce qui invaliderait tous les certificats déjà émis. Lorsqu'une
// hiérarchie existe, les clés des tokens sont revérifiées contre les
// certificats enregistrés : un token remplacé est détecté au lieu de produire
// des signatures invérifiables.
func RunCeremony(ctx context.Context, o CeremonyOptions) (*Hierarchy, error) {
	if err := o.applyDefaults(); err != nil {
		return nil, err
	}

	existing, err := loadHierarchy(ctx, o.Store)
	if err != nil && !errors.Is(err, castore.ErrNotFound) {
		return nil, err
	}
	if existing != nil {
		if err := matchesSigner(existing.Root, o.RootSigner); err != nil {
			return nil, fmt.Errorf("ca: racine déjà enregistrée mais clé du token différente: %w", err)
		}
		if err := matchesSigner(existing.Issuing, o.IssuingSigner); err != nil {
			return nil, fmt.Errorf("ca: émettrice déjà enregistrée mais clé du token différente: %w", err)
		}
		return existing, nil
	}

	now := o.Clock()
	root, err := o.signRoot(now)
	if err != nil {
		return nil, err
	}
	issuing, err := o.signIssuing(now, root)
	if err != nil {
		return nil, err
	}

	for _, a := range []castore.Authority{
		{Name: AuthorityRoot, SubjectDN: root.Subject.String(), DER: root.Raw,
			TokenLabel: o.RootTokenLabel, KeyLabel: o.RootKeyLabel, CreatedAt: now},
		{Name: AuthorityIssuing, SubjectDN: issuing.Subject.String(), DER: issuing.Raw,
			TokenLabel: o.IssuingTokenLabel, KeyLabel: o.IssuingKeyLabel, CreatedAt: now},
	} {
		if err := o.Store.SaveAuthority(ctx, a); err != nil {
			return nil, err
		}
	}

	// Procès-verbal de cérémonie (ETSI EN 319 411-1 §6.5.1) : les empreintes
	// permettent de rattacher a posteriori une signature à la clé exacte
	// créée ce jour-là, sans exposer la clé elle-même.
	if o.Recorder != nil {
		if err := o.Recorder.Append(audit.EventCAceremony, map[string]any{
			"operateur":           o.Operator,
			"date":                now.UTC().Format(time.RFC3339),
			"racine_sujet":        root.Subject.String(),
			"racine_serie":        root.SerialNumber.String(),
			"racine_empreinte":    fingerprint(root),
			"racine_token":        o.RootTokenLabel,
			"racine_not_after":    root.NotAfter.UTC().Format(time.RFC3339),
			"emettrice_sujet":     issuing.Subject.String(),
			"emettrice_serie":     issuing.SerialNumber.String(),
			"emettrice_empreinte": fingerprint(issuing),
			"emettrice_token":     o.IssuingTokenLabel,
			"emettrice_not_after": issuing.NotAfter.UTC().Format(time.RFC3339),
		}); err != nil {
			return nil, fmt.Errorf("ca: journal d'audit de la cérémonie: %w", err)
		}
	}
	return &Hierarchy{Root: root, Issuing: issuing, Created: true}, nil
}

// fingerprint est l'empreinte SHA-256 du DER, telle que `openssl x509
// -fingerprint -sha256` la produit : un auditeur peut la recalculer sans
// outil propre au projet.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func (o *CeremonyOptions) caTemplate(cn string, now time.Time, validity time.Duration, signer crypto.Signer) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(signer.Public())
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{o.Organization},
			Country:      []string{o.Country},
		},
		NotBefore: now.Add(-5 * time.Minute).Truncate(time.Second),
		NotAfter:  now.Add(validity).Truncate(time.Second),
		// Une autorité signe des certificats ET des CRL : sans cRLSign, le
		// service d'état de révocation deviendrait invérifiable.
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
	}, nil
}

func (o *CeremonyOptions) signRoot(now time.Time) (*x509.Certificate, error) {
	tmpl, err := o.caTemplate(o.RootCN, now, o.RootValidity, o.RootSigner)
	if err != nil {
		return nil, err
	}
	// La racine ne signe qu'une CA émettrice, qui ne signe que des entités
	// finales : pathLenConstraint = 1 interdit toute sous-autorité
	// supplémentaire, y compris à qui obtiendrait la clé de l'émettrice.
	tmpl.MaxPathLen = 1
	cert, err := createAndVerify(tmpl, tmpl, o.RootSigner.Public(), o.RootSigner, "racine", true)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (o *CeremonyOptions) signIssuing(now time.Time, root *x509.Certificate) (*x509.Certificate, error) {
	tmpl, err := o.caTemplate(o.IssuingCN, now, o.IssuingValidity, o.IssuingSigner)
	if err != nil {
		return nil, err
	}
	if !tmpl.NotAfter.Before(root.NotAfter) {
		// Une émettrice qui survivrait à sa racine émettrait des certificats
		// invérifiables sur sa dernière période.
		tmpl.NotAfter = root.NotAfter
	}
	tmpl.MaxPathLen = 0
	tmpl.MaxPathLenZero = true
	tmpl.AuthorityKeyId = root.SubjectKeyId
	return createAndVerify(tmpl, root, o.IssuingSigner.Public(), o.RootSigner, "CA émettrice", false)
}

// createAndVerify signe puis relit le certificat produit et le soumet aux
// règles ETSI : même exigence que pour les entités finales, une autorité non
// conforme ne doit pas exister.
func createAndVerify(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer, label string, root bool) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("ca: signature du certificat de %s: %w", label, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: relecture du certificat de %s: %w", label, err)
	}
	if err := conformance.CheckCACertificate(label, cert, root).Err(); err != nil {
		return nil, fmt.Errorf("ca: le certificat de %s produit n'est pas conforme: %w", label, err)
	}
	return cert, nil
}

// LoadHierarchy relit la hiérarchie enregistrée. C'est ce que fait le service
// à chaque démarrage : il ne recrée jamais d'autorité, il retrouve la sienne.
func LoadHierarchy(ctx context.Context, store castore.Store) (*Hierarchy, error) {
	return loadHierarchy(ctx, store)
}

func loadHierarchy(ctx context.Context, store castore.Store) (*Hierarchy, error) {
	root, err := loadAuthority(ctx, store, AuthorityRoot)
	if err != nil {
		return nil, err
	}
	issuing, err := loadAuthority(ctx, store, AuthorityIssuing)
	if err != nil {
		return nil, err
	}
	return &Hierarchy{Root: root, Issuing: issuing}, nil
}

func loadAuthority(ctx context.Context, store castore.Store, name string) (*x509.Certificate, error) {
	a, err := store.Authority(ctx, name)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(a.DER)
	if err != nil {
		return nil, fmt.Errorf("ca: certificat de l'autorité %q illisible en base: %w", name, err)
	}
	return cert, nil
}
