package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/open-eidas/open-eidas/internal/conformance"
)

// Noms des profils servis par cette autorité.
const (
	ProfileTSASigner     = "tsa_signer"
	ProfileOCSPResponder = "ocsp_responder"
)

// Profile décrit ce qu'un certificat émis par cette autorité contient, sous
// forme de structure Go compilée et testée — et non de configuration
// interprétée au démarrage.
//
// C'est la correction directe du défaut relevé dans INDEPENDANCE.md : un
// profil OpenXPKI mal formé (durée relative au mauvais format, champ scalaire
// là où une liste était attendue) échouait silencieusement côté moteur NICE,
// à l'émission, sans que rien ne signale l'erreur au chargement. Ici, un
// profil incohérent est soit une erreur de compilation, soit un test rouge.
type Profile struct {
	Name  string
	Label string

	// Parties fixes du sujet. Seul le CN provient de la CSR : le reste est
	// imposé par l'autorité, de sorte qu'un demandeur ne puisse pas se
	// déclarer d'une autre organisation que celle qu'il sert.
	OrganizationalUnit string
	Organization       string
	Country            string

	Validity time.Duration

	KeyUsage    x509.KeyUsage
	ExtKeyUsage []asn1.ObjectIdentifier
	// EKUCritical marque extendedKeyUsage critique. ETSI EN 319 421 §7.7.2
	// l'exige pour un certificat de TSU : sans criticité, un vérificateur
	// peut ignorer la restriction d'usage.
	EKUCritical bool

	// OCSPNoCheck ajoute id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1).
	OCSPNoCheck bool

	// Publication des points de distribution. Les URL elles-mêmes sont
	// construites par l'émettrice à partir de son propre nom : le profil
	// décide seulement de leur présence, il ne porte pas de gabarit de chaîne
	// à substituer au démarrage.
	IncludeCRLDistributionPoint bool
	IncludeCAIssuers            bool
	IncludeOCSPResponder        bool

	// Check applique les règles ETSI propres à ce profil au certificat
	// réellement émis, relu depuis son DER.
	Check func(subject string, cert *x509.Certificate) conformance.Findings
}

// OID des usages étendus employés par ces profils.
var (
	oidEKUTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidEKUOCSPSigning  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// Subject construit le sujet du certificat : le CN vient de la demande, le
// reste du profil.
func (p *Profile) Subject(commonName string) pkix.Name {
	n := pkix.Name{CommonName: commonName}
	if p.OrganizationalUnit != "" {
		n.OrganizationalUnit = []string{p.OrganizationalUnit}
	}
	if p.Organization != "" {
		n.Organization = []string{p.Organization}
	}
	if p.Country != "" {
		n.Country = []string{p.Country}
	}
	return n
}

// tsaSigner reproduit le profil ETSI EN 319 422 / EN 319 421 §7.7.2 de
// l'unité d'horodatage, précédemment porté par
// deploy/openxpki/.../profile/tsa_signer.yaml.
var tsaSigner = &Profile{
	Name:               ProfileTSASigner,
	Label:              "Open eIDAS Time-Stamping Unit",
	OrganizationalUnit: "Time Stamping Authority",
	Organization:       "Open eIDAS",
	Country:            "FR",
	Validity:           365 * 24 * time.Hour,
	// nonRepudiation (contentCommitment) accompagne digitalSignature : un
	// jeton d'horodatage engage l'autorité sur la date, il ne s'agit pas
	// d'une simple authentification.
	KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	ExtKeyUsage:                 []asn1.ObjectIdentifier{oidEKUTimeStamping},
	EKUCritical:                 true,
	IncludeCRLDistributionPoint: true,
	IncludeCAIssuers:            true,
	IncludeOCSPResponder:        true,
	Check:                       conformance.CheckTSUCertificate,
}

// ocspResponder reproduit le profil du répondeur OCSP, précédemment porté par
// deploy/openxpki/.../profile/ocsp_responder.yaml.
//
// Ni CDP ni AIA : ocsp-nocheck dispense de vérifier la révocation de ce
// certificat, et la durée de vie courte est la contrepartie de cette dispense.
var ocspResponder = &Profile{
	Name:                        ProfileOCSPResponder,
	Label:                       "Open eIDAS OCSP Responder",
	OrganizationalUnit:          "OCSP Responder",
	Organization:                "Open eIDAS",
	Country:                     "FR",
	Validity:                    90 * 24 * time.Hour,
	KeyUsage:                    x509.KeyUsageDigitalSignature,
	ExtKeyUsage:                 []asn1.ObjectIdentifier{oidEKUOCSPSigning},
	EKUCritical:                 true,
	OCSPNoCheck:                 true,
	IncludeCRLDistributionPoint: false,
	IncludeCAIssuers:            false,
	IncludeOCSPResponder:        false,
	Check:                       conformance.CheckOCSPResponderCertificate,
}

var profiles = map[string]*Profile{
	ProfileTSASigner:     tsaSigner,
	ProfileOCSPResponder: ocspResponder,
}

// ProfileByName retourne le profil demandé. Un nom inconnu est une erreur
// explicite : aucun profil par défaut n'est appliqué en silence, ce qui est
// précisément l'héritage implicite qui piégeait la configuration OpenXPKI.
func ProfileByName(name string) (*Profile, error) {
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("ca: profil de certificat inconnu: %q", name)
	}
	return p, nil
}

// ProfileNames liste les profils servis, pour les interfaces d'exploitation.
func ProfileNames() []string {
	return []string{ProfileTSASigner, ProfileOCSPResponder}
}
