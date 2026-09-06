// Package tsa implémente le cœur métier d'une autorité d'horodatage
// conforme à la RFC 3161 (profil ETSI EN 319 422).
package tsa

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/digitorus/timestamp"
)

// oidExtKeyUsage est l'OID de l'extension extendedKeyUsage (2.5.29.37).
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// acceptedHashes liste les empreintes acceptées dans un messageImprint.
// SHA-1 est volontairement refusé : il est proscrit par ETSI TS 119 312.
var acceptedHashes = map[crypto.Hash]bool{
	crypto.SHA256: true,
	crypto.SHA384: true,
	crypto.SHA512: true,
}

// Rejection décrit un refus protocolaire : il est converti par la couche HTTP
// en une TimeStampResp de statut « rejection », qui reste une réponse valide.
type Rejection struct {
	Status  timestamp.Status
	Failure timestamp.FailureInfo
	Reason  string
}

func (r *Rejection) Error() string { return r.Reason }

func reject(failure timestamp.FailureInfo, format string, args ...any) *Rejection {
	return &Rejection{
		Status:  timestamp.Rejection,
		Failure: failure,
		Reason:  fmt.Sprintf(format, args...),
	}
}

type Options struct {
	Signer        crypto.Signer
	Certificate   *x509.Certificate
	Chain         []*x509.Certificate
	Policy        asn1.ObjectIdentifier
	Accuracy      time.Duration
	SigningDigest crypto.Hash
	Clock         func() time.Time
}

type Authority struct {
	opts Options
}

// Warning décrit un écart au profil qualifié détecté au démarrage, sans être
// bloquant pour un déploiement de démonstration.
type Warning string

// New valide la cohérence du matériel cryptographique et construit l'autorité.
// Les avertissements retournés signalent les écarts au profil ETSI qui
// empêcheraient une qualification, mais laissent le prototype démarrer.
func New(o Options) (*Authority, []Warning, error) {
	if o.Signer == nil {
		return nil, nil, errors.New("tsa: signer manquant")
	}
	if o.Certificate == nil {
		return nil, nil, errors.New("tsa: certificat TSU manquant")
	}
	if len(o.Policy) == 0 {
		return nil, nil, errors.New("tsa: OID de politique d'horodatage manquant")
	}
	if o.SigningDigest == 0 || !o.SigningDigest.Available() {
		return nil, nil, errors.New("tsa: algorithme d'empreinte de signature indisponible")
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}

	certPub, err := x509.MarshalPKIXPublicKey(o.Certificate.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tsa: clé publique du certificat illisible: %w", err)
	}
	signerPub, err := x509.MarshalPKIXPublicKey(o.Signer.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("tsa: clé publique du signer illisible: %w", err)
	}
	if !bytes.Equal(certPub, signerPub) {
		return nil, nil, errors.New("tsa: la clé du token PKCS#11 ne correspond pas au certificat TSU")
	}

	if !hasTimeStampingEKU(o.Certificate) {
		return nil, nil, errors.New("tsa: le certificat TSU ne porte pas l'extendedKeyUsage id-kp-timeStamping")
	}

	var warnings []Warning
	if !isEKUCritical(o.Certificate) {
		warnings = append(warnings, "l'extension extendedKeyUsage n'est pas marquée critique (exigée par ETSI EN 319 422)")
	}
	if len(o.Certificate.ExtKeyUsage) > 1 || len(o.Certificate.UnknownExtKeyUsage) > 0 {
		warnings = append(warnings, "le certificat TSU porte d'autres usages étendus que id-kp-timeStamping")
	}
	now := o.Clock()
	if now.After(o.Certificate.NotAfter) {
		return nil, nil, fmt.Errorf("tsa: certificat TSU expiré depuis le %s", o.Certificate.NotAfter.Format(time.RFC3339))
	}
	if now.Before(o.Certificate.NotBefore) {
		return nil, nil, fmt.Errorf("tsa: certificat TSU pas encore valide (à partir du %s)", o.Certificate.NotBefore.Format(time.RFC3339))
	}

	return &Authority{opts: o}, warnings, nil
}

func (a *Authority) Certificate() *x509.Certificate { return a.opts.Certificate }
func (a *Authority) Chain() []*x509.Certificate     { return a.opts.Chain }
func (a *Authority) Policy() asn1.ObjectIdentifier  { return a.opts.Policy }
func (a *Authority) Accuracy() time.Duration        { return a.opts.Accuracy }
func (a *Authority) AcceptedHashes() []crypto.Hash {
	return []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
}

// Timestamp consomme une TimeStampReq encodée en DER et retourne une
// TimeStampResp DER de statut « granted ». Un refus protocolaire est signalé
// par une erreur *Rejection ; toute autre erreur relève d'une défaillance
// interne.
func (a *Authority) Timestamp(reqDER []byte) ([]byte, error) {
	req, err := timestamp.ParseRequest(reqDER)
	if err != nil {
		return nil, reject(timestamp.BadDataFormat, "requête RFC 3161 illisible: %v", err)
	}
	if !req.HashAlgorithm.Available() || !acceptedHashes[req.HashAlgorithm] {
		return nil, reject(timestamp.BadAlgorithm, "algorithme d'empreinte refusé par la politique")
	}
	if len(req.HashedMessage) != req.HashAlgorithm.Size() {
		return nil, reject(timestamp.BadDataFormat, "longueur d'empreinte incohérente avec l'algorithme annoncé")
	}
	if len(req.TSAPolicyOID) > 0 && !req.TSAPolicyOID.Equal(a.opts.Policy) {
		return nil, reject(timestamp.UnacceptedPolicy, "politique demandée %s non servie par cette TSA", req.TSAPolicyOID)
	}
	for _, ext := range req.Extensions {
		if ext.Critical {
			return nil, reject(timestamp.UnacceptedExtension, "extension critique non supportée: %s", ext.Id)
		}
	}

	token := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              a.opts.Clock().UTC().Truncate(time.Second),
		Accuracy:          a.opts.Accuracy,
		Nonce:             req.Nonce,
		Policy:            a.opts.Policy,
		Ordering:          false,
		Qualified:         false,
		AddTSACertificate: req.Certificates,
		Certificates:      a.opts.Chain,
	}

	respDER, err := token.CreateResponseWithOpts(a.opts.Certificate, a.opts.Signer, a.opts.SigningDigest)
	if err != nil {
		return nil, fmt.Errorf("tsa: génération du jeton: %w", err)
	}
	return respDER, nil
}

// ErrorResponse encode une TimeStampResp de refus exploitable par le client.
func ErrorResponse(status timestamp.Status, failure timestamp.FailureInfo) ([]byte, error) {
	return timestamp.CreateErrorResponse(status, failure)
}

func hasTimeStampingEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}
	return false
}

func isEKUCritical(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtKeyUsage) {
			return ext.Critical
		}
	}
	return false
}
