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

	"github.com/open-eidas/open-eidas/internal/audit"
	"github.com/open-eidas/open-eidas/internal/conformance"
)

// Rejection décrit un refus protocolaire : il est converti par la couche HTTP
// en une TimeStampResp de statut « rejection », qui reste une réponse valide.
type Rejection struct {
	Status  timestamp.Status
	Failure timestamp.FailureInfo
	Reason  string
}

func (r *Rejection) Error() string { return r.Reason }

// record consigne une décision. Une défaillance du journal est fatale pour la
// requête : un jeton dont l'émission n'est pas tracée n'est pas défendable.
func (a *Authority) record(event string, data map[string]any) error {
	if a.opts.Recorder == nil {
		return nil
	}
	if err := a.opts.Recorder.Append(event, data); err != nil {
		return fmt.Errorf("tsa: journal d'audit: %w", err)
	}
	return nil
}

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
	Clock         Clock
	Recorder      Recorder
}

// Recorder consigne les décisions de l'autorité dans le journal d'audit.
type Recorder interface {
	Append(event string, data map[string]any) error
}

// Clock fournit l'heure à estampiller. Une erreur signifie que l'heure n'est
// pas rattachable à UTC dans les limites annoncées : la TSA doit alors
// refuser de signer plutôt que de produire un jeton non fiable.
type Clock interface {
	Now() (time.Time, error)
}

type systemClock struct{}

func (systemClock) Now() (time.Time, error) { return time.Now(), nil }

type Authority struct {
	opts Options
}

// Warning décrit un écart au profil signalé au démarrage sans être bloquant.
// Les écarts bloquants, eux, empêchent l'autorité de démarrer : voir
// internal/conformance, qui porte la distinction une fois pour toutes.
type Warning string

// New valide la cohérence du matériel cryptographique et construit l'autorité.
//
// Les règles ETSI appliquées au certificat TSU ne sont pas réécrites ici :
// elles viennent d'internal/conformance, seul endroit du dépôt où elles sont
// définies. Un écart bloquant (usage étendu non critique ou surnuméraire, clé
// trop courte, durée de vie aberrante) empêche le démarrage ; les
// avertissements sont journalisés.
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
		o.Clock = systemClock{}
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

	findings := conformance.CheckTSUCertificate("certificat TSU", o.Certificate)
	if err := findings.Err(); err != nil {
		return nil, nil, fmt.Errorf("tsa: %w", err)
	}
	var warnings []Warning
	for _, f := range findings.Advisories() {
		warnings = append(warnings, Warning(f.String()))
	}
	// La validité du certificat se vérifie sur l'heure système : à ce stade
	// la surveillance n'a pas encore de mesure, et un certificat expiré doit
	// être détecté même sans traçabilité.
	now := time.Now()
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
func (a *Authority) AcceptedHashes() []crypto.Hash  { return conformance.AdmittedHashes() }

// Timestamp consomme une TimeStampReq encodée en DER et retourne une
// TimeStampResp DER de statut « granted ». Un refus protocolaire est signalé
// par une erreur *Rejection ; toute autre erreur relève d'une défaillance
// interne.
func (a *Authority) Timestamp(reqDER []byte) ([]byte, error) {
	respDER, err := a.timestamp(reqDER)
	if err != nil {
		var rejection *Rejection
		if errors.As(err, &rejection) {
			if recErr := a.record(audit.EventTimestampRejected, map[string]any{
				"failure_info": rejection.Failure.String(),
				"reason":       rejection.Reason,
			}); recErr != nil {
				return nil, recErr
			}
		}
		return nil, err
	}
	return respDER, nil
}

func (a *Authority) timestamp(reqDER []byte) ([]byte, error) {
	req, err := timestamp.ParseRequest(reqDER)
	if err != nil {
		return nil, reject(timestamp.BadDataFormat, "requête RFC 3161 illisible: %v", err)
	}
	if !req.HashAlgorithm.Available() || !conformance.HashAdmitted(req.HashAlgorithm) {
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

	genTime, err := a.opts.Clock.Now()
	if err != nil {
		return nil, reject(timestamp.TimeNotAvailable, "source de temps indisponible: %v", err)
	}

	token := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              genTime.UTC().Truncate(time.Second),
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

	// Le jeton est relu pour consigner exactement ce qu'il contient, et non
	// ce que le service croit y avoir mis.
	issued, err := timestamp.ParseResponse(respDER)
	if err != nil {
		return nil, fmt.Errorf("tsa: relecture du jeton émis: %w", err)
	}
	if err := a.record(audit.EventTimestampGranted, map[string]any{
		"serial_number":   issued.SerialNumber.String(),
		"gen_time":        issued.Time.UTC().Format(time.RFC3339Nano),
		"policy":          issued.Policy.String(),
		"hash_algorithm":  issued.HashAlgorithm.String(),
		"message_imprint": fmt.Sprintf("%x", issued.HashedMessage),
		"nonce":           issued.Nonce != nil,
	}); err != nil {
		return nil, err
	}
	return respDER, nil
}

// ErrorResponse encode une TimeStampResp de refus exploitable par le client.
func ErrorResponse(status timestamp.Status, failure timestamp.FailureInfo) ([]byte, error) {
	return timestamp.CreateErrorResponse(status, failure)
}
