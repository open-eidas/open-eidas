// Package raflow porte la machine à états d'enrôlement et d'approbation de
// l'autorité d'enregistrement (RA).
//
// Elle remplace le moteur de workflow générique d'OpenXPKI par un unique
// workflow explicite :
//
//	           (HMAC valide)      (approbation, opérateur)      (émission)
//	CSR ──────────────────► PENDING ──────────────────► APPROVED ─────────► ISSUED
//	                           │
//	                           └──── (rejet, opérateur) ────► REJECTED
//
// Deux propriétés sont le cœur du paquet, et chacune corrige un défaut
// constaté sur OpenXPKI (voir INDEPENDANCE.md) :
//
//   - aucune fonction ne fait passer une demande de PENDING à ISSUED sans
//     passer par Approve ; il n'existe aucune règle d'éligibilité, aucune
//     auto-approbation, aucun chemin dérobé ;
//   - Approve et Reject exigent l'identité de l'opérateur qui décide, et la
//     consignent en base comme au journal d'audit (ETSI EN 319 411-1 §6.2.1).
package raflow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/open-eidas/open-eidas/internal/audit"
	"github.com/open-eidas/open-eidas/internal/ca"
	"github.com/open-eidas/open-eidas/internal/castore"
)

var (
	// ErrUnauthenticated signale une demande dont la signature HMAC ne
	// correspond pas au secret partagé.
	ErrUnauthenticated = errors.New("raflow: demande non authentifiée")
	// ErrRejected signale une demande qu'un opérateur a refusée.
	ErrRejected = errors.New("raflow: demande rejetée par l'autorité d'enregistrement")
	// ErrNotFound signale une demande inconnue.
	ErrNotFound = errors.New("raflow: demande inconnue")
	// ErrNotPending signale une décision sur une demande qui n'est plus en
	// attente : elle a déjà été tranchée, ou le certificat est déjà émis.
	ErrNotPending = errors.New("raflow: la demande n'est plus en attente de décision")
)

// Recorder consigne les décisions au journal d'audit.
type Recorder interface {
	Append(event string, data map[string]any) error
}

// DeciderOptions configure la partie « décision » de la machine à états.
//
// Elle est séparée du reste parce qu'un opérateur RA n'a aucune raison de
// détenir la clé de l'autorité : approuver, c'est décider, pas signer. La
// commande `ca-server ra approve` n'ouvre donc aucun token PKCS#11 ;
// l'émission a lieu côté `serve`, quand le demandeur revient chercher son
// certificat.
type DeciderOptions struct {
	Store    castore.Store
	Recorder Recorder
	Clock    func() time.Time
}

// Decider porte les transitions PENDING → APPROVED et PENDING → REJECTED.
type Decider struct {
	opts DeciderOptions
}

// NewDecider construit l'interface de décision de l'opérateur RA.
func NewDecider(o DeciderOptions) (*Decider, error) {
	if o.Store == nil {
		return nil, errors.New("raflow: magasin de persistance manquant")
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Decider{opts: o}, nil
}

// Options configure la machine à états complète (décision et émission).
type Options struct {
	Store  castore.Store
	Issuer *ca.Issuer
	// HMACSecret authentifie le demandeur. Vide, l'enrôlement devient anonyme :
	// refusé explicitement à la construction plutôt que toléré par défaut.
	HMACSecret string
	Recorder   Recorder
	// RetryAfter est le délai suggéré au client tant que sa demande attend
	// une décision.
	RetryAfter time.Duration
	Clock      func() time.Time
}

// Flow est la machine à états complète : décision (par composition d'un
// Decider) et émission.
type Flow struct {
	*Decider
	opts Options
}

func New(o Options) (*Flow, error) {
	if o.Store == nil {
		return nil, errors.New("raflow: magasin de persistance manquant")
	}
	if o.Issuer == nil {
		return nil, errors.New("raflow: autorité émettrice manquante")
	}
	if o.HMACSecret == "" {
		// Une PKI qui délivre à quiconque le demande n'a pas de valeur : le
		// secret partagé n'est pas une identité, mais il est le minimum.
		return nil, errors.New("raflow: secret HMAC d'enrôlement non configuré (enrôlement anonyme refusé)")
	}
	if o.RetryAfter <= 0 {
		o.RetryAfter = 5 * time.Second
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	decider, err := NewDecider(DeciderOptions{Store: o.Store, Recorder: o.Recorder, Clock: o.Clock})
	if err != nil {
		return nil, err
	}
	return &Flow{Decider: decider, opts: o}, nil
}

func (d *Decider) now() time.Time { return d.opts.Clock() }

func (d *Decider) record(event string, data map[string]any) error {
	if d.opts.Recorder == nil {
		return nil
	}
	if err := d.opts.Recorder.Append(event, data); err != nil {
		return fmt.Errorf("raflow: journal d'audit: %w", err)
	}
	return nil
}

// Signature calcule l'authentifiant HMAC-SHA256 attendu sur les octets DER
// bruts d'une CSR. Le client et le serveur appellent la même fonction : le
// protocole est défini par ce dépôt, et non déduit du comportement d'un tiers.
func Signature(csrDER []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(csrDER)
	return hex.EncodeToString(mac.Sum(nil))
}

// Fingerprint est l'empreinte SHA-256 hexadécimale de la CSR. Elle sert de
// clé d'idempotence : re-soumettre la même CSR retrouve la même demande.
func Fingerprint(csrDER []byte) string {
	sum := sha256.Sum256(csrDER)
	return hex.EncodeToString(sum[:])
}

// TransactionID dérive l'identifiant public d'une demande de sa CSR. Étant
// déterministe, un client qui l'a perdu peut le recalculer sans que le serveur
// ait à tenir un état côté client.
func TransactionID(csrDER []byte) string {
	return Fingerprint(csrDER)[:32]
}

// Result décrit l'issue d'une soumission.
type Result struct {
	State         castore.RequestState
	TransactionID string
	// RetryAfter est renseigné tant que la demande attend une décision.
	RetryAfter time.Duration
	// Certificate et Chain ne sont renseignés qu'à l'état ISSUED.
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}

// Submit reçoit une demande d'enrôlement, ou reprend celle qui correspond
// déjà à cette CSR.
//
// C'est aussi le point où une demande approuvée devient un certificat :
// l'émission a lieu ici, dans le processus qui détient la clé de l'autorité,
// et non au moment de l'approbation — l'opérateur RA décide, il ne signe pas.
func (f *Flow) Submit(ctx context.Context, csrDER []byte, profileName, signature string) (*Result, error) {
	if !hmac.Equal([]byte(signature), []byte(Signature(csrDER, f.opts.HMACSecret))) {
		return nil, ErrUnauthenticated
	}
	profile, err := ca.ProfileByName(profileName)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("raflow: demande de certificat illisible: %w", err)
	}
	if err := ca.ValidateCSR(csr); err != nil {
		return nil, err
	}

	fingerprint := Fingerprint(csrDER)
	existing, err := f.opts.Store.RequestByFingerprint(ctx, fingerprint)
	if err != nil && !errors.Is(err, castore.ErrNotFound) {
		return nil, err
	}
	if existing == nil {
		return f.open(ctx, csrDER, csr, profile, fingerprint)
	}
	if existing.Profile != profileName {
		return nil, fmt.Errorf("raflow: cette demande a été soumise pour le profil %q, pas %q",
			existing.Profile, profileName)
	}
	return f.resume(ctx, existing, csr, profile)
}

func (f *Flow) open(ctx context.Context, csrDER []byte, csr *x509.CertificateRequest, profile *ca.Profile, fingerprint string) (*Result, error) {
	r := castore.Request{
		TransactionID:  TransactionID(csrDER),
		CSRFingerprint: fingerprint,
		CSRDER:         csrDER,
		Profile:        profile.Name,
		SubjectCN:      csr.Subject.CommonName,
		State:          castore.StatePending,
		CreatedAt:      f.now(),
	}
	if err := f.opts.Store.CreateRequest(ctx, r); err != nil {
		return nil, err
	}
	if err := f.record(audit.EventCARequestReceived, map[string]any{
		"transaction": r.TransactionID,
		"profil":      r.Profile,
		"sujet_cn":    r.SubjectCN,
		"empreinte":   fingerprint,
	}); err != nil {
		return nil, err
	}
	return &Result{
		State:         castore.StatePending,
		TransactionID: r.TransactionID,
		RetryAfter:    f.opts.RetryAfter,
	}, nil
}

func (f *Flow) resume(ctx context.Context, r *castore.Request, csr *x509.CertificateRequest, profile *ca.Profile) (*Result, error) {
	switch r.State {
	case castore.StatePending:
		return &Result{
			State:         castore.StatePending,
			TransactionID: r.TransactionID,
			RetryAfter:    f.opts.RetryAfter,
		}, nil

	case castore.StateRejected:
		return nil, fmt.Errorf("%w (opérateur %s%s)", ErrRejected, r.Operator, comment(r.Comment))

	case castore.StateApproved:
		return f.issue(ctx, r, csr, profile)

	case castore.StateIssued:
		cert, err := f.issuedCertificate(ctx, r)
		if err != nil {
			return nil, err
		}
		return &Result{
			State:         castore.StateIssued,
			TransactionID: r.TransactionID,
			Certificate:   cert,
			Chain:         f.opts.Issuer.FullChain(),
		}, nil

	default:
		return nil, fmt.Errorf("raflow: état de demande inattendu: %q", r.State)
	}
}

func comment(c string) string {
	if c == "" {
		return ""
	}
	return " : " + c
}

func (f *Flow) issuedCertificate(ctx context.Context, r *castore.Request) (*x509.Certificate, error) {
	if r.CertificateSerial == nil {
		return nil, fmt.Errorf("raflow: demande %s marquée émise sans certificat associé", r.TransactionID)
	}
	rec, err := f.opts.Store.Certificate(ctx, r.CertificateSerial)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(rec.DER)
	if err != nil {
		return nil, fmt.Errorf("raflow: certificat illisible en base: %w", err)
	}
	return cert, nil
}

// issue transforme une demande approuvée en certificat, puis applique la
// politique « une seule unité active par sujet » en révoquant les certificats
// précédents du même sujet.
func (f *Flow) issue(ctx context.Context, r *castore.Request, csr *x509.CertificateRequest, profile *ca.Profile) (*Result, error) {
	// Les certificats actifs du sujet sont relevés AVANT l'émission : après,
	// le nouveau certificat en ferait partie et se révoquerait lui-même.
	subjectDN := profile.Subject(csr.Subject.CommonName).String()
	previous, err := f.opts.Store.ActiveBySubject(ctx, subjectDN, f.now())
	if err != nil {
		return nil, err
	}

	cert, err := f.opts.Issuer.Issue(ctx, csr, profile, r.TransactionID)
	if err != nil {
		return nil, err
	}

	updated := *r
	updated.State = castore.StateIssued
	updated.IssuedAt = f.now()
	updated.CertificateSerial = cert.SerialNumber
	if err := f.opts.Store.UpdateRequest(ctx, updated, castore.StateApproved); err != nil {
		return nil, err
	}

	// reasonCode 4 = superseded (RFC 5280 §5.3.1) : le motif exact compte,
	// « unspecified » ne justifierait rien devant un auditeur.
	const superseded = 4
	for _, old := range previous {
		if err := f.opts.Issuer.Revoke(ctx, old.Serial, superseded,
			"raflow:renouvellement", "remplacé par "+cert.SerialNumber.String()); err != nil {
			return nil, err
		}
	}

	return &Result{
		State:         castore.StateIssued,
		TransactionID: r.TransactionID,
		Certificate:   cert,
		Chain:         f.opts.Issuer.FullChain(),
	}, nil
}

// Approve fait passer une demande de PENDING à APPROVED. C'est la SEULE
// transition qui y mène, et elle exige l'identité de l'opérateur : c'est ce
// qui rend la décision imputable, exigence d'ETSI EN 319 411-1 §6.2.1.
func (d *Decider) Approve(ctx context.Context, transactionID, operator, comment string) (*castore.Request, error) {
	return d.decide(ctx, transactionID, operator, comment, castore.StateApproved)
}

// Reject refuse définitivement une demande. Le demandeur en est informé lors
// de sa prochaine soumission, avec le nom de l'opérateur et son motif.
func (d *Decider) Reject(ctx context.Context, transactionID, operator, comment string) (*castore.Request, error) {
	return d.decide(ctx, transactionID, operator, comment, castore.StateRejected)
}

func (d *Decider) decide(ctx context.Context, transactionID, operator, comment string, target castore.RequestState) (*castore.Request, error) {
	if operator == "" {
		return nil, errors.New("raflow: la décision exige l'identité de l'opérateur qui la prend")
	}
	r, err := d.opts.Store.RequestByTransactionID(ctx, transactionID)
	if errors.Is(err, castore.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if r.State != castore.StatePending {
		return nil, fmt.Errorf("%w (état actuel: %s)", ErrNotPending, r.State)
	}

	updated := *r
	updated.State = target
	updated.Operator = operator
	updated.Comment = comment
	updated.DecidedAt = d.now()
	if err := d.opts.Store.UpdateRequest(ctx, updated, castore.StatePending); err != nil {
		if errors.Is(err, castore.ErrConflict) {
			return nil, ErrNotPending
		}
		return nil, err
	}

	event := audit.EventCARequestApproved
	if target == castore.StateRejected {
		event = audit.EventCARequestRejected
	}
	if err := d.record(event, map[string]any{
		"transaction": updated.TransactionID,
		"profil":      updated.Profile,
		"sujet_cn":    updated.SubjectCN,
		"operateur":   operator,
		"commentaire": comment,
		"date":        updated.DecidedAt.UTC().Format(time.RFC3339),
	}); err != nil {
		return nil, err
	}
	return &updated, nil
}

// Requests liste les demandes dans l'état donné (toutes si l'état est vide),
// pour l'interface d'exploitation de l'opérateur RA.
func (d *Decider) Requests(ctx context.Context, state castore.RequestState) ([]castore.Request, error) {
	return d.opts.Store.Requests(ctx, state)
}
