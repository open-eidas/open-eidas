// Package ocspresponder implémente un répondeur OCSP (RFC 6960) autonome
// pour la CA émettrice de la TSU. OpenXPKI Community n'embarque aucun
// répondeur OCSP : ce service comble cet écart en s'appuyant sur la seule
// source de vérité déjà publiée par la PKI, la CRL (voir
// docs/ARCHITECTURE.md), plutôt que d'accéder directement à la base
// OpenXPKI.
package ocspresponder

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// crlNameFilter reproduit le filtre Template Toolkit du point de
// distribution de CRL défini dans le profil OpenXPKI
// (ISSUER.CN.0.replace('[^\w-]','_')), afin de dériver la même URL de CRL
// sans nécessiter de configuration séparée.
var crlNameFilter = regexp.MustCompile(`[^\w-]`)

// CRLURL déduit l'URL de la CRL de la CA émettrice à partir de l'adresse
// publique de la PKI et du nom courant de l'émetteur.
func CRLURL(pkiPublicURL string, issuer *x509.Certificate) string {
	name := crlNameFilter.ReplaceAllString(issuer.Subject.CommonName, "_")
	return fmt.Sprintf("%s/download/%s.crl", pkiPublicURL, name)
}

type Options struct {
	// Signer et Certificate sont la clé et le certificat de signature OCSP,
	// émis par la PKI avec l'extension id-pkix-ocsp-nocheck.
	Signer      crypto.Signer
	Certificate *x509.Certificate
	// Issuer est le certificat de la CA émettrice dont ce répondeur atteste
	// le statut de révocation des certificats délivrés.
	Issuer *x509.Certificate

	CRLURL          string
	CRLRefresh      time.Duration
	HTTPClient      *http.Client
	MaxRequestBytes int64
	Logger          *slog.Logger
}

type revoked struct {
	at     time.Time
	reason int
}

// Responder répond aux requêtes OCSP en consultant un instantané de CRL
// rafraîchi périodiquement en arrière-plan.
type Responder struct {
	opts Options
	http *http.Client

	mu         sync.RWMutex
	revokedSet map[string]revoked
	thisUpdate time.Time
	nextUpdate time.Time
	lastFetch  time.Time
	lastErr    error
}

func New(o Options) (*Responder, error) {
	if o.Signer == nil || o.Certificate == nil || o.Issuer == nil {
		return nil, fmt.Errorf("ocspresponder: signataire, certificat et émetteur requis")
	}
	if o.CRLURL == "" {
		return nil, fmt.Errorf("ocspresponder: URL de CRL requise")
	}
	if o.CRLRefresh <= 0 {
		o.CRLRefresh = 5 * time.Minute
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.MaxRequestBytes <= 0 {
		o.MaxRequestBytes = 16 * 1024
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Responder{opts: o, http: o.HTTPClient}, nil
}

// Start amorce un premier chargement bloquant de la CRL puis rafraîchit en
// arrière-plan jusqu'à annulation du contexte.
func (r *Responder) Start(ctx context.Context) error {
	if err := r.refresh(ctx); err != nil {
		return fmt.Errorf("ocspresponder: chargement initial de la CRL: %w", err)
	}
	go func() {
		ticker := time.NewTicker(r.opts.CRLRefresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.refresh(ctx); err != nil {
					r.opts.Logger.Error("rafraîchissement de la CRL impossible, conservation du dernier instantané", "err", err)
				}
			}
		}
	}()
	return nil
}

func (r *Responder) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.opts.CRLURL, nil)
	if err != nil {
		return err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		r.recordErr(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("la PKI a répondu %s", resp.Status)
		r.recordErr(err)
		return err
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		r.recordErr(err)
		return err
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		r.recordErr(err)
		return fmt.Errorf("CRL illisible: %w", err)
	}
	if err := crl.CheckSignatureFrom(r.opts.Issuer); err != nil {
		r.recordErr(err)
		return fmt.Errorf("signature de la CRL invalide: %w", err)
	}

	set := make(map[string]revoked, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		set[serialKey(entry.SerialNumber)] = revoked{at: entry.RevocationTime, reason: entry.ReasonCode}
	}

	r.mu.Lock()
	r.revokedSet = set
	r.thisUpdate = crl.ThisUpdate
	r.nextUpdate = crl.NextUpdate
	r.lastFetch = time.Now()
	r.lastErr = nil
	r.mu.Unlock()

	r.opts.Logger.Info("CRL rafraîchie", "revoques", len(set), "prochaine_maj", crl.NextUpdate.UTC().Format(time.RFC3339))
	return nil
}

func (r *Responder) recordErr(err error) {
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
}

func serialKey(n *big.Int) string {
	return hex.EncodeToString(n.Bytes())
}

// ServeHTTP traite une requête OCSP encodée en DER (RFC 6960 §4.1) transmise
// en POST, seule méthode dont le support est obligatoire.
func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "méthode non supportée : POST uniquement", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, r.opts.MaxRequestBytes))
	if err != nil {
		http.Error(w, "corps de requête illisible", http.StatusBadRequest)
		return
	}
	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		r.writeResponse(w, ocsp.MalformedRequestErrorResponse)
		return
	}
	if !ocspReq.HashAlgorithm.Available() {
		r.writeResponse(w, ocsp.MalformedRequestErrorResponse)
		return
	}
	issuerNameHash, issuerKeyHash := computeIssuerHashes(r.opts.Issuer, ocspReq.HashAlgorithm)
	if !equalHash(ocspReq.IssuerNameHash, issuerNameHash) || !equalHash(ocspReq.IssuerKeyHash, issuerKeyHash) {
		r.writeResponse(w, ocsp.UnauthorizedErrorResponse)
		return
	}

	r.mu.RLock()
	set, thisUpdate, nextUpdate, lastFetch := r.revokedSet, r.thisUpdate, r.nextUpdate, r.lastFetch
	r.mu.RUnlock()

	if time.Since(lastFetch) > 2*r.opts.CRLRefresh {
		// La CRL n'a pas pu être rafraîchie depuis trop longtemps : mieux
		// vaut refuser de répondre que de garantir un statut obsolète.
		r.writeResponse(w, ocsp.TryLaterErrorResponse)
		return
	}

	status := ocsp.Good
	tmpl := ocsp.Response{
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		Certificate:  r.opts.Certificate,
		// Reprend l'algorithme de hachage utilisé par le demandeur pour ses
		// propres IssuerNameHash/IssuerKeyHash, par cohérence.
		IssuerHash: ocspReq.HashAlgorithm,
	}
	if rev, ok := set[serialKey(ocspReq.SerialNumber)]; ok {
		status = ocsp.Revoked
		tmpl.RevokedAt = rev.at
		tmpl.RevocationReason = rev.reason
	}
	tmpl.Status = status

	der, err := ocsp.CreateResponse(r.opts.Issuer, r.opts.Certificate, tmpl, r.opts.Signer)
	if err != nil {
		r.opts.Logger.Error("signature de la réponse OCSP impossible", "err", err)
		r.writeResponse(w, ocsp.InternalErrorErrorResponse)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(der)
}

func (r *Responder) writeResponse(w http.ResponseWriter, der []byte) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(der)
}

// publicKeyInfo reflète la structure ASN.1 SubjectPublicKeyInfo, pour en
// extraire la seule BIT STRING de clé publique (RFC 6960 exige le hash de
// cette BIT STRING seule, sans l'identifiant d'algorithme qui l'accompagne).
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func computeIssuerHashes(issuer *x509.Certificate, hash crypto.Hash) (nameHash, keyHash []byte) {
	h := hash.New()
	h.Write(issuer.RawSubject)
	nameHash = h.Sum(nil)

	var spki publicKeyInfo
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		// Ne devrait jamais arriver pour un certificat déjà analysé par
		// x509.ParseCertificate ; laisse un hash vide, qui ne pourra que
		// mener à un rejet "unauthorized" côté appelant.
		return nameHash, nil
	}
	h = hash.New()
	h.Write(spki.PublicKey.RightAlign())
	keyHash = h.Sum(nil)
	return nameHash, keyHash
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
