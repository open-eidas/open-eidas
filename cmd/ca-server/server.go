package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-eidas/open-eidas/internal/ca"
	"github.com/open-eidas/open-eidas/internal/castore"
	"github.com/open-eidas/open-eidas/internal/certs"
	"github.com/open-eidas/open-eidas/internal/conformance"
	"github.com/open-eidas/open-eidas/internal/raflow"
)

// Server expose l'autorité de certification en HTTP.
//
// Les chemins de publication (/download/<CN>.cer et .crl) sont exactement ceux
// qu'OpenXPKI servait auparavant : les URL déjà gravées dans les extensions
// CDP/AIA des certificats émis restent valables, et le répondeur OCSP retrouve
// la CRL au même endroit.
type Server struct {
	issuer  *ca.Issuer
	flow    *raflow.Flow
	logger  *slog.Logger
	version string
	maxBody int64

	// Dernière CRL publiée, tenue en mémoire pour être servie sans aller-retour
	// en base à chaque requête.
	mu      sync.RWMutex
	crl     *castore.CRL
	crlErr  error
	caDER   []byte
	caPEM   []byte
	crlName string
	caName  string
}

func NewServer(issuer *ca.Issuer, flow *raflow.Flow, logger *slog.Logger, version string, maxBody int64) *Server {
	name := certs.FileName(issuer.Certificate().Subject.CommonName)
	s := &Server{
		issuer:  issuer,
		flow:    flow,
		logger:  logger,
		version: version,
		maxBody: maxBody,
		caDER:   issuer.Certificate().Raw,
		crlName: "/download/" + name + ".crl",
		caName:  "/download/" + name + ".cer",
	}
	var b strings.Builder
	for _, c := range issuer.FullChain() {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	s.caPEM = []byte(b.String())
	return s
}

// Handler compose le routeur du service.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /api/v1/ca.pem", s.handleCAPEM)
	mux.HandleFunc("GET /api/v1/conformance", s.handleConformance)
	mux.HandleFunc("GET "+s.caName, s.handleCADER)
	mux.HandleFunc("GET "+s.crlName, s.handleCRL)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

// StartCRLPublication publie une CRL immédiatement puis à intervalle régulier,
// jusqu'à annulation du contexte. La première publication est bloquante : le
// service ne doit pas se déclarer prêt sans état de révocation servable.
func (s *Server) StartCRLPublication(ctx context.Context, every time.Duration) error {
	if err := s.publishCRL(ctx); err != nil {
		return fmt.Errorf("publication initiale de la CRL: %w", err)
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.publishCRL(ctx); err != nil {
					// L'ancienne CRL reste servie : elle est encore valide
					// jusqu'à son nextUpdate, et /healthz bascule en 503 dès
					// qu'elle ne l'est plus.
					s.logger.Error("publication de la CRL impossible, conservation de la précédente", "err", err)
				}
			}
		}
	}()
	return nil
}

// currentCRL retourne la CRL à servir. Elle est relue depuis le registre, et
// non seulement depuis le cache mémoire : une révocation décidée par une
// commande d'exploitation (`ca-server revoke`) publie une nouvelle CRL depuis
// un AUTRE processus, et une révocation qui n'est pas servie ne protège
// personne. Le cache ne sert que de repli si le registre est momentanément
// injoignable.
func (s *Server) currentCRL(ctx context.Context) (*castore.CRL, error) {
	latest, err := s.issuer.CurrentCRL(ctx)
	if err != nil {
		s.mu.RLock()
		cached := s.crl
		s.mu.RUnlock()
		if cached != nil {
			s.logger.Warn("registre injoignable, CRL servie depuis le cache", "err", err, "numero", cached.Number)
			return cached, nil
		}
		return nil, err
	}
	s.mu.Lock()
	if s.crl == nil || latest.Number > s.crl.Number {
		s.crl = latest
	}
	s.mu.Unlock()
	return latest, nil
}

func (s *Server) publishCRL(ctx context.Context) error {
	crl, err := s.issuer.PublishCRL(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.crlErr = err
		return err
	}
	s.crl, s.crlErr = crl, nil
	s.logger.Info("CRL publiée", "numero", crl.Number,
		"next_update", crl.NextUpdate.UTC().Format(time.RFC3339))
	return nil
}

// enrollRequest est le corps attendu par POST /api/v1/enroll.
//
// Le protocole est défini par ce dépôt, contrairement à l'ancien RPC OpenXPKI
// dont plusieurs comportements avaient dû être rétro-ingénierés : la CSR est
// transmise en PEM, la signature est le HMAC-SHA256 hexadécimal de ses octets
// DER (voir raflow.Signature).
type enrollRequest struct {
	Profile   string `json:"profile"`
	PKCS10    string `json:"pkcs10"`
	Signature string `json:"signature"`
	Comment   string `json:"comment,omitempty"`
}

// enrollResponse est la réponse d'enrôlement. `state` reprend les états de la
// machine (PENDING, ISSUED) ; un code 202 accompagne toujours PENDING.
type enrollResponse struct {
	State         string   `json:"state"`
	TransactionID string   `json:"transaction_id"`
	RetryAfter    int      `json:"retry_after,omitempty"`
	Certificate   string   `json:"certificate,omitempty"`
	Chain         []string `json:"chain,omitempty"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "corps de requête illisible")
		return
	}
	var req enrollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "corps JSON illisible")
		return
	}
	csrDER, err := decodeCSR(req.PKCS10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := s.flow.Submit(r.Context(), csrDER, req.Profile, req.Signature)
	switch {
	case errors.Is(err, raflow.ErrUnauthenticated):
		// Volontairement laconique : distinguer « secret faux » de « CSR
		// invalide » renseignerait un attaquant sur ce qu'il doit corriger.
		writeError(w, http.StatusUnauthorized, "demande non authentifiée")
		return
	case errors.Is(err, raflow.ErrRejected):
		writeError(w, http.StatusForbidden, err.Error())
		return
	case err != nil:
		s.logger.Warn("enrôlement refusé", "err", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := enrollResponse{State: string(result.State), TransactionID: result.TransactionID}
	status := http.StatusOK
	if result.State == castore.StatePending {
		// 202 Accepted : la demande est enregistrée, la décision appartient à
		// un opérateur RA. Le client reviendra.
		status = http.StatusAccepted
		resp.RetryAfter = int(result.RetryAfter.Seconds())
		w.Header().Set("Retry-After", fmt.Sprintf("%d", resp.RetryAfter))
	} else {
		resp.Certificate = encodePEM(result.Certificate.Raw)
		for _, c := range result.Chain {
			resp.Chain = append(resp.Chain, encodePEM(c.Raw))
		}
	}
	writeJSON(w, status, resp)
}

// decodeCSR accepte la CSR en PEM ou en base64 de son DER : le premier est ce
// que produisent les outils courants, le second évite aux clients JSON de
// transporter des sauts de ligne.
func decodeCSR(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("champ pkcs10 vide")
	}
	if block, _ := pem.Decode([]byte(raw)); block != nil {
		if block.Type != "CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("bloc PEM de type %q, attendu CERTIFICATE REQUEST", block.Type)
		}
		return block.Bytes, nil
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("champ pkcs10 : ni PEM ni base64 exploitable")
	}
	return der, nil
}

func encodePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (s *Server) handleCAPEM(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.caPEM)
}

// handleCADER sert le certificat de la CA émettrice au format DER, à
// l'adresse exacte que porte l'extension AIA ca_issuers des certificats émis.
func (s *Server) handleCADER(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/pkix-cert")
	_, _ = w.Write(s.caDER)
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	crl, err := s.currentCRL(r.Context())
	if err != nil {
		s.logger.Error("CRL indisponible", "err", err)
		http.Error(w, "aucune CRL publiée", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(crl.DER)
}

// handleConformance sert la matrice ETSI telle que l'instance qui tourne
// l'applique : un auditeur peut ainsi comparer le document du dépôt à ce que
// le service déclare réellement.
func (s *Server) handleConformance(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, conformance.NewReport(s.version))
}

type healthReport struct {
	Statut      string `json:"statut"`
	Version     string `json:"version"`
	Emettrice   string `json:"emettrice"`
	CRLNumero   int64  `json:"crl_numero,omitempty"`
	CRLValidite string `json:"crl_next_update,omitempty"`
	Détail      string `json:"detail,omitempty"`
}

// handleHealth bascule en 503 dès que l'état de révocation n'est plus
// servable : un service qui ne peut plus dire ce qui est révoqué ne doit pas
// se déclarer sain (ETSI EN 319 411-1 §6.3.10).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	crl, err := s.currentCRL(r.Context())
	if err != nil {
		crl = nil
	}
	s.mu.RLock()
	crlErr := s.crlErr
	s.mu.RUnlock()
	if crlErr == nil {
		crlErr = err
	}

	rep := healthReport{
		Statut:    "ok",
		Version:   s.version,
		Emettrice: s.issuer.Certificate().Subject.String(),
	}
	status := http.StatusOK
	switch {
	case crl == nil:
		rep.Statut, rep.Détail = "degrade", "aucune CRL publiée"
		status = http.StatusServiceUnavailable
	case time.Now().After(crl.NextUpdate):
		rep.Statut = "degrade"
		rep.Détail = "la CRL publiée est périmée depuis le " + crl.NextUpdate.UTC().Format(time.RFC3339)
		status = http.StatusServiceUnavailable
	}
	if crl != nil {
		rep.CRLNumero = crl.Number
		rep.CRLValidite = crl.NextUpdate.UTC().Format(time.RFC3339)
	}
	if crlErr != nil && rep.Détail == "" {
		rep.Détail = "dernière publication en échec : " + crlErr.Error()
	}
	writeJSON(w, status, rep)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
