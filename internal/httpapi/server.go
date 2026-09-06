// Package httpapi expose l'autorité d'horodatage en HTTP : l'endpoint binaire
// RFC 3161 d'une part, une façade JSON de confort d'autre part.
package httpapi

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/open-eidas/tsa/internal/tsa"
)

const (
	mimeQuery = "application/timestamp-query"
	mimeReply = "application/timestamp-reply"
)

type Options struct {
	Authority       *tsa.Authority
	MaxRequestBytes int64
	Logger          *slog.Logger
	Version         string
}

func New(o Options) http.Handler {
	s := &server{opts: o}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tsa", s.handleRFC3161)
	mux.HandleFunc("POST /api/v1/timestamp", s.handleJSON)
	mux.HandleFunc("GET /api/v1/policy", s.handlePolicy)
	mux.HandleFunc("GET /api/v1/certificate", s.handleCertificate)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.withLogging(mux)
}

type server struct {
	opts Options
}

func (s *server) handleRFC3161(w http.ResponseWriter, r *http.Request) {
	if ct := contentType(r); ct != "" && ct != mimeQuery && ct != "application/octet-stream" {
		s.writeRejection(w, timestamp.BadRequest, "content-type "+ct+" inattendu")
		return
	}
	body, err := s.readBody(r)
	if err != nil {
		s.writeRejection(w, timestamp.BadDataFormat, err.Error())
		return
	}
	if strings.EqualFold(r.Header.Get("Content-Transfer-Encoding"), "base64") {
		decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if derr != nil {
			s.writeRejection(w, timestamp.BadDataFormat, "corps base64 invalide")
			return
		}
		body = decoded
	}

	respDER, err := s.opts.Authority.Timestamp(body)
	if err != nil {
		s.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", mimeReply)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respDER)
}

type jsonRequest struct {
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
	CertReq   *bool  `json:"cert_req"`
	Nonce     bool   `json:"nonce"`
}

type jsonResponse struct {
	Granted       bool   `json:"granted"`
	Token         string `json:"token"`
	GenTime       string `json:"gen_time"`
	SerialNumber  string `json:"serial_number"`
	Policy        string `json:"policy"`
	AccuracySecs  string `json:"accuracy"`
	HashAlgorithm string `json:"hash_algorithm"`
}

// handleJSON offre un chemin d'appel testable en une commande curl, sans
// avoir à fabriquer une requête ASN.1 : le service construit lui-même la
// TimeStampReq à partir de l'empreinte fournie.
func (s *server) handleJSON(w http.ResponseWriter, r *http.Request) {
	body, err := s.readBody(r)
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	var in jsonRequest
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "corps JSON invalide")
		return
	}
	hash, err := parseHash(in.Algorithm)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	digest, err := decodeDigest(in.Hash)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(digest) != hash.Size() {
		writeJSONError(w, http.StatusBadRequest, "longueur d'empreinte incohérente avec l'algorithme demandé")
		return
	}

	req := timestamp.Request{
		HashAlgorithm: hash,
		HashedMessage: digest,
		Certificates:  in.CertReq == nil || *in.CertReq,
	}
	if in.Nonce {
		nonce, nerr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
		if nerr != nil {
			writeJSONError(w, http.StatusInternalServerError, "génération du nonce impossible")
			return
		}
		req.Nonce = nonce
	}
	reqDER, err := req.Marshal()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "encodage de la requête impossible")
		return
	}

	respDER, err := s.opts.Authority.Timestamp(reqDER)
	if err != nil {
		var rejection *tsa.Rejection
		if errors.As(err, &rejection) {
			writeJSONError(w, http.StatusBadRequest, rejection.Reason)
			return
		}
		s.logger().Error("horodatage impossible", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "défaillance interne de la TSA")
		return
	}

	parsed, err := timestamp.ParseResponse(respDER)
	if err != nil {
		s.logger().Error("relecture du jeton impossible", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "défaillance interne de la TSA")
		return
	}
	writeJSON(w, http.StatusOK, jsonResponse{
		Granted:       true,
		Token:         base64.StdEncoding.EncodeToString(respDER),
		GenTime:       parsed.Time.UTC().Format(time.RFC3339),
		SerialNumber:  parsed.SerialNumber.String(),
		Policy:        parsed.Policy.String(),
		AccuracySecs:  s.opts.Authority.Accuracy().String(),
		HashAlgorithm: hashName(parsed.HashAlgorithm),
	})
}

func (s *server) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	cert := s.opts.Authority.Certificate()
	hashes := make([]string, 0, 3)
	for _, h := range s.opts.Authority.AcceptedHashes() {
		hashes = append(hashes, hashName(h))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_oid":       s.opts.Authority.Policy().String(),
		"accuracy":         s.opts.Authority.Accuracy().String(),
		"accepted_hashes":  hashes,
		"tsu_subject":      cert.Subject.String(),
		"tsu_issuer":       cert.Issuer.String(),
		"tsu_not_after":    cert.NotAfter.UTC().Format(time.RFC3339),
		"tsu_serial":       cert.SerialNumber.String(),
		"rfc3161_endpoint": "/tsa",
		"version":          s.opts.Version,
	})
}

func (s *server) handleCertificate(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	certs := append([]*x509.Certificate{s.opts.Authority.Certificate()}, s.opts.Authority.Chain()...)
	for _, c := range certs {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	cert := s.opts.Authority.Certificate()
	status := http.StatusOK
	state := "ok"
	if time.Now().After(cert.NotAfter) {
		status, state = http.StatusServiceUnavailable, "certificat TSU expiré"
	}
	writeJSON(w, status, map[string]string{"status": state, "version": s.opts.Version})
}

func (s *server) readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, s.opts.MaxRequestBytes))
	if err != nil {
		return nil, errors.New("corps de requête illisible ou trop volumineux")
	}
	if len(body) == 0 {
		return nil, errors.New("corps de requête vide")
	}
	return body, nil
}

func (s *server) writeError(w http.ResponseWriter, err error) {
	var rejection *tsa.Rejection
	if errors.As(err, &rejection) {
		s.logger().Info("requête rejetée", "raison", rejection.Reason)
		s.writeTimestampResponse(w, http.StatusOK, rejection.Status, rejection.Failure)
		return
	}
	s.logger().Error("défaillance interne", "err", err)
	s.writeTimestampResponse(w, http.StatusInternalServerError, timestamp.Rejection, timestamp.SystemFailure)
}

func (s *server) writeRejection(w http.ResponseWriter, failure timestamp.FailureInfo, reason string) {
	s.logger().Info("requête rejetée", "raison", reason)
	s.writeTimestampResponse(w, http.StatusOK, timestamp.Rejection, failure)
}

func (s *server) writeTimestampResponse(w http.ResponseWriter, code int, status timestamp.Status, failure timestamp.FailureInfo) {
	der, err := tsa.ErrorResponse(status, failure)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", mimeReply)
	w.WriteHeader(code)
	_, _ = w.Write(der)
}

func (s *server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger().Info("requête traitée",
			"method", r.Method, "path", r.URL.Path, "duree", time.Since(start).String())
	})
}

func (s *server) logger() *slog.Logger {
	if s.opts.Logger != nil {
		return s.opts.Logger
	}
	return slog.Default()
}

func contentType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

func parseHash(name string) (crypto.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, errors.New("algorithme non supporté (sha256, sha384, sha512)")
	}
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return h.String()
	}
}

func decodeDigest(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("champ hash manquant")
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("champ hash: encodage hexadécimal ou base64 attendu")
	}
	return b, nil
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
}
