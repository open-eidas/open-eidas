// Package enroll obtient le certificat de l'unité d'horodatage auprès de la
// PKI OpenXPKI, via son endpoint RPC d'enrôlement (méthode RequestCertificate).
package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/open-eidas/tsa/internal/certs"
)

type Options struct {
	Endpoint  string
	CAFile    string
	Insecure  bool
	Timeout   time.Duration
	Logger    *slog.Logger
	UserAgent string
	// HMACSecret authentifie le demandeur auprès de la politique
	// d'enrôlement OpenXPKI (allow_anon_enroll: 0) : sans lui, la PKI
	// n'accepte pas de requête anonyme. Voir computeSignature.
	HMACSecret string
}

type Client struct {
	opts Options
	http *http.Client
}

func NewClient(o Options) (*Client, error) {
	if o.Endpoint == "" {
		return nil, errors.New("enroll: endpoint RPC OpenXPKI non configuré")
	}
	if _, err := url.Parse(o.Endpoint); err != nil {
		return nil, fmt.Errorf("enroll: endpoint invalide: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case o.CAFile != "":
		pemBytes, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("enroll: lecture de l'ancre de confiance: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("enroll: aucune ancre de confiance exploitable dans %s", o.CAFile)
		}
		tlsCfg.RootCAs = pool
	case o.Insecure:
		// Toléré uniquement pour la démonstration locale, où le conteneur
		// OpenXPKI s'auto-génère un certificat TLS non vérifiable.
		tlsCfg.InsecureSkipVerify = true
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Minute
	}
	return &Client{
		opts: o,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Subject décrit le sujet demandé pour le certificat de la TSU.
type Subject struct {
	CommonName         string
	OrganizationalUnit string
	Organization       string
	Country            string
}

func (s Subject) pkix() pkix.Name {
	n := pkix.Name{CommonName: s.CommonName}
	if s.OrganizationalUnit != "" {
		n.OrganizationalUnit = []string{s.OrganizationalUnit}
	}
	if s.Organization != "" {
		n.Organization = []string{s.Organization}
	}
	if s.Country != "" {
		n.Country = []string{s.Country}
	}
	return n
}

// Result porte le certificat émis et sa chaîne d'émission.
type Result struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}

// Request génère une CSR signée par la clé du HSM puis la soumet à OpenXPKI.
// L'appel boucle tant que le workflow est en attente (approbation manuelle,
// vérification d'éligibilité) jusqu'à expiration du délai configuré.
func (c *Client) Request(ctx context.Context, signer crypto.Signer, subject Subject) (*Result, error) {
	csrDER, csrPEM, err := buildCSR(signer, subject)
	if err != nil {
		return nil, err
	}
	var signature string
	if c.opts.HMACSecret != "" {
		signature = computeSignature(csrDER, c.opts.HMACSecret)
	}

	deadline := time.Now().Add(c.opts.Timeout)
	transactionID := ""
	for attempt := 1; ; attempt++ {
		body, err := c.post(ctx, csrPEM, signature, transactionID)
		if err != nil {
			return nil, err
		}
		result, retryAfter, err := parseResponse(body)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
		if retryAfter == 0 {
			retryAfter = 5 * time.Second
		}
		if time.Now().Add(retryAfter).After(deadline) {
			return nil, fmt.Errorf("enroll: certificat toujours en attente d'approbation après %s", c.opts.Timeout)
		}
		transactionID = lastTransactionID(body)
		c.logger().Info("enrôlement en attente côté PKI",
			"tentative", attempt, "nouvelle_tentative_dans", retryAfter.String())
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryAfter):
		}
	}
}

func (c *Client) post(ctx context.Context, csrPEM, signature, transactionID string) ([]byte, error) {
	form := url.Values{}
	form.Set("pkcs10", csrPEM)
	form.Set("comment", "Open eIDAS TSU enrollment")
	if signature != "" {
		form.Set("signature", signature)
	}
	if transactionID != "" {
		form.Set("transaction_id", transactionID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.opts.UserAgent != "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: appel de %s: %w", c.opts.Endpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("enroll: lecture de la réponse: %w", err)
	}
	// Un workflow en attente est signalé par un code 202 accompagné du même
	// corps JSON : seul un 4xx/5xx sans corps JSON exploitable est fatal ici.
	if resp.StatusCode >= 400 && !json.Valid(body) {
		return nil, fmt.Errorf("enroll: la PKI a répondu %s: %s", resp.Status, truncate(string(body), 200))
	}
	return body, nil
}

type rpcEnvelope struct {
	Error *struct {
		Code    json.Number `json:"code"`
		Message string      `json:"message"`
	} `json:"error"`
	Result *struct {
		State      string          `json:"state"`
		RetryAfter json.Number     `json:"retry_after"`
		Data       json.RawMessage `json:"data"`
	} `json:"result"`
}

type rpcData struct {
	Certificate   string          `json:"certificate"`
	Chain         json.RawMessage `json:"chain"`
	CertID        string          `json:"cert_identifier"`
	TransactionID string          `json:"transaction_id"`
	ErrorCode     string          `json:"error_code"`
}

// parseResponse retourne le certificat émis, ou (nil, délai) si le workflow
// est encore en cours côté PKI.
func parseResponse(body []byte) (*Result, time.Duration, error) {
	var env rpcEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, 0, fmt.Errorf("enroll: réponse JSON illisible: %s", truncate(string(body), 200))
	}
	if env.Error != nil {
		return nil, 0, fmt.Errorf("enroll: la PKI a refusé la demande (code %s): %s", env.Error.Code, env.Error.Message)
	}
	if env.Result == nil {
		return nil, 0, fmt.Errorf("enroll: réponse inattendue: %s", truncate(string(body), 200))
	}

	var data rpcData
	if len(env.Result.Data) > 0 {
		if err := json.Unmarshal(env.Result.Data, &data); err != nil {
			return nil, 0, fmt.Errorf("enroll: bloc data illisible: %w", err)
		}
	}
	if data.ErrorCode != "" {
		return nil, 0, fmt.Errorf("enroll: workflow en erreur: %s", data.ErrorCode)
	}
	if data.Certificate == "" {
		retry, _ := env.Result.RetryAfter.Int64()
		return nil, time.Duration(retry) * time.Second, nil
	}

	leaf, err := certs.ParsePEM([]byte(data.Certificate))
	if err != nil {
		return nil, 0, fmt.Errorf("enroll: certificat émis illisible: %w", err)
	}
	chain, err := parseChain(data.Chain)
	if err != nil {
		return nil, 0, err
	}
	return &Result{Certificate: leaf[0], Chain: dropLeaf(chain, leaf[0])}, 0, nil
}

// parseChain accepte les deux formes rencontrées côté OpenXPKI : une liste de
// blocs PEM, ou un unique bloc concaténé.
func parseChain(raw json.RawMessage) ([]*x509.Certificate, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		var single string
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			return nil, fmt.Errorf("enroll: chaîne d'émission illisible: %w", err)
		}
		list = []string{single}
	}
	var out []*x509.Certificate
	for _, item := range list {
		if strings.TrimSpace(item) == "" {
			continue
		}
		parsed, err := certs.ParsePEM([]byte(item))
		if err != nil {
			return nil, fmt.Errorf("enroll: chaîne d'émission illisible: %w", err)
		}
		out = append(out, parsed...)
	}
	return out, nil
}

func dropLeaf(chain []*x509.Certificate, leaf *x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(chain))
	for _, c := range chain {
		if !bytes.Equal(c.Raw, leaf.Raw) {
			out = append(out, c)
		}
	}
	return out
}

func lastTransactionID(body []byte) string {
	var env rpcEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Result == nil {
		return ""
	}
	var data rpcData
	if err := json.Unmarshal(env.Result.Data, &data); err != nil {
		return ""
	}
	return data.TransactionID
}

func buildCSR(signer crypto.Signer, subject Subject) (der []byte, pemStr string, err error) {
	tmpl := &x509.CertificateRequest{
		Subject:            subject.pkix(),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err = x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return nil, "", fmt.Errorf("enroll: génération de la CSR: %w", err)
	}
	return der, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// computeSignature authentifie le CSR pour la politique HMAC d'OpenXPKI.
// Doit reproduire exactement
// OpenXPKI::Server::Workflow::Activity::Tools::CalculateRequestHMAC :
// HMAC-SHA256 hexadécimal des octets DER bruts de la CSR.
func computeSignature(csrDER []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(csrDER)
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Client) logger() *slog.Logger {
	if c.opts.Logger != nil {
		return c.opts.Logger
	}
	return slog.Default()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
