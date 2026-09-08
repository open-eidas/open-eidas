// Package enroll obtient le certificat d'un service d'Open eIDAS (unité
// d'horodatage, répondeur OCSP) auprès de l'autorité de certification du
// projet (cmd/ca-server), via son API d'enrôlement.
//
// Le protocole est entièrement défini par ce dépôt : une CSR en PEM, un
// authentifiant HMAC-SHA256 sur ses octets DER, et une réponse JSON. Le client
// et le serveur partagent la même fonction de signature (raflow.Signature) —
// il n'y a plus rien à rétro-ingénierier, ce qui était le reproche central
// fait à l'ancien endpoint RPC OpenXPKI (voir INDEPENDANCE.md).
package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/open-eidas/open-eidas/internal/certs"
	"github.com/open-eidas/open-eidas/internal/raflow"
)

type Options struct {
	// Endpoint est l'URL complète de l'API d'enrôlement de la CA, par exemple
	// http://ca:8320/api/v1/enroll.
	Endpoint string
	// Profile nomme le profil de certificat demandé (voir internal/ca).
	Profile   string
	CAFile    string
	Insecure  bool
	Timeout   time.Duration
	Logger    *slog.Logger
	UserAgent string
	// HMACSecret authentifie le demandeur auprès de la CA. Sans lui, la
	// demande est refusée avant même d'atteindre la machine à états.
	HMACSecret string
}

type Client struct {
	opts Options
	http *http.Client
}

func NewClient(o Options) (*Client, error) {
	if o.Endpoint == "" {
		return nil, errors.New("enroll: endpoint d'enrôlement non configuré")
	}
	if _, err := url.Parse(o.Endpoint); err != nil {
		return nil, fmt.Errorf("enroll: endpoint invalide: %w", err)
	}
	if o.Profile == "" {
		return nil, errors.New("enroll: profil de certificat non configuré")
	}
	if o.HMACSecret == "" {
		return nil, errors.New("enroll: secret d'enrôlement non configuré")
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
		// Toléré uniquement pour la démonstration locale, où l'API de la CA
		// est jointe en HTTP interne ou derrière un certificat auto-signé.
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

// Subject décrit le nom courant demandé pour le certificat. Le reste du sujet
// (unité, organisation, pays) est imposé par le profil côté autorité : un
// demandeur ne choisit pas l'organisation dont il se réclame.
type Subject struct {
	CommonName string
}

// Result porte le certificat émis et sa chaîne d'émission.
type Result struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}

// Request génère une CSR signée par la clé du HSM puis la soumet à la CA.
// L'appel boucle tant que la demande attend la décision d'un opérateur RA,
// jusqu'à expiration du délai configuré.
func (c *Client) Request(ctx context.Context, signer crypto.Signer, subject Subject) (*Result, error) {
	csrDER, csrPEM, err := buildCSR(signer, subject)
	if err != nil {
		return nil, err
	}
	signature := raflow.Signature(csrDER, c.opts.HMACSecret)

	deadline := time.Now().Add(c.opts.Timeout)
	for attempt := 1; ; attempt++ {
		resp, err := c.post(ctx, csrPEM, signature)
		if err != nil {
			return nil, err
		}
		if resp.Certificate != "" {
			return parseResult(resp)
		}

		retryAfter := time.Duration(resp.RetryAfter) * time.Second
		if retryAfter <= 0 {
			retryAfter = 5 * time.Second
		}
		if time.Now().Add(retryAfter).After(deadline) {
			return nil, fmt.Errorf("enroll: demande %s toujours en attente d'approbation après %s",
				resp.TransactionID, c.opts.Timeout)
		}
		c.logger().Info("enrôlement en attente de l'approbation d'un opérateur RA",
			"transaction", resp.TransactionID, "tentative", attempt,
			"nouvelle_tentative_dans", retryAfter.String())
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryAfter):
		}
	}
}

type request struct {
	Profile   string `json:"profile"`
	PKCS10    string `json:"pkcs10"`
	Signature string `json:"signature"`
	Comment   string `json:"comment,omitempty"`
}

type response struct {
	State         string   `json:"state"`
	TransactionID string   `json:"transaction_id"`
	RetryAfter    int      `json:"retry_after"`
	Certificate   string   `json:"certificate"`
	Chain         []string `json:"chain"`
	Error         string   `json:"error"`
}

func (c *Client) post(ctx context.Context, csrPEM, signature string) (*response, error) {
	body, err := json.Marshal(request{
		Profile:   c.opts.Profile,
		PKCS10:    csrPEM,
		Signature: signature,
		Comment:   "Open eIDAS service enrollment",
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.opts.UserAgent != "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: appel de %s: %w", c.opts.Endpoint, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("enroll: lecture de la réponse: %w", err)
	}

	var parsed response
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("enroll: réponse illisible (%s): %s", resp.Status, truncate(string(raw), 200))
	}
	// 202 accompagne une demande en attente : c'est un déroulement normal, pas
	// une erreur. Tout autre code hors 2xx est un refus.
	if resp.StatusCode >= 300 {
		if parsed.Error != "" {
			return nil, fmt.Errorf("enroll: la PKI a refusé la demande (%s): %s", resp.Status, parsed.Error)
		}
		return nil, fmt.Errorf("enroll: la PKI a répondu %s: %s", resp.Status, truncate(string(raw), 200))
	}
	return &parsed, nil
}

func parseResult(resp *response) (*Result, error) {
	leaf, err := certs.ParsePEM([]byte(resp.Certificate))
	if err != nil {
		return nil, fmt.Errorf("enroll: certificat émis illisible: %w", err)
	}
	var chain []*x509.Certificate
	for _, item := range resp.Chain {
		if strings.TrimSpace(item) == "" {
			continue
		}
		parsed, err := certs.ParsePEM([]byte(item))
		if err != nil {
			return nil, fmt.Errorf("enroll: chaîne d'émission illisible: %w", err)
		}
		chain = append(chain, parsed...)
	}
	return &Result{Certificate: leaf[0], Chain: dropLeaf(chain, leaf[0])}, nil
}

// dropLeaf retire de la chaîne le certificat émis lui-même : selon la
// configuration, la CA peut le renvoyer dans les deux champs.
func dropLeaf(chain []*x509.Certificate, leaf *x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(chain))
	for _, c := range chain {
		if !bytes.Equal(c.Raw, leaf.Raw) {
			out = append(out, c)
		}
	}
	return out
}

func buildCSR(signer crypto.Signer, subject Subject) (der []byte, pemStr string, err error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: subject.CommonName},
		SignatureAlgorithm: signatureAlgorithm(signer),
	}
	der, err = x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return nil, "", fmt.Errorf("enroll: génération de la CSR: %w", err)
	}
	return der, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// signatureAlgorithm choisit SHA-256 quel que soit le type de clé du token.
// SHA-1 n'est jamais une option : la CA refuserait la CSR (ETSI TS 119 312),
// autant ne pas la produire.
func signatureAlgorithm(signer crypto.Signer) x509.SignatureAlgorithm {
	if _, ok := signer.Public().(*rsa.PublicKey); ok {
		return x509.SHA256WithRSA
	}
	return x509.ECDSAWithSHA256
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
