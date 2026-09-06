// Package crosstsa fait attester la tête du journal d'audit par une ou
// plusieurs autorités d'horodatage tierces et publiques.
//
// Le scellement de internal/audit est auto-référentiel : la TSU horodate sa
// propre empreinte, ce qui ne prouve rien à qui ne fait pas déjà confiance au
// service. En faisant compter le même hachage par une autorité indépendante
// (RFC 3161 standard, comme n'importe quel client), un auditeur peut vérifier
// après coup — avec les outils standards, sans dépendre d'Open eIDAS — que la
// tête de chaîne existait à une date donnée, attestée par un tiers.
package crosstsa

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
)

const mimeQuery = "application/timestamp-query"

type Options struct {
	// URLs des TSA tierces interrogées. Chaque contreseing réussi est
	// consigné séparément : la perte d'une source ne bloque pas les autres.
	URLs    []string
	Timeout time.Duration
	Logger  *slog.Logger
}

type Client struct {
	opts Options
	http *http.Client
}

func New(o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	return &Client{opts: o, http: &http.Client{Timeout: o.Timeout}}
}

// Attestation est le résultat d'un contreseing réussi.
type Attestation struct {
	TSA     string `json:"tsa"`
	GenTime string `json:"gen_time"`
	Serial  string `json:"serial"`
	Token   string `json:"token"` // TimeStampResp DER, encodée en base64
}

// Seal soumet l'empreinte donnée à chaque TSA configurée et retourne les
// contreseings obtenus. Une TSA injoignable ou en erreur est journalisée et
// simplement absente du résultat plutôt que de faire échouer les autres.
func (c *Client) Seal(ctx context.Context, digest []byte, hash crypto.Hash) []Attestation {
	var out []Attestation
	for _, url := range c.opts.URLs {
		att, err := c.query(ctx, url, digest, hash)
		if err != nil {
			c.logger().Warn("contreseing par une TSA tierce impossible", "tsa", url, "err", err)
			continue
		}
		out = append(out, *att)
	}
	return out
}

func (c *Client) query(ctx context.Context, url string, digest []byte, hash crypto.Hash) (*Attestation, error) {
	reqDER, err := (&timestamp.Request{
		HashAlgorithm: hash,
		HashedMessage: digest,
		Certificates:  true,
	}).Marshal()
	if err != nil {
		return nil, fmt.Errorf("encodage de la requête RFC 3161: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", mimeQuery)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requête HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("lecture de la réponse: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}

	token, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("réponse RFC 3161 illisible: %w", err)
	}
	if !bytes.Equal(token.HashedMessage, digest) {
		return nil, fmt.Errorf("la TSA a retourné une empreinte différente de celle soumise")
	}

	name := url
	if len(token.Certificates) > 0 {
		name = token.Certificates[0].Subject.String()
	}
	return &Attestation{
		TSA:     name,
		GenTime: token.Time.UTC().Format(time.RFC3339Nano),
		Serial:  token.SerialNumber.String(),
		Token:   base64.StdEncoding.EncodeToString(body),
	}, nil
}

func (c *Client) logger() *slog.Logger {
	if c.opts.Logger != nil {
		return c.opts.Logger
	}
	return slog.Default()
}
