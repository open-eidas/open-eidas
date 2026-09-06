// Package replicate copie le journal d'audit vers un stockage distant après
// chaque scellement, afin qu'une défaillance ou une compromission de
// l'instance ne fasse pas disparaître la seule copie du journal.
//
// Le protocole retenu est WebDAV (PUT authentifié) : c'est le plus petit
// dénominateur commun côté hébergement souverain — Nextcloud, les offres de
// stockage d'objets exposées en WebDAV, ou un simple serveur dédié — sans
// imposer de dépendance à un fournisseur cloud particulier.
package replicate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

type Options struct {
	// URL de base WebDAV, par ex. https://dav.example.org/open-eidas/
	URL      string
	Username string
	Password string
	Timeout  time.Duration
}

type Client struct {
	opts Options
	http *http.Client
}

// New construit un client de réplication. L'appelant est responsable de ne
// pas en construire lorsque la réplication est désactivée (URL vide).
func New(o Options) (*Client, error) {
	if o.URL == "" {
		return nil, fmt.Errorf("replicate: URL WebDAV manquante")
	}
	if _, err := url.Parse(o.URL); err != nil {
		return nil, fmt.Errorf("replicate: URL invalide: %w", err)
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	return &Client{opts: o, http: &http.Client{Timeout: o.Timeout}}, nil
}

// Result résume une réplication réussie.
type Result struct {
	URL    string
	Bytes  int
	SHA256 string
}

// Replicate dépose le contenu donné sous le nom indiqué. Le nom porte
// l'horodatage de l'appelant : chaque scellement produit donc une copie
// distincte, ce qui protège aussi contre un PUT écrasant une version saine
// par une version déjà corrompue localement.
func (c *Client) Replicate(ctx context.Context, filename string, content []byte) (*Result, error) {
	base, err := url.Parse(c.opts.URL)
	if err != nil {
		return nil, err
	}
	base.Path = path.Join(base.Path, filename)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base.String(), bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(content))
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.opts.Username != "" {
		req.SetBasicAuth(c.opts.Username, c.opts.Password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", base.String(), err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PUT %s: HTTP %s", base.String(), resp.Status)
	}

	sum := sha256.Sum256(content)
	return &Result{URL: base.String(), Bytes: len(content), SHA256: hex.EncodeToString(sum[:])}, nil
}
