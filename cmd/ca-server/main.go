// Command ca-server est l'autorité de certification et d'enregistrement
// d'Open eIDAS. Elle remplace OpenXPKI (voir INDEPENDANCE.md) : elle émet les
// certificats de l'unité d'horodatage et du répondeur OCSP depuis une CSR,
// publie l'état de révocation, et porte le point d'approbation RA.
//
// Sous-commandes :
//
//	ceremony      crée la hiérarchie racine + émettrice dans les tokens PKCS#11
//	serve         expose l'API d'enrôlement et publie la CRL
//	ra list       liste les demandes d'enrôlement
//	ra approve    approuve une demande, sous l'identité d'un opérateur
//	ra reject     rejette une demande, sous l'identité d'un opérateur
//	revoke        révoque un certificat émis
//	conformance   produit la matrice de conformité ETSI
//	verify-audit  relit le journal d'audit et contrôle sa chaîne de hachage
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/open-eidas/open-eidas/internal/audit"
	"github.com/open-eidas/open-eidas/internal/ca"
	"github.com/open-eidas/open-eidas/internal/castore"
	"github.com/open-eidas/open-eidas/internal/conformance"
	"github.com/open-eidas/open-eidas/internal/hsm"
	"github.com/open-eidas/open-eidas/internal/raflow"
)

var version = "dev"

const usage = `usage: ca-server <ceremony|serve|ra|revoke|conformance|verify-audit|version>

  ceremony                                  crée la hiérarchie de CA (idempotent)
  serve                                     expose l'API d'enrôlement et publie la CRL
  ra list [PENDING|APPROVED|ISSUED|REJECTED]  liste les demandes d'enrôlement
  ra approve <transaction_id> <opérateur> [motif]
  ra reject  <transaction_id> <opérateur> [motif]
  revoke <numéro_de_série> <code_motif> <opérateur> [commentaire]
  conformance [--markdown]                  matrice de conformité ETSI
  healthcheck                               interroge /healthz de cette instance
  verify-audit [fichier]                    vérifie la chaîne du journal
`

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "ceremony":
		err = runCeremony(logger)
	case "serve":
		err = runServe(logger)
	case "ra":
		err = runRA(logger, os.Args[2:])
	case "revoke":
		err = runRevoke(logger, os.Args[2:])
	case "conformance":
		err = runConformance(os.Args[2:])
	case "healthcheck":
		err = runHealthcheck()
	case "verify-audit":
		err = runVerifyAudit()
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("commande inconnue: %s", os.Args[1])
	}
	if err != nil {
		logger.Error("arrêt sur erreur", "err", err)
		os.Exit(1)
	}
}

// openStore ouvre le registre et applique les migrations.
func openStore(ctx context.Context, cfg *Config) (castore.Store, error) {
	return castore.OpenPostgres(ctx, cfg.DSN)
}

// openIssuingKey ouvre le token de la CA émettrice. La clé est générée au
// premier appel : la cérémonie est ainsi reproductible sans manipulation
// préalable, tout en restant confinée au module cryptographique.
func openIssuingKey(cfg *Config, logger *slog.Logger) (*hsm.Token, crypto.Signer, error) {
	return openKey(cfg, logger, cfg.IssuingTokenLabel, cfg.IssuingKeyLabel, cfg.IssuingPIN, "CA émettrice")
}

func openRootKey(cfg *Config, logger *slog.Logger) (*hsm.Token, crypto.Signer, error) {
	pin := cfg.RootPIN
	if pin == "" {
		// La racine et l'émettrice peuvent partager un PIN en démonstration ;
		// en production, ce sont deux tokens distincts sous deux contrôles
		// distincts — voir docs/CA.md.
		pin = cfg.IssuingPIN
	}
	return openKey(cfg, logger, cfg.RootTokenLabel, cfg.RootKeyLabel, pin, "racine")
}

func openKey(cfg *Config, logger *slog.Logger, tokenLabel, keyLabel, pin, role string) (*hsm.Token, crypto.Signer, error) {
	token, err := hsm.Open(hsm.Options{
		ModulePath: cfg.PKCS11Module,
		TokenLabel: tokenLabel,
		KeyLabel:   keyLabel,
		PIN:        pin,
	})
	if err != nil {
		return nil, nil, err
	}
	signer, err := token.Signer()
	if errors.Is(err, hsm.ErrKeyNotFound) {
		logger.Info("génération de la clé d'autorité dans le HSM",
			"role", role, "bits", cfg.KeyBits, "token", tokenLabel, "label", keyLabel)
		signer, err = token.GenerateRSAKey(cfg.KeyBits)
	}
	if err != nil {
		token.Close()
		return nil, nil, err
	}
	return token, signer, nil
}

// openJournal ouvre le journal d'audit de la CA et contrôle que la durée de
// conservation configurée satisfait ETSI EN 319 401 §7.10.
func openJournal(cfg *Config) (*audit.Log, error) {
	if err := conformance.CheckAuditRetention(cfg.AuditRetention).Err(); err != nil {
		return nil, err
	}
	return audit.Open(cfg.AuditFile)
}

func runCeremony(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.CeremonyOperator == "" {
		return errors.New("OPENEIDAS_CEREMONY_OPERATOR est obligatoire : la cérémonie de clé doit être imputable (ETSI EN 319 411-1 §6.5.1)")
	}
	ctx := context.Background()

	store, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	journal, err := openJournal(cfg)
	if err != nil {
		return err
	}
	defer journal.Close()

	rootToken, rootSigner, err := openRootKey(cfg, logger)
	if err != nil {
		return err
	}
	defer rootToken.Close()

	issuingToken, issuingSigner, err := openIssuingKey(cfg, logger)
	if err != nil {
		return err
	}
	defer issuingToken.Close()

	h, err := ca.RunCeremony(ctx, ca.CeremonyOptions{
		RootSigner:        rootSigner,
		IssuingSigner:     issuingSigner,
		RootCN:            cfg.RootCN,
		IssuingCN:         cfg.IssuingCN,
		Organization:      cfg.Organization,
		Country:           cfg.Country,
		RootValidity:      cfg.RootValidity,
		IssuingValidity:   cfg.IssuingValidity,
		RootTokenLabel:    cfg.RootTokenLabel,
		RootKeyLabel:      cfg.RootKeyLabel,
		IssuingTokenLabel: cfg.IssuingTokenLabel,
		IssuingKeyLabel:   cfg.IssuingKeyLabel,
		Store:             store,
		Recorder:          journal,
		Operator:          cfg.CeremonyOperator,
	})
	if err != nil {
		return err
	}
	logger.Info("hiérarchie de CA en place",
		"creee", h.Created,
		"racine", h.Root.Subject.String(),
		"emettrice", h.Issuing.Subject.String(),
		"emettrice_expiration", h.Issuing.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// buildIssuer relit la hiérarchie enregistrée et construit l'autorité
// émettrice. Il ne crée jamais d'autorité : `ceremony` est le seul chemin par
// lequel une hiérarchie apparaît.
func buildIssuer(ctx context.Context, cfg *Config, store castore.Store, journal *audit.Log, logger *slog.Logger) (*ca.Issuer, *hsm.Token, error) {
	h, err := ca.LoadHierarchy(ctx, store)
	if errors.Is(err, castore.ErrNotFound) {
		return nil, nil, errors.New("aucune hiérarchie de CA enregistrée : exécutez d'abord `ca-server ceremony`")
	}
	if err != nil {
		return nil, nil, err
	}
	token, signer, err := openIssuingKey(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	issuer, err := ca.New(ca.Options{
		Signer:      signer,
		Certificate: h.Issuing,
		Chain:       []*x509.Certificate{h.Root},
		Store:       store,
		Recorder:    journal,
		PublicURL:   cfg.PublicURL,
		OCSPURL:     cfg.OCSPURL,
		CRLValidity: cfg.CRLValidity,
		CRLGrace:    cfg.CRLGrace,
	})
	if err != nil {
		token.Close()
		return nil, nil, err
	}
	return issuer, token, nil
}

func runServe(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	journal, err := openJournal(cfg)
	if err != nil {
		return err
	}
	defer journal.Close()

	issuer, token, err := buildIssuer(ctx, cfg, store, journal, logger)
	if err != nil {
		return err
	}
	defer token.Close()

	flow, err := raflow.New(raflow.Options{
		Store:      store,
		Issuer:     issuer,
		HMACSecret: cfg.EnrollHMACKey,
		Recorder:   journal,
	})
	if err != nil {
		return err
	}

	if err := journal.Append(audit.EventOpened, map[string]any{
		"version":    version,
		"role":       "ca-server",
		"emettrice":  issuer.Certificate().Subject.String(),
		"public_url": cfg.PublicURL,
	}); err != nil {
		return err
	}

	srv := NewServer(issuer, flow, logger, version, cfg.MaxRequestBytes)
	if err := srv.StartCRLPublication(ctx, cfg.CRLRefresh); err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("autorité de certification en écoute",
			"adresse", cfg.Listen,
			"emettrice", issuer.Certificate().Subject.String(),
			"crl", issuer.CRLURL())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("arrêt demandé, fermeture en cours")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// runRA est l'interface de l'opérateur d'enregistrement. Approuver et rejeter
// exigent une identité d'opérateur, qui est consignée en base et au journal :
// c'est ce qui rend la décision imputable (ETSI EN 319 411-1 §6.2.1).
func runRA(logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ca-server ra <list|approve|reject> ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()

	store, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	switch args[0] {
	case "list":
		state := castore.RequestState("")
		if len(args) > 1 {
			state = castore.RequestState(args[1])
		}
		return listRequests(ctx, store, state)
	case "approve", "reject":
		if len(args) < 3 {
			return fmt.Errorf("usage: ca-server ra %s <transaction_id> <opérateur> [motif]", args[0])
		}
		return decide(ctx, cfg, store, logger, args[0], args[1], args[2], joinRest(args, 3))
	default:
		return fmt.Errorf("sous-commande ra inconnue: %s", args[0])
	}
}

func joinRest(args []string, from int) string {
	if len(args) <= from {
		return ""
	}
	out := args[from]
	for _, a := range args[from+1:] {
		out += " " + a
	}
	return out
}

func listRequests(ctx context.Context, store castore.Store, state castore.RequestState) error {
	requests, err := store.Requests(ctx, state)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TRANSACTION\tPROFIL\tSUJET (CN)\tÉTAT\tOPÉRATEUR\tREÇUE LE")
	for _, r := range requests {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.TransactionID, r.Profile, r.SubjectCN, r.State, orDash(r.Operator),
			r.CreatedAt.UTC().Format(time.RFC3339))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(requests) == 0 {
		fmt.Println("(aucune demande)")
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// decide ouvre le journal et l'autorité pour appliquer une décision. Le
// binaire n'a pas besoin de la clé de signature pour approuver : l'émission
// a lieu côté `serve`, lorsque le demandeur revient chercher son certificat.
func decide(ctx context.Context, cfg *Config, store castore.Store, logger *slog.Logger, action, transactionID, operator, comment string) error {
	journal, err := openJournal(cfg)
	if err != nil {
		return err
	}
	defer journal.Close()

	flow, err := raflow.NewDecider(raflow.DeciderOptions{
		Store:    store,
		Recorder: journal,
	})
	if err != nil {
		return err
	}

	var r *castore.Request
	if action == "approve" {
		r, err = flow.Approve(ctx, transactionID, operator, comment)
	} else {
		r, err = flow.Reject(ctx, transactionID, operator, comment)
	}
	if err != nil {
		return err
	}
	logger.Info("décision enregistrée",
		"action", action, "transaction", r.TransactionID,
		"profil", r.Profile, "sujet_cn", r.SubjectCN, "operateur", operator)
	return nil
}

func runRevoke(logger *slog.Logger, args []string) error {
	if len(args) < 3 {
		return errors.New("usage: ca-server revoke <numéro_de_série> <code_motif> <opérateur> [commentaire]")
	}
	serial, ok := new(big.Int).SetString(args[0], 10)
	if !ok {
		// Le numéro affiché par `openssl x509 -serial` est hexadécimal ;
		// celui de `ra list` et du journal est décimal. Les deux sont acceptés.
		serial, ok = new(big.Int).SetString(args[0], 16)
	}
	if !ok {
		return fmt.Errorf("numéro de série illisible: %q", args[0])
	}
	var reason int
	if _, err := fmt.Sscanf(args[1], "%d", &reason); err != nil {
		return fmt.Errorf("code de motif RFC 5280 attendu (1=keyCompromise, 4=superseded, 5=cessationOfOperation), reçu %q", args[1])
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()
	store, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	journal, err := openJournal(cfg)
	if err != nil {
		return err
	}
	defer journal.Close()

	issuer, token, err := buildIssuer(ctx, cfg, store, journal, logger)
	if err != nil {
		return err
	}
	defer token.Close()

	if err := issuer.Revoke(ctx, serial, reason, args[2], joinRest(args, 3)); err != nil {
		return err
	}
	// La CRL est republiée immédiatement : une révocation qui n'est pas
	// publiée ne protège personne.
	crl, err := issuer.PublishCRL(ctx)
	if err != nil {
		return err
	}
	logger.Info("certificat révoqué et CRL republiée",
		"serie", serial.String(), "motif", reason, "operateur", args[2], "crl", crl.Number)
	return nil
}

// runConformance produit la matrice de conformité ETSI. Le code de sortie est
// non nul si la matrice est incohérente — une exigence déclarée couverte sans
// mécanisme ni test, un écart sans cible — de sorte que la CI échoue avant que
// le document publié ne perde son sens.
func runConformance(args []string) error {
	markdown := false
	for _, a := range args {
		if a == "--markdown" {
			markdown = true
		}
	}
	return conformance.WriteReport(os.Stdout, os.Stderr, version, markdown)
}

// runHealthcheck interroge le /healthz de l'instance locale. Il existe pour
// que le conteneur puisse déclarer sa disponibilité sans embarquer curl ni
// wget : l'image ne contient que ce qu'elle exécute.
func runHealthcheck() error {
	listen := env("OPENEIDAS_LISTEN", ":8320")
	if strings.HasPrefix(listen, ":") {
		listen = "127.0.0.1" + listen
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + listen + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("service non disponible (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	fmt.Println(strings.TrimSpace(string(body)))
	return nil
}

func runVerifyAudit() error {
	path := os.Getenv("OPENEIDAS_AUDIT_FILE")
	if len(os.Args) > 2 {
		path = os.Args[2]
	}
	if path == "" {
		path = "/var/lib/open-eidas/state/ca-audit.log"
	}
	report, err := audit.Verify(path)
	if err != nil {
		return err
	}
	fmt.Printf("journal          : %s\n", path)
	fmt.Printf("enregistrements  : %d (n° %d à %d)\n", report.Records, report.First, report.Last)
	fmt.Printf("scellements      : %d\n", report.Seals)
	fmt.Printf("tête de chaîne   : %s\n", report.Head)
	fmt.Println("chaîne de hachage continue et intègre")
	return nil
}
