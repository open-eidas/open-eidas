// Command ocsp-responder répond aux requêtes OCSP (RFC 6960) pour la CA
// émettrice de la TSU, en s'appuyant sur la CRL publiée par l'autorité
// (cmd/ca-server) plutôt que sur un accès direct à son registre — voir
// docs/ARCHITECTURE.md et internal/ocspresponder.
//
// Sous-commandes, sur le même modèle que tsa-server :
//
//	enroll       obtient (ou renouvelle) le certificat de signature OCSP
//	             auprès de la CA, la clé privée restant dans le HSM ;
//	serve        expose le répondeur en HTTP ;
//	conformance  produit la matrice de conformité ETSI du système.
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/open-eidas/open-eidas/internal/certs"
	"github.com/open-eidas/open-eidas/internal/conformance"
	"github.com/open-eidas/open-eidas/internal/enroll"
	"github.com/open-eidas/open-eidas/internal/hsm"
	"github.com/open-eidas/open-eidas/internal/ocspresponder"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ocsp-responder <serve|enroll|conformance|version>")
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(logger)
	case "enroll":
		err = runEnroll(logger)
	case "conformance":
		// La même matrice que ca-server : elle décrit le système entier, pas
		// ce seul binaire, et doit donc être consultable depuis n'importe
		// lequel des trois services.
		err = conformance.WriteReport(os.Stdout, os.Stderr, version, hasFlag(os.Args[2:], "--markdown"))
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

func runServe(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	token, err := hsm.Open(hsm.Options{
		ModulePath: cfg.PKCS11Module,
		TokenLabel: cfg.TokenLabel,
		KeyLabel:   cfg.KeyLabel,
		PIN:        cfg.PIN,
	})
	if err != nil {
		return err
	}
	defer token.Close()

	signer, err := token.Signer()
	if err != nil {
		return err
	}
	leaf, chain, err := loadMaterial(cfg)
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return fmt.Errorf("chaîne d'émission absente de %s : émetteur requis pour répondre aux requêtes OCSP", cfg.ChainFile)
	}
	issuer := chain[0]

	crlHTTPClient, err := newCRLHTTPClient(cfg)
	if err != nil {
		return err
	}

	responder, err := ocspresponder.New(ocspresponder.Options{
		Signer:          signer,
		Certificate:     leaf,
		Issuer:          issuer,
		CRLURL:          ocspresponder.CRLURL(cfg.PKIInternalURL, issuer),
		CRLRefresh:      cfg.CRLRefresh,
		HTTPClient:      crlHTTPClient,
		MaxRequestBytes: cfg.MaxRequestBytes,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := responder.Start(ctx); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ocsp", responder.ServeHTTP)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("répondeur OCSP en écoute",
			"adresse", cfg.Listen,
			"sujet", leaf.Subject.String(),
			"emetteur", issuer.Subject.String(),
			"crl", ocspresponder.CRLURL(cfg.PKIInternalURL, issuer))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		return srv.Shutdown(shutdownCtx)
	}
}

func runEnroll(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	token, err := hsm.Open(hsm.Options{
		ModulePath: cfg.PKCS11Module,
		TokenLabel: cfg.TokenLabel,
		KeyLabel:   cfg.KeyLabel,
		PIN:        cfg.PIN,
	})
	if err != nil {
		return err
	}
	defer token.Close()

	signer, err := token.Signer()
	if errors.Is(err, hsm.ErrKeyNotFound) {
		logger.Info("génération de la clé de signature dans le HSM", "bits", cfg.KeyBits, "label", cfg.KeyLabel)
		signer, err = token.GenerateRSAKey(cfg.KeyBits)
	}
	if err != nil {
		return err
	}

	if ok, reason := currentCertUsable(cfg, signer); ok {
		logger.Info("certificat OCSP déjà en place, enrôlement ignoré", "raison", reason)
		return nil
	} else if reason != "" {
		logger.Info("enrôlement nécessaire", "raison", reason)
	}

	client, err := enroll.NewClient(enroll.Options{
		Endpoint:   cfg.EnrollEndpoint,
		Profile:    cfg.EnrollProfile,
		CAFile:     cfg.EnrollCAFile,
		Insecure:   cfg.EnrollInsecure,
		Timeout:    cfg.EnrollTimeout,
		HMACSecret: cfg.EnrollHMACKey,
		Logger:     logger,
		UserAgent:  "open-eidas-ocsp-responder/" + version,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.EnrollTimeout)
	defer cancel()

	result, err := client.Request(ctx, signer, enroll.Subject{CommonName: cfg.SubjectCN})
	if err != nil {
		return err
	}
	if err := certs.WriteFile(cfg.CertFile, []*x509.Certificate{result.Certificate}); err != nil {
		return fmt.Errorf("écriture du certificat OCSP: %w", err)
	}
	if len(result.Chain) == 0 {
		return fmt.Errorf("la PKI n'a pas renvoyé de chaîne d'émission : impossible d'identifier l'émetteur")
	}
	if err := certs.WriteFile(cfg.ChainFile, result.Chain); err != nil {
		return fmt.Errorf("écriture de la chaîne d'émission: %w", err)
	}

	logger.Info("certificat de signature OCSP émis par la PKI",
		"sujet", result.Certificate.Subject.String(),
		"emetteur", result.Certificate.Issuer.String(),
		"expiration", result.Certificate.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// newCRLHTTPClient construit le client HTTP interrogeant périodiquement la
// CRL de la PKI, sur le même principe que enroll.NewClient : une ancre de
// confiance explicite (OPENEIDAS_PKI_CA_FILE) ou, à défaut en démonstration
// locale, la tolérance explicite d'un certificat auto-signé
// (OPENEIDAS_PKI_INSECURE).
func newCRLHTTPClient(cfg *Config) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case cfg.PKICAFile != "":
		pemBytes, err := os.ReadFile(cfg.PKICAFile)
		if err != nil {
			return nil, fmt.Errorf("lecture de l'ancre de confiance de la PKI: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("aucune ancre de confiance exploitable dans %s", cfg.PKICAFile)
		}
		tlsCfg.RootCAs = pool
	case cfg.PKIInsecure:
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func loadMaterial(cfg *Config) (*x509.Certificate, []*x509.Certificate, error) {
	leafs, err := certs.LoadFile(cfg.CertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("lecture du certificat OCSP %s: %w", cfg.CertFile, err)
	}
	chain, err := certs.LoadFileOptional(cfg.ChainFile)
	if err != nil {
		return nil, nil, fmt.Errorf("lecture de la chaîne %s: %w", cfg.ChainFile, err)
	}
	return leafs[0], chain, nil
}

// currentCertUsable rend l'enrôlement idempotent, sur le même principe que
// tsa-server : au redémarrage, un certificat encore valide et apparié à la
// clé du HSM est conservé.
func currentCertUsable(cfg *Config, signer crypto.Signer) (bool, string) {
	existing, err := certs.LoadFileOptional(cfg.CertFile)
	if err != nil || len(existing) == 0 {
		return false, "aucun certificat OCSP exploitable en cache"
	}
	cert := existing[0]
	certPub, err1 := x509.MarshalPKIXPublicKey(cert.PublicKey)
	signerPub, err2 := x509.MarshalPKIXPublicKey(signer.Public())
	if err1 != nil || err2 != nil || string(certPub) != string(signerPub) {
		return false, "le certificat en cache ne correspond pas à la clé du HSM"
	}
	if remaining := time.Until(cert.NotAfter); remaining < cfg.RenewBefore {
		return false, fmt.Sprintf("certificat expirant dans %s", remaining.Round(time.Hour))
	}
	return true, "valide jusqu'au " + cert.NotAfter.UTC().Format(time.RFC3339)
}

// hasFlag cherche un drapeau parmi les arguments restants.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
