// Command tsa-server est le service d'horodatage RFC 3161 d'Open eIDAS.
//
// Deux sous-commandes :
//
//	enroll  obtient (ou renouvelle) le certificat de l'unité d'horodatage
//	        auprès d'OpenXPKI, la clé privée restant dans le HSM ;
//	serve   expose l'autorité d'horodatage en HTTP.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/open-eidas/tsa/internal/certs"
	"github.com/open-eidas/tsa/internal/config"
	"github.com/open-eidas/tsa/internal/enroll"
	"github.com/open-eidas/tsa/internal/hsm"
	"github.com/open-eidas/tsa/internal/httpapi"
	"github.com/open-eidas/tsa/internal/timesource"
	"github.com/open-eidas/tsa/internal/tsa"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tsa-server <serve|enroll|version>")
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(logger)
	case "enroll":
		err = runEnroll(logger)
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
	cfg, err := config.Load()
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

	clock, err := timesource.New(timesource.Options{
		Servers:      cfg.TimeSources,
		Policy:       cfg.TimePolicy,
		MinSources:   cfg.TimeMinSources,
		MaxOffset:    cfg.TimeMaxOffset,
		MaxAge:       cfg.TimeMaxAge,
		PollInterval: cfg.TimePoll,
		Timeout:      cfg.TimeTimeout,
		Logger:       logger,
	})
	if err != nil {
		return err
	}

	authority, warnings, err := tsa.New(tsa.Options{
		Signer:        signer,
		Certificate:   leaf,
		Chain:         chain,
		Policy:        cfg.PolicyOID,
		Accuracy:      cfg.Accuracy,
		SigningDigest: cfg.SigningDigest,
		Clock:         clock,
	})
	if err != nil {
		return err
	}
	for _, w := range warnings {
		logger.Warn("écart au profil ETSI", "detail", string(w))
	}

	handler := httpapi.New(httpapi.Options{
		Authority:       authority,
		TimeSource:      clock,
		MaxRequestBytes: cfg.MaxRequestBytes,
		Logger:          logger,
		Version:         version,
	})
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	clock.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("TSA en écoute",
			"adresse", cfg.Listen,
			"politique", cfg.PolicyOID.String(),
			"tsu", leaf.Subject.String(),
			"expiration", leaf.NotAfter.UTC().Format(time.RFC3339))
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
	cfg, err := config.Load()
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
		logger.Info("certificat TSU déjà en place, enrôlement ignoré", "raison", reason)
		return nil
	} else if reason != "" {
		logger.Info("enrôlement nécessaire", "raison", reason)
	}

	client, err := enroll.NewClient(enroll.Options{
		Endpoint:  cfg.EnrollEndpoint,
		CAFile:    cfg.EnrollCAFile,
		Insecure:  cfg.EnrollInsecure,
		Timeout:   cfg.EnrollTimeout,
		Logger:    logger,
		UserAgent: "open-eidas-tsa/" + version,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.EnrollTimeout)
	defer cancel()

	result, err := client.Request(ctx, signer, enroll.Subject{
		CommonName:         cfg.SubjectCN,
		OrganizationalUnit: cfg.SubjectOU,
		Organization:       cfg.SubjectO,
		Country:            cfg.SubjectC,
	})
	if err != nil {
		return err
	}
	if err := certs.WriteFile(cfg.CertFile, []*x509.Certificate{result.Certificate}); err != nil {
		return fmt.Errorf("écriture du certificat TSU: %w", err)
	}
	if len(result.Chain) > 0 {
		if err := certs.WriteFile(cfg.ChainFile, result.Chain); err != nil {
			return fmt.Errorf("écriture de la chaîne d'émission: %w", err)
		}
	}
	logger.Info("certificat TSU émis par la PKI",
		"sujet", result.Certificate.Subject.String(),
		"emetteur", result.Certificate.Issuer.String(),
		"expiration", result.Certificate.NotAfter.UTC().Format(time.RFC3339),
		"chaine", len(result.Chain))
	return nil
}

func loadMaterial(cfg *config.Config) (*x509.Certificate, []*x509.Certificate, error) {
	leafs, err := certs.LoadFile(cfg.CertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("lecture du certificat TSU %s: %w", cfg.CertFile, err)
	}
	chain, err := certs.LoadFileOptional(cfg.ChainFile)
	if err != nil {
		return nil, nil, fmt.Errorf("lecture de la chaîne %s: %w", cfg.ChainFile, err)
	}
	return leafs[0], chain, nil
}

// currentCertUsable rend l'enrôlement idempotent : au redémarrage, un
// certificat encore valide et apparié à la clé du HSM est conservé.
func currentCertUsable(cfg *config.Config, signer crypto.Signer) (bool, string) {
	existing, err := certs.LoadFileOptional(cfg.CertFile)
	if err != nil || len(existing) == 0 {
		return false, "aucun certificat TSU exploitable en cache"
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
