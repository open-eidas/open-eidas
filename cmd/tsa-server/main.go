// Command tsa-server est le service d'horodatage RFC 3161 d'Open eIDAS.
//
// Deux sous-commandes :
//
//	enroll  obtient (ou renouvelle) le certificat de l'unité d'horodatage
//	        auprès d'OpenXPKI, la clé privée restant dans le HSM ;
//	serve   expose l'autorité d'horodatage en HTTP ;
//	verify-audit  relit le journal d'audit et contrôle sa chaîne de hachage.
package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/open-eidas/tsa/internal/audit"
	"github.com/open-eidas/tsa/internal/certs"
	"github.com/open-eidas/tsa/internal/config"
	"github.com/open-eidas/tsa/internal/crosstsa"
	"github.com/open-eidas/tsa/internal/enroll"
	"github.com/open-eidas/tsa/internal/hsm"
	"github.com/open-eidas/tsa/internal/httpapi"
	"github.com/open-eidas/tsa/internal/replicate"

	"github.com/open-eidas/tsa/internal/timesource"
	"github.com/open-eidas/tsa/internal/tsa"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tsa-server <serve|enroll|verify-audit|version>")
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(logger)
	case "enroll":
		err = runEnroll(logger)
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

	journal, err := audit.Open(cfg.AuditFile)
	if err != nil {
		return err
	}
	defer journal.Close()

	clock, err := timesource.New(timesource.Options{
		Servers:      cfg.TimeSources,
		Policy:       cfg.TimePolicy,
		MinSources:   cfg.TimeMinSources,
		MaxOffset:    cfg.TimeMaxOffset,
		MaxAge:       cfg.TimeMaxAge,
		PollInterval: cfg.TimePoll,
		Timeout:      cfg.TimeTimeout,
		Logger:       logger,
		Recorder:     journal,
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
		Recorder:      journal,
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

	if err := journal.Append(audit.EventOpened, map[string]any{
		"version":     version,
		"tsu_subject": leaf.Subject.String(),
		"tsu_serial":  leaf.SerialNumber.String(),
		"policy":      cfg.PolicyOID.String(),
		"time_policy": string(cfg.TimePolicy),
	}); err != nil {
		return err
	}

	crossClient := crosstsa.New(crosstsa.Options{
		URLs:    cfg.CrossTSAURLs,
		Timeout: cfg.CrossTSATimeout,
		Logger:  logger,
	})

	var replicaClient *replicate.Client
	if cfg.AuditReplicaURL != "" {
		replicaClient, err = replicate.New(replicate.Options{
			URL:      cfg.AuditReplicaURL,
			Username: cfg.AuditReplicaUser,
			Password: cfg.AuditReplicaPassword,
			Timeout:  cfg.AuditReplicaTimeout,
		})
		if err != nil {
			return err
		}
	} else {
		logger.Warn("réplication hors site du journal d'audit désactivée (OPENEIDAS_AUDIT_REPLICA_URL non configurée)")
	}

	clock.Start(ctx)
	startSealing(ctx, journal, authority, crossClient, replicaClient, cfg.AuditFile, cfg.AuditSealInterval, logger)

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
	journal, err := audit.Open(cfg.AuditFile)
	if err != nil {
		return err
	}
	defer journal.Close()
	if err := journal.Append(audit.EventEnrollmentAccepted, map[string]any{
		"subject":   result.Certificate.Subject.String(),
		"issuer":    result.Certificate.Issuer.String(),
		"serial":    result.Certificate.SerialNumber.String(),
		"not_after": result.Certificate.NotAfter.UTC().Format(time.RFC3339),
	}); err != nil {
		return err
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

// startSealing scelle périodiquement la tête de chaîne du journal : la TSU
// horodate sa propre empreinte, ce qui date le contenu du journal à cet
// instant. Un horodatage croisé par une TSA tierce reste à ajouter pour
// qu'un auditeur n'ait pas à se fier au seul service.
func startSealing(ctx context.Context, journal *audit.Log, authority *tsa.Authority, cross *crosstsa.Client, replica *replicate.Client, auditFile string, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		logger.Warn("scellement périodique du journal d'audit désactivé")
		return
	}
	seal := func() {
		seq, head := journal.Head()
		digest, err := hex.DecodeString(head)
		if err != nil || len(digest) != sha256.Size {
			logger.Error("tête de chaîne inexploitable pour le scellement", "tete", head)
			return
		}
		req, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: digest}).Marshal()
		if err != nil {
			logger.Error("scellement impossible", "err", err)
			return
		}
		token, err := authority.Timestamp(req)
		if err != nil {
			logger.Error("scellement impossible", "err", err)
			return
		}
		if err := journal.Append(audit.EventSealed, map[string]any{
			"sealed_seq":  seq,
			"sealed_head": head,
			"token":       base64.StdEncoding.EncodeToString(token),
		}); err != nil {
			logger.Error("scellement non consigné", "err", err)
			return
		}
		logger.Info("journal d'audit scellé", "enregistrements", seq, "tete", head[:16]+"…")

		// Contreseing par des TSA tierces publiques : lève le caractère
		// auto-référentiel du scellement ci-dessus, chaque attestation étant
		// vérifiable indépendamment avec les outils RFC 3161 standards.
		attestations := cross.Seal(ctx, digest, crypto.SHA256)
		if len(attestations) == 0 {
			return
		}
		data := map[string]any{"sealed_seq": seq, "sealed_head": head}
		for i, att := range attestations {
			data[fmt.Sprintf("attestation_%d_tsa", i)] = att.TSA
			data[fmt.Sprintf("attestation_%d_gen_time", i)] = att.GenTime
			data[fmt.Sprintf("attestation_%d_serial", i)] = att.Serial
			data[fmt.Sprintf("attestation_%d_token", i)] = att.Token
		}
		if err := journal.Append(audit.EventCrossSealed, data); err != nil {
			logger.Error("contreseing non consigné", "err", err)
			return
		}
		logger.Info("journal d'audit contresigné par des TSA tierces", "attestations", len(attestations))

		// La réplication a lieu après le contreseing pour que la copie
		// distante embarque, elle aussi, la preuve d'antériorité tierce.
		if replica == nil {
			return
		}
		content, err := os.ReadFile(auditFile)
		if err != nil {
			logger.Error("réplication impossible : lecture du journal", "err", err)
			return
		}
		filename := fmt.Sprintf("audit-%s-seq%06d.log", time.Now().UTC().Format("20060102T150405Z"), seq)
		result, err := replica.Replicate(ctx, filename, content)
		if err != nil {
			logger.Error("réplication hors site impossible", "err", err)
			return
		}
		if err := journal.Append(audit.EventReplicated, map[string]any{
			"sealed_seq": seq,
			"url":        result.URL,
			"bytes":      result.Bytes,
			"sha256":     result.SHA256,
		}); err != nil {
			logger.Error("réplication non consignée", "err", err)
			return
		}
		logger.Info("journal d'audit répliqué hors site", "url", result.URL, "octets", result.Bytes)
	}

	go func() {
		seal()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				seal()
			}
		}
	}()
}

func runVerifyAudit() error {
	path := os.Getenv("OPENEIDAS_AUDIT_FILE")
	if len(os.Args) > 2 {
		path = os.Args[2]
	}
	if path == "" {
		path = "/var/lib/open-eidas/audit.log"
	}

	report, err := audit.Verify(path)
	if err != nil {
		return err
	}
	fmt.Printf("journal      : %s\n", path)
	fmt.Printf("enregistrements : %d (n° %d à %d)\n", report.Records, report.First, report.Last)
	fmt.Printf("scellements  : %d\n", report.Seals)
	fmt.Printf("tête de chaîne : %s\n", report.Head)
	fmt.Println("chaîne de hachage continue et intègre")
	return nil
}
