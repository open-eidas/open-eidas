package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config regroupe les paramètres de l'autorité de certification, tous pilotés
// par variables d'environnement (12-factor), sur le même principe que
// internal/config pour la TSA et cmd/ocsp-responder pour le répondeur.
type Config struct {
	Listen          string
	ShutdownTimeout time.Duration
	MaxRequestBytes int64

	// DSN de la base PostgreSQL qui porte le registre de la CA.
	DSN string

	PKCS11Module string
	// La racine et l'émettrice vivent dans deux tokens distincts : la racine
	// ne sert qu'à la cérémonie et n'a aucune raison d'être accessible au
	// service en fonctionnement.
	RootTokenLabel    string
	RootKeyLabel      string
	RootPIN           string
	IssuingTokenLabel string
	IssuingKeyLabel   string
	IssuingPIN        string
	KeyBits           int

	RootCN          string
	IssuingCN       string
	Organization    string
	Country         string
	RootValidity    time.Duration
	IssuingValidity time.Duration
	// CeremonyOperator identifie qui conduit la cérémonie ; consigné au
	// procès-verbal (ETSI EN 319 411-1 §6.5.1).
	CeremonyOperator string

	// PublicURL est l'adresse à laquelle cette CA est joignable par qui
	// vérifie un certificat : elle est gravée dans les extensions CDP et AIA.
	// À ne pas confondre avec l'adresse interne à laquelle les services de la
	// pile joignent la CA pour s'enrôler.
	PublicURL string
	OCSPURL   string

	EnrollHMACKey string

	CRLValidity time.Duration
	CRLRefresh  time.Duration
	CRLGrace    time.Duration

	AuditFile      string
	AuditRetention time.Duration
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		Listen:            env("OPENEIDAS_LISTEN", ":8320"),
		ShutdownTimeout:   15 * time.Second,
		DSN:               env("OPENEIDAS_DB_DSN", ""),
		PKCS11Module:      env("OPENEIDAS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"),
		RootTokenLabel:    env("OPENEIDAS_ROOT_TOKEN_LABEL", "open-eidas-root"),
		RootKeyLabel:      env("OPENEIDAS_ROOT_KEY_LABEL", "root-ca-key"),
		RootPIN:           os.Getenv("OPENEIDAS_ROOT_PIN"),
		IssuingTokenLabel: env("OPENEIDAS_ISSUING_TOKEN_LABEL", "open-eidas-issuing"),
		IssuingKeyLabel:   env("OPENEIDAS_ISSUING_KEY_LABEL", "issuing-ca-key"),
		IssuingPIN:        os.Getenv("OPENEIDAS_ISSUING_PIN"),
		RootCN:            env("OPENEIDAS_ROOT_CN", "Open eIDAS Root CA"),
		IssuingCN:         env("OPENEIDAS_ISSUING_CN", "Open eIDAS Issuing CA"),
		Organization:      env("OPENEIDAS_CA_ORGANIZATION", "Open eIDAS"),
		Country:           env("OPENEIDAS_CA_COUNTRY", "FR"),
		CeremonyOperator:  env("OPENEIDAS_CEREMONY_OPERATOR", ""),
		PublicURL:         env("OPENEIDAS_PKI_PUBLIC_URL", ""),
		OCSPURL:           env("OPENEIDAS_OCSP_PUBLIC_URL", ""),
		EnrollHMACKey:     os.Getenv("OPENEIDAS_ENROLL_HMAC_KEY"),
		AuditFile:         env("OPENEIDAS_AUDIT_FILE", "/var/lib/open-eidas/state/ca-audit.log"),
	}

	var err error
	if cfg.MaxRequestBytes, err = envInt64("OPENEIDAS_MAX_REQUEST_BYTES", 64*1024); err != nil {
		return nil, err
	}
	if cfg.KeyBits, err = envInt("OPENEIDAS_CA_KEY_BITS", 4096); err != nil {
		return nil, err
	}
	// Une CA signe des certificats qui lui survivent : sa clé est tenue à une
	// exigence au moins égale à celle des entités finales (ETSI TS 119 312).
	if cfg.KeyBits < 3072 {
		return nil, fmt.Errorf("OPENEIDAS_CA_KEY_BITS=%d: ETSI TS 119 312 impose au moins 3072 bits pour RSA", cfg.KeyBits)
	}
	if cfg.RootValidity, err = envDuration("OPENEIDAS_ROOT_VALIDITY", 20*365*24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.IssuingValidity, err = envDuration("OPENEIDAS_ISSUING_VALIDITY", 10*365*24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.CRLValidity, err = envDuration("OPENEIDAS_CRL_VALIDITY", 24*time.Hour); err != nil {
		return nil, err
	}
	// La CRL est republiée bien avant d'expirer : un répondeur OCSP qui
	// n'obtiendrait qu'une CRL périmée refuse de répondre plutôt que de
	// garantir un statut obsolète.
	if cfg.CRLRefresh, err = envDuration("OPENEIDAS_CRL_REFRESH", time.Hour); err != nil {
		return nil, err
	}
	if cfg.CRLGrace, err = envDuration("OPENEIDAS_CRL_GRACE", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.AuditRetention, err = envDuration("OPENEIDAS_AUDIT_RETENTION", 365*24*time.Hour); err != nil {
		return nil, err
	}

	if cfg.DSN == "" {
		return nil, fmt.Errorf("OPENEIDAS_DB_DSN est obligatoire (DSN PostgreSQL du registre de la CA)")
	}
	if cfg.IssuingPIN == "" {
		return nil, fmt.Errorf("OPENEIDAS_ISSUING_PIN est obligatoire (code PIN du token PKCS#11 de la CA émettrice)")
	}
	if cfg.PublicURL == "" {
		return nil, fmt.Errorf("OPENEIDAS_PKI_PUBLIC_URL est obligatoire (adresse publique gravée dans les extensions CDP/AIA)")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: entier attendu, reçu %q", key, v)
	}
	return n, nil
}

func envInt64(key string, fallback int64) (int64, error) {
	n, err := envInt(key, int(fallback))
	return int64(n), err
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: durée attendue (ex. 1h, 24h), reçu %q", key, v)
	}
	return d, nil
}
