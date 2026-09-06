package config

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/open-eidas/tsa/internal/timesource"
)

// Config regroupe l'ensemble des paramètres du service, tous pilotés par
// variables d'environnement (12-factor) pour rester déployable en conteneur.
type Config struct {
	Listen          string
	ShutdownTimeout time.Duration
	MaxRequestBytes int64

	PKCS11Module string
	TokenLabel   string
	KeyLabel     string
	KeyBits      int
	PIN          string

	CertFile  string
	ChainFile string

	AuditFile         string
	AuditSealInterval time.Duration

	PolicyOID     asn1.ObjectIdentifier
	Accuracy      time.Duration
	SigningDigest crypto.Hash

	TimePolicy     timesource.Policy
	TimeSources    []string
	TimeMinSources int
	TimeMaxOffset  time.Duration
	TimeMaxAge     time.Duration
	TimePoll       time.Duration
	TimeTimeout    time.Duration

	EnrollEndpoint string
	EnrollCAFile   string
	EnrollInsecure bool
	EnrollTimeout  time.Duration
	SubjectCN      string
	SubjectOU      string
	SubjectO       string
	SubjectC       string
	RenewBefore    time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:          env("OPENEIDAS_LISTEN", ":8318"),
		ShutdownTimeout: 15 * time.Second,
		PKCS11Module:    env("OPENEIDAS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"),
		TokenLabel:      env("OPENEIDAS_TOKEN_LABEL", "open-eidas-tsa"),
		KeyLabel:        env("OPENEIDAS_KEY_LABEL", "tsu-signing-key"),
		PIN:             os.Getenv("OPENEIDAS_PIN"),
		CertFile:        env("OPENEIDAS_CERT_FILE", "/var/lib/open-eidas/tsu.pem"),
		ChainFile:       env("OPENEIDAS_CHAIN_FILE", "/var/lib/open-eidas/chain.pem"),
		AuditFile:       env("OPENEIDAS_AUDIT_FILE", "/var/lib/open-eidas/audit.log"),
		EnrollEndpoint:  env("OPENEIDAS_ENROLL_ENDPOINT", ""),
		EnrollCAFile:    env("OPENEIDAS_ENROLL_CA_FILE", ""),
		SubjectCN:       env("OPENEIDAS_SUBJECT_CN", "Open eIDAS Time-Stamping Unit 1"),
		SubjectOU:       env("OPENEIDAS_SUBJECT_OU", "Time Stamping Authority"),
		SubjectO:        env("OPENEIDAS_SUBJECT_O", "Open eIDAS"),
		SubjectC:        env("OPENEIDAS_SUBJECT_C", "FR"),
		TimeSources:     splitList(env("OPENEIDAS_TIME_SOURCES", "ntp.obspm.fr,ptbtime1.ptb.de")),
	}

	var err error
	if cfg.MaxRequestBytes, err = envInt64("OPENEIDAS_MAX_REQUEST_BYTES", 64*1024); err != nil {
		return nil, err
	}
	if cfg.KeyBits, err = envInt("OPENEIDAS_KEY_BITS", 3072); err != nil {
		return nil, err
	}
	if cfg.KeyBits < 3072 {
		return nil, fmt.Errorf("OPENEIDAS_KEY_BITS=%d: ETSI TS 119 312 impose au moins 3072 bits pour RSA", cfg.KeyBits)
	}
	if cfg.Accuracy, err = envDuration("OPENEIDAS_ACCURACY", time.Second); err != nil {
		return nil, err
	}
	if cfg.EnrollTimeout, err = envDuration("OPENEIDAS_ENROLL_TIMEOUT", 5*time.Minute); err != nil {
		return nil, err
	}
	if cfg.RenewBefore, err = envDuration("OPENEIDAS_RENEW_BEFORE", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.EnrollInsecure, err = envBool("OPENEIDAS_ENROLL_INSECURE", false); err != nil {
		return nil, err
	}
	if cfg.AuditSealInterval, err = envDuration("OPENEIDAS_AUDIT_SEAL_INTERVAL", time.Hour); err != nil {
		return nil, err
	}
	if cfg.TimeMinSources, err = envInt("OPENEIDAS_TIME_MIN_SOURCES", 2); err != nil {
		return nil, err
	}
	if cfg.TimeMaxOffset, err = envDuration("OPENEIDAS_TIME_MAX_OFFSET", 500*time.Millisecond); err != nil {
		return nil, err
	}
	if cfg.TimeMaxAge, err = envDuration("OPENEIDAS_TIME_MAX_AGE", time.Hour); err != nil {
		return nil, err
	}
	if cfg.TimePoll, err = envDuration("OPENEIDAS_TIME_POLL", 5*time.Minute); err != nil {
		return nil, err
	}
	if cfg.TimeTimeout, err = envDuration("OPENEIDAS_TIME_TIMEOUT", 5*time.Second); err != nil {
		return nil, err
	}
	if cfg.TimePolicy, err = timesource.ParsePolicy(env("OPENEIDAS_TIME_POLICY", "enforce")); err != nil {
		return nil, err
	}
	if cfg.PolicyOID, err = parseOID(env("OPENEIDAS_POLICY_OID", "1.3.6.1.4.1.99999.1.1.1")); err != nil {
		return nil, err
	}
	if cfg.SigningDigest, err = parseDigest(env("OPENEIDAS_SIGNING_DIGEST", "sha256")); err != nil {
		return nil, err
	}
	if cfg.PIN == "" {
		return nil, fmt.Errorf("OPENEIDAS_PIN est obligatoire (code PIN du token PKCS#11)")
	}
	return cfg, nil
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID invalide: %q", s)
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("OID invalide: %q", s)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

func parseDigest(s string) (crypto.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("algorithme de signature non supporté: %q (sha256, sha384 ou sha512)", s)
	}
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
		return 0, fmt.Errorf("%s: durée attendue (ex. 1s, 500ms), reçu %q", key, v)
	}
	return d, nil
}

func envBool(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: booléen attendu, reçu %q", key, v)
	}
	return b, nil
}
