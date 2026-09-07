package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config regroupe les paramètres du répondeur OCSP, tous pilotés par
// variables d'environnement (12-factor), sur le même principe que
// internal/config pour la TSA. Un jeu de paramètres séparé plutôt qu'un
// import de internal/config évite d'imposer à ce service des champs qui ne
// le concernent pas (journal d'audit, contreseing, traçabilité temporelle).
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

	EnrollEndpoint string
	EnrollCAFile   string
	EnrollInsecure bool
	EnrollTimeout  time.Duration
	EnrollHMACKey  string
	SubjectCN      string
	SubjectOU      string
	SubjectO       string
	SubjectC       string
	RenewBefore    time.Duration

	// PKIInternalURL sert à dériver l'URL de la CRL de la CA émettrice à
	// interroger (voir ocspresponder.CRLURL). C'est l'adresse à laquelle CE
	// SERVICE joint OpenXPKI — typiquement interne au réseau du conteneur/
	// cluster — et non l'adresse publique gravée dans les certificats
	// (celle-ci est substituée côté serveur OpenXPKI, sans rapport avec ce
	// binaire).
	PKIInternalURL string
	// PKIInsecure tolère le certificat TLS auto-signé d'OpenXPKI en
	// démonstration locale, comme OPENEIDAS_ENROLL_INSECURE pour
	// l'enrôlement.
	PKIInsecure bool
	PKICAFile   string
	CRLRefresh  time.Duration
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		Listen:          env("OPENEIDAS_LISTEN", ":8319"),
		ShutdownTimeout: 15 * time.Second,
		PKCS11Module:    env("OPENEIDAS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"),
		TokenLabel:      env("OPENEIDAS_TOKEN_LABEL", "open-eidas-ocsp"),
		KeyLabel:        env("OPENEIDAS_KEY_LABEL", "ocsp-signing-key"),
		PIN:             os.Getenv("OPENEIDAS_PIN"),
		CertFile:        env("OPENEIDAS_CERT_FILE", "/var/lib/open-eidas/ocsp.pem"),
		ChainFile:       env("OPENEIDAS_CHAIN_FILE", "/var/lib/open-eidas/chain.pem"),
		EnrollEndpoint:  env("OPENEIDAS_ENROLL_ENDPOINT", ""),
		EnrollCAFile:    env("OPENEIDAS_ENROLL_CA_FILE", ""),
		EnrollHMACKey:   os.Getenv("OPENEIDAS_ENROLL_HMAC_KEY"),
		SubjectCN:       env("OPENEIDAS_SUBJECT_CN", "Open eIDAS OCSP Responder 1"),
		SubjectOU:       env("OPENEIDAS_SUBJECT_OU", "OCSP Responder"),
		SubjectO:        env("OPENEIDAS_SUBJECT_O", "Open eIDAS"),
		SubjectC:        env("OPENEIDAS_SUBJECT_C", "FR"),
		PKIInternalURL:  env("OPENEIDAS_PKI_INTERNAL_URL", ""),
		PKICAFile:       env("OPENEIDAS_PKI_CA_FILE", ""),
	}

	var err error
	if cfg.MaxRequestBytes, err = envInt64("OPENEIDAS_MAX_REQUEST_BYTES", 16*1024); err != nil {
		return nil, err
	}
	if cfg.KeyBits, err = envInt("OPENEIDAS_KEY_BITS", 3072); err != nil {
		return nil, err
	}
	if cfg.KeyBits < 3072 {
		return nil, fmt.Errorf("OPENEIDAS_KEY_BITS=%d: ETSI TS 119 312 impose au moins 3072 bits pour RSA", cfg.KeyBits)
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
	if cfg.PKIInsecure, err = envBool("OPENEIDAS_PKI_INSECURE", false); err != nil {
		return nil, err
	}
	if cfg.CRLRefresh, err = envDuration("OPENEIDAS_OCSP_CRL_REFRESH", 5*time.Minute); err != nil {
		return nil, err
	}
	if cfg.PIN == "" {
		return nil, fmt.Errorf("OPENEIDAS_PIN est obligatoire (code PIN du token PKCS#11)")
	}
	if cfg.PKIInternalURL == "" {
		return nil, fmt.Errorf("OPENEIDAS_PKI_INTERNAL_URL est obligatoire (URL, interne au déploiement, à laquelle interroger la CRL)")
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
