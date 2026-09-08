// Package certs regroupe la lecture et l'écriture des fichiers PEM
// manipulés par le service (certificat TSU et chaîne d'émission).
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// LoadFile lit un fichier PEM et retourne tous les certificats qu'il contient.
func LoadFile(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePEM(raw)
}

// LoadFileOptional se comporte comme LoadFile mais tolère un fichier absent.
func LoadFileOptional(path string) ([]*x509.Certificate, error) {
	certs, err := LoadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return certs, err
}

func ParsePEM(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificat PEM invalide: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("aucun certificat trouvé dans les données PEM")
	}
	return out, nil
}

func WriteFile(path string, certs []*x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, c := range certs {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return f.Close()
}

// safeFileName remplace tout caractère hors [A-Za-z0-9_-] par un souligné.
var safeFileName = regexp.MustCompile(`[^\w-]`)

// FileName dérive d'un nom courant (CN) le nom de fichier sous lequel la CA
// publie son certificat et sa CRL, par exemple
// « Open eIDAS Issuing CA » → « Open_eIDAS_Issuing_CA ».
//
// Cette dérivation est celle qu'emploient à la fois l'émetteur (qui grave
// l'URL dans les extensions CDP/AIA), le serveur qui publie les fichiers, et
// le répondeur OCSP qui va chercher la CRL : elle doit rester définie à un
// seul endroit, faute de quoi les trois divergent silencieusement.
func FileName(commonName string) string {
	return safeFileName.ReplaceAllString(commonName, "_")
}
