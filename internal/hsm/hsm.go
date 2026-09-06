// Package hsm encapsule l'accès à la clé de signature de l'unité
// d'horodatage (TSU) via PKCS#11. La clé privée ne quitte jamais le token :
// le service ne manipule qu'un crypto.Signer dont chaque appel Sign est
// délégué au module cryptographique.
package hsm

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/eclipse-keypont/crypto11"
)

// ErrKeyNotFound signale l'absence de bi-clé pour le label configuré.
var ErrKeyNotFound = errors.New("hsm: bi-clé introuvable sur le token")

type Options struct {
	ModulePath string
	TokenLabel string
	KeyLabel   string
	PIN        string
}

type Token struct {
	ctx      *crypto11.Context
	keyLabel string
	keyID    []byte
}

func Open(o Options) (*Token, error) {
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       o.ModulePath,
		TokenLabel: o.TokenLabel,
		Pin:        o.PIN,
	})
	if err != nil {
		return nil, fmt.Errorf("hsm: ouverture du token %q via %s: %w", o.TokenLabel, o.ModulePath, err)
	}
	// CKA_ID doit être stable et non vide : crypto11 s'en sert pour apparier
	// la clé privée et la clé publique lors des recherches.
	id := sha256.Sum256([]byte(o.KeyLabel))
	return &Token{ctx: ctx, keyLabel: o.KeyLabel, keyID: id[:8]}, nil
}

func (t *Token) Close() error { return t.ctx.Close() }

func (t *Token) Signer() (crypto.Signer, error) {
	keys, err := t.ctx.FindKeyPairs(t.keyID, []byte(t.keyLabel))
	if err != nil {
		return nil, fmt.Errorf("hsm: recherche de la clé %q: %w", t.keyLabel, err)
	}
	if len(keys) == 0 {
		return nil, ErrKeyNotFound
	}
	return keys[0], nil
}

func (t *Token) GenerateRSAKey(bits int) (crypto.Signer, error) {
	signer, err := t.ctx.GenerateRSAKeyPairWithLabel(t.keyID, []byte(t.keyLabel), bits)
	if err != nil {
		return nil, fmt.Errorf("hsm: génération de la bi-clé RSA-%d: %w", bits, err)
	}
	return signer, nil
}
