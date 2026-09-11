// Commande gen-audit-fixture régénère tests/fixtures/audit/go-produced.log à
// partir du code Go de référence (internal/audit), pour que oe-audit (Rust)
// prouve qu'il peut vérifier un journal produit par le binaire Go — jalon
// critique de compatibilité J5 du plan de migration
// (/home/philippe/.claude/plans/witty-hopping-nest.md).
//
// Le champ "reason" du second enregistrement contient délibérément des
// caractères que encoding/json échappe par défaut (<, >, &) : c'est le test
// le plus probable de divergence de sérialisation entre encoding/json (Go) et
// serde_json (Rust), donc le plus important à figer dans une fixture.
package main

import (
	"fmt"
	"os"

	"github.com/open-eidas/open-eidas/internal/audit"
)

const fixturePath = "tests/fixtures/audit/go-produced.log"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-audit-fixture:", err)
		os.Exit(1)
	}
}

func run() error {
	_ = os.Remove(fixturePath)

	log, err := audit.Open(fixturePath)
	if err != nil {
		return err
	}
	defer log.Close()

	if err := log.Append(audit.EventOpened, nil); err != nil {
		return err
	}
	if err := log.Append(audit.EventTimestampGranted, map[string]any{
		"serial_number":   42,
		"message_imprint": "a1b2c3",
		"reason":          "valeur <sensible> & \"citée\" avec accents éàî",
	}); err != nil {
		return err
	}
	if err := log.Append(audit.EventTimeMeasurement, map[string]any{
		"traceable": true,
		"sources": map[string]any{
			"ntp.obspm.fr":    "12ms",
			"ptbtime1.ptb.de": "-8ms",
		},
	}); err != nil {
		return err
	}
	if err := log.Append(audit.EventSealed, nil); err != nil {
		return err
	}
	return nil
}
