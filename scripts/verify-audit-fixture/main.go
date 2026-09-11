// Commande verify-audit-fixture vérifie, avec le code Go de référence
// (internal/audit), un journal produit par n'importe quel binaire — utilisée
// pour prouver la compatibilité Rust -> Go (jalon J5 du plan de migration).
package main

import (
	"fmt"
	"os"

	"github.com/open-eidas/open-eidas/internal/audit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: verify-audit-fixture <chemin-du-journal>")
		os.Exit(2)
	}
	report, err := audit.Verify(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-audit-fixture:", err)
		os.Exit(1)
	}
	fmt.Printf("ok: %d enregistrements (premier=%d dernier=%d scellements=%d) tête=%s\n",
		report.Records, report.First, report.Last, report.Seals, report.Head)
}
