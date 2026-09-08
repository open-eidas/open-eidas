//go:build unix

package audit

import (
	"fmt"
	"os"
	"syscall"
)

// Verrou consultatif à l'échelle du fichier, posé pendant toute la durée d'un
// ajout. Il est nécessaire parce que plusieurs processus écrivent légitimement
// dans le même journal : le service de la CA (`ca-server serve`) et les
// commandes d'exploitation lancées à côté (`ca-server ra approve`, `revoke`).
//
// Sans lui, chaque processus tiendrait sa propre idée de la tête de chaîne et
// les deux écritures se contrediraient — rupture détectée à la relecture, donc
// journal inexploitable. Un mutex en mémoire ne suffit pas ici : il ne couvre
// qu'un seul processus.
func lockExclusive(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("audit: verrouillage du journal: %w", err)
	}
	return nil
}

func unlock(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("audit: déverrouillage du journal: %w", err)
	}
	return nil
}
