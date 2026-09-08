package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLog(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, path
}

func appendSome(t *testing.T, log *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := log.Append(EventTimestampGranted, map[string]any{"serial_number": i}); err != nil {
			t.Fatal(err)
		}
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAcceptsIntactChain(t *testing.T) {
	log, path := newLog(t)
	appendSome(t, log, 3)

	report, err := Verify(path)
	if err != nil {
		t.Fatalf("un journal intact doit être accepté: %v", err)
	}
	if report.Records != 3 || report.First != 1 || report.Last != 3 {
		t.Errorf("relecture incohérente: %+v", report)
	}
	if _, head, err := log.Head(); err != nil {
		t.Fatal(err)
	} else if head != report.Head {
		t.Error("la tête relue diffère de la tête en mémoire")
	}
}

func TestVerifyAcceptsMissingLog(t *testing.T) {
	report, err := Verify(filepath.Join(t.TempDir(), "absent.log"))
	if err != nil {
		t.Fatalf("un journal absent doit être traité comme vide: %v", err)
	}
	if report.Records != 0 || report.Head != GenesisHash {
		t.Errorf("état initial inattendu: %+v", report)
	}
}

func TestVerifyDetectsModifiedRecord(t *testing.T) {
	log, path := newLog(t)
	appendSome(t, log, 3)

	lines := readLines(t, path)
	lines[1] = strings.Replace(lines[1], `"serial_number":1`, `"serial_number":9`, 1)
	writeLines(t, path, lines)

	if _, err := Verify(path); err == nil {
		t.Fatal("la modification d'un enregistrement doit rompre la vérification")
	}
}

func TestVerifyDetectsDeletedRecord(t *testing.T) {
	log, path := newLog(t)
	appendSome(t, log, 3)

	lines := readLines(t, path)
	writeLines(t, path, []string{lines[0], lines[2]})

	if _, err := Verify(path); err == nil {
		t.Fatal("la suppression d'un enregistrement doit rompre la chaîne")
	}
}

func TestVerifyDetectsTruncatedAndRewrittenTail(t *testing.T) {
	log, path := newLog(t)
	appendSome(t, log, 2)

	// Une ligne forgée, correctement hachée mais rattachée à la mauvaise
	// empreinte précédente, doit être rejetée.
	lines := readLines(t, path)
	forged := Record{Seq: 3, Time: "2026-09-06T00:00:00Z", Event: EventTimestampGranted, Prev: GenesisHash}
	hash, err := forged.computeHash()
	if err != nil {
		t.Fatal(err)
	}
	forged.Hash = hash
	line, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	writeLines(t, path, append(lines, string(line)))

	if _, err := Verify(path); err == nil {
		t.Fatal("un enregistrement rattaché à la mauvaise empreinte doit être rejeté")
	}
}

func TestOpenResumesExistingChain(t *testing.T) {
	log, path := newLog(t)
	appendSome(t, log, 2)
	_, headBefore, err := log.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("la réouverture d'un journal valide doit réussir: %v", err)
	}
	defer reopened.Close()

	seq, head, err := reopened.Head()
	if err != nil {
		t.Fatal(err)
	}
	if seq != 2 || head != headBefore {
		t.Fatalf("reprise incorrecte: seq=%d head=%s", seq, head)
	}
	if err := reopened.Append(EventSealed, nil); err != nil {
		t.Fatal(err)
	}

	report, err := Verify(path)
	if err != nil {
		t.Fatalf("la chaîne doit rester valide après réouverture: %v", err)
	}
	if report.Records != 3 || report.Seals != 1 {
		t.Errorf("relecture inattendue: %+v", report)
	}
}

func TestOpenRefusesTamperedLog(t *testing.T) {
	log, path := newLog(t)
	appendSome(t, log, 2)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, path)
	writeLines(t, path, lines[:1])
	lines = readLines(t, path)
	lines[0] = strings.Replace(lines[0], `"seq":1`, `"seq":2`, 1)
	writeLines(t, path, lines)

	if _, err := Open(path); err == nil {
		t.Fatal("un journal altéré ne doit pas pouvoir être rouvert en écriture")
	}
}

// Deux processus écrivent légitimement dans le même journal : le service de
// la CA et les commandes d'exploitation lancées à côté (`ca-server ra
// approve`). Chacun tenant sa propre idée de la tête de chaîne, les écritures
// se contrediraient sans verrou de fichier ni relecture — la chaîne serait
// rompue et le journal inexploitable. Ce test reproduit exactement ce cas.
func TestDeuxEcrivainsPartagentLaMemeChaine(t *testing.T) {
	premier, path := newLog(t)
	defer premier.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("ouverture du second écrivain: %v", err)
	}
	defer second.Close()

	// Écritures entrelacées, comme le service et la CLI le feraient.
	for i := 0; i < 3; i++ {
		if err := premier.Append(EventOpened, map[string]any{"ecrivain": "service", "n": i}); err != nil {
			t.Fatalf("écriture du service: %v", err)
		}
		if err := second.Append(EventCARequestApproved, map[string]any{"ecrivain": "cli", "n": i}); err != nil {
			t.Fatalf("écriture de la CLI: %v", err)
		}
	}

	report, err := Verify(path)
	if err != nil {
		t.Fatalf("la chaîne doit rester continue malgré deux écrivains: %v", err)
	}
	if report.Records != 6 || report.Last != 6 {
		t.Fatalf("relecture incohérente: %+v", report)
	}

	// Chaque écrivain doit voir la tête réelle du journal, pas seulement la
	// sienne : c'est cette tête qui est scellée et contresignée.
	for nom, log := range map[string]*Log{"service": premier, "cli": second} {
		seq, head, err := log.Head()
		if err != nil {
			t.Fatalf("%s: %v", nom, err)
		}
		if seq != report.Last || head != report.Head {
			t.Errorf("%s voit seq=%d head=%s, attendu seq=%d head=%s", nom, seq, head, report.Last, report.Head)
		}
	}
}
