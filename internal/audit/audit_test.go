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
	if _, head := log.Head(); head != report.Head {
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
	_, headBefore := log.Head()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("la réouverture d'un journal valide doit réussir: %v", err)
	}
	defer reopened.Close()

	seq, head := reopened.Head()
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
