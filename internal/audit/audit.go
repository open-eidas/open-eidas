// Package audit tient le journal d'audit du service sous forme de chaîne de
// hachage : chaque enregistrement porte l'empreinte du précédent, si bien
// qu'aucune ligne ne peut être modifiée, supprimée ou intercalée sans rompre
// la chaîne — ce qui est détectable par quiconque relit le fichier.
//
// Le journal est écrit en JSON Lines, un enregistrement par ligne, et
// synchronisé sur disque à chaque écriture. Il est relu et vérifié à
// l'ouverture : un journal altéré empêche le service de démarrer.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GenesisHash est l'empreinte conventionnelle précédant le premier
// enregistrement d'un journal.
var GenesisHash = strings.Repeat("0", 64)

// Événements consignés par le service.
const (
	EventOpened             = "log.opened"
	EventSealed             = "log.sealed"
	EventCrossSealed        = "log.cross_sealed"
	EventTimestampGranted   = "timestamp.granted"
	EventTimestampRejected  = "timestamp.rejected"
	EventTimeMeasurement    = "time.measurement"
	EventEnrollmentAccepted = "enrollment.completed"
)

// Record est une ligne du journal.
type Record struct {
	Seq   uint64         `json:"seq"`
	Time  string         `json:"time"`
	Event string         `json:"event"`
	Data  map[string]any `json:"data,omitempty"`
	Prev  string         `json:"prev"`
	Hash  string         `json:"hash"`
}

// payload est la partie couverte par l'empreinte. Les champs d'une structure
// sont sérialisés dans l'ordre de déclaration et les clés d'une map par ordre
// alphabétique : la sérialisation est donc reproductible.
type payload struct {
	Seq   uint64         `json:"seq"`
	Time  string         `json:"time"`
	Event string         `json:"event"`
	Data  map[string]any `json:"data,omitempty"`
	Prev  string         `json:"prev"`
}

func (r Record) computeHash() (string, error) {
	raw, err := json.Marshal(payload{Seq: r.Seq, Time: r.Time, Event: r.Event, Data: r.Data, Prev: r.Prev})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Log est un journal ouvert en écriture.
type Log struct {
	mu   sync.Mutex
	file *os.File
	seq  uint64
	head string
	now  func() time.Time
}

// Open relit et vérifie le journal existant, puis l'ouvre en ajout.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("audit: création du répertoire du journal: %w", err)
	}
	report, err := Verify(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: ouverture du journal: %w", err)
	}
	return &Log{file: file, seq: report.Last, head: report.Head, now: time.Now}, nil
}

// Append ajoute un enregistrement et le synchronise sur disque.
func (l *Log) Append(event string, data map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	record := Record{
		Seq:   l.seq + 1,
		Time:  l.now().UTC().Format(time.RFC3339Nano),
		Event: event,
		Data:  data,
		Prev:  l.head,
	}
	hash, err := record.computeHash()
	if err != nil {
		return fmt.Errorf("audit: calcul de l'empreinte: %w", err)
	}
	record.Hash = hash

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("audit: sérialisation: %w", err)
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: écriture: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("audit: synchronisation sur disque: %w", err)
	}

	l.seq = record.Seq
	l.head = record.Hash
	return nil
}

// Head retourne le numéro et l'empreinte du dernier enregistrement.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.head
}

func (l *Log) Close() error { return l.file.Close() }

// Report résume la relecture d'un journal.
type Report struct {
	Records uint64
	First   uint64
	Last    uint64
	Head    string
	Seals   uint64
}

// Verify relit intégralement un journal et contrôle la continuité de la
// chaîne. Un journal absent est considéré comme vide et valide.
func Verify(path string) (Report, error) {
	report := Report{Head: GenesisHash}

	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return report, fmt.Errorf("audit: lecture du journal: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var line uint64
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(raw, &record); err != nil {
			return report, fmt.Errorf("audit: ligne %d illisible: %w", line, err)
		}
		if record.Prev != report.Head {
			return report, fmt.Errorf("audit: chaîne rompue à l'enregistrement %d: empreinte précédente attendue %s, trouvée %s",
				record.Seq, report.Head, record.Prev)
		}
		expected := report.Last + 1
		if report.Records == 0 {
			expected = record.Seq
		}
		if record.Seq != expected {
			return report, fmt.Errorf("audit: numérotation rompue: enregistrement %d attendu, %d trouvé", expected, record.Seq)
		}
		hash, err := record.computeHash()
		if err != nil {
			return report, fmt.Errorf("audit: enregistrement %d: %w", record.Seq, err)
		}
		if hash != record.Hash {
			return report, fmt.Errorf("audit: enregistrement %d altéré: empreinte %s attendue, %s inscrite",
				record.Seq, hash, record.Hash)
		}

		if report.Records == 0 {
			report.First = record.Seq
		}
		if record.Event == EventSealed {
			report.Seals++
		}
		report.Records++
		report.Last = record.Seq
		report.Head = record.Hash
	}
	if err := scanner.Err(); err != nil {
		return report, fmt.Errorf("audit: parcours du journal: %w", err)
	}
	return report, nil
}
