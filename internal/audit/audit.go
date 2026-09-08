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
	"io"
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
	EventReplicated         = "log.replicated"
	EventTimestampGranted   = "timestamp.granted"
	EventTimestampRejected  = "timestamp.rejected"
	EventTimeMeasurement    = "time.measurement"
	EventEnrollmentAccepted = "enrollment.completed"
)

// Événements consignés par l'autorité de certification (ETSI EN 319 401 §7.10
// et EN 319 411-1 §6.2.1 : toute décision d'émission doit être imputable).
// Ils partagent le même journal chaîné que les événements ci-dessus : un
// auditeur relit une seule chaîne pour l'ensemble du cycle de vie.
const (
	EventCAceremony            = "ca.ceremony"
	EventCARequestReceived     = "ca.request_received"
	EventCARequestApproved     = "ca.request_approved"
	EventCARequestRejected     = "ca.request_rejected"
	EventCACertificateIssued   = "ca.certificate_issued"
	EventCACertificateRevoked  = "ca.certificate_revoked"
	EventCACRLPublished        = "ca.crl_published"
	EventCAIssuanceRefused     = "ca.issuance_refused"
	EventCAConformanceReported = "ca.conformance_reported"
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
//
// Plusieurs processus peuvent légitimement écrire dans le même journal : le
// service de la CA et les commandes d'exploitation lancées à côté
// (`ca-server ra approve`, `revoke`). Chaque ajout prend donc un verrou de
// fichier et relit ce qui a pu être écrit entre-temps, de sorte que la chaîne
// reste continue quel que soit l'ordre des écritures.
type Log struct {
	mu   sync.Mutex
	file *os.File
	seq  uint64
	head string
	// offset est la position, en octets, jusqu'à laquelle le journal a été
	// relu et vérifié par cette instance.
	offset int64
	now    func() time.Time
}

// Open relit et vérifie le journal existant, puis l'ouvre en ajout.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("audit: création du répertoire du journal: %w", err)
	}
	// O_RDWR et non O_WRONLY : l'ajout doit pouvoir relire ce qu'un autre
	// processus aurait écrit depuis la dernière écriture de celui-ci.
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: ouverture du journal: %w", err)
	}
	l := &Log{file: file, head: GenesisHash, now: time.Now}
	if err := lockExclusive(file); err != nil {
		file.Close()
		return nil, err
	}
	err = l.catchUp()
	_ = unlock(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	return l, nil
}

// catchUp relit le journal à partir de l'offset déjà vérifié et met à jour la
// tête de chaîne. Doit être appelé sous le verrou de fichier.
func (l *Log) catchUp() error {
	if _, err := l.file.Seek(l.offset, io.SeekStart); err != nil {
		return fmt.Errorf("audit: positionnement dans le journal: %w", err)
	}
	report := Report{Last: l.seq, Head: l.head, Records: l.seq}
	read, err := scanChain(l.file, &report)
	if err != nil {
		return err
	}
	l.offset += read
	l.seq = report.Last
	l.head = report.Head
	return nil
}

// Append ajoute un enregistrement et le synchronise sur disque.
func (l *Log) Append(event string, data map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := lockExclusive(l.file); err != nil {
		return err
	}
	defer func() { _ = unlock(l.file) }()

	// Un autre processus a pu écrire depuis notre dernier ajout : la tête de
	// chaîne est reprise depuis le fichier, jamais supposée.
	if err := l.catchUp(); err != nil {
		return err
	}

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
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		return fmt.Errorf("audit: écriture: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("audit: synchronisation sur disque: %w", err)
	}

	l.seq = record.Seq
	l.head = record.Hash
	l.offset += int64(len(line))
	return nil
}

// Head retourne le numéro et l'empreinte du dernier enregistrement, en
// tenant compte de ce qu'un autre processus aurait écrit entre-temps : c'est
// cette tête de chaîne qui est scellée et contresignée, elle doit couvrir
// tout le journal, pas seulement les écritures de ce processus.
func (l *Log) Head() (uint64, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := lockExclusive(l.file); err != nil {
		return 0, "", err
	}
	defer func() { _ = unlock(l.file) }()
	if err := l.catchUp(); err != nil {
		return 0, "", err
	}
	return l.seq, l.head, nil
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

	if _, err := scanChain(file, &report); err != nil {
		return report, err
	}
	return report, nil
}

// scanChain relit des enregistrements depuis r, contrôle la continuité de la
// chaîne et met à jour report. Il retourne le nombre d'octets consommés, ce
// qui permet à un journal ouvert en écriture de reprendre exactement là où il
// s'était arrêté.
func scanChain(r io.Reader, report *Report) (int64, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		line uint64
		read int64
	)
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		read += int64(len(raw)) + 1 // le saut de ligne consommé par le scanner
		if len(raw) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(raw, &record); err != nil {
			return read, fmt.Errorf("audit: ligne %d illisible: %w", line, err)
		}
		if record.Prev != report.Head {
			return read, fmt.Errorf("audit: chaîne rompue à l'enregistrement %d: empreinte précédente attendue %s, trouvée %s",
				record.Seq, report.Head, record.Prev)
		}
		expected := report.Last + 1
		if report.Records == 0 {
			expected = record.Seq
		}
		if record.Seq != expected {
			return read, fmt.Errorf("audit: numérotation rompue: enregistrement %d attendu, %d trouvé", expected, record.Seq)
		}
		hash, err := record.computeHash()
		if err != nil {
			return read, fmt.Errorf("audit: enregistrement %d: %w", record.Seq, err)
		}
		if hash != record.Hash {
			return read, fmt.Errorf("audit: enregistrement %d altéré: empreinte %s attendue, %s inscrite",
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
		return read, fmt.Errorf("audit: parcours du journal: %w", err)
	}
	return read, nil
}
