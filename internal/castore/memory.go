package castore

import (
	"context"
	"math/big"
	"sort"
	"sync"
	"time"
)

// Memory est une implémentation en mémoire de Store, destinée aux tests
// unitaires du moteur de CA et de la machine à états d'enrôlement. Elle
// reproduit les mêmes contraintes que la base — unicité du numéro de série,
// unicité de l'empreinte de CSR, transition conditionnée par l'état de
// départ — pour que ce qui passe ici passe aussi en PostgreSQL.
type Memory struct {
	mu            sync.Mutex
	authorities   map[string]Authority
	certificates  map[string]Certificate // clé : numéro de série en base 16
	requests      map[string]Request     // clé : transaction_id
	byFingerprint map[string]string      // empreinte de CSR → transaction_id
	crls          []CRL
	nextCRL       int64
}

// NewMemory construit un magasin en mémoire vide.
func NewMemory() *Memory {
	return &Memory{
		authorities:   map[string]Authority{},
		certificates:  map[string]Certificate{},
		requests:      map[string]Request{},
		byFingerprint: map[string]string{},
	}
}

func serialKey(n *big.Int) string {
	if n == nil {
		return ""
	}
	return n.Text(16)
}

func (m *Memory) SaveAuthority(_ context.Context, a Authority) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authorities[a.Name] = a
	return nil
}

func (m *Memory) Authority(_ context.Context, name string) (*Authority, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.authorities[name]
	if !ok {
		return nil, ErrNotFound
	}
	return &a, nil
}

func (m *Memory) ReserveSerial(_ context.Context, serial *big.Int, profile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := serialKey(serial)
	if _, exists := m.certificates[key]; exists {
		return ErrSerialTaken
	}
	m.certificates[key] = Certificate{Serial: serial, Profile: profile, Status: StatusReserved}
	return nil
}

func (m *Memory) SaveCertificate(_ context.Context, c Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := serialKey(c.Serial)
	existing, ok := m.certificates[key]
	if !ok {
		return ErrNotFound
	}
	if existing.Status != StatusReserved {
		return ErrConflict
	}
	m.certificates[key] = c
	return nil
}

func (m *Memory) Certificate(_ context.Context, serial *big.Int) (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.certificates[serialKey(serial)]
	if !ok || c.Status == StatusReserved {
		return nil, ErrNotFound
	}
	return &c, nil
}

func (m *Memory) ActiveBySubject(_ context.Context, subjectDN string, now time.Time) ([]Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Certificate
	for _, c := range m.certificates {
		if c.Status != StatusIssued || c.SubjectDN != subjectDN || !now.Before(c.NotAfter) {
			continue
		}
		out = append(out, c)
	}
	sortBySerial(out)
	return out, nil
}

func (m *Memory) Revoke(_ context.Context, serial *big.Int, at time.Time, reason int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := serialKey(serial)
	c, ok := m.certificates[key]
	if !ok || c.Status == StatusReserved {
		return ErrNotFound
	}
	if c.Status == StatusRevoked {
		// Première révocation faisant foi : réécrire la date permettrait de
		// repousser après coup l'instant à partir duquel le certificat n'est
		// plus fiable.
		return nil
	}
	c.Status = StatusRevoked
	c.RevokedAt = at
	c.RevocationReason = reason
	m.certificates[key] = c
	return nil
}

func (m *Memory) Revoked(_ context.Context, now time.Time, grace time.Duration) ([]Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Certificate
	for _, c := range m.certificates {
		if c.Status != StatusRevoked {
			continue
		}
		if now.After(c.NotAfter.Add(grace)) {
			continue
		}
		out = append(out, c)
	}
	sortBySerial(out)
	return out, nil
}

func sortBySerial(certs []Certificate) {
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].Serial.Cmp(certs[j].Serial) < 0
	})
}

func (m *Memory) CreateRequest(_ context.Context, r Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byFingerprint[r.CSRFingerprint]; exists {
		return ErrConflict
	}
	if _, exists := m.requests[r.TransactionID]; exists {
		return ErrConflict
	}
	m.requests[r.TransactionID] = r
	m.byFingerprint[r.CSRFingerprint] = r.TransactionID
	return nil
}

func (m *Memory) RequestByFingerprint(_ context.Context, fingerprint string) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byFingerprint[fingerprint]
	if !ok {
		return nil, ErrNotFound
	}
	r := m.requests[id]
	return &r, nil
}

func (m *Memory) RequestByTransactionID(_ context.Context, transactionID string) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.requests[transactionID]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

func (m *Memory) Requests(_ context.Context, state RequestState) ([]Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Request
	for _, r := range m.requests {
		if state != "" && r.State != state {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].TransactionID < out[j].TransactionID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (m *Memory) UpdateRequest(_ context.Context, r Request, from RequestState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.requests[r.TransactionID]
	if !ok {
		return ErrNotFound
	}
	if existing.State != from {
		return ErrConflict
	}
	m.requests[r.TransactionID] = r
	return nil
}

func (m *Memory) NextCRLNumber(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextCRL++
	return m.nextCRL, nil
}

func (m *Memory) SaveCRL(_ context.Context, c CRL) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crls = append(m.crls, c)
	return nil
}

func (m *Memory) LatestCRL(_ context.Context) (*CRL, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.crls) == 0 {
		return nil, ErrNotFound
	}
	latest := m.crls[0]
	for _, c := range m.crls[1:] {
		if c.Number > latest.Number {
			latest = c
		}
	}
	return &latest, nil
}

func (m *Memory) Close() error { return nil }
