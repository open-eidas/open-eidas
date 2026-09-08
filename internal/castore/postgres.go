package castore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Postgres est l'implémentation de Store adossée à PostgreSQL, utilisée en
// exploitation. Les contraintes d'intégrité — unicité du numéro de série,
// unicité de l'empreinte de CSR, imputabilité de la décision d'approbation —
// sont portées par le schéma et non seulement par le code : une écriture
// fautive est refusée par la base, y compris si elle vient d'ailleurs.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres établit le pool de connexions et applique les migrations.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("castore: connexion à PostgreSQL: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("castore: PostgreSQL injoignable: %w", err)
	}
	s := &Postgres{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// migrate applique les fichiers de migrations/, dans l'ordre de leur nom, une
// seule fois chacun. Chaque migration s'exécute dans sa propre transaction :
// une migration qui échoue laisse la base dans l'état de la précédente plutôt
// qu'à moitié appliquée.
func (s *Postgres) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )`); err != nil {
		return fmt.Errorf("castore: création de schema_migrations: %w", err)
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		var applied bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, name,
		).Scan(&applied); err != nil {
			return fmt.Errorf("castore: lecture de schema_migrations: %w", err)
		}
		if applied {
			continue
		}
		sqlBytes, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("castore: migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("castore: validation de la migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *Postgres) Close() error {
	s.pool.Close()
	return nil
}

// isUniqueViolation reconnaît le code SQLSTATE 23505, seul moyen fiable de
// distinguer une collision de clé d'une véritable panne.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Postgres) SaveAuthority(ctx context.Context, a Authority) error {
	_, err := s.pool.Exec(ctx, `
        INSERT INTO authorities (name, subject_dn, der, token_label, key_label, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (name) DO UPDATE SET
            subject_dn = EXCLUDED.subject_dn,
            der        = EXCLUDED.der,
            token_label = EXCLUDED.token_label,
            key_label   = EXCLUDED.key_label`,
		a.Name, a.SubjectDN, a.DER, a.TokenLabel, a.KeyLabel, a.CreatedAt)
	if err != nil {
		return fmt.Errorf("castore: enregistrement de l'autorité %q: %w", a.Name, err)
	}
	return nil
}

func (s *Postgres) Authority(ctx context.Context, name string) (*Authority, error) {
	var a Authority
	err := s.pool.QueryRow(ctx, `
        SELECT name, subject_dn, der, token_label, key_label, created_at
        FROM authorities WHERE name = $1`, name,
	).Scan(&a.Name, &a.SubjectDN, &a.DER, &a.TokenLabel, &a.KeyLabel, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("castore: lecture de l'autorité %q: %w", name, err)
	}
	return &a, nil
}

func (s *Postgres) ReserveSerial(ctx context.Context, serial *big.Int, profile string) error {
	_, err := s.pool.Exec(ctx, `
        INSERT INTO certificates (serial_hex, profile, status) VALUES ($1, $2, 'reserved')`,
		serialKey(serial), profile)
	if isUniqueViolation(err) {
		return ErrSerialTaken
	}
	if err != nil {
		return fmt.Errorf("castore: réservation du numéro de série: %w", err)
	}
	return nil
}

func (s *Postgres) SaveCertificate(ctx context.Context, c Certificate) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE certificates SET
            profile = $2, subject_dn = $3, issuer_dn = $4,
            not_before = $5, not_after = $6, der = $7, status = $8,
            request_transaction_id = $9
        WHERE serial_hex = $1 AND status = 'reserved'`,
		serialKey(c.Serial), c.Profile, c.SubjectDN, c.IssuerDN,
		c.NotBefore, c.NotAfter, c.DER, string(c.Status), c.RequestTransactionID)
	if err != nil {
		return fmt.Errorf("castore: enregistrement du certificat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Soit la réservation n'existe pas, soit elle a déjà été complétée :
		// dans les deux cas, écraser serait pire que refuser.
		return ErrConflict
	}
	return nil
}

// scanCertificate lit une ligne du registre. Les colonnes nullables (celles
// qu'une simple réservation n'a pas encore renseignées) passent par des
// pointeurs plutôt que par des valeurs nulles silencieuses.
func scanCertificate(row pgx.Row) (*Certificate, error) {
	var (
		c         Certificate
		serialHex string
		notBefore *time.Time
		notAfter  *time.Time
		der       []byte
		revokedAt *time.Time
		status    string
	)
	if err := row.Scan(&serialHex, &c.Profile, &c.SubjectDN, &c.IssuerDN,
		&notBefore, &notAfter, &der, &status, &revokedAt,
		&c.RevocationReason, &c.RequestTransactionID); err != nil {
		return nil, err
	}
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return nil, fmt.Errorf("castore: numéro de série illisible en base: %q", serialHex)
	}
	c.Serial = serial
	c.Status = CertificateStatus(status)
	c.DER = der
	if notBefore != nil {
		c.NotBefore = *notBefore
	}
	if notAfter != nil {
		c.NotAfter = *notAfter
	}
	if revokedAt != nil {
		c.RevokedAt = *revokedAt
	}
	return &c, nil
}

const certificateColumns = `serial_hex, profile, subject_dn, issuer_dn,
    not_before, not_after, der, status, revoked_at, revocation_reason,
    request_transaction_id`

func (s *Postgres) Certificate(ctx context.Context, serial *big.Int) (*Certificate, error) {
	c, err := scanCertificate(s.pool.QueryRow(ctx,
		`SELECT `+certificateColumns+` FROM certificates
         WHERE serial_hex = $1 AND status <> 'reserved'`, serialKey(serial)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("castore: lecture du certificat: %w", err)
	}
	return c, nil
}

func (s *Postgres) queryCertificates(ctx context.Context, sql string, args ...any) ([]Certificate, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Postgres) ActiveBySubject(ctx context.Context, subjectDN string, now time.Time) ([]Certificate, error) {
	out, err := s.queryCertificates(ctx,
		`SELECT `+certificateColumns+` FROM certificates
         WHERE status = 'issued' AND subject_dn = $1 AND not_after > $2
         ORDER BY serial_hex`, subjectDN, now)
	if err != nil {
		return nil, fmt.Errorf("castore: liste des certificats actifs de %q: %w", subjectDN, err)
	}
	return out, nil
}

func (s *Postgres) Revoke(ctx context.Context, serial *big.Int, at time.Time, reason int) error {
	// La clause status = 'issued' rend l'opération idempotente ET protège la
	// date de première révocation : une seconde révocation ne la repousse pas.
	tag, err := s.pool.Exec(ctx, `
        UPDATE certificates
        SET status = 'revoked', revoked_at = $2, revocation_reason = $3
        WHERE serial_hex = $1 AND status = 'issued'`,
		serialKey(serial), at, reason)
	if err != nil {
		return fmt.Errorf("castore: révocation du certificat: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Aucune ligne modifiée : soit le certificat est déjà révoqué (sans
	// erreur), soit il n'existe pas (ErrNotFound).
	var status string
	err = s.pool.QueryRow(ctx,
		`SELECT status FROM certificates WHERE serial_hex = $1`, serialKey(serial)).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || status == string(StatusReserved) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("castore: état du certificat: %w", err)
	}
	return nil
}

func (s *Postgres) Revoked(ctx context.Context, now time.Time, grace time.Duration) ([]Certificate, error) {
	out, err := s.queryCertificates(ctx,
		`SELECT `+certificateColumns+` FROM certificates
         WHERE status = 'revoked' AND not_after + $2::interval >= $1
         ORDER BY serial_hex`, now, grace.String())
	if err != nil {
		return nil, fmt.Errorf("castore: liste des certificats révoqués: %w", err)
	}
	return out, nil
}

func (s *Postgres) CreateRequest(ctx context.Context, r Request) error {
	_, err := s.pool.Exec(ctx, `
        INSERT INTO enrollment_requests
            (transaction_id, csr_fingerprint, csr_der, profile, subject_cn, state, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		r.TransactionID, r.CSRFingerprint, r.CSRDER, r.Profile, r.SubjectCN,
		string(r.State), r.CreatedAt)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("castore: ouverture de la demande d'enrôlement: %w", err)
	}
	return nil
}

const requestColumns = `transaction_id, csr_fingerprint, csr_der, profile,
    subject_cn, state, created_at, decided_at, operator, comment, issued_at,
    certificate_serial_hex`

func scanRequest(row pgx.Row) (*Request, error) {
	var (
		r         Request
		state     string
		decidedAt *time.Time
		issuedAt  *time.Time
		serialHex *string
	)
	if err := row.Scan(&r.TransactionID, &r.CSRFingerprint, &r.CSRDER, &r.Profile,
		&r.SubjectCN, &state, &r.CreatedAt, &decidedAt, &r.Operator, &r.Comment,
		&issuedAt, &serialHex); err != nil {
		return nil, err
	}
	r.State = RequestState(state)
	if decidedAt != nil {
		r.DecidedAt = *decidedAt
	}
	if issuedAt != nil {
		r.IssuedAt = *issuedAt
	}
	if serialHex != nil && *serialHex != "" {
		serial, ok := new(big.Int).SetString(*serialHex, 16)
		if !ok {
			return nil, fmt.Errorf("castore: numéro de série illisible en base: %q", *serialHex)
		}
		r.CertificateSerial = serial
	}
	return &r, nil
}

func (s *Postgres) requestBy(ctx context.Context, column, value string) (*Request, error) {
	r, err := scanRequest(s.pool.QueryRow(ctx,
		`SELECT `+requestColumns+` FROM enrollment_requests WHERE `+column+` = $1`, value))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("castore: lecture de la demande: %w", err)
	}
	return r, nil
}

func (s *Postgres) RequestByFingerprint(ctx context.Context, fingerprint string) (*Request, error) {
	return s.requestBy(ctx, "csr_fingerprint", fingerprint)
}

func (s *Postgres) RequestByTransactionID(ctx context.Context, transactionID string) (*Request, error) {
	return s.requestBy(ctx, "transaction_id", transactionID)
}

func (s *Postgres) Requests(ctx context.Context, state RequestState) ([]Request, error) {
	sql := `SELECT ` + requestColumns + ` FROM enrollment_requests`
	var args []any
	if state != "" {
		sql += ` WHERE state = $1`
		args = append(args, string(state))
	}
	sql += ` ORDER BY created_at, transaction_id`

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("castore: liste des demandes: %w", err)
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Postgres) UpdateRequest(ctx context.Context, r Request, from RequestState) error {
	var serialHex *string
	if r.CertificateSerial != nil {
		hex := serialKey(r.CertificateSerial)
		serialHex = &hex
	}
	var decidedAt, issuedAt *time.Time
	if !r.DecidedAt.IsZero() {
		decidedAt = &r.DecidedAt
	}
	if !r.IssuedAt.IsZero() {
		issuedAt = &r.IssuedAt
	}

	// La clause state = $2 est le verrou optimiste : deux opérateurs qui
	// décident simultanément ne peuvent pas appliquer deux transitions à la
	// même demande, le second obtient ErrConflict.
	tag, err := s.pool.Exec(ctx, `
        UPDATE enrollment_requests SET
            state = $3, decided_at = $4, operator = $5, comment = $6,
            issued_at = $7, certificate_serial_hex = $8
        WHERE transaction_id = $1 AND state = $2`,
		r.TransactionID, string(from), string(r.State), decidedAt, r.Operator,
		r.Comment, issuedAt, serialHex)
	if err != nil {
		return fmt.Errorf("castore: transition de la demande %s: %w", r.TransactionID, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM enrollment_requests WHERE transaction_id = $1)`,
			r.TransactionID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		return ErrConflict
	}
	return nil
}

func (s *Postgres) NextCRLNumber(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT nextval('crl_number_seq')`).Scan(&n); err != nil {
		return 0, fmt.Errorf("castore: allocation du CRLNumber: %w", err)
	}
	return n, nil
}

func (s *Postgres) SaveCRL(ctx context.Context, c CRL) error {
	_, err := s.pool.Exec(ctx, `
        INSERT INTO crls (number, der, this_update, next_update) VALUES ($1, $2, $3, $4)`,
		c.Number, c.DER, c.ThisUpdate, c.NextUpdate)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("castore: enregistrement de la CRL: %w", err)
	}
	return nil
}

func (s *Postgres) LatestCRL(ctx context.Context) (*CRL, error) {
	var c CRL
	err := s.pool.QueryRow(ctx, `
        SELECT number, der, this_update, next_update FROM crls
        ORDER BY number DESC LIMIT 1`,
	).Scan(&c.Number, &c.DER, &c.ThisUpdate, &c.NextUpdate)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("castore: lecture de la dernière CRL: %w", err)
	}
	return &c, nil
}
