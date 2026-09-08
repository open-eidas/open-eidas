// Package castore porte l'état persistant de l'autorité de certification :
// les autorités elles-mêmes, le registre des certificats émis, les demandes
// d'enrôlement en cours et l'historique des listes de révocation.
//
// L'interface Store est délibérément étroite et explicite : chaque méthode
// correspond à une opération que le moteur de CA doit pouvoir défendre devant
// un auditeur. Deux implémentations la satisfont — PostgreSQL en exploitation,
// mémoire pour les tests unitaires du moteur — et la même suite de tests les
// exerce toutes les deux.
package castore

import (
	"context"
	"errors"
	"math/big"
	"time"
)

var (
	// ErrNotFound signale l'absence de l'objet demandé.
	ErrNotFound = errors.New("castore: introuvable")
	// ErrSerialTaken signale qu'un numéro de série est déjà réservé. Le
	// moteur d'émission doit alors en tirer un autre : c'est cette contrainte
	// d'unicité, portée par la base, qui garantit qu'aucun numéro ne peut
	// être émis deux fois même si deux instances signent en parallèle.
	ErrSerialTaken = errors.New("castore: numéro de série déjà réservé")
	// ErrConflict signale une transition d'état concurrente : la demande a
	// changé d'état entre sa lecture et son écriture.
	ErrConflict = errors.New("castore: état modifié entre-temps")
)

// CertificateStatus est l'état d'un certificat au registre.
type CertificateStatus string

const (
	// StatusReserved marque un numéro de série réservé mais dont le
	// certificat n'est pas encore signé. Un tel enregistrement ne doit jamais
	// apparaître dans une CRL ni dans une réponse d'enrôlement.
	StatusReserved CertificateStatus = "reserved"
	// StatusIssued marque un certificat délivré et non révoqué.
	StatusIssued CertificateStatus = "issued"
	// StatusRevoked marque un certificat révoqué.
	StatusRevoked CertificateStatus = "revoked"
)

// Certificate est l'enregistrement d'un certificat au registre de la CA.
type Certificate struct {
	Serial    *big.Int
	Profile   string
	SubjectDN string
	IssuerDN  string
	NotBefore time.Time
	NotAfter  time.Time
	DER       []byte
	Status    CertificateStatus

	RevokedAt time.Time
	// RevocationReason reprend les codes de RFC 5280 §5.3.1. La valeur 0
	// (unspecified) est acceptée mais signalée par internal/conformance :
	// elle ne justifie pas une décision devant un auditeur.
	RevocationReason int
	// RequestTransactionID relie le certificat à la demande d'enrôlement qui
	// l'a produit, et donc à l'opérateur qui l'a approuvée.
	RequestTransactionID string
}

// RequestState est l'état d'une demande d'enrôlement. Ces quatre valeurs sont
// les seules : la machine à états d'internal/raflow n'en connaît pas d'autre,
// et aucune ne mène à ISSUED sans passer par APPROVED.
type RequestState string

const (
	StatePending  RequestState = "PENDING"
	StateApproved RequestState = "APPROVED"
	StateIssued   RequestState = "ISSUED"
	StateRejected RequestState = "REJECTED"
)

// Request est une demande d'enrôlement.
type Request struct {
	TransactionID string
	// CSRFingerprint est l'empreinte SHA-256 hexadécimale de la CSR DER. Elle
	// porte la contrainte d'unicité qui rend l'enrôlement idempotent : une
	// re-soumission identique retrouve la demande existante au lieu d'en
	// ouvrir une seconde.
	CSRFingerprint string
	CSRDER         []byte
	Profile        string
	SubjectCN      string
	State          RequestState
	CreatedAt      time.Time

	// DecidedAt et Operator tracent la décision d'approbation ou de rejet.
	// Operator est obligatoire pour toute sortie de l'état PENDING : c'est
	// l'exigence d'imputabilité d'ETSI EN 319 411-1 §6.2.1.
	DecidedAt time.Time
	Operator  string
	Comment   string

	IssuedAt time.Time
	// CertificateSerial est renseigné lorsque la demande atteint ISSUED.
	CertificateSerial *big.Int
}

// Authority est une autorité de la hiérarchie, telle que la cérémonie de clé
// l'a créée. La clé privée n'y figure pas : elle ne quitte jamais le token
// PKCS#11, et seuls ses labels d'accès sont conservés.
type Authority struct {
	Name       string // "root" ou "issuing"
	SubjectDN  string
	DER        []byte
	TokenLabel string
	KeyLabel   string
	CreatedAt  time.Time
}

// CRL est une liste de révocation publiée.
type CRL struct {
	Number     int64
	DER        []byte
	ThisUpdate time.Time
	NextUpdate time.Time
}

// Store est la surface de persistance du moteur de CA.
type Store interface {
	// SaveAuthority enregistre ou remplace une autorité de la hiérarchie.
	SaveAuthority(ctx context.Context, a Authority) error
	// Authority retourne l'autorité nommée, ou ErrNotFound.
	Authority(ctx context.Context, name string) (*Authority, error)

	// ReserveSerial réserve un numéro de série avant signature. Retourne
	// ErrSerialTaken s'il est déjà pris, ce qui oblige l'appelant à en tirer
	// un autre plutôt qu'à écraser un certificat existant.
	ReserveSerial(ctx context.Context, serial *big.Int, profile string) error
	// SaveCertificate complète une réservation avec le certificat signé.
	SaveCertificate(ctx context.Context, c Certificate) error
	// Certificate retourne un certificat par son numéro de série.
	Certificate(ctx context.Context, serial *big.Int) (*Certificate, error)
	// ActiveBySubject liste les certificats non révoqués et non expirés d'un
	// sujet donné, pour appliquer la politique « une seule unité active ».
	ActiveBySubject(ctx context.Context, subjectDN string, now time.Time) ([]Certificate, error)
	// Revoke marque un certificat révoqué. Révoquer un certificat déjà
	// révoqué est sans effet et sans erreur : la première date fait foi.
	Revoke(ctx context.Context, serial *big.Int, at time.Time, reason int) error
	// Revoked liste les certificats révoqués à porter dans la CRL. Les
	// certificats expirés depuis plus de `grace` en sont retirés : RFC 5280
	// §5 autorise à ne plus lister un certificat après son expiration, et
	// c'est ce qui empêche la CRL de croître indéfiniment.
	Revoked(ctx context.Context, now time.Time, grace time.Duration) ([]Certificate, error)

	// CreateRequest ouvre une demande d'enrôlement.
	CreateRequest(ctx context.Context, r Request) error
	// RequestByFingerprint retrouve une demande par l'empreinte de sa CSR.
	RequestByFingerprint(ctx context.Context, fingerprint string) (*Request, error)
	// RequestByTransactionID retrouve une demande par son identifiant public.
	RequestByTransactionID(ctx context.Context, transactionID string) (*Request, error)
	// Requests liste les demandes dans l'état donné, les plus anciennes
	// d'abord. Un état vide les liste toutes.
	Requests(ctx context.Context, state RequestState) ([]Request, error)
	// UpdateRequest applique une transition d'état. `from` est l'état attendu
	// avant la transition : si la demande n'y est plus, ErrConflict est
	// retourné et rien n'est écrit.
	UpdateRequest(ctx context.Context, r Request, from RequestState) error

	// NextCRLNumber alloue le numéro de la prochaine CRL, strictement
	// supérieur à tous les précédents.
	NextCRLNumber(ctx context.Context) (int64, error)
	// SaveCRL enregistre une CRL publiée.
	SaveCRL(ctx context.Context, c CRL) error
	// LatestCRL retourne la dernière CRL publiée, ou ErrNotFound.
	LatestCRL(ctx context.Context) (*CRL, error)

	// Close libère les ressources sous-jacentes.
	Close() error
}
