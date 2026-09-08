-- Schéma initial du registre de l'autorité de certification d'Open eIDAS.
--
-- Trois choix structurants, tous destinés à ce qu'un auditeur puisse relire la
-- base sans connaître le code :
--
--   * le numéro de série est stocké en hexadécimal minuscule sans zéro de
--     tête (serial_hex) plutôt qu'en NUMERIC : 128 bits y tiennent
--     exactement, et la clé primaire porte à elle seule la garantie
--     d'unicité qu'exige ETSI EN 319 412-1 ;
--   * une réservation précède toujours la signature (status = 'reserved') :
--     le numéro est pris avant que le certificat n'existe, de sorte que deux
--     instances qui signent en parallèle ne peuvent pas produire le même ;
--   * l'empreinte de la CSR est unique : c'est ce qui rend l'enrôlement
--     idempotent, une re-soumission retrouvant sa demande au lieu d'en ouvrir
--     une seconde.

CREATE TABLE IF NOT EXISTS authorities (
    name        TEXT PRIMARY KEY,
    subject_dn  TEXT        NOT NULL,
    der         BYTEA       NOT NULL,
    token_label TEXT        NOT NULL,
    key_label   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    serial_hex             TEXT PRIMARY KEY,
    profile                TEXT    NOT NULL,
    subject_dn             TEXT    NOT NULL DEFAULT '',
    issuer_dn              TEXT    NOT NULL DEFAULT '',
    not_before             TIMESTAMPTZ,
    not_after              TIMESTAMPTZ,
    der                    BYTEA,
    status                 TEXT    NOT NULL
        CHECK (status IN ('reserved', 'issued', 'revoked')),
    revoked_at             TIMESTAMPTZ,
    revocation_reason      INTEGER NOT NULL DEFAULT 0,
    request_transaction_id TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS certificates_subject_actifs_idx
    ON certificates (subject_dn) WHERE status = 'issued';
CREATE INDEX IF NOT EXISTS certificates_revoques_idx
    ON certificates (not_after) WHERE status = 'revoked';

CREATE TABLE IF NOT EXISTS enrollment_requests (
    transaction_id         TEXT PRIMARY KEY,
    csr_fingerprint        TEXT        NOT NULL UNIQUE,
    csr_der                BYTEA       NOT NULL,
    profile                TEXT        NOT NULL,
    subject_cn             TEXT        NOT NULL DEFAULT '',
    state                  TEXT        NOT NULL
        CHECK (state IN ('PENDING', 'APPROVED', 'ISSUED', 'REJECTED')),
    created_at             TIMESTAMPTZ NOT NULL,
    decided_at             TIMESTAMPTZ,
    -- L'opérateur qui a approuvé ou rejeté la demande. Obligatoire dès que
    -- l'état quitte PENDING : c'est l'imputabilité exigée par ETSI
    -- EN 319 411-1 §6.2.1, et la contrainte ci-dessous l'impose en base, pas
    -- seulement dans le code.
    operator               TEXT        NOT NULL DEFAULT '',
    comment                TEXT        NOT NULL DEFAULT '',
    issued_at              TIMESTAMPTZ,
    certificate_serial_hex TEXT,
    CONSTRAINT decision_imputable CHECK (
        state = 'PENDING' OR (operator <> '' AND decided_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS enrollment_requests_etat_idx
    ON enrollment_requests (state, created_at);

CREATE TABLE IF NOT EXISTS crls (
    number      BIGINT PRIMARY KEY,
    der         BYTEA       NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL
);

-- La monotonie du CRLNumber (RFC 5280 §5.2.3) est portée par une séquence :
-- elle ne recule jamais, même si une CRL est supprimée de l'historique.
CREATE SEQUENCE IF NOT EXISTS crl_number_seq START WITH 1;
