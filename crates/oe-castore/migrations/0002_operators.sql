-- Registre des opérateurs et preuves de décision (docs/WEBUI.md §2, §4, §10).
--
-- Ces tables appartiennent à ca-server, seul écrivain : ra-console n'y a que
-- des droits de lecture (crates/oe-castore/sql/ra_console_grants.sql). C'est
-- ce qui empêche une console compromise de s'inscrire une clé ou de faire
-- exécuter une décision, puisque approuver déclenche l'émission
-- (oe_raflow::Flow::resume, WEBUI.md §16 « Faille identifiée »).
--
-- Les invariants qui comptent sont des contraintes SQL, pas seulement des
-- vérifications applicatives, comme decision_imputable dans 0001 :
--
--   * une clé sans attestation vérifiable, ou copiable (backup_eligible),
--     n'entre jamais dans le registre ;
--   * une clé n'est active qu'une fois confirmée (sauf le tout premier
--     administrateur, amorcé localement) ;
--   * un opérateur ne compte qu'une fois par action ;
--   * un challenge WebAuthn ne sert qu'une fois.

CREATE TABLE IF NOT EXISTS operators (
    id          UUID PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    role        TEXT        NOT NULL
        CHECK (role IN ('auditeur', 'ra_operateur', 'ca_operateur', 'admin')),
    created_at  TIMESTAMPTZ NOT NULL,
    created_by  TEXT        NOT NULL,
    disabled_at TIMESTAMPTZ,
    disabled_by TEXT
);

-- Un credential par clé FIDO2 physique. credential_id est l'identifiant que
-- l'authentificateur choisit lui-même (base64url).
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id      TEXT        PRIMARY KEY,
    operator_id        UUID        NOT NULL REFERENCES operators(id),
    public_key         BYTEA       NOT NULL,
    sign_count         BIGINT      NOT NULL DEFAULT 0,
    aaguid             UUID        NOT NULL,
    transports         TEXT[]      NOT NULL DEFAULT '{}',
    attestation_format TEXT        NOT NULL,
    attestation_object BYTEA       NOT NULL,
    backup_eligible    BOOLEAN     NOT NULL,
    label              TEXT        NOT NULL DEFAULT '',
    last_used_at       TIMESTAMPTZ,
    initiated_by       TEXT        NOT NULL,
    initiated_at       TIMESTAMPTZ NOT NULL,
    confirmed_by       TEXT,
    confirmed_at       TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    revoked_by         TEXT,
    revoked_reason     TEXT,
    CONSTRAINT credential_confirmed_before_active CHECK (
        revoked_at IS NOT NULL
        OR (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL)
        OR initiated_by = 'bootstrap-admin'
    ),
    CONSTRAINT attestation_required CHECK (attestation_format <> 'none'),
    CONSTRAINT not_backup_eligible CHECK (backup_eligible = false)
);

CREATE INDEX IF NOT EXISTS webauthn_credentials_operator_idx
    ON webauthn_credentials (operator_id) WHERE revoked_at IS NULL;

-- Invitation d'un nouvel opérateur. Le jeton n'est conservé que haché.
CREATE TABLE IF NOT EXISTS operator_invites (
    id           UUID        PRIMARY KEY,
    operator_id  UUID        NOT NULL REFERENCES operators(id),
    token_hash   BYTEA       NOT NULL UNIQUE,
    created_by   TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ
);

-- Clé enregistrée mais pas encore confirmée : elle ne peut pas vivre dans
-- webauthn_credentials, dont la contrainte interdit toute ligne non confirmée.
CREATE TABLE IF NOT EXISTS pending_credentials (
    credential_id      TEXT        PRIMARY KEY,
    operator_id        UUID        NOT NULL REFERENCES operators(id),
    public_key         BYTEA       NOT NULL,
    aaguid             UUID        NOT NULL,
    attestation_format TEXT        NOT NULL CHECK (attestation_format <> 'none'),
    attestation_object BYTEA       NOT NULL,
    backup_eligible    BOOLEAN     NOT NULL CHECK (backup_eligible = false),
    invite_id          UUID        NOT NULL REFERENCES operator_invites(id),
    registered_at      TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL
);

-- Une action, créée par ca-server quand il émet le premier challenge : le
-- corps est figé ici, et c'est ce corps-là qui s'exécute.
CREATE TABLE IF NOT EXISTS actions (
    id          UUID        PRIMARY KEY,
    body        JSONB       NOT NULL,
    body_hash   BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    executed_at TIMESTAMPTZ
);

-- Un challenge WebAuthn émis sur une action. Jamais purgé : decision_evidence
-- le référence.
CREATE TABLE IF NOT EXISTS action_challenges (
    challenge_id  UUID        PRIMARY KEY,
    action_id     UUID        NOT NULL REFERENCES actions(id),
    challenge     BYTEA       NOT NULL UNIQUE,
    operator_hint UUID        REFERENCES operators(id),
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ
);

-- Preuve de chaque décision, une ligne par assertion. La signature porte sur
-- le challenge ; le lien challenge → corps est établi par actions.body_hash
-- tel qu'écrit au journal chaîné avant la signature (WEBUI.md §4).
CREATE TABLE IF NOT EXISTS decision_evidence (
    id                 UUID        PRIMARY KEY,
    challenge_id       UUID        NOT NULL UNIQUE REFERENCES action_challenges(challenge_id),
    action_id          UUID        NOT NULL REFERENCES actions(id),
    operator_id        UUID        NOT NULL REFERENCES operators(id),
    credential_id      TEXT        NOT NULL REFERENCES webauthn_credentials(credential_id),
    authenticator_data BYTEA       NOT NULL,
    client_data_json   BYTEA       NOT NULL,
    signature          BYTEA       NOT NULL,
    verified_at        TIMESTAMPTZ NOT NULL,
    UNIQUE (action_id, operator_id)
);
