-- Tables propres à ra-console (docs/WEBUI.md §2, §16) : ce qui ne donne aucun
-- pouvoir sur la PKI. Un ra-console compromis peut les altérer ; il ne peut ni
-- émettre, ni révoquer, ni s'ajouter une clé (ces tables n'accordent rien, et le
-- registre lui reste en lecture seule).
--
-- Elles vivent dans la même base que celles de ca-server et sont appliquées avec
-- les mêmes migrations, mais leur seul écrivain est le rôle de ra-console
-- (sql/ra_console_grants.sql).
--
-- Les tables des incidents et du quorum viendront avec ces fonctions.

-- Challenges de connexion et d'enregistrement. Pour 'action', la table servira à
-- relayer à ca-server le corps exact qui a été montré puis signé : la protection
-- contre le rejeu qui compte est action_challenges, côté ca-server.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id            UUID        PRIMARY KEY,
    kind          TEXT        NOT NULL
        CHECK (kind IN ('register', 'login', 'action')),
    challenge     BYTEA       NOT NULL,
    -- NULL pour 'login' tant que l'opérateur n'est pas identifié par son
    -- assertion ; obligatoire pour 'register' et 'action'.
    operator_id   UUID        REFERENCES operators(id),
    request_body  JSONB,
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    -- Non négociable : un challenge vit 5 minutes au plus.
    CONSTRAINT challenge_short_lived CHECK (expires_at <= created_at + interval '5 minutes'),
    CONSTRAINT challenge_operator_known CHECK (kind = 'login' OR operator_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry_idx ON webauthn_challenges (expires_at);

-- Sessions révocables côté serveur, pas un JWT auto-porteur : révoquer une
-- session (départ d'un opérateur) doit être immédiat, pas attendre l'expiration
-- d'un jeton qu'on ne peut pas rappeler.
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT        PRIMARY KEY,  -- identifiant opaque, 256 bits
    operator_id   UUID        NOT NULL REFERENCES operators(id),
    credential_id TEXT        NOT NULL REFERENCES webauthn_credentials(credential_id),
    created_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS sessions_operator_idx ON sessions (operator_id) WHERE revoked_at IS NULL;

-- Compteur de signatures vu par ra-console sur les seules connexions
-- (webauthn_credentials.sign_count, lui, n'est écrit que par ca-server).
CREATE TABLE IF NOT EXISTS login_counters (
    credential_id   TEXT   PRIMARY KEY REFERENCES webauthn_credentials(credential_id),
    last_sign_count BIGINT NOT NULL
);
