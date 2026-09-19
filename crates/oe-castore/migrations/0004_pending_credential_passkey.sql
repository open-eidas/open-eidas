-- La clé WebAuthn sérialisée d'une clé en attente de confirmation : c'est elle
-- que la confirmation fera passer dans webauthn_credentials.passkey.
--
-- Aucun code n'alimentait pending_credentials avant cette migration : la
-- colonne peut être NOT NULL sans valeur par défaut.
ALTER TABLE pending_credentials ADD COLUMN IF NOT EXISTS passkey JSONB;
ALTER TABLE pending_credentials ALTER COLUMN passkey SET NOT NULL;
