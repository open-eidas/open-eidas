-- La clé WebAuthn sérialisée, telle que la bibliothèque la rend à l'enregistrement.
--
-- webauthn-rs relance une authentification à partir de cette structure
-- (AttestedPasskey), pas de nos colonnes séparées : on la conserve donc
-- entière. public_key, aaguid et attestation_* restent lisibles en clair
-- pour un auditeur, sans dépendre de la bibliothèque.
--
-- La table n'est alimentée par aucun code avant cette migration : la colonne
-- peut être NOT NULL sans valeur par défaut.
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS passkey JSONB;
ALTER TABLE webauthn_credentials ALTER COLUMN passkey SET NOT NULL;
