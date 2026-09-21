-- Nombre de signatures d'opérateurs distincts exigé pour exécuter une action
-- (docs/WEBUI.md §8). Posé par ca-server à l'émission du premier challenge, à
-- partir de *sa* politique : jamais d'un champ transmis par ra-console, sans
-- quoi une console compromise ramènerait le seuil à 1.
--
-- Les actions existantes n'exigeaient qu'une signature : DEFAULT 1.
ALTER TABLE actions ADD COLUMN IF NOT EXISTS required_signatures INTEGER NOT NULL DEFAULT 1
    CHECK (required_signatures >= 1);
