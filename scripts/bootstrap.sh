#!/usr/bin/env bash
# Amorce la pile Open eIDAS : base, autorité de certification (cérémonie de
# clé comprise), autorité d'horodatage et répondeur OCSP.
#
# Le script est idempotent : il peut être relancé sans détruire l'existant.
# La cérémonie de clé ne recrée jamais une hiérarchie déjà enregistrée.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_DIR="$ROOT/deploy/local"

# Opérateur sous l'identité duquel les approbations RA et la cérémonie sont
# consignées. C'est un compte technique : la démonstration et la CI doivent
# s'amorcer sans intervention humaine. Un déploiement destiné à la
# qualification doit lui substituer un opérateur nominatif — l'écart est
# visible dans le journal d'audit, précisément parce que cette identité y est
# consignée telle quelle (voir docs/CA.md).
OPERATOR="${OPENEIDAS_RA_OPERATOR:-ci-bootstrap}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cd "$ROOT"
mkdir -p "$LOCAL_DIR"

log "Secret d'authentification de l'enrôlement (HMAC)"
if [ ! -f "$LOCAL_DIR/enroll-hmac.key" ]; then
    openssl rand -hex 32 > "$LOCAL_DIR/enroll-hmac.key"
    chmod 600 "$LOCAL_DIR/enroll-hmac.key"
    echo "secret généré dans $LOCAL_DIR/enroll-hmac.key"
else
    echo "secret déjà présent"
fi
OPENEIDAS_ENROLL_HMAC_KEY="$(cat "$LOCAL_DIR/enroll-hmac.key")"
export OPENEIDAS_ENROLL_HMAC_KEY
export OPENEIDAS_CEREMONY_OPERATOR="$OPERATOR"

log "Démarrage de la base et de l'autorité de certification"
# Le conteneur ca exécute la cérémonie de clé au démarrage puis publie une
# première CRL ; son healthcheck ne passe qu'une fois cet état servable.
docker compose up -d --build --wait db ca

log "Hiérarchie de CA en place"
docker compose exec -T ca ca-server ra list || true

log "Démarrage de l'autorité d'horodatage et du répondeur OCSP"
docker compose up -d --build tsa ocsp-responder

log "Approbation des demandes d'enrôlement et attente des certificats"
# Chaque demande atterrit en attente d'une décision (état PENDING) : il
# n'existe aucun chemin d'auto-approbation dans le code (voir
# internal/raflow). Elle est approuvée ici automatiquement sous l'identité du
# compte technique ci-dessus, pour que la pile de démonstration s'amorce sans
# opérateur humain — ce qui reste un écart assumé vis-à-vis d'une revue
# nominative réelle, tracé comme tel au journal d'audit.
for _ in $(seq 1 60); do
    # La liste est capturée AVANT d'itérer : `docker compose exec -T` lit son
    # entrée standard, et consommerait les lignes restantes s'il était appelé
    # depuis l'intérieur d'un tube.
    pending="$(docker compose exec -T ca ca-server ra list PENDING 2>/dev/null \
        | awk 'NR > 1 && $1 != "(aucune" {print $1}')"
    for tx in $pending; do
        echo "approbation de la demande ${tx}"
        docker compose exec -T ca ca-server ra approve "$tx" "$OPERATOR" \
            "approbation automatique de la pile de démonstration" </dev/null || true
    done

    if curl -fsS http://localhost:8318/healthz >/dev/null 2>&1 \
        && curl -fsS http://localhost:8319/healthz >/dev/null 2>&1; then
        curl -fsS http://localhost:8318/api/v1/policy
        echo
        log "Pile opérationnelle — lancez ./scripts/demo.sh"
        exit 0
    fi
    sleep 5
done

echo "La TSA ou le répondeur OCSP n'a pas démarré dans le délai imparti. Journaux :" >&2
docker compose logs --tail 50 ca tsa ocsp-responder >&2
exit 1
