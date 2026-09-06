#!/usr/bin/env bash
# Amorce la pile Open eIDAS : configuration OpenXPKI, hiérarchie de CA de
# test, puis démarrage de l'autorité d'horodatage.
#
# Le script est idempotent : il peut être relancé sans détruire l'existant.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$ROOT/deploy/openxpki/openxpki-config"
OVERLAY_DIR="$ROOT/deploy/openxpki/overlay"
LOCAL_DIR="$ROOT/deploy/openxpki/local"
MARKER="$ROOT/deploy/openxpki/.sampleconfig-done"
CONFIG_REF="${OXI_CONFIG_REF:-community}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cd "$ROOT"

log "Récupération de la configuration OpenXPKI (branche ${CONFIG_REF})"
if [ ! -d "$CONFIG_DIR/.git" ]; then
    git clone --depth 1 --single-branch --branch "$CONFIG_REF" \
        https://github.com/openxpki/openxpki-config.git "$CONFIG_DIR"
else
    echo "configuration déjà présente dans $CONFIG_DIR"
fi
mkdir -p "$CONFIG_DIR/tls" "$LOCAL_DIR"

log "Clé d'authentification de la CLI d'administration"
if [ ! -f "$LOCAL_DIR/client.key" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$LOCAL_DIR/client.key"
    chmod 644 "$LOCAL_DIR/client.key"
fi
{
    echo "# Généré par scripts/bootstrap.sh — clé publique de l'administrateur CLI."
    echo "auth:"
    echo "    pkiadm:"
    echo "        key: |"
    openssl pkey -in "$LOCAL_DIR/client.key" -pubout | sed 's/^/            /'
    echo "        role: RA Operator"
} > "$CONFIG_DIR/config.d/system/cli.yaml"

log "Clé de chiffrement du coffre de données (datavault)"
if grep -q '##SVAULTKEY##' "$CONFIG_DIR/config.d/system/crypto.yaml"; then
    SVAULT_KEY="$(openssl rand -hex 32)"
    sed -i "s|you must put your own 64 characters key here ##SVAULTKEY##|${SVAULT_KEY}|" \
        "$CONFIG_DIR/config.d/system/crypto.yaml"
    echo "clé générée — conservez une copie de $CONFIG_DIR/config.d/system/crypto.yaml"
else
    echo "clé déjà définie"
fi

log "Application de l'overlay Open eIDAS (profil TSU + endpoint RPC)"
cp -a "$OVERLAY_DIR/." "$CONFIG_DIR/"

log "Secret d'authentification de l'enrôlement (HMAC)"
if [ ! -f "$LOCAL_DIR/enroll-hmac.key" ]; then
    openssl rand -hex 32 > "$LOCAL_DIR/enroll-hmac.key"
    chmod 600 "$LOCAL_DIR/enroll-hmac.key"
fi
ENROLL_HMAC_KEY="$(cat "$LOCAL_DIR/enroll-hmac.key")"
export OPENEIDAS_ENROLL_HMAC_KEY="$ENROLL_HMAC_KEY"
sed -i "s|##ENROLLHMACKEY##|${ENROLL_HMAC_KEY}|" \
    "$CONFIG_DIR/config.d/realm.tpl/rpc/tsa.yaml"

log "Démarrage de la PKI"
docker compose up -d --wait pki-web

if [ ! -f "$MARKER" ]; then
    log "Génération de la hiérarchie de CA de test (root + issuing)"
    docker compose exec -u pkiadm pki-server /bin/bash /etc/openxpki/contrib/sampleconfig.sh
    touch "$MARKER"
    docker compose restart pki-server pki-client
    docker compose up -d --wait pki-web
else
    log "Hiérarchie de CA déjà initialisée"
fi

log "Construction et démarrage de l'autorité d'horodatage"
docker compose up -d --build tsa

log "Attente de la délivrance du certificat de la TSU"
for _ in $(seq 1 60); do
    if curl -fsS http://localhost:8318/healthz >/dev/null 2>&1; then
        curl -fsS http://localhost:8318/api/v1/policy
        echo
        log "Pile opérationnelle — lancez ./scripts/demo.sh"
        exit 0
    fi
    sleep 5
done

echo "La TSA n'a pas démarré dans le délai imparti. Journaux :" >&2
docker compose logs --tail 50 tsa >&2
exit 1
