#!/usr/bin/env bash
# Initialise un token SoftHSM2 local pour les tests d'intégration de
# oe-hsm (jalon J2 du plan de migration Rust). Jamais utilisé en
# production : PIN/SO-PIN fixes, réservés au développement.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CONF_DIR="target/softhsm-dev"
TOKENS_DIR="$CONF_DIR/tokens"
CONF_FILE="$CONF_DIR/softhsm2.conf"

mkdir -p "$TOKENS_DIR"
cat > "$CONF_FILE" <<EOF
directories.tokendir = $(pwd)/$TOKENS_DIR
objectstore.backend = file
log.level = INFO
EOF

export SOFTHSM2_CONF="$(pwd)/$CONF_FILE"

TOKEN_LABEL="open-eidas-tsa-dev-test"
PIN="1234"
SO_PIN="5678"

if softhsm2-util --show-slots --module /usr/lib/softhsm/libsofthsm2.so 2>/dev/null | grep -q "$TOKEN_LABEL"; then
    echo "token '$TOKEN_LABEL' déjà initialisé dans $TOKENS_DIR"
else
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
        --so-pin "$SO_PIN" --pin "$PIN" \
        --module /usr/lib/softhsm/libsofthsm2.so
    echo "token '$TOKEN_LABEL' initialisé dans $TOKENS_DIR"
fi

echo
echo "Pour lancer les tests d'intégration oe-hsm :"
echo "  export SOFTHSM2_CONF=$(pwd)/$CONF_FILE"
echo "  cargo test -p oe-hsm --test pkcs11_integration -- --ignored"
