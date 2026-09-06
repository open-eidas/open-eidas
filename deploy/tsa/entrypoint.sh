#!/bin/sh
# Prépare le token PKCS#11 puis enrôle la TSU avant de servir l'horodatage.
set -eu

: "${OPENEIDAS_TOKEN_LABEL:=open-eidas-tsa}"
: "${OPENEIDAS_PIN:?OPENEIDAS_PIN est obligatoire}"
: "${OPENEIDAS_SO_PIN:=${OPENEIDAS_PIN}}"

if ! softhsm2-util --show-slots | grep -q "Label: *${OPENEIDAS_TOKEN_LABEL}"; then
    echo "initialisation du token SoftHSM ${OPENEIDAS_TOKEN_LABEL}"
    softhsm2-util --init-token --free \
        --label "${OPENEIDAS_TOKEN_LABEL}" \
        --pin "${OPENEIDAS_PIN}" \
        --so-pin "${OPENEIDAS_SO_PIN}"
fi

if [ "${1:-serve}" = "serve" ] && [ -n "${OPENEIDAS_ENROLL_ENDPOINT:-}" ]; then
    # La PKI met un certain temps à devenir disponible au premier démarrage :
    # on réessaie tant qu'elle n'a pas délivré le certificat de la TSU.
    attempt=1
    until tsa-server enroll; do
        if [ "${attempt}" -ge "${OPENEIDAS_ENROLL_ATTEMPTS:-60}" ]; then
            echo "abandon : la PKI n'a pas délivré de certificat après ${attempt} tentatives" >&2
            exit 1
        fi
        echo "enrôlement impossible (tentative ${attempt}), nouvel essai dans 10 s"
        attempt=$((attempt + 1))
        sleep 10
    done
fi

exec tsa-server "$@"
