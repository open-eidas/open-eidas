#!/bin/sh
# Prépare les deux tokens PKCS#11 de la hiérarchie (racine et CA émettrice),
# exécute la cérémonie de clé — idempotente — puis démarre le service.
#
# Deux tokens et non un seul : la racine ne signe que la CA émettrice. En
# production, ils sont portés par deux modules distincts, sous deux contrôles
# distincts, et seule l'émettrice reste accessible au service en
# fonctionnement (voir docs/CA.md).
set -eu

: "${OPENEIDAS_ROOT_TOKEN_LABEL:=open-eidas-root}"
: "${OPENEIDAS_ISSUING_TOKEN_LABEL:=open-eidas-issuing}"
: "${OPENEIDAS_ISSUING_PIN:?OPENEIDAS_ISSUING_PIN est obligatoire}"
: "${OPENEIDAS_ROOT_PIN:=${OPENEIDAS_ISSUING_PIN}}"

init_token() {
    label="$1"
    pin="$2"
    # SoftHSM refuse silencieusement un PIN hors de cette plage et se rabat sur
    # une invite interactive, ce qui bloquerait le conteneur sans message clair.
    len=${#pin}
    if [ "$len" -lt 4 ] || [ "$len" -gt 255 ]; then
        echo "le PIN du token ${label} doit contenir entre 4 et 255 caractères (SoftHSM)" >&2
        exit 1
    fi
    if ! softhsm2-util --show-slots | grep -q "Label: *${label}"; then
        echo "initialisation du token SoftHSM ${label}"
        softhsm2-util --init-token --free --label "${label}" \
            --pin "${pin}" --so-pin "${pin}"
    fi
}

init_token "${OPENEIDAS_ROOT_TOKEN_LABEL}" "${OPENEIDAS_ROOT_PIN}"
init_token "${OPENEIDAS_ISSUING_TOKEN_LABEL}" "${OPENEIDAS_ISSUING_PIN}"

if [ "${1:-serve}" = "serve" ]; then
    # PostgreSQL peut mettre un moment à accepter des connexions au premier
    # démarrage : la cérémonie est réessayée, et reste sans effet une fois la
    # hiérarchie créée.
    attempt=1
    until ca-server ceremony; do
        if [ "${attempt}" -ge "${OPENEIDAS_CEREMONY_ATTEMPTS:-30}" ]; then
            echo "abandon : la cérémonie de clé a échoué après ${attempt} tentatives" >&2
            exit 1
        fi
        echo "cérémonie impossible (tentative ${attempt}), nouvel essai dans 5 s"
        attempt=$((attempt + 1))
        sleep 5
    done
fi

exec ca-server "$@"
