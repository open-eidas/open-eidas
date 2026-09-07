#!/usr/bin/env bash
# Démonstration de bout en bout : horodatage d'un fichier puis vérification
# cryptographique du jeton avec l'outil openssl ts.
set -euo pipefail

TSA_URL="${TSA_URL:-http://localhost:8318}"
OCSP_URL="${OCSP_URL:-http://localhost:8319/ocsp}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

log() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cd "$WORKDIR"
echo "Facture électronique de démonstration — $(date -Is)" > facture.txt

log "1. Politique publiée par la TSA"
curl -fsS "$TSA_URL/api/v1/policy"
echo

log "2. Horodatage via l'API JSON (une seule commande curl)"
DIGEST="$(sha256sum facture.txt | cut -d' ' -f1)"
curl -fsS -X POST "$TSA_URL/api/v1/timestamp" \
    -H 'Content-Type: application/json' \
    -d "{\"hash\":\"${DIGEST}\",\"algorithm\":\"sha256\",\"nonce\":true}"
echo

log "3. Horodatage via le protocole RFC 3161 natif"
openssl ts -query -data facture.txt -sha256 -cert -out facture.tsq
curl -fsS -H 'Content-Type: application/timestamp-query' \
    --data-binary @facture.tsq "$TSA_URL/tsa" -o facture.tsr

log "4. Contenu du jeton d'horodatage"
openssl ts -reply -in facture.tsr -text | sed -n '1,20p'

log "5. Vérification cryptographique contre la chaîne de la TSA"
curl -fsS "$TSA_URL/api/v1/certificate" -o tsa-chain.pem
# Le premier bloc PEM est le certificat de la TSU, les suivants sa chaîne
# d'émission : seule cette dernière sert d'ancre de confiance.
awk '/BEGIN CERTIFICATE/{n++} {print > (n == 1 ? "tsu.pem" : "ca.pem")}' tsa-chain.pem
if openssl ts -verify -in facture.tsr -queryfile facture.tsq -CAfile ca.pem 2>&1; then
    echo
    printf '\033[1;32mJeton vérifié : le fichier existait bien à la date attestée.\033[0m\n'
else
    echo
    echo "La vérification a échoué : la chaîne de confiance n'est pas complète." >&2
    exit 1
fi

log "6. Statut de révocation du certificat TSU (OCSP, RFC 6960)"
if openssl ocsp -issuer ca.pem -cert tsu.pem -CAfile ca.pem -no_nonce \
    -url "$OCSP_URL" -resp_text 2>&1 | tee ocsp-response.txt | grep -q "tsu.pem: good"; then
    echo
    printf '\033[1;32mCertificat TSU non révoqué, attesté par le répondeur OCSP.\033[0m\n'
else
    echo
    cat ocsp-response.txt >&2
    echo "La vérification OCSP a échoué." >&2
    exit 1
fi
