# Certificat TSU de test (oe-tsa-core)

`tsu-key.pem` / `tsu-cert.pem` — bi-clé RSA-3072 et certificat auto-signé
générés par `openssl req` (profil `keyUsage=critical,digitalSignature,
nonRepudiation`, `extendedKeyUsage=critical,timeStamping`,
`basicConstraints=critical,CA:FALSE`). Utilisés par les tests de
`crates/oe-tsa-core` (`tests/end_to_end.rs`, tests unitaires de `lib.rs`).

**Pas un secret** : ce matériel n'a d'autre usage que ces tests. Ne jamais le
réutiliser en dehors du dépôt.

Régénérer :

```
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout tests/fixtures/tsa/tsu-key.pem \
  -out tests/fixtures/tsa/tsu-cert.pem \
  -days 7300 \
  -subj "/CN=Open eIDAS Time-Stamping Unit (fixture de test Rust)" \
  -addext "keyUsage=critical,digitalSignature,nonRepudiation" \
  -addext "extendedKeyUsage=critical,timeStamping" \
  -addext "basicConstraints=critical,CA:FALSE"
```
