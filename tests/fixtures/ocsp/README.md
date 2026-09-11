# Fixtures OCSP (oe-ocsp-core)

Matériel de test pour `crates/oe-ocsp-core/tests/against_real_crl.rs`. **Pas
des secrets** : aucun usage en dehors de ces tests.

- `issuer-key.pem` / `issuer-cert.pem` — CA auto-signée de test (RSA-3072).
- `responder-key.pem` / `responder-cert.pem` — certificat de signature OCSP
  (`extendedKeyUsage=OCSPSigning`, `id-pkix-ocsp-nocheck`), émis par la CA
  ci-dessus.
- `issuer.crl.der` — CRL réelle signée par la CA, générée via `openssl ca`,
  contenant un certificat révoqué (motif `keyCompromise`).
- `request-good.der` / `request-revoked.der` — vraies requêtes OCSP DER
  produites par `openssl ocsp -issuer ... -cert ...` pour un certificat sain
  et un certificat révoqué émis par cette même CA.

Régénéré via une CA `openssl ca` classique (répertoire `newcerts`/`index.txt`)
puis `openssl ocsp -reqout` — voir l'historique de commit introduisant ces
fichiers pour la séquence exacte de commandes.
