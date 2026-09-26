# Changelog

## [0.2.0](https://github.com/otspi/open-eidas/compare/v0.1.0...v0.2.0) (2026-09-26)


### Features

* **actions:** actions d'opérateur signées, vérifiées et exécutées par ca-server ([#17](https://github.com/otspi/open-eidas/issues/17)) ([3c28d73](https://github.com/otspi/open-eidas/commit/3c28d73a7b5823ad5fbcd53921efc65bff2357a5))
* **actions:** actions signées sur le registre des opérateurs (invitation, confirmation, révocation, rôle) ([#20](https://github.com/otspi/open-eidas/issues/20)) ([255f06c](https://github.com/otspi/open-eidas/commit/255f06c9376d45eb53316a0fff55079c96f1e612))
* **actions:** amorçage du premier administrateur (ca-server operators bootstrap-admin) ([#18](https://github.com/otspi/open-eidas/issues/18)) ([2c7d29f](https://github.com/otspi/open-eidas/commit/2c7d29ff43a1bd16a32991c58af32d440b375348))
* **actions:** audit de la chaîne du registre des opérateurs (operators audit) ([#25](https://github.com/otspi/open-eidas/issues/25)) ([e78b606](https://github.com/otspi/open-eidas/commit/e78b60659e6169e1b11f15356644707ea6bf07cb))
* **actions:** double contrôle des actions sensibles (quorum de signatures) ([#22](https://github.com/otspi/open-eidas/issues/22)) ([127ceb8](https://github.com/otspi/open-eidas/commit/127ceb85d47cbee2ecd306c18ec5a5875836a01f))
* **actions:** récupération de l'administrateur (recover-admin) et garde du quorum impossible ([#24](https://github.com/otspi/open-eidas/issues/24)) ([b30e8a1](https://github.com/otspi/open-eidas/commit/b30e8a1aa9d089a4e41493ff42c57b8806520d77))
* **actions:** rejeu du journal, blocage du registre divergent et operators reconcile ([#26](https://github.com/otspi/open-eidas/issues/26)) ([1f58888](https://github.com/otspi/open-eidas/commit/1f588885d778ee3fa78bc35e1864dd3c613b6fb9))
* **actions:** révocation de certificat par action signée (revoke_certificate) ([#21](https://github.com/otspi/open-eidas/issues/21)) ([603cf44](https://github.com/otspi/open-eidas/commit/603cf447e615ec2b9e2d441fcb79ee49e5deaf8c))
* **ca-server:** lien interne (routes, mTLS) et enregistrement de clé des opérateurs ([#19](https://github.com/otspi/open-eidas/issues/19)) ([fb1ea95](https://github.com/otspi/open-eidas/commit/fb1ea95e3584430d54e9dc2464f9279df320f66e))
* **ca:** dépôt public des certificats + marquage STAGING du staging ([#10](https://github.com/otspi/open-eidas/issues/10)) ([9329b5f](https://github.com/otspi/open-eidas/commit/9329b5f4389f91ff3b91a17d8f91874f241e87fd))
* **castore:** registre des opérateurs et droits en lecture seule de ra-console ([#15](https://github.com/otspi/open-eidas/issues/15)) ([ea3a702](https://github.com/otspi/open-eidas/commit/ea3a702e86e0685d985b727daa74068b028733c6))
* **deploy:** port interne, ConfigMap et NetworkPolicy de la CA dans le chart Helm ([#23](https://github.com/otspi/open-eidas/issues/23)) ([f0d3ea5](https://github.com/otspi/open-eidas/commit/f0d3ea5853b1f8818dc73794a0392c8d35f9f32e))
* enhance mirror setup script with initial sync for all repos ([b53129c](https://github.com/otspi/open-eidas/commit/b53129c914fadb4bc2c1387af38b3af3c021e41e))
* **oe-ca-core:** journal bloquant avant toute écriture durable ([#42](https://github.com/otspi/open-eidas/issues/42)) ([6d4fe5a](https://github.com/otspi/open-eidas/commit/6d4fe5a5d67848bcd93440fb79e25fa958ca59ad))
* **oe-raflow:** journal bloquant, exception documentée pour Decider::decide ([#45](https://github.com/otspi/open-eidas/issues/45)) ([1a3b496](https://github.com/otspi/open-eidas/commit/1a3b4964f694699e9ca08026da28c2b1d16f085f))
* **oe-s3:** client S3-compatible minimal (SigV4) ([#43](https://github.com/otspi/open-eidas/issues/43)) ([a600350](https://github.com/otspi/open-eidas/commit/a600350b9a392641efc255971789de810ea7146c))
* **oe-tsa-core,oe-timesource:** journal bloquant, deux traits restent synchrones ([#47](https://github.com/otspi/open-eidas/issues/47)) ([4ba7ab0](https://github.com/otspi/open-eidas/commit/4ba7ab02e28926fa520e4ad6c243b1d7f83ca349))
* **provenance:** copie hors poste de l'archive et archivages concurrents ([#48](https://github.com/otspi/open-eidas/issues/48)) ([0a3d834](https://github.com/otspi/open-eidas/commit/0a3d834473b3861d27ce196ebec37f57d18aa8cd))
* **ra-console:** connexion par nom, login/begin et login/finish (1c-1) ([#34](https://github.com/otspi/open-eidas/issues/34)) ([0530043](https://github.com/otspi/open-eidas/commit/0530043550e625d4fc6b2dc403bf86dc29945ee9))
* **ra-console:** journal d'audit propre à la console (2b-A) ([#41](https://github.com/otspi/open-eidas/issues/41)) ([d3b0309](https://github.com/otspi/open-eidas/commit/d3b03091c180e3d166c13f1017b3e5f0aaea12f2))
* **ra-console:** lecture seule de la file d'enrôlement (2a) ([#40](https://github.com/otspi/open-eidas/issues/40)) ([357608e](https://github.com/otspi/open-eidas/commit/357608ed5d52f2af53ca877cc3911db072a7907f))
* **ra-console:** purge périodique des sessions et challenges expirés (1c-2b) ([#39](https://github.com/otspi/open-eidas/issues/39)) ([b451c85](https://github.com/otspi/open-eidas/commit/b451c857a1d16e65640dda2976e3dd837eceb71f))
* **ra-console:** relais de l'enregistrement de clé vers ca-server ([#29](https://github.com/otspi/open-eidas/issues/29)) ([bb8b19f](https://github.com/otspi/open-eidas/commit/bb8b19f458c798038b34e2b9e9a2b10514e476d0))
* **ra-console:** sessions, cookie, /api/v1/me et déconnexion (1c-2a) ([#37](https://github.com/otspi/open-eidas/issues/37)) ([0abcb28](https://github.com/otspi/open-eidas/commit/0abcb2893dba3581f6f30590a69c2303792543ab))
* **ra-console:** squelette de la console (lien mTLS, garde du rôle PostgreSQL, healthz) ([#28](https://github.com/otspi/open-eidas/issues/28)) ([566e04d](https://github.com/otspi/open-eidas/commit/566e04d013a78b5e9b117bf08987902734d1c812))
* **tsa:** CORS configurable pour l'API HTTP, activé pour demo.open-eidas.eu ([#7](https://github.com/otspi/open-eidas/issues/7)) ([2d97c3c](https://github.com/otspi/open-eidas/commit/2d97c3c6ab9e1e668ed2d9ac35d5b9d7d6163cd3))
* **webauthn:** vérification WebAuthn des opérateurs (oe-webauthn) ([#16](https://github.com/otspi/open-eidas/issues/16)) ([d2110d8](https://github.com/otspi/open-eidas/commit/d2110d8d2546010735367e1813a9d7573de3bf34))


### Bug Fixes

* **ca-server:** commandes d'exploitation sans secret de HSM, et garde de CI contre les tests PostgreSQL ignorés ([#27](https://github.com/otspi/open-eidas/issues/27)) ([59bd6fc](https://github.com/otspi/open-eidas/commit/59bd6fcc713fb2fcab918c8bf18d964281f26d85))
* **ca-server:** recover-admin, audit et reconcile sur Config::load_without_hsm ([#33](https://github.com/otspi/open-eidas/issues/33)) ([a50318e](https://github.com/otspi/open-eidas/commit/a50318ed7e1e013700ae7dc686424b923358ba6b))
* **chart:** ajoute fsGroup aux pods ca/tsa/ocsp pour SoftHSM ([cf00ec6](https://github.com/otspi/open-eidas/commit/cf00ec6e39a0768d0aa343248b29c12335d2ae79))
* **chart:** ajoute fsGroup aux pods ca/tsa/ocsp pour SoftHSM ([c4f8a71](https://github.com/otspi/open-eidas/commit/c4f8a719492eac21b1c17cb09b633f71db6af7ed))
* corrige des vulnérabilités HIGH introduites par l'ajout de golang.org/x/crypto/ocsp ([5c5dabc](https://github.com/otspi/open-eidas/commit/5c5dabc8c031a9b61399707372c1d9e2e4cd0f80))
* corrige une vulnérabilité CRITICAL golang.org/x/crypto (CVE-2026-56854) ([91fac96](https://github.com/otspi/open-eidas/commit/91fac96cd40b066e928aa07ed93afb10138baf91))
* **images:** applique les correctifs de sécurité Debian au build ([83b0f72](https://github.com/otspi/open-eidas/commit/83b0f727e4ce84cd61dd6c0aec36c456f85665b4))
* **images:** applique les correctifs de sécurité Debian au build ([e95781c](https://github.com/otspi/open-eidas/commit/e95781c8d4c385dc562f5f06d6429d1529097691))
* **images:** invalide le cache apt-get une fois par jour (CACHEBUST) ([fd40e43](https://github.com/otspi/open-eidas/commit/fd40e43199cb00857c585e25b2b89695fdec5113))
* probes k8s trop strictes + budget d'attente CI insuffisant ([0738b16](https://github.com/otspi/open-eidas/commit/0738b164ef6880986c86d4bbf99f156e2cd8e84d))
* **ra-console:** ne plus lier cryptoki (feature pkcs11 d'oe-hsm) ([#30](https://github.com/otspi/open-eidas/issues/30)) ([9f1f0b9](https://github.com/otspi/open-eidas/commit/9f1f0b9b30566c7d9f58238a0a5128d1fa437ca0))
* **tsa:** numéro de série du jeton en DER minimal (1 jeton sur 512 était rejeté) ([#31](https://github.com/otspi/open-eidas/issues/31)) ([3a9e2e2](https://github.com/otspi/open-eidas/commit/3a9e2e247167f436bbfd2a44e1af6aacb6ca941e))
* **tsa:** restreint vraiment le CORS à l'origine configurée ([#8](https://github.com/otspi/open-eidas/issues/8)) ([5a7acf1](https://github.com/otspi/open-eidas/commit/5a7acf1bd0d1db822eed87dff0728d18eabe2dc9))
* valide la longueur du PIN SoftHSM (4-255) au lieu de bloquer sur une invite ([81decf3](https://github.com/otspi/open-eidas/commit/81decf3a4a520fde5c8ba96430a57c978648c028))
