# Changelog

## [0.2.0](https://github.com/open-eidas/open-eidas/compare/v0.1.0...v0.2.0) (2026-09-13)


### Features

* enhance mirror setup script with initial sync for all repos ([b53129c](https://github.com/open-eidas/open-eidas/commit/b53129c914fadb4bc2c1387af38b3af3c021e41e))
* **tsa:** CORS configurable pour l'API HTTP, activé pour demo.open-eidas.eu ([#7](https://github.com/open-eidas/open-eidas/issues/7)) ([2d97c3c](https://github.com/open-eidas/open-eidas/commit/2d97c3c6ab9e1e668ed2d9ac35d5b9d7d6163cd3))


### Bug Fixes

* **chart:** ajoute fsGroup aux pods ca/tsa/ocsp pour SoftHSM ([cf00ec6](https://github.com/open-eidas/open-eidas/commit/cf00ec6e39a0768d0aa343248b29c12335d2ae79))
* **chart:** ajoute fsGroup aux pods ca/tsa/ocsp pour SoftHSM ([c4f8a71](https://github.com/open-eidas/open-eidas/commit/c4f8a719492eac21b1c17cb09b633f71db6af7ed))
* corrige des vulnérabilités HIGH introduites par l'ajout de golang.org/x/crypto/ocsp ([5c5dabc](https://github.com/open-eidas/open-eidas/commit/5c5dabc8c031a9b61399707372c1d9e2e4cd0f80))
* corrige une vulnérabilité CRITICAL golang.org/x/crypto (CVE-2026-56854) ([91fac96](https://github.com/open-eidas/open-eidas/commit/91fac96cd40b066e928aa07ed93afb10138baf91))
* **images:** applique les correctifs de sécurité Debian au build ([83b0f72](https://github.com/open-eidas/open-eidas/commit/83b0f727e4ce84cd61dd6c0aec36c456f85665b4))
* **images:** applique les correctifs de sécurité Debian au build ([e95781c](https://github.com/open-eidas/open-eidas/commit/e95781c8d4c385dc562f5f06d6429d1529097691))
* **images:** invalide le cache apt-get une fois par jour (CACHEBUST) ([fd40e43](https://github.com/open-eidas/open-eidas/commit/fd40e43199cb00857c585e25b2b89695fdec5113))
* probes k8s trop strictes + budget d'attente CI insuffisant ([0738b16](https://github.com/open-eidas/open-eidas/commit/0738b164ef6880986c86d4bbf99f156e2cd8e84d))
* valide la longueur du PIN SoftHSM (4-255) au lieu de bloquer sur une invite ([81decf3](https://github.com/open-eidas/open-eidas/commit/81decf3a4a520fde5c8ba96430a57c978648c028))
