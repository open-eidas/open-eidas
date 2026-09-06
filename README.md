# Open eIDAS — l'horodatage qualifié comme infrastructure ouverte

**Une autorité d'horodatage RFC 3161 libre, automatisable et sans rente.**

La dématérialisation est devenue obligatoire en Europe : facturation
électronique, archivage à valeur probante, signature de documents. Chacun de
ces usages a besoin d'une preuve d'antériorité opposable — un jeton
d'horodatage qualifié. Aujourd'hui, cette brique élémentaire se vend au jeton,
derrière des contrats annuels, des portails propriétaires et des délais
d'intégration qui se comptent en semaines. Le même verrou existait pour TLS
avant Let's Encrypt.

Open eIDAS applique le modèle de l'ISRG à l'horodatage : une association à but
non lucratif, une infrastructure auditable, une API publique, un coût
d'intégration nul.

```bash
DIGEST=$(sha256sum facture.pdf | cut -d' ' -f1)

curl -s -X POST http://localhost:8318/api/v1/timestamp \
     -H 'Content-Type: application/json' \
     -d "{\"hash\":\"$DIGEST\"}"
```

Voilà l'intégration complète. Pas de compte, pas de SDK, pas de bon de
commande.

---

## Ce que fait ce dépôt

Un prototype **fonctionnel et vérifiable** de la pile technique cible :

- un service d'horodatage **RFC 3161** écrit en Go, dont la clé de signature
  ne quitte jamais un module cryptographique (**PKCS#11**) ;
- une **PKI OpenXPKI** complète — racine, CA émettrice, profil de certificat
  contraint à `id-kp-timeStamping` — qui délivre le certificat de l'unité
  d'horodatage par enrôlement automatisé ;
- un **HSM logiciel SoftHSM2** parlant le protocole d'un HSM certifié, pour que
  le passage en production soit un changement de configuration, pas de code ;
- le tout orchestré en `docker compose`, démarrable en une commande.

Ce n'est pas encore une TSA qualifiée : les écarts avec le référentiel eIDAS
sont listés explicitement dans
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#6-écarts-assumés-du-prototype-vis-à-vis-dune-tsa-qualifiée)
— source de temps, HSM certifié, journal d'audit, audit d'un organisme
accrédité. Le chiffrage de ce chemin est connu : **70 à 95 k€** pour
l'infrastructure et l'audit initial.

## Démarrage

Prérequis : Docker avec le plugin Compose, `git`, `openssl`, `curl`.

```bash
git clone https://github.com/open-eidas/open-eidas.git
cd open-eidas

make up      # amorce la PKI, émet le certificat TSU, démarre la TSA
make demo    # horodate un fichier et vérifie le jeton avec openssl ts
```

`make up` est idempotent et prend quelques minutes au premier lancement : il
récupère la configuration OpenXPKI amont, génère une hiérarchie de CA de test,
crée la bi-clé RSA-3072 dans le token SoftHSM, puis obtient le certificat de
l'unité d'horodatage via l'endpoint RPC de la PKI.

### Vérifier un jeton avec les outils standards

```bash
openssl ts -query -data facture.pdf -sha256 -cert -out facture.tsq

curl -s -H 'Content-Type: application/timestamp-query' \
     --data-binary @facture.tsq http://localhost:8318/tsa -o facture.tsr

curl -s http://localhost:8318/api/v1/certificate -o tsa-chain.pem
awk '/BEGIN CERTIFICATE/{n++} {print > (n == 1 ? "tsu.pem" : "ca.pem")}' tsa-chain.pem

openssl ts -verify -in facture.tsr -queryfile facture.tsq -CAfile ca.pem
```

L'interface d'administration de la PKI est disponible sur
<https://localhost:8443/webui/> (certificat auto-signé).

Autres cibles : `make test`, `make lint`, `make logs`, `make down`,
`make purge`.

## Documentation

- [Architecture technique](docs/ARCHITECTURE.md) — choix de conception,
  séquence de démarrage, écarts au référentiel, trajectoire de qualification.
- [Référence de l'API](docs/API.md) — endpoints, codes d'erreur RFC 3161,
  variables de configuration.

## Structure du dépôt

```
cmd/tsa-server/      point d'entrée : sous-commandes enroll et serve
internal/tsa/        cœur RFC 3161 : validation, TSTInfo, CMS SignedData
internal/hsm/        accès PKCS#11 à la clé de signature
internal/enroll/     client RPC d'enrôlement OpenXPKI
internal/httpapi/    endpoints HTTP (RFC 3161 + façade JSON)
deploy/tsa/          image du service
deploy/openxpki/     overlay de configuration de la PKI (profil TSU, RPC)
scripts/             amorçage et démonstration
```

## Modèle

Association à but non lucratif, financée par mécénat d'acteurs de la
souveraineté numérique. Service gratuit ou à prix coûtant, sans quota
commercial. Code, politique d'horodatage et rapports d'audit publics.

## Contribuer

Les contributions sont bienvenues, en particulier sur la source de temps
traçable, l'intégration de HSM certifiés, le journal d'audit inaltérable et la
conformité ETSI EN 319 421 / 319 422.

## Licence

Apache 2.0 — voir [LICENSE](LICENSE).
