# Open eIDAS — Les services de confiance eIDAS comme infrastructure ouverte

**Démocratiser la confiance numérique eIDAS dans toute l'économie, de façon sûre, ouverte et sans rente.**

Le règlement européen eIDAS a posé le cadre juridique de la confiance numérique : horodatage qualifié, signature et cachet électroniques, archivage à valeur probante, envoi recommandé et portefeuilles d'identité numérique (eIDAS 2.0 / EUDI).

Pourtant, dans la pratique économique, ces briques indispensables restent captives d'un modèle de rente oligopolistique :
- **Facturation au jeton ou à l'acte**, transformant des obligations légales (facturation électronique obligatoire B2B, archivage légal, contractualisation dématérialisée) en péage privé récurrent ;
- **Friction technique et contractuelle majeure** : portails fermés, SDK propriétaires, délais d'intégration qui se comptent en semaines ;
- **Fracture pour l'économie réelle** : là où de grands groupes négocient des volumes, les TPE/PME, éditeurs indépendants et administrations de proximité sont freinés ou contraints de bricoler sans garanties de conformité.

Le même verrou existait pour le chiffrement web avant Let's Encrypt.

**Open eIDAS applique le modèle de l'ISRG à l'écosystème eIDAS** : une gouvernance d'intérêt général à but non lucratif, une infrastructure cryptographique souveraine et auditable, des API ouvertes et standardisées, et un coût d'accès nul ou à prix coûtant. Notre mission est de démocratiser eIDAS dans l'économie de manière rigoureuse et pérenne — sans compromis sur la sécurité.

---

## Notre premier service : l'horodatage qualifié (RFC 3161)

Pour bâtir un édifice de confiance, il faut d'abord maîtriser le temps. L'**horodatage qualifié** est le premier service développé par Open eIDAS : il constitue le socle d'antériorité et d'intégrité temporelle universel, nécessaire à la signature électronique (validité à long terme LTA), au cachet d'entreprise, à la facturation électronique et à l'archivage à valeur probante.

Là où le marché impose des barrières contractuelles, l'intégration Open eIDAS est immédiate :

```bash
DIGEST=$(sha256sum facture.pdf | cut -d' ' -f1)

curl -s -X POST http://localhost:8318/api/v1/timestamp \
     -H 'Content-Type: application/json' \
     -d "{\"hash\":\"$DIGEST\"}"
```

Voilà l'intégration complète. Pas de compte, pas de SDK propriétaire, pas de bon de commande.

La feuille de route d'Open eIDAS étendra progressivement ce socle aux autres services de confiance essentiels : **cachet électronique de personne morale (seal)** automatisable, **validation de signatures qualifiées**, et passerelles d'attestation conformes à eIDAS 2.

---

## Ce que fait ce dépôt

Ce dépôt héberge le prototype **fonctionnel et vérifiable** du premier service Open eIDAS — l'autorité d'horodatage (TSA) :

- un service d'horodatage **RFC 3161** écrit en Go, dont la clé de signature
  ne quitte jamais un module cryptographique (**PKCS#11**) ;
- une **PKI OpenXPKI** complète — racine, CA émettrice, profil de certificat
  contraint à `id-kp-timeStamping` — qui délivre le certificat de l'unité
  d'horodatage par enrôlement automatisé ;
- un **HSM logiciel SoftHSM2** parlant le protocole d'un HSM certifié, pour que
  le passage en production soit un changement de configuration, pas de code ;
- une **heure traçable jusqu'à UTC** : le service recoupe deux serveurs de
  laboratoires de métrologie (Observatoire de Paris, PTB) et **cesse d'émettre**
  dès que la dérive dépasse le seuil annoncé, comme l'exige ETSI EN 319 421 ;
- un **journal d'audit chaîné par hachage, contresigné par des TSA tierces
  publiques** (FreeTSA.org, DigiCert) : chaque scellement se vérifie avec les
  outils RFC 3161 standards, sans dépendre de la confiance en Open eIDAS ;
- le tout orchestré en `docker compose`, démarrable en une commande.

Ce n'est pas encore une TSA qualifiée : les écarts avec le référentiel eIDAS
sont listés explicitement dans
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#8-écarts-assumés-du-prototype-vis-à-vis-dune-tsa-qualifiée)
— HSM certifié, réplication du journal hors site, redondance, audit d'un
organisme accrédité. Le chiffrage de ce chemin est connu : **70 à 95 k€** pour
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

### Relire le journal d'audit

```bash
docker compose exec tsa tsa-server verify-audit
```

Autres cibles : `make test`, `make lint`, `make audit`, `make logs`,
`make down`, `make purge`.

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
internal/timesource/ surveillance de la traçabilité de l'heure
internal/audit/      journal d'audit chaîné par hachage
internal/crosstsa/   contreseing du journal par des TSA tierces publiques
internal/enroll/     client RPC d'enrôlement OpenXPKI
internal/httpapi/    endpoints HTTP (RFC 3161 + façade JSON)
deploy/tsa/          image du service
deploy/openxpki/     overlay de configuration de la PKI (profil TSU, RPC)
scripts/             amorçage et démonstration
```

## Modèle & Sûreté

- **Gouvernance non lucrative d'intérêt général** : association financée par le mécénat et le soutien d'acteurs de la souveraineté numérique. Service gratuit ou à prix coûtant, sans quota commercial ni rente monopolistique.
- **Sûreté intransigeante** : aucun compromis sur la sécurité. L'architecture est conçue pour satisfaire rigoureusement les normes ETSI (EN 319 421, EN 319 422, etc.) et les exigences de qualification eIDAS / ANSSI.
- **Transparence intégrale** : code source libre, politiques de service publiques, traçabilité métrologique documentée et rapports d'audit tiers publiés.

## Contribuer

Les contributions sont bienvenues, en particulier sur l'intégration de HSM
certifiés, le journal d'audit inaltérable, la redondance du service, la
conformité ETSI EN 319 421 / 319 422 et le développement des futurs services de confiance.

## Licence

GNU Affero General Public License v3.0 (AGPLv3) — voir [LICENSE](LICENSE).

L'AGPL garantit que toute amélioration apportée à cette infrastructure de confiance partagée reste un bien commun ouvert à tous, y compris lorsqu'elle est opérée en tant que service réseau.
