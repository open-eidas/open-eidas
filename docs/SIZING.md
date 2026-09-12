# Dimensionnement de la pile

Mesures directes du plancher réel de RAM de chaque service, et de CPU pour
`ca-server` (le seul dont l'opération dominante — la cérémonie de clé — est
sensiblement limitée par le CPU), pour que les demandes/limites déclarées
dans `docker-compose.yml` et `deploy/helm/open-eidas/values.yaml` soient des
faits vérifiés plutôt que des estimations. Un service produisant des
signatures cryptographiques pour un tiers de confiance mérite mieux qu'un
chiffre au doigt mouillé.

Les limites CPU de `postgres`, `tsa`, `ocsp-responder` et du réplica
d'audit, elles, ne sont pas issues d'une mesure de plancher de rupture :
faute d'opération CPU-bound comparable à la cérémonie de clé chez ces
services, elles reprennent un ratio raisonnable par rapport à leur RAM
retenue plutôt qu'un chiffre mesuré. `[À COMPLÉTER — mesurer effectivement
ces plancher CPU si une contrainte de capacité concrète l'exige]`

Cohérent avec la mission de l'association (voir README.md) : une
infrastructure aussi frugale que possible réduit le coût d'exploitation, donc
le coût du service rendu.

## Méthode

Chaque service a été isolé (réseau Docker dédié, hors du `docker-compose.yml`
normal) et testé sous contrainte croissante avec `docker run
--memory=<N> --memory-swap=<N> --cpus=<N>`, en observant :

1. l'échec net (`OOMKilled`, code de sortie non nul) — le plancher que rien
   ne doit franchir ;
2. le régime réellement coûteux — pas le service au repos, mais l'opération
   la plus lourde qu'il exécute : la cérémonie de clé pour la CA (deux
   paires RSA-4096), l'enrôlement pour la TSA et le répondeur OCSP (une
   paire RSA-3072 chacun), une salve de requêtes réelles (horodatage,
   réponse OCSP, publication de CRL) une fois en service.

Les valeurs retenues dans la configuration ne sont **pas** les planchers de
rupture : elles portent une marge (typiquement ×2 sur la mémoire) pour
absorber la variabilité d'un hôte de production (bruit voisin, pics de
l'allocateur mémoire sous charge, connexions concurrentes) que ce protocole
de mesure, volontairement isolé, ne reproduit pas.

## Résultats

### PostgreSQL (registre de la CA)

| Test | Résultat |
|---|---|
| 32 Mio | **Échec net** — `OOMKilled` pendant `initdb`, reproductible |
| 40-48 Mio | Démarre et répond, ~20 Mio réellement utilisés |
| 64 Mio (retenu, requête) | Marge confortable |

### `ca-server` — cérémonie de clé (2× RSA-4096 via PKCS#11/SoftHSM)

| Mémoire | Résultat |
|---|---|
| 6 Mio (plancher minimal accepté par Docker lui-même) | **Réussit**, de façon reproductible |

Aucun plancher mémoire n'a pu être atteint dans la plage que Docker autorise.

| CPU | Durée de la cérémonie |
|---|---|
| 1,0 | ~2 s |
| 0,5 | ~3 s |
| 0,25 | ~9 s |
| 0,1 | ~32 s |
| 0,05 | ~41 s |
| 0,02 | **Échec** après ~8 min (délai dépassé ailleurs dans la chaîne) |

Le CPU n'est donc pas un facteur de risque de panne pour la cérémonie, mais
un facteur de **durée** — opération ponctuelle au premier démarrage, pas un
coût récurrent.

### `ca-server` — régime `serve` sous charge réelle d'enrôlement

Une CA en service, recevant une vraie demande d'enrôlement (parsing de CSR,
écritures PostgreSQL, ajout au journal d'audit chaîné) — plus coûteux qu'un
simple `GET /healthz` :

| Mémoire | Résultat |
|---|---|
| 8 Mio | **Instable** — un `OOMKilled` observé sous salve concurrente (rafale de `GET` + enrôlement simultané), mais l'enrôlement seul réussit de façon répétée |
| 9-16 Mio | Stable de façon répétée, y compris sous enrôlement réel |
| 32 Mio (retenu, requête) | Usage observé : 4-5 Mio — large marge |

### `tsa-server` / `ocsp-responder` — enrôlement (1× RSA-3072)

| Mémoire | Résultat |
|---|---|
| 6 Mio (plancher Docker) | **Réussit**, pour les deux services |

### `tsa-server` / `ocsp-responder` — régime `serve` sous charge réelle

Dix horodatages RFC 3161 signés consécutivement (TSA), cinq requêtes OCSP
vérifiées `openssl ocsp` (répondeur) :

| Service | Mémoire testée | Usage observé sous charge |
|---|---|---|
| TSA | 16 Mio | jusqu'à 9,3 Mio |
| Répondeur OCSP | 16 Mio | 3,3 Mio |

Retenu : 32 Mio (TSA) / 24 Mio (OCSP) — marge confortable au-dessus de
l'usage observé.

## Configuration retenue

| Service | Requête CPU | Limite CPU | Requête RAM | Limite RAM |
|---|---|---|---|---|
| `ca` (cérémonie + service) | 100m | 1 | 32Mi | 128Mi |
| `ca` — approbation automatique (démonstration) | 5m | 50m | 16Mi | 64Mi |
| `tsa` | 25m | 250m | 32Mi | 128Mi |
| `ocsp-responder` | 15m | 150m | 24Mi | 96Mi |
| `postgres` | 50m | 500m | 64Mi | 256Mi |
| réplica d'audit (WebDAV) | 10m | 100m | 24Mi | 96Mi |

**Total `docker-compose.yml`** (`ca`, `tsa`, `ocsp-responder`, `postgres`,
réplica d'audit — l'approbation RA y est une boucle dans
`scripts/bootstrap.sh`, pas un conteneur séparé) : ~200m CPU demandés (2,0
CPU en limite), ~176 Mio de RAM demandée (~704 Mio en limite).

**Total chart Helm** (les mêmes, plus le conteneur `ra-autoapprove`) : ~205m
CPU demandés (2,05 CPU en limite), ~192 Mio de RAM demandée (~768 Mio en
limite).

Sur un unique nœud modeste dans les deux cas, là où la pile OpenXPKI
précédente exigeait 4 conteneurs supplémentaires (MariaDB compris) pour un
service fonctionnellement plus restreint (voir
[INDEPENDANCE.md](../INDEPENDANCE.md)).

## Limite de la méthode

Ces mesures isolent un service à la fois : elles ne capturent pas la
contention réelle d'un nœud de production sous charge simultanée de tous les
services, ni le comportement du disque/réseau sous IO concurrentes. Les
marges retenues (généralement ×2 sur la mémoire testée stable) sont un choix
délibérément prudent pour cette raison, pas une tentative de reproduire un
environnement de production. Une observation `docker stats` /
`kubectl top pod` sur un déploiement réel reste la vérification qui fait
foi ; ces chiffres sont un point de départ documenté, pas une garantie.
