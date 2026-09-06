# Chart Helm Open eIDAS

Déploie la même pile que le `docker-compose.yml` de démonstration — MariaDB,
une PKI OpenXPKI (racine + CA émettrice, profil TSU dédié), un serveur WebDAV
de réplication du journal d'audit et le service d'horodatage — sur
Kubernetes, pilotable par ArgoCD.

**Comme le docker-compose, ce chart est une démonstration** : hiérarchie de
CA jetable, enrôlement authentifié par secret partagé et auto-approuvé, SoftHSM en lieu d'un HSM
certifié. Voir [docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) pour les
écarts au référentiel eIDAS.

## Installation

```bash
helm install open-eidas deploy/helm/open-eidas --namespace open-eidas --create-namespace
```

L'amorçage complet (récupération de la configuration OpenXPKI, génération de
la hiérarchie de CA, enrôlement de la TSU) prend 1 à 2 minutes. Suivre la
progression :

```bash
kubectl -n open-eidas get pods -w
kubectl -n open-eidas logs deploy/open-eidas-openxpki -c bootstrap -f
```

Vérifier l'horodatage :

```bash
kubectl -n open-eidas port-forward svc/open-eidas-tsa 8318:8318 &
curl -s -X POST http://localhost:8318/api/v1/timestamp \
     -H 'Content-Type: application/json' \
     -d "{\"hash\":\"$(sha256sum facture.pdf | cut -d' ' -f1)\"}"
```

## Déploiement avec ArgoCD

Voir [deploy/argocd/application.yaml](../../argocd/application.yaml).

## Architecture du chart

| Ressource | Rôle |
|---|---|
| `<release>-mariadb` (StatefulSet) | Persistance OpenXPKI (workflows, clés de CA chiffrées) |
| `<release>-openxpki` (Deployment) | Un seul Pod à 4 conteneurs (`server`, `client`, `web`, `bootstrap`) partageant des volumes éphémères — topologie équivalente au docker-compose, sans exiger de PVC `ReadWriteMany` |
| `<release>-audit-replica` (Deployment) | Serveur WebDAV cible de la réplication du journal d'audit |
| `<release>-tsa` (Deployment) | Service d'horodatage, avec PVC pour le token SoftHSM et l'état (certificat, journal d'audit) |
| `<release>-generated` (Secret) | Mots de passe MariaDB, PIN SoftHSM, clé du coffre de données, mot de passe WebDAV, secret HMAC d'enrôlement — générés une fois et stables d'un `helm upgrade` à l'autre (motif `lookup`) |

Rien de ce qui vit dans le Pod `openxpki` n'a besoin de survivre à un
redémarrage : la hiérarchie de CA et ses clés sont stockées chiffrées dans
MariaDB (`config.d/system/crypto.yaml`, `key_store: OPENXPKI`), donc
persistantes indépendamment de ce Pod. Le conteneur `bootstrap` vérifie
l'idempotence en interrogeant OpenXPKI lui-même (`oxi token list`) plutôt que
via un marqueur sur disque, pour rester correct même après une recréation du
Pod postérieure à un premier amorçage réussi.

## Écarts notables avec le docker-compose

Adapter Apache/OpenXPKI au modèle de permissions Kubernetes (uid/gid partagés
entre plusieurs conteneurs d'un même Pod, plutôt que plusieurs conteneurs
Docker indépendants) a demandé quelques ajustements documentés en commentaire
dans `templates/openxpki-deployment.yaml`, en particulier :

- `fsGroup` + `supplementalGroups` remplacent le `group_add` de Docker Compose ;
- le vhost Apache personnalisé (`contrib/apache2-openxpki-site.conf`) est
  recopié explicitement, faute d'équivalent au bind-mount de fichier unique
  utilisé par Docker Compose ;
- le groupe des processus worker Apache est forcé à `openxpki` (au lieu de
  `www-data`) pour qu'ils accèdent au socket Unix du client OpenXPKI, qui
  hérite du groupe partagé du Pod.

## Valeurs principales

Voir `values.yaml` pour la liste complète. Les plus utiles :

| Valeur | Rôle |
|---|---|
| `tsa.image.repository` / `tsa.image.tag` | Image du service d'horodatage |
| `tsa.time.policy` | `enforce`, `monitor` ou `disabled` — passer à `monitor` si le cluster n'a pas de sortie UDP/123 |
| `tsa.ingress.enabled` / `tsa.ingress.host` | Exposition HTTP du service |
| `tsa.pin` / `auditReplica.password` | Valeurs explicites plutôt que générées aléatoirement |
| `mariadb.persistence.size`, `tsa.persistence.*.size`, `auditReplica.persistence.size` | Tailles des volumes persistants |

## Développement local (kind)

```bash
docker build -f deploy/tsa/Dockerfile -t openeidas-tsa:dev .
kind create cluster --name open-eidas
kind load docker-image openeidas-tsa:dev --name open-eidas
helm install open-eidas deploy/helm/open-eidas -n open-eidas --create-namespace \
    --set tsa.image.repository=openeidas-tsa --set tsa.image.tag=dev
```
