# Chart Helm Open eIDAS

Déploie la même pile que le `docker-compose.yml` de démonstration —
PostgreSQL, l'autorité de certification maison (racine + CA émettrice,
`cmd/ca-server`), un serveur WebDAV de réplication du journal d'audit, le
répondeur OCSP et le service d'horodatage — sur Kubernetes, pilotable par
ArgoCD.

**Comme le docker-compose, ce chart est une démonstration** : cérémonie de
clé sans double contrôle ni témoin, approbation RA automatisée sous un compte
technique, SoftHSM en lieu d'un HSM certifié. L'état exigence par exigence
est dans [docs/CONFORMITE-ETSI.md](../../../docs/CONFORMITE-ETSI.md) ; les
écarts au référentiel eIDAS dans
[docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md).

## Installation

```bash
helm install open-eidas deploy/helm/open-eidas --namespace open-eidas --create-namespace
```

L'amorçage complet (cérémonie de clé, publication de la première CRL,
enrôlement puis approbation de la TSU et du répondeur OCSP) prend 1 à 2
minutes — l'essentiel étant la génération de deux bi-clés RSA-4096 dans
SoftHSM. Suivre la progression :

```bash
kubectl -n open-eidas get pods -w
kubectl -n open-eidas logs deploy/open-eidas-ca -c ca -f
kubectl -n open-eidas logs deploy/open-eidas-ca -c ra-autoapprove -f
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

## Déploiement public de démonstration (staging)

Guide détaillé pas-à-pas : [docs/STAGING.md](../../../docs/STAGING.md).

`values-staging.yaml` expose la TSA sur `staging-api.open-eidas.eu` et la
publication de la CA (CRL, certificat de la CA émettrice) sur
`staging-pki.open-eidas.eu`, avec un certificat TLS public géré par
cert-manager/Let's Encrypt. L'API d'enrôlement, elle, n'est jamais exposée :
seuls les services du cluster s'y adressent.

Préalables sur le cluster cible (à provisionner séparément, non gérés par ce
chart) :

1. Un ingress controller exposé publiquement, par exemple :
   ```bash
   helm install ingress-nginx ingress-nginx \
       --repo https://kubernetes.github.io/ingress-nginx \
       --namespace ingress-nginx --create-namespace
   ```
2. [cert-manager](https://cert-manager.io/docs/installation/), puis le
   `ClusterIssuer` Let's Encrypt :
   ```bash
   kubectl apply -f deploy/cert-manager/cluster-issuer-letsencrypt.yaml
   ```
   (adapter l'e-mail de contact du `ClusterIssuer` avant application).
3. Deux enregistrements DNS pointant vers l'adresse publique de l'ingress
   controller (`kubectl -n ingress-nginx get svc ingress-nginx-controller`) :
   `staging-api.open-eidas.eu` et `staging-pki.open-eidas.eu`. Le défi
   HTTP-01 de Let's Encrypt exige que ces noms résolvent déjà vers l'ingress
   avant la première émission de certificat.

Puis, soit en `helm install` direct :

```bash
helm install open-eidas deploy/helm/open-eidas \
    --namespace open-eidas-staging --create-namespace \
    -f deploy/helm/open-eidas/values-staging.yaml
```

soit via ArgoCD : [deploy/argocd/application-staging.yaml](../../argocd/application-staging.yaml).

La première émission de certificat TLS par cert-manager peut prendre
quelques minutes après que l'ingress soit joignable ; suivre avec
`kubectl -n open-eidas-staging get certificate,challenge`.

## Architecture du chart

| Ressource | Rôle |
|---|---|
| `<release>-postgres` (StatefulSet) | Registre de la CA : autorités, certificats émis, demandes d'enrôlement, historique des CRL |
| `<release>-ca` (Deployment) | Autorité de certification et d'enregistrement. Deux conteneurs : `ca` (cérémonie, émission, publication de la CRL) et `ra-autoapprove` (approbation automatique — voir ci-dessous). PVC pour ses deux tokens SoftHSM et son journal d'audit |
| `<release>-audit-replica` (Deployment) | Serveur WebDAV cible de la réplication du journal d'audit |
| `<release>-tsa` (Deployment) | Service d'horodatage, avec PVC pour le token SoftHSM et l'état (certificat, journal d'audit) |
| `<release>-ocsp` (Deployment) | Répondeur OCSP (RFC 6960) pour la CA émettrice — PVC dédié pour son propre token SoftHSM et son état |
| `<release>-generated` (Secret) | Mot de passe PostgreSQL, PIN SoftHSM (un par token : TSU, OCSP, racine, émettrice), mot de passe WebDAV, secret HMAC d'enrôlement — générés une fois et stables d'un `helm upgrade` à l'autre (motif `lookup`) |

Le Pod `ca` est le seul à détenir les clés d'autorité, et il n'a qu'un
réplica : les tokens PKCS#11 et le journal d'audit chaîné vivent sur des
volumes `ReadWriteOnce`, et la clé d'une CA n'a pas vocation à être répliquée.
La cérémonie de clé est idempotente et rejouée à chaque démarrage : elle relit
la hiérarchie enregistrée plutôt que d'en créer une seconde, et refuse de
démarrer si la clé d'un token ne correspond plus au certificat enregistré.

## Approbation RA — écart assumé

Le conteneur `ra-autoapprove` approuve les demandes d'enrôlement sous
l'identité `ca.autoApprove.operator` (`ci-bootstrap` par défaut), afin que la
démonstration et la CI s'amorcent sans opérateur humain.

Ce n'est **pas** un contournement du point d'approbation : aucun chemin du
code ne mène à l'émission sans décision identifiée (voir `internal/raflow`),
et cette identité technique figure telle quelle au journal d'audit — l'écart
est donc visible d'un auditeur, pas masqué. Le conteneur ne monte d'ailleurs
aucun token PKCS#11 : approuver, c'est décider, pas signer.

Un déploiement destiné à la qualification pose :

```yaml
ca:
  autoApprove:
    enabled: false
```

et approuve à la main, sous une identité nominative :

```bash
kubectl -n open-eidas exec deploy/open-eidas-ca -c ca -- ca-server ra list PENDING
kubectl -n open-eidas exec deploy/open-eidas-ca -c ca -- \
    ca-server ra approve <transaction_id> "prenom.nom" "identité vérifiée le ..."
```

## Écarts notables avec le docker-compose

Aucun, désormais, sur le plan des permissions : le remplacement d'OpenXPKI par
`cmd/ca-server` a fait disparaître le Pod à quatre conteneurs et les
contournements qu'il imposait (`fsGroup` et `supplementalGroups` partagés,
vhost Apache recopié faute d'équivalent au bind-mount de fichier unique,
groupe des workers Apache forcé pour atteindre un socket Unix). Les trois
services sont des binaires Go qui écoutent en HTTP et n'ont besoin d'aucun
partage de socket entre conteneurs.

Reste une différence de forme : l'approbation automatique des demandes est un
conteneur permanent ici, une boucle dans `scripts/bootstrap.sh` en
docker-compose.

## Valeurs principales

Voir `values.yaml` pour la liste complète. Les plus utiles :

| Valeur | Rôle |
|---|---|
| `tsa.image.repository` / `tsa.image.tag` | Image du service d'horodatage |
| `tsa.time.policy` | `enforce`, `monitor` ou `disabled` — passer à `monitor` si le cluster n'a pas de sortie UDP/123 |
| `tsa.ingress.enabled` / `tsa.ingress.host` | Exposition HTTP du service |
| `tsa.pin` / `ocsp.pin` / `auditReplica.password` | Valeurs explicites plutôt que générées aléatoirement |
| `ca.publicURL` / `ca.ingress.enabled` / `ca.ingress.host` | Adresse publique gravée dans les points CRL et AIA des certificats émis — à fixer si les certificats seront vérifiés par des tiers hors du cluster |
| `ca.autoApprove.enabled` / `ca.autoApprove.operator` | Approbation RA automatique (voir ci-dessus) |
| `ca.keyBits`, `ca.rootCommonName`, `ca.issuingCommonName` | Paramètres de la cérémonie de clé — sans effet une fois la hiérarchie créée |
| `ca.crl.validity` / `ca.crl.refresh` | Fenêtre de validité des CRL et fréquence de republication |
| `ca.audit.retention` | Durée de conservation du journal (ETSI EN 319 401 §7.10) ; le service refuse de démarrer en deçà d'un an |
| `ocsp.publicURL` / `ocsp.ingress.enabled` / `ocsp.ingress.host` | Adresse publique gravée dans l'extension AIA du certificat TSU, et son exposition HTTP |
| `postgres.persistence.size`, `tsa.persistence.*.size`, `ocsp.persistence.*.size`, `auditReplica.persistence.size` | Tailles des volumes persistants |

## Développement local (kind)

```bash
docker build -f deploy/ca-server/Dockerfile -t openeidas-ca:dev .
docker build -f deploy/tsa/Dockerfile -t openeidas-tsa:dev .
docker build -f deploy/ocsp-responder/Dockerfile -t openeidas-ocsp-responder:dev .
kind create cluster --name open-eidas
for image in openeidas-ca openeidas-tsa openeidas-ocsp-responder; do
    kind load docker-image "$image:dev" --name open-eidas
done
helm install open-eidas deploy/helm/open-eidas -n open-eidas --create-namespace \
    --set ca.image.repository=openeidas-ca --set ca.image.tag=dev \
    --set tsa.image.repository=openeidas-tsa --set tsa.image.tag=dev \
    --set ocsp.image.repository=openeidas-ocsp-responder --set ocsp.image.tag=dev
```
