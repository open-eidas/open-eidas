# Déploiement de staging public

Guide pas-à-pas pour mettre en ligne la démonstration Open eIDAS sur
`staging-api.open-eidas.eu` (TSA) et `staging-pki.open-eidas.eu` (PKI —
interface, CRL, AIA), à partir d'un cluster Kubernetes managé vierge.

Ce guide part du principe que le cluster est déjà créé et que `kubectl` y
est configuré (`kubectl cluster-info` répond) — la création du cluster
lui-même (console web de l'hébergeur, facturation, choix de région) est
spécifique à chaque fournisseur et reste à faire séparément. Tout ce qui
suit est générique à n'importe quel Kubernetes managé (Scaleway Kapsule,
OVHcloud Managed Kubernetes, DigitalOcean, etc.) ou à un `k3s` sur VM.

**Dimensionnement recommandé pour cet usage (démonstration, pas de charge
réelle)** : un unique nœud, 2 vCPU / 4 Go de RAM suffisent largement (la
pile complète — PostgreSQL, autorité de certification, TSA, répondeur OCSP,
réplica d'audit — représente au
total moins de 2 Go de limites mémoire cumulées, voir `values.yaml`).

## 0. Outils requis en local

- `kubectl` configuré sur le cluster cible (`kubectl config current-context`
  doit pointer dessus)
- `helm` (v3)
- Optionnel : `argocd` CLI, si vous préférez piloter le déploiement via
  ArgoCD plutôt qu'en `helm install` direct

## 1. Installer un ingress controller

Expose les services du cluster sur une adresse IP publique. `ingress-nginx`
est le plus répandu et celui déjà référencé par
`deploy/helm/open-eidas/values-staging.yaml` (`ingressClassName: nginx`) :

```bash
helm install ingress-nginx ingress-nginx \
    --repo https://kubernetes.github.io/ingress-nginx \
    --namespace ingress-nginx --create-namespace
```

Attendre qu'une adresse IP externe soit attribuée (peut prendre 1 à 2
minutes selon l'hébergeur) :

```bash
kubectl -n ingress-nginx get svc ingress-nginx-controller -w
```

Noter l'`EXTERNAL-IP` affichée (Ctrl+C une fois qu'elle n'est plus
`<pending>`) — c'est l'adresse à utiliser à l'étape 3.

## 2. Installer cert-manager

Gère automatiquement l'émission et le renouvellement des certificats TLS
publics via Let's Encrypt :

```bash
helm install cert-manager cert-manager \
    --repo https://charts.jetstack.io \
    --namespace cert-manager --create-namespace \
    --set crds.enabled=true
```

Vérifier que les 3 pods du contrôleur sont `Running` :

```bash
kubectl -n cert-manager get pods
```

## 3. Configurer le DNS

Créer trois enregistrements DNS (A si `EXTERNAL-IP` est une IPv4, CNAME si
l'hébergeur fournit un nom d'hôte de load-balancer) pointant vers l'adresse
notée à l'étape 1 :

| Nom | Cible |
|---|---|
| `staging-api.open-eidas.eu` | `EXTERNAL-IP` de l'étape 1 |
| `staging-pki.open-eidas.eu` | `EXTERNAL-IP` de l'étape 1 |
| `staging-ocsp.open-eidas.eu` | `EXTERNAL-IP` de l'étape 1 |

Vérifier la propagation avant de continuer (le défi HTTP-01 de Let's
Encrypt à l'étape 5 échouera tant que ce n'est pas résolu) :

```bash
dig +short staging-api.open-eidas.eu
dig +short staging-pki.open-eidas.eu
dig +short staging-ocsp.open-eidas.eu
```

## 4. Appliquer le ClusterIssuer Let's Encrypt

Ouvrir `deploy/cert-manager/cluster-issuer-letsencrypt.yaml` et adapter le
champ `email` (adresse recevant les notifications d'expiration de
certificat), puis :

```bash
kubectl apply -f deploy/cert-manager/cluster-issuer-letsencrypt.yaml
kubectl get clusterissuer letsencrypt-prod
# READY doit passer à True après quelques secondes
```

## 5. Déployer Open eIDAS

Deux options équivalentes :

**Option A — `helm install` direct :**

```bash
helm install open-eidas deploy/helm/open-eidas \
    --namespace open-eidas-staging --create-namespace \
    -f deploy/helm/open-eidas/values-staging.yaml
```

**Option B — ArgoCD** (si déjà installé sur le cluster) :

Appliquer une fois `root-app.yaml` du dépôt
[open-eidas/deploy](https://github.com/open-eidas/deploy) (motif
app-of-apps) :

```bash
kubectl apply -f root-app.yaml
```

ArgoCD crée alors l'Application `open-eidas-staging` (définie dans
`apps/open-eidas-staging.yaml` de ce même dépôt) et synchronise
automatiquement tout changement fusionné dans `deploy/helm/open-eidas/` sur
`main`.

## 6. Suivre l'amorçage

Compter 1 à 3 minutes pour l'amorçage complet — cérémonie de clé, première
CRL, puis enrôlement et approbation de la TSU et du répondeur OCSP (voir
`docs/CA.md`) — puis quelques minutes de plus pour l'émission du certificat
TLS par cert-manager :

```bash
kubectl -n open-eidas-staging get pods -w
kubectl -n open-eidas-staging logs deploy/open-eidas-ca -c ca -f
kubectl -n open-eidas-staging get certificate,challenge
```

Un `Certificate` passe à `READY: True` une fois le défi HTTP-01 validé et
le certificat émis.

## 7. Vérifier le déploiement

```bash
echo "test staging $(date -Is)" > facture.txt
openssl ts -query -data facture.txt -sha256 -cert -out facture.tsq
curl -sf -H 'Content-Type: application/timestamp-query' \
    --data-binary @facture.tsq https://staging-api.open-eidas.eu/tsa \
    -o facture.tsr
curl -sf https://staging-api.open-eidas.eu/api/v1/certificate -o chain.pem
awk '/BEGIN CERTIFICATE/{n++} {print > (n == 1 ? "tsu.pem" : "ca.pem")}' chain.pem
openssl ts -verify -in facture.tsr -queryfile facture.tsq -CAfile ca.pem

# Vérifie que la CRL publiée est effectivement récupérable publiquement :
curl -sf https://staging-pki.open-eidas.eu/download/*.crl -o staging.crl \
    2>/dev/null || echo "adapter le nom de fichier — voir l'AIA du certificat TSU"
openssl x509 -in tsu.pem -noout -text | grep -A3 "CRL Distribution"

# Vérifie que le répondeur OCSP répond publiquement pour ce certificat :
openssl ocsp -issuer ca.pem -cert tsu.pem -CAfile ca.pem -no_nonce \
    -url https://staging-ocsp.open-eidas.eu/ocsp -resp_text
```

## Dépannage

- **`Certificate` reste `False` / `Challenge` en échec** : vérifier que le
  DNS pointe bien vers l'ingress (`dig`) et que rien ne bloque le port 80
  entrant depuis Internet (certains hébergeurs filtrent par défaut au
  niveau du security group / firewall cloud, à ouvrir explicitement).
- **`kubectl wait` ou `helm install` semblent bloqués sur le Pod `ca`** :
  la cérémonie génère deux bi-clés RSA-4096 dans SoftHSM, ce qui prend
  jusqu'à quelques minutes sur un nœud modeste. Suivre
  `kubectl logs deploy/open-eidas-ca -c ca -f`.
- **La TSA ou le répondeur OCSP restent en attente de certificat** : leur
  demande attend une décision de l'autorité d'enregistrement. Vérifier que le
  conteneur d'approbation automatique tourne
  (`kubectl logs deploy/open-eidas-ca -c ra-autoapprove`), ou approuver à la
  main si `ca.autoApprove.enabled` est à `false` :
  `kubectl exec deploy/open-eidas-ca -c ca -- ca-server ra list PENDING`.
- **La TSA refuse de signer (`heure non traçable`)** : le cluster n'a pas
  de sortie UDP/123 vers les serveurs NTP configurés
  (`tsa.time.policy` / `tsa.time.sources`, voir `values.yaml`) — vérifier
  que le security group du cluster autorise le trafic UDP sortant, ou à
  défaut passer `tsa.time.policy=monitor` dans `values-staging.yaml` (perte
  de la traçabilité temporelle ETSI EN 319 421, à documenter comme écart
  dans `docs/ARCHITECTURE.md` si conservé au-delà d'un test ponctuel).
