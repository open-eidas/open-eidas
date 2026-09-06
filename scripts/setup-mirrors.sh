#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Open eIDAS — Script de configuration des miroirs Codeberg & GitLab
# ==============================================================================
# Ce script automatise :
# 1. La création des dépôts miroirs sur Codeberg (Forgejo) et GitLab
# 2. La désactivation stricte des fonctionnalités (Issues, PR/MR, Wiki, CI)
# 3. L'enregistrement des secrets sur GitHub via le CLI gh
# 4. La synchronisation miroir initiale (git push --mirror)
# ==============================================================================

REPOS=("open-eidas" "website" "organisation" ".github")
CODEBERG_ORG="open-eidas"
DEFAULT_GITLAB_GROUP="open-eidas"

echo "=== Configuration des miroirs Open eIDAS (Codeberg & GitLab) ==="
echo ""

# 1. Vérification des outils requis
for cmd in curl git gh; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Erreur : '$cmd' est requis mais non installé." >&2
    exit 1
  fi
done

# 2. Récupération des tokens
CODEBERG_TOKEN="${CODEBERG_TOKEN:-}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"
GITLAB_NAMESPACE="${GITLAB_NAMESPACE:-$DEFAULT_GITLAB_GROUP}"

if [ -z "$CODEBERG_TOKEN" ]; then
  read -rsp "Entrez votre token d'accès personnel Codeberg (scopes repo & organization) : " CODEBERG_TOKEN
  echo ""
fi

if [ -z "$GITLAB_TOKEN" ]; then
  read -rsp "Entrez votre token d'accès personnel GitLab (scopes api ou write_repository) : " GITLAB_TOKEN
  echo ""
fi

# 3. Validation du token Codeberg
echo ""
echo "--> Validation du token Codeberg..."
CODEBERG_USER=$(curl -s -H "Authorization: token $CODEBERG_TOKEN" https://codeberg.org/api/v1/user | grep -o '"username":"[^"]*' | cut -d'"' -f4 || true)
if [ -z "$CODEBERG_USER" ]; then
  echo "Erreur : Token Codeberg invalide ou non autorisé." >&2
  exit 1
fi
echo "    Connecté à Codeberg en tant que : $CODEBERG_USER"

# 4. Validation du token GitLab
echo "--> Validation du token GitLab..."
GITLAB_USER=$(curl -s -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://gitlab.com/api/v4/user | grep -o '"username":"[^"]*' | cut -d'"' -f4 || true)
if [ -z "$GITLAB_USER" ]; then
  echo "Erreur : Token GitLab invalide ou non autorisé." >&2
  exit 1
fi
echo "    Connecté à GitLab en tant que : $GITLAB_USER"

# Vérification ou création du namespace GitLab si nécessaire
echo "--> Vérification du groupe / namespace GitLab '$GITLAB_NAMESPACE'..."
GL_GROUP_ID=$(curl -s -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/groups/$GITLAB_NAMESPACE" | grep -o '"id":[0-9]*' | head -n1 | cut -d: -f2 || true)

if [ -z "$GL_GROUP_ID" ]; then
  echo "    Le groupe '$GITLAB_NAMESPACE' n'a pas été trouvé. Tentative de création du groupe..."
  CREATE_GROUP_RES=$(curl -s -X POST -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$GITLAB_NAMESPACE\",\"path\":\"$GITLAB_NAMESPACE\",\"visibility\":\"public\",\"description\":\"Infrastructure ouverte de services de confiance eIDAS\"}" \
    https://gitlab.com/api/v4/groups)
  GL_GROUP_ID=$(echo "$CREATE_GROUP_RES" | grep -o '"id":[0-9]*' | head -n1 | cut -d: -f2 || true)
  if [ -n "$GL_GROUP_ID" ]; then
    echo "    Groupe GitLab '$GITLAB_NAMESPACE' créé avec succès (ID: $GL_GROUP_ID)."
  else
    echo "    Impossible de créer le groupe '$GITLAB_NAMESPACE', utilisation du compte personnel '$GITLAB_USER' comme cible."
    GITLAB_NAMESPACE="$GITLAB_USER"
  fi
else
  echo "    Groupe GitLab '$GITLAB_NAMESPACE' trouvé (ID: $GL_GROUP_ID)."
fi

# 5. Traitement pour chaque dépôt
for repo in "${REPOS[@]}"; do
  echo ""
  echo "=================================================================="
  echo "  Traitement du dépôt : $repo"
  echo "=================================================================="

  DESC="[Miroir] Dépôt miroir d'Open eIDAS. Les contributions et issues se font sur https://github.com/open-eidas/$repo"

  # --- A. CODEBERG ---
  echo "  [Codeberg] Vérification de $CODEBERG_ORG/$repo..."
  CB_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: token $CODEBERG_TOKEN" "https://codeberg.org/api/v1/repos/$CODEBERG_ORG/$repo")

  if [ "$CB_STATUS" = "404" ]; then
    echo "  [Codeberg] Création du dépôt $CODEBERG_ORG/$repo avec issues et PRs désactivées..."
    curl -s -X POST "https://codeberg.org/api/v1/orgs/$CODEBERG_ORG/repos" \
      -H "Authorization: token $CODEBERG_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"name\": \"$repo\",
        \"description\": \"$DESC\",
        \"private\": false,
        \"has_issues\": false,
        \"has_pull_requests\": false,
        \"has_wiki\": false,
        \"has_projects\": false,
        \"website\": \"https://open-eidas.eu\"
      }" > /dev/null
  else
    echo "  [Codeberg] Le dépôt existe. Mise à jour des paramètres (désactivation issues & PRs)..."
    curl -s -X PATCH "https://codeberg.org/api/v1/repos/$CODEBERG_ORG/$repo" \
      -H "Authorization: token $CODEBERG_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"description\": \"$DESC\",
        \"has_issues\": false,
        \"has_pull_requests\": false,
        \"has_wiki\": false,
        \"has_projects\": false,
        \"website\": \"https://open-eidas.eu\"
      }" > /dev/null
  fi
  echo "  [Codeberg] Configuré avec succès : https://codeberg.org/$CODEBERG_ORG/$repo"

  # --- B. GITLAB ---
  echo "  [GitLab] Vérification de $GITLAB_NAMESPACE/$repo..."
  ENCODED_PATH=$(echo "$GITLAB_NAMESPACE/$repo" | sed 's/\//%2F/g')
  GL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/projects/$ENCODED_PATH")

  if [ "$GL_STATUS" = "404" ]; then
    echo "  [GitLab] Création du projet $GITLAB_NAMESPACE/$repo avec issues et MRs désactivées..."
    PAYLOAD="{\"name\":\"$repo\",\"path\":\"$repo\",\"visibility\":\"public\",\"description\":\"$DESC\",\"issues_access_level\":\"disabled\",\"merge_requests_access_level\":\"disabled\",\"wiki_access_level\":\"disabled\",\"snippets_access_level\":\"disabled\",\"builds_access_level\":\"disabled\",\"container_registry_access_level\":\"disabled\""
    if [ -n "$GL_GROUP_ID" ] && [ "$GITLAB_NAMESPACE" != "$GITLAB_USER" ]; then
      PAYLOAD="$PAYLOAD,\"namespace_id\":$GL_GROUP_ID}"
    else
      PAYLOAD="$PAYLOAD}"
    fi
    curl -s -X POST "https://gitlab.com/api/v4/projects" \
      -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" > /dev/null
  else
    echo "  [GitLab] Le projet existe. Mise à jour des paramètres (désactivation issues & MRs)..."
    curl -s -X PUT "https://gitlab.com/api/v4/projects/$ENCODED_PATH" \
      -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"description\": \"$DESC\",
        \"issues_access_level\": \"disabled\",
        \"merge_requests_access_level\": \"disabled\",
        \"wiki_access_level\": \"disabled\",
        \"snippets_access_level\": \"disabled\",
        \"builds_access_level\": \"disabled\",
        \"container_registry_access_level\": \"disabled\"
      }" > /dev/null
  fi
  echo "  [GitLab] Configuré avec succès : https://gitlab.com/$GITLAB_NAMESPACE/$repo"

  # --- C. GITHUB SECRETS ---
  echo "  [GitHub] Configuration des secrets de synchronisation sur open-eidas/$repo..."
  echo "$CODEBERG_TOKEN" | gh secret set CODEBERG_TOKEN --repo "open-eidas/$repo"
  echo "$GITLAB_TOKEN" | gh secret set GITLAB_TOKEN --repo "open-eidas/$repo"
  echo "$GITLAB_NAMESPACE" | gh secret set GITLAB_NAMESPACE --repo "open-eidas/$repo"
  echo "  [GitHub] Secrets configurés pour open-eidas/$repo."

  # --- D. SYNCHRONISATION INITIALE ---
  echo "  [Sync] Synchronisation miroir immédiate pour $repo..."
  TMP_MIRROR=$(mktemp -d)
  if git clone --bare "https://github.com/open-eidas/${repo}.git" "$TMP_MIRROR" 2>/dev/null; then
    git --git-dir="$TMP_MIRROR" push --prune --tags "https://${CODEBERG_TOKEN}@codeberg.org/${CODEBERG_ORG}/${repo}.git" "+refs/heads/*:refs/heads/*" || true
    git --git-dir="$TMP_MIRROR" push --prune --tags "https://oauth2:${GITLAB_TOKEN}@gitlab.com/${GITLAB_NAMESPACE}/${repo}.git" "+refs/heads/*:refs/heads/*" || true
    echo "  [Sync] $repo synchronisé avec succès sur Codeberg et GitLab."
  else
    echo "  [Sync] Note : Le dépôt github open-eidas/$repo est peut-être encore vide ou non initialisé."
  fi
  rm -rf "$TMP_MIRROR"

done

echo ""
echo "=== Tout est configuré avec succès ! ==="
echo "Codeberg : https://codeberg.org/$CODEBERG_ORG"
echo "GitLab   : https://gitlab.com/$GITLAB_NAMESPACE"
echo "Les issues, pull requests / merge requests, wikis et pipelines CI ont été désactivés sur les deux forges."
echo "La synchronisation se fera automatiquement à chaque push via le workflow GitHub Actions."
