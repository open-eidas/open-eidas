# Spécification UX et Système de Design — Console d'Opération (RA/CA)

**Statut : Spécification de référence UX/UI pour `ra-console` / Open-eIDAS.**  
Ce document définit les principes d'expérience utilisateur (UX), les flux d'interaction critiques, les règles d'accessibilité et le système de design (UI) applicables à l'interface web d'opération d'Open-eIDAS. Il complète l'architecture fonctionnelle et cryptographique décrite dans [WEBUI.md](WEBUI.md).

---

## 1. Vision et Principes Directeurs d'UX

L'interface d'opération d'Open-eIDAS n'est pas une application SaaS grand public : c'est un poste de travail pour **opérateurs de confiance et auditeurs** manipulant une infrastructure à clés publiques (PKI) régie par des exigences réglementaires strictes (eIDAS, ETSI EN 319 401, EN 319 411-1/2). 

Les principes directeurs suivants s'imposent à tout écran et composant :

1. **Sobriété et clarté chirurgicale (Zero Distraction)** :
   - Aucun élément décoratif superflu, aucune animation superflue, aucun artifice marketing.
   - Densité d'information élevée, adaptée à des postes de supervision professionnels (écrans larges 1080p/4K).
   - Hiérarchie visuelle stricte : l'action critique et les données certifiantes priment sur tout le reste.

2. **WYSIWYS (What You See Is What You Sign)** :
   - Tout engagement cryptographique de l'opérateur (via clé FIDO2 / WebAuthn) doit présenter sous forme canonique et inaltérable l'exact contenu qui sera signé (numéro de série, motif de révocation, identité du demandeur, empreinte SHA-256).
   - L'opérateur ne doit jamais valider une action sur la foi d'un libellé générique ("Confirmer ?").

3. **Asymétrie d'effort et prévention des erreurs critiques** :
   - Les actions sûres et fréquentes (lecture, recherche, filtrage) doivent être fluides et instantanées (navigation clavier `j`/`k`).
   - Les actions sensibles et irréversibles (révocation de certificat, rejet d'enrôlement, clôture d'incident) imposent une friction intentionnelle : confirmation explicite, saisie obligatoire d'une justification, et geste physique sur authentificateur FIDO2.

4. **Imputabilité et contexte permanent** :
   - L'opérateur doit à tout instant voir :
     - L'environnement courant (**PRODUCTION** en rouge/ambre vif, **STAGING** en bleu/vert discret).
     - Son identité authentifiée et son rôle actif (`auditeur`, `ra_operateur`, `ca_operateur`).
     - L'état de santé du HSM et l'échéance de la prochaine CRL.

5. **Ergonomie sous astreinte et en situation de crise** :
   - En cas d'incident de sécurité (suspicion de compromission de clé privée), l'opérateur est sous stress. Les parcours d'urgence (révocation immédiate, ouverture de dossier d'investigation) doivent être guidés, sans ambiguïté, avec un vocabulaire standardisé conforme au RFC 5280 et à l'ETSI.

---

## 2. Architecture de l'Information & Disposition d'Écran

L'application adopte une disposition en 3 zones stables, sans superposition modale intempestive.

```
+-----------------------------------------------------------------------------------------+
| [Bannière d'Environnement : PROD / STAGING]                                             |
| [Logo Open-eIDAS] [Statut HSM: OK] [Prochaine CRL: 03h 42m] | [Alice (ca_op)] [🔑 FIDO] |
+------------------+----------------------------------------------------------------------+
| NAVIGATION       | ZONE DE TRAVAIL PRINCIPALE                                           |
|                  |                                                                      |
| 📥 Demandes RA   |  +----------------------------------------------------------------+  |
|    (4 en attente)|  | Filtres / Recherche rapide (ex: serial, nom, date)             |  |
| 📜 Certificats   |  +----------------------------------------------------------------+  |
| ⚠️ Quorum (1)    |  | TABLEAU DE DONNÉES DENSE                                       |  |
| 🛡️ Incidents (0) |  | [Statut] [N° Série] [Sujet] [Demandeur] [Date] [Actions]      |  |
| 🔍 Journal Audit |  | ...                                                            |  |
| ⚙️ Matrice ETSI  |  +----------------------------------------------------------------+  |
|                  |  | INSPECTEUR LATERAL / SPLIT-PANE (Détail de l'élément sélectionné)|  |
|                  |  | - Visualisation du CSR / Certificat                             |  |
|                  |  | - Historique de la chaîne d'audit                              |  |
|                  |  | - Boutons d'action : [Approuver...] [Rejeter...]               |  |
+------------------+----------------------------------------------------------------------+
```

### 2.1. Barre Supérieure de Sécurité (Global Security Bar)
Toujours visible, fixe en haut d'écran :
- **Badge d'Environnement** :
  - *Production* : bandeau rouge rubis ou bordeaux foncé (`#991b1b`) avec texte contrasté blanc gras `"ENVIRONNEMENT : PRODUCTION (AUTORITÉ QUALIFIÉE)"`.
  - *Staging / Test* : bandeau bleu ardoise sobre (`#1e293b`) `"ENVIRONNEMENT : TEST / BAC À SABLE"`.
- **Indicateurs d'Infrastructure** :
  - Statut HSM : pastille verte/rouge (`HSM PKCS#11 : CONNECTÉ`).
  - Décompte CRL : compte à rebours avant la prochaine génération obligatoire de CRL (ex. `"CRL dans 03h 18m"` ; alerte orange sous 2h, alerte rouge sous 30m).
- **Bloc Identité Opérateur** :
  - Nom affiché, badge de rôle (`auditeur`, `ra_operateur`, `ca_operateur`), indicateur de présence de la clé WebAuthn et bouton de déconnexion explicite.

### 2.2. Navigation Latérale (Sidebar)
Menu vertical sobre avec compteurs dynamiques en temps réel :
1. **Demandes d'enrôlement** (`/requests`) : badge avec le nombre de demandes `PENDING`.
2. **Certificats émis** (`/certificates`) : recherche par serial, DN, date, statut.
3. **Salle de Quorum / Double Contrôle** (`/quorum`) : badge visible dès qu'une action M-sur-N attend une seconde approbation.
4. **Dossiers d'Incident** (`/incidents`) : liste des investigations ouvertes.
5. **Journal d'Audit** (`/audit`) : interface de recherche en lecture seule dans la chaîne de hachage.
6. **Conformité & Santé** (`/conformance`) : statut ETSI temps réel issu de `oe-conformance`.

### 2.3. Disposition Split-Pane (Liste + Inspecteur)
Pour éviter les allers-retours de navigation et la perte de repères :
- La liste principale reste visible à gauche (60% de largeur).
- La sélection d'une ligne ouvre un **panneau d'inspection latéral** à droite (40% de largeur) affichant les détails complets (champs X.509, extensions, historique d'audit, boutons de décision).

---

## 3. Motifs d'Interaction Clés (UX Patterns)

### 3.1. Cérémonie WebAuthn & Signature de Payload

Chaque action d'approbation, rejet ou révocation nécessite une signature FIDO2 conforme au schéma décrit dans [WEBUI.md](WEBUI.md) §4.

**Déroulement UX de la modale de signature :**
1. **Étape 1 : Récapitulatif canonique (WYSIWYS)**
   - La modale affiche le corps JSON canonique de la requête ainsi que sa synthèse humaine en clair.
   - Affichage de l'empreinte `SHA-256(payload)` en police monospace groupée par octets.
2. **Étape 2 : Déclenchement de l'assertion matérielle**
   - Clic sur `"Signer avec ma clé FIDO2"`.
   - Message d'état explicite avec pictogramme animé sobre : `"Touchez votre clé de sécurité matérielle..."`.
   - Compte à rebours de timeout WebAuthn (60 secondes).
3. **Étape 3 : Résultat et audit**
   - En cas de succès : coche verte instantanée, fermeture automatique après 800ms, rafraîchissement de la vue avec le nouvel événement d'audit affiché.
   - En cas d'erreur (annulation, timeout, PIN erroné, credential inconnu) : message d'erreur précis sans fermer la modale, permettant de relancer sans ressaisir les données.

```
+-------------------------------------------------------------+
| 🔑 Signature de l'action : Révocation de Certificat         |
+-------------------------------------------------------------+
| Vous êtes sur le point de révoquer définitivement :        |
|                                                             |
|   Certificat : TSA-Signer-2026-A                            |
|   Numéro de série : 3A:F8:9C:12:00:4E:91:B2                 |
|   Motif RFC 5280  : keyCompromise (1)                       |
|   Justification   : Signalement CERT-FR incident #2026-991  |
|                                                             |
| Empreinte de la requête (SHA-256) :                         |
|   e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c... |
|                                                             |
| +---------------------------------------------------------+ |
| |  👉 Touchez votre clé de sécurité FIDO2 pour valider   | |
| |     [Animation pulsation discrète] (Expire dans 45s)    | |
| +---------------------------------------------------------+ |
|                                                             |
| [ Annuler ]                                                 |
+-------------------------------------------------------------+
```

### 3.2. Salle d'Attente de Quorum (Double Contrôle M-sur-N)

Pour les actions critiques soumises à double contrôle ([WEBUI.md](WEBUI.md) §8) :

1. **Initiation par Opérateur 1** :
   - L'opérateur prépare la requête (ex. révocation d'une sous-autorité), signe son assertion WebAuthn.
   - La requête passe à l'état `AWAITING_QUORUM` avec un timer d'expiration (ex. 30 minutes).
2. **Notification & Visibilité** :
   - Un badge clignotant discret apparaît dans la sidebar pour tous les autres opérateurs habilités.
   - Une bannière informative apparaît en tête de console : `"Action critique en attente de quorum : Révocation CA-Intermédiaire-1 initiée par Alice il y a 4 min."`.
3. **Validation par Opérateur 2** :
   - L'opérateur 2 ouvre la demande.
   - L'interface met en avant :
     - L'identité de l'initiateur (Alice) et son horodatage de signature.
     - L'avertissement d'impossibilité d'auto-validation (si l'utilisateur connecté est Alice, le bouton de validation est désactivé avec le message `"Le double contrôle requiert un opérateur distinct"`).
     - Le hash exact du corps de requête signé par Alice.
   - L'opérateur 2 déclenche sa propre assertion WebAuthn.
4. **Exécution et Clôture** :
   - Dès la seconde assertion vérifiée par le serveur, l'action est exécutée atomiquement et consignée dans le journal d'audit avec les deux identités.

### 3.3. Explorateur d'Audit avec Vérification Cryptographique Visuelle

Le journal d'audit (`oe-audit`) est une chaîne inaltérable de hachages SHA-256. L'UX de consultation doit traduire cette propriété mathématique :

- **Indicateur de Chaîne Intègre** :
  - En haut du journal, un badge vert certifie : `"Chaîne d'audit vérifiée : 14 285 entrées intègres depuis la racine"`.
  - Si un bloc est corrompu ou manquant : alerte rouge écarlate bloquante `"RUPTURE D'INTÉGRITÉ DÉTECTÉE À LA SÉQUENCE #12044"`.
- **Présentation d'une ligne d'audit** :
  - N° de séquence (`#00014285`), Date ISO UTC précise à la milliseconde, Opérateur (avec lien vers son profil), Type d'événement (`ENROLL_APPROVE`, `REVOKE`, etc.).
  - Vue détaillée dépliable : hash précédent (`prev_hash`), hash courant, payload JSON formaté avec coloration syntaxique.

### 3.4. Workflow de Traitement RA (Demandes d'Enrôlement)

Pour un traitement efficace et sans erreur :
- Affichage du CSR (Certificate Signing Request) décodé : Subject DN, SANs (Subject Alternative Names), clé publique (type, taille, courbe), extensions demandées.
- Comparaison automatique avec la politique de certification : mise en évidence verte des champs conformes, avertissement orange si un SAN est inhabituel.
- Boutons d'action bien séparés :
  - `[ Approuver la demande... ]` (Bouton primaire émeraude, déclenche la modale WebAuthn).
  - `[ Rejeter la demande... ]` (Bouton secondaire neutre avec modale exigeant un motif de rejet textuel obligatoire).

---

## 4. Système de Design Visuel (Design Tokens)

### 4.1. Thème et Palette de Couleurs

L'interface privilégie un thème sombre technique par défaut (réduction de la fatigue visuelle pour les postes de supervision SOC/NOC), avec support natif d'un thème clair contrasté via variables CSS.

#### Couleurs de Surface et d'Arrière-Plan (Dark Theme par défaut)
| Token | Valeur Hex | Usage |
|---|---|---|
| `--bg-canvas` | `#090d16` | Fond principal de l'application |
| `--bg-surface` | `#111827` | Fond des panneaux, cartes et tables |
| `--bg-surface-elevated` | `#1f2937` | Fond des modales, popovers et menus |
| `--border-subtle` | `#374151` | Bordures de séparation de tableau et panneaux |
| `--border-focus` | `#38bdf8` | Anneau de focus clavier (bleu ciel vif) |

#### Couleurs Sémantiques d'État des Certificats et Demandes
Pour satisfaire les critères d'accessibilité (daltonisme), **aucune information ne doit reposer uniquement sur la couleur** : chaque badge d'état associe une couleur, une forme de bordure et une icône explicite.

| État | Couleur Fond / Texte | Icône | Forme / Bordure | Description |
|---|---|---|---|---|
| `VALID` / `ACTIF` | `#064e3b` / `#34d399` | `●` ou `✓` | Bordure fine verte | Certificat émis, non révoqué, en cours de validité |
| `PENDING` / `ATTENTE` | `#451a03` / `#fbbf24` | `⏳` ou `⏱` | Bordure pointillée ambre | Demande en attente de décision RA ou de quorum |
| `REVOKED` / `RÉVOQUÉ` | `#450a0a` / `#f87171` | `✕` ou `⊘` | Bordure pleine rouge rubis | Certificat révoqué (définitif) |
| `EXPIRED` / `EXPIRÉ` | `#1e293b` / `#94a3b8` | `⏹` | Bordure grise neutre | Certificat dont la date de validité est dépassée |
| `SUSPENDED` / `SUSPENDU`| `#2e1065` / `#c084fc` | `⏸` | Bordure violette | Certificat temporairement suspendu |
| `TAMPERED` / `ALERTE` | `#831843` / `#f43f5e` | `⚠️` | Bordure épaisse magenta clignotante | Anomalie cryptographique ou violation de contrainte |

#### Couleurs des Rôles Opérateurs
- `auditeur` : Bleu ardoise (`#0284c7`) — lecture seule, consultation.
- `ra_operateur` : Vert émeraude (`#059669`) — décisions d'enrôlement, incidents.
- `ca_operateur` : Violet profond (`#7c3aed`) — révocation, opérations cryptographiques.
- `admin` : Ambre / Cuivre (`#d97706`) — gestion des credentials et configuration système.

### 4.2. Typographie

- **Texte d'interface général (UI)** :
  - Famille : `system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif` (zéro dépendance à des polices web externes via CDN, étanchéité réseau).
  - Tailles :
    - Titres de section : `18px`, graisse `600`.
    - Texte courant / cellules de table : `13px` ou `14px`, hauteur de ligne `1.4`.
    - Métadonnées secondaires : `11px`, graisse `500`, couleur atténuée (`--text-muted: #9ca3af`).

- **Données cryptographiques et techniques (Identifiants, Hachages, Dates)** :
  - Famille : `'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace` avec zéros barrés activés (`font-variant-numeric: slashed-zero tabular-nums`).
  - Nombres de série et clés :
    - Les numéros de série hexadécimaux s'affichent par paires séparées par deux-points : `04:A2:3F:89:1B:77`.
    - Les empreintes SHA-256 sont affichées avec un bouton de copie rapide et un tooltip affichant le hash complet.
  - Dates et Horodatages :
    - Toujours au format ISO 8601 UTC : `YYYY-MM-DD HH:mm:ss [UTC]`.
    - Un indicateur relatif est fourni au survol ou en texte secondaire : `(il y a 12 min)` ou `(dans 4 jours)`.

---

## 5. Spécifications des Composants d'Interface

### 5.1. Tableaux de Données Haute Densité (Data Tables)
- Hauteur de ligne fixée à `36px` ou `40px` maximum pour afficher au moins 15 à 20 enregistrements sans défilement sur écran standard.
- En-têtes de colonnes fixes (*sticky headers*) lors du défilement vertical.
- Tri direct par clic sur l'en-tête (indiqué par une flèche discrète `▲`/`▼`).
- Ligne sélectionnée mise en surbrillance avec bordure gauche colorée de 3px.
- Support du défilement horizontal sans masquage des colonnes d'action clés (colonne d'action épinglée à droite si nécessaire).

### 5.2. Boîtes de Dialogue et Modales Sécurisées
- Utilisation de l'élément HTML natif `<dialog>` avec `showModal()` pour garantir le piégeage du focus (*focus trapping*) et la fermeture native par `Esc` (sauf pendant une cérémonie WebAuthn active).
- Voile d'arrière-plan semi-opaque sombre (`backdrop-filter: blur(4px); background: rgba(0, 0, 0, 0.7)`).
- Toute modale d'action destructive désactive le clic extérieur pour fermer afin d'empêcher les fermetures accidentelles.

### 5.3. Panneau Inspecteur Dépliable (Drawer / Inspector)
- Positionné sur la droite de l'écran, largeur minimale de `420px`.
- Découpé en onglets thématiques :
  - `Général` : Identité, numéro de série, dates d'effet et expiration, profil.
  - `Clés & Extensions` : Algorithme, taille, KeyUsage, ExtKeyUsage, SANs, Subject DN.
  - `Chaîne d'Audit` : Historique chronologique complet des événements liés à cet objet.

---

## 6. Accessibilité (A11y), Ergonomie Clavier et Sécurité Frontend

### 6.1. Navigation Exhaustive au Clavier
Les opérateurs chevronnés doivent pouvoir traiter une file de demandes sans utiliser la souris :
- `j` / `k` ou `↓` / `↑` : Déplacer la sélection dans le tableau de demandes/certificats.
- `Entrée` ou `Espace` : Ouvrir le panneau d'inspection de l'élément sélectionné.
- `a` : Déclencher l'approbation de la demande courante (ouvre la modale WebAuthn).
- `r` : Déclencher le rejet de la demande courante.
- `Escape` : Fermer l'inspecteur ou la modale ouverte.
- `/` : Donner le focus à la barre de recherche rapide.

### 6.2. Exigences d'Accessibilité (WCAG 2.1 AA / AAA)
- **Contraste des textes** : Ratio supérieur à 7:1 pour les textes normaux sur leur arrière-plan (niveau AAA), et supérieur à 4.5:1 pour les textes secondaires.
- **Indicateurs de Focus** : Anneau de focus visible et sans ambiguïté (`outline: 2px solid #38bdf8; outline-offset: 2px`) sur tous les éléments interactifs.
- **Support des lecteurs d'écran** : Balisage ARIA strict (`aria-expanded`, `aria-live="polite"` pour les statuts d'attente WebAuthn, `aria-haspopup="dialog"`).

### 6.3. Hygiène de Sécurité Frontend
Compte tenu de la criticité du système :
- **Politique de Sécurité de Contenu (CSP) stricte** :
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';
  ```
  - Zéro `unsafe-inline`, zéro `unsafe-eval`.
  - Aucun chargement de polices, scripts ou styles depuis des CDN tiers (intégrité totale en environnement fermé ou sans accès Internet).
- **Verrouillage de Session Inactive** :
  - Décompte d'inactivité de 15 minutes.
  - Au bout de 14 minutes : avertissement modal non bloquant.
  - À 15 minutes : verrouillage de l'écran, suppression du cookie de session côté client et ré-authentification FIDO2 exigée.
- **Protection contre le détournement de clic (Clickjacking)** :
  - `X-Frame-Options: DENY` et CSP `frame-ancestors 'none'`.

---

## 7. Directives de Réalisation Technique (Stack Frontend)

Pour respecter la philosophie du projet Open-eIDAS (minimalisme, auditabilité, pérennité, pas de dette de dépendances superflues) :

1. **Architecture sans framework lourd** :
   - Éviter les frameworks massifs nécessitant des centaines de dépendances npm (React, Vue, Angular) si un outillage léger suffit.
   - Préférence pour des **Web Components natifs** (Custom Elements + Shadow DOM ou Light DOM documenté) ou un micro-framework typé sans build complexe.
   - Zéro dépendance pour les fonctions cryptographiques côté client : utilisation stricte de l'API standard `navigator.credentials` et de `SubtleCrypto` pour le hachage SHA-256 canonique.
2. **Distribution des fichiers** :
   - Les assets statiques (HTML, CSS, JS) sont compilés/minifiés et peuvent être servis directement embarqués dans le binaire Rust `ra-console` via `rust-embed` ou `include_str!`.
   - Cela garantit qu'un déploiement de `ra-console` est un **binaire unique autonome**, sans dépendance vers un serveur web externe ou des répertoires d'assets dispersés.

---

## 8. Maquettes de Référence (HTML/CSS) et Captures d'Écran

Quatre maquettes HTML complètes et interactives ont été créées dans le répertoire `docs/mockups/` pour servir de gabarit technique et visuel :

1. **Console d'Opération RA Split-Pane** :
   - Fichier : [`docs/mockups/dashboard.html`](mockups/dashboard.html)
   - Capture : [`docs/mockups/screenshots/01_dashboard_ra.png`](mockups/screenshots/01_dashboard_ra.png)
   - Illustre : Barre de sécurité globale (PROD, HSM, compte à rebours CRL), table haute densité, panneau inspecteur CSR/ETSI latéral et raccourcis clavier.

2. **Modale de Cérémonie WebAuthn (WYSIWYS)** :
   - Fichier : [`docs/mockups/webauthn_modal.html`](mockups/webauthn_modal.html)
   - Capture : [`docs/mockups/screenshots/02_webauthn_modal.png`](mockups/screenshots/02_webauthn_modal.png)
   - Illustre : Récapitulatif canonique d'une action irréversible (révocation), hash SHA-256 en monospace, animation de pulsation du prompt matériel FIDO2.

3. **Salle de Quorum & Double Contrôle M-sur-N** :
   - Fichier : [`docs/mockups/quorum.html`](mockups/quorum.html)
   - Capture : [`docs/mockups/screenshots/03_quorum_dual_control.png`](mockups/screenshots/03_quorum_dual_control.png)
   - Illustre : Jauge de progression 1/2, détails du premier signataire vérifié, éligibilité du second opérateur distinct et interdiction d'auto-validation.

4. **Explorateur du Journal d'Audit Inaltérable** :
   - Fichier : [`docs/mockups/audit.html`](mockups/audit.html)
   - Capture : [`docs/mockups/screenshots/04_audit_explorer.png`](mockups/screenshots/04_audit_explorer.png)
   - Illustre : Témoin d'intégrité de la chaîne cryptographique, liaisons `prev_hash → current_hash`, payloads JSON dépliables et assertions FIDO2 associées.

---

## 9. Documents Connexes
- [WEBUI.md](WEBUI.md) : Architecture fonctionnelle de l'interface web, flux WebAuthn et surface API.
- [ARCHITECTURE.md](ARCHITECTURE.md) : Architecture globale du système Open-eIDAS.
- [CPS.md](CPS.md) : Déclaration des Pratiques de Certification (politiques de gestion des clés et séparation des rôles).
- [CONFORMITE-ETSI.md](CONFORMITE-ETSI.md) : Matrice des exigences ETSI EN 319 401 et EN 319 411-1/2.
