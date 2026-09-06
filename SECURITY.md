# Politique de sécurité

Open eIDAS manipule des clés cryptographiques et produit des preuves
opposables : une vulnérabilité ici a un impact différent de la plupart des
projets logiciels. Merci de la signaler de façon responsable.

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue publique.** Utilisez l'onglet *Security* du dépôt
GitHub (« Report a vulnerability »), qui crée une discussion privée entre vous
et les mainteneurs.

Si cette option n'est pas disponible, décrivez la classe de problème dans une
issue sans détailler la méthode d'exploitation, et demandez un canal privé.

Merci d'inclure :

- le composant concerné (service d'horodatage, enrôlement, journal d'audit,
  configuration OpenXPKI/SoftHSM2 fournie) ;
- les conditions de déclenchement ;
- l'impact tel que vous l'évaluez (falsification de jeton, contournement de
  la traçabilité de l'heure, exposition de clé, etc.).

## Périmètre

Sont concernés :

- le code de ce dépôt (`internal/`, `cmd/`) ;
- les configurations de déploiement fournies (`deploy/`, `docker-compose.yml`).

Ne sont pas couverts par cette politique les composants tiers embarqués
(OpenXPKI, SoftHSM2, MariaDB) : signalez leurs vulnérabilités à leurs projets
respectifs. Une exposition résultant uniquement de la configuration de
*démonstration* documentée comme telle (enrôlement anonyme et auto-approuvé,
TLS non vérifié, OID de politique de test) est un écart connu, listé dans
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#8-écarts-assumés-du-prototype-vis-à-vis-dune-tsa-qualifiée) ;
elle reste toutefois bienvenue à signaler si vous identifiez une aggravation
non documentée.

## Délai de traitement

Ce projet est un prototype en préfiguration associative, maintenu
bénévolement : accusé de réception sous une semaine, sans engagement de délai
de correction. Une vulnérabilité critique touchant l'intégrité des jetons ou
la confidentialité des clés sera traitée en priorité.
