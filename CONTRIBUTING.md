# Contribuer à Open eIDAS

Merci de l'intérêt porté à ce projet. Open eIDAS vise une infrastructure de
confiance ouverte et auditable : les contributions techniques comme la
relecture critique de l'architecture ont de la valeur.

## Avant d'écrire du code

Pour tout changement non trivial (nouvelle fonctionnalité, changement de
comportement cryptographique ou protocolaire, dépendance ajoutée), ouvrez une
*issue* décrivant le problème avant d'envoyer une pull request. Ce projet
touche à de la cryptographie et à de la conformité réglementaire : discuter
l'approche en amont évite du travail jeté.

## Domaines où l'aide est particulièrement utile

Voir la section « Écarts assumés » de [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
pour le détail de chaque point :

- intégration de HSM certifiés (au-delà de SoftHSM2) ;
- redondance du service et procédure de bascule ;
- conformité fine à ETSI EN 319 421 / 319 422 ;
- durcissement de la configuration OpenXPKI de démonstration.

## Mettre en place l'environnement de développement

```bash
git clone https://github.com/open-eidas/open-eidas.git
cd open-eidas
make up      # amorce la pile complète (PKI + TSA)
make demo    # vérifie qu'un jeton s'émet et se valide
```

Le développement du service Go seul ne nécessite pas Go installé localement :
`make test` et `make lint` s'exécutent dans un conteneur `golang`. Aucune
version de Go n'est donc requise sur la machine de développement, seul Docker
l'est.

## Avant d'envoyer une pull request

```bash
make lint   # gofmt + go vet
make test   # tests unitaires
make demo   # bout en bout, si le changement touche à l'horodatage, l'enrôlement
            # ou la PKI
```

La CI exécute les mêmes vérifications, plus un scan de vulnérabilités de
l'image et un amorçage complet de la pile en conteneurs.

## Style de code

- Pas de commentaire qui répète ce que fait le code ; un commentaire n'existe
  que pour expliquer un choix non évident (contrainte cryptographique,
  exigence normative, contournement documenté).
- Pas d'abstraction ni de configuration pour un besoin hypothétique : ce
  dépôt est un prototype, pas un framework.
- Toute nouvelle vérification de conformité (algorithme accepté, usage de
  certificat requis, etc.) doit citer la norme dont elle découle, en
  commentaire ou dans le message de commit.

## Sécurité

Ne pas ouvrir d'*issue* publique pour une vulnérabilité. Voir
[SECURITY.md](SECURITY.md).

## Licence

En contribuant, vous acceptez que vos changements soient publiés sous la
licence du projet, AGPL-3.0 (voir [LICENSE](LICENSE)).
