# PhishGuard

**Détecteur d'URL de phishing par machine learning, qui explique chaque décision et ne visite jamais le lien.**

**[▶ Essayer la démo en ligne](https://alawiahmeddev.github.io/phishguard/)**, qui fonctionne entièrement dans votre navigateur · *[English version](README.md)*

Collez un lien : PhishGuard montre le domaine qu'il ouvre réellement, lui attribue un score avec un modèle de gradient boosting entraîné sur 200 000 URL, et liste les caractéristiques qui ont fait monter ce score. Seul le texte de l'URL est analysé : c'est instantané, ça fonctionne hors ligne et c'est sans danger, même sur des liens de phishing actifs.

![Interface web PhishGuard](docs/screenshot.png)

## Résultats

Évaluation sur **39 857 URL provenant de sites que le modèle n'a jamais vus pendant l'entraînement** (découpage par hôte) :

| | Exactitude | Précision | Rappel | F1 | ROC AUC | Taux de faux positifs |
|---|---|---|---|---|---|---|
| Modèle (gradient boosting) | 0,872 | 0,908 | 0,826 | 0,865 | 0,931 | 8,3 % |
| Système complet (modèle + réputation des domaines) | 0,872 | 0,915 | 0,818 | 0,864 | — | 7,5 % |

Sur un jeu séparé de **50 URL légitimes modernes** (Google, PayPal, GitHub, banques et universités marocaines...), le modèle seul en signale 29 à tort, surtout des pages de connexion. Le système complet en signale 3. L'explication de cet écart se trouve [plus bas](#le-problème-que-ce-projet-a-dû-résoudre).

> Ces scores sont plus bas que les 97 à 99 % souvent annoncés pour ce type de classifieur. Ces résultats viennent en général d'un découpage aléatoire : des pages d'un même site se retrouvent à la fois dans l'entraînement et dans le test, et le modèle reconnaît en partie des sites déjà vus. Ici, chaque site du test est nouveau pour le modèle.

## Fonctionnement

1. **Normalisation.** Le schéma (`http/https`) et le `www.` sont retirés. Dans les jeux de données publics, les URL légitimes n'ont pas de schéma alors que les URL de phishing récentes en ont presque toujours un : un modèle qui verrait le schéma apprendrait le jeu de données, pas le phishing.
2. **Caractéristiques.** 32 caractéristiques calculées à partir du texte seul : longueurs, nombre de sous-domaines, chiffres et tirets, caractère aléatoire du chemin (entropie), mots-clés de phishing, nom de marque utilisé hors du vrai domaine (`apple.com.security-check.ru`), adresse IP, sosies en punycode, extensions abusées, hébergeurs gratuits (`web.app`, `workers.dev`...), raccourcisseurs, jetons aléatoires.
3. **Modèle.** `HistGradientBoostingClassifier`, retenu face à trois alternatives.
4. **Réputation.** Si le domaine figure parmi les ~10 000 domaines les plus visités, le lien est jugé sûr, sauf sur les plateformes où tout le monde peut publier (`github.io`, `firebaseapp.com`, `sites.google.com`...). Les liens raccourcis sont signalés comme suspects, car leur destination est cachée.
5. **Explication.** Chaque caractéristique est remise tour à tour à sa valeur typique sur les URL légitimes, et on mesure la baisse des indices de phishing (en log-odds). Les caractéristiques qui font le plus baisser le score sont affichées comme raisons, avec leur part.

## Comparaison des modèles

![Comparaison des modèles](docs/model_comparison.png)

| Modèle | Précision | Rappel | F1 | ROC AUC | Entraînement |
|---|---|---|---|---|---|
| Régression logistique (caractéristiques) | 0,839 | 0,701 | 0,764 | 0,864 | 1 s |
| Random forest (caractéristiques) | 0,900 | 0,824 | 0,861 | 0,925 | 17 s |
| **Gradient boosting (caractéristiques), retenu** | **0,908** | **0,826** | **0,865** | **0,931** | **12 s** |
| N-grammes de caractères TF-IDF + régression logistique | 0,934 | 0,874 | 0,903 | 0,964 | 50 s |

Le modèle à n-grammes obtient un meilleur score, mais il travaille sur 200 000 fragments de texte opaques et ne peut pas dire *pourquoi* un lien est suspect. Le gradient boosting a été retenu pour ses explications, sa taille (1,3 Mo) et sa vitesse (quelques millisecondes par URL). Combiner les deux est la prochaine étape.

## Le problème que ce projet a dû résoudre

La première version obtenait un F1 de 0,91 et semblait terminée. Testée sur 50 vraies pages de connexion de sites connus, **elle en signalait 28 comme du phishing**.

La cause venait des données : les URL légitimes des jeux publics sont soit anciennes (vers 2011), soit de simples pages d'accueil, presque sans pages de connexion. Les URL de phishing, elles, sont pleines de `login`, `signin`, `verify`. Le modèle avait appris « page de connexion = phishing ».

Trois corrections ont été apportées :

1. **Ajout d'URL légitimes modernes avec chemin**, extraites d'une quarantaine de listes « awesome » maintenues par la communauté sur GitHub. Les pages ordinaires obtiennent maintenant un score bas : Wikipédia 0,22, Stack Overflow 0,01, BBC 0,02.
2. **Échantillonnage équilibré par source et limite par hôte**, pour que le modèle ne puisse pas distinguer les classes simplement selon le jeu de données d'origine.
3. **Une couche de réputation des domaines**, comme dans les vrais filtres. Une page de connexion sur un domaine inconnu mérite la prudence ; les vraies pages de connexion sont sur des domaines populaires.

Les 3 URL légitimes encore signalées (`attijariwafabank.com/fr`, `binance.com/en/login`, `notion.so/login`) sont sur des domaines absents de la liste fournie. La commande `phishguard update-reputation` la remplace par le classement [Tranco](https://tranco-list.eu) actuel.

## Démarrage rapide

```bash
git clone https://github.com/AlawiAhmedDev/phishguard.git
cd phishguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

phishguard check https://appleid.apple.com.security-check.ru/ https://github.com/login
phishguard serve            # interface web sur http://127.0.0.1:5000
```

Les autres commandes (`--json`, `--fail-on-phishing`, `train`, `update-reputation`) et l'API JSON sont décrites dans le [README anglais](README.md#other-commands).

## Limites

- **Analyse lexicale uniquement.** Une page de phishing sur une URL d'apparence propre, ou sur un site légitime piraté, ne sera pas détectée. Dans le test, 175 URL de phishing étaient hébergées sur des domaines populaires et sont manquées par construction.
- **Rappel de 82 %** : environ un lien de phishing sur cinq passe. PhishGuard est un premier filtre, pas une garantie.
- **La liste de popularité n'est pas une liste de sécurité.** Des pages que n'importe qui peut créer sur un domaine de confiance (un Google Forms, par exemple) sont aussi jugées sûres.
- **Âge des données.** Le phishing évolue vite : il faut réentraîner régulièrement avec `phishguard train`.

## Auteur

**Alawi Masfar**, Master en Cybersécurité et Intelligence Artificielle. GitHub : [@AlawiAhmedDev](https://github.com/AlawiAhmedDev)

## Licence

[MIT](LICENSE). Les jeux de données conservent leurs propres licences.
