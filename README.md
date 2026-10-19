# Alertes portefeuille

Surveille une liste de titres cotés, envoie un message **Telegram** dès qu'un stop-loss, un take profit ou un niveau d'achat est touché, et publie un **tableau de bord protégé par mot de passe**.

- **Portefeuille** : titres détenus, avec un **stop-loss** (alerte de vente si le cours descend) et/ou un **take profit** (alerte de vente si le cours monte).
- **Watchlist** : titres à acheter, avec une **limite d'achat** (alerte si le cours descend à ce niveau).
- Un niveau est *touché* si le **plus bas du jour** est ≤ le stop-loss ou la limite d'achat, ou si le **plus haut du jour** est ≥ le take profit. Un passage entre deux contrôles est donc détecté aussi.
- Un message par titre, par sens et par séance. Si le cours reste dans la zone, un rappel est envoyé à la séance suivante.
- Contrôle **toutes les 10 minutes**, du lundi au vendredi, de 03h à 24h (heure suisse). GitHub peut décaler un passage de quelques minutes.
- Cours Yahoo Finance (gratuit), différés de 0 à 15 min selon la place de cotation.
- Coût : **0**. Le dépôt GitHub est public, ce qui rend les passages illimités.

## Confidentialité (dépôt public)

| Visible par tout le monde | Chiffré avec le mot de passe |
|---|---|
| Le programme | La liste des titres et les limites (`watchlist.enc.json`) |
| La page de mot de passe du tableau de bord | Les cours, statuts et alertes affichés (`site/data.enc.json`) |
| L'heure des modifications de la liste et de la sauvegarde hebdomadaire | L'historique des alertes (`state/state.enc.json`) |

- Les jetons Telegram et le mot de passe sont dans les *Secrets* GitHub : invisibles.
- Les journaux du robot, publics, ne contiennent que des compteurs (« 40 cours récupérés », « 1 alerte »).
- L'historique passe d'un contrôle à l'autre par un cache : aucun enregistrement dans le dépôt ne trahit l'heure d'une alerte.
- **Choisir un mot de passe long**, par exemple 5 mots au hasard (`girafe-moteur-bleu-sapin-orage`). Les fichiers chiffrés sont téléchargeables : un mot de passe court pourrait être deviné.
- `*.csv` est exclu de Git (`.gitignore`) : une liste en clair ne peut pas partir sur GitHub par erreur.

## Fichiers

| Fichier | Rôle |
|---|---|
| `watchlist.enc.json` | La liste suivie, chiffrée (colonnes `liste, ticker, yahoo, nom, limite_basse, limite_haute, note` : limite basse = stop-loss ou achat, limite haute = take profit). Modifiable depuis le tableau de bord (bouton *Modifier la liste*). |
| `config.json` | Nom du portefeuille (affiché dans les messages) et fuseau horaire. |
| `alerts.py` | Le robot : cours → détection → Telegram → tableau de bord chiffré. |
| `site/index.html` | Le tableau de bord. |
| `.github/workflows/monitor.yml` | La planification. |

Les tickers sont au format Bloomberg (`AAPL US`, `700 HK`, `SHOP CN`, `NESN SW`…) et sont convertis automatiquement au format Yahoo. **Les limites sont dans la devise de cotation du titre**, affichée dans le tableau de bord. Attention : `.L` est souvent en pence (GBp).

## Mise en place (une seule fois)

### 1. Telegram
1. Dans Telegram, ouvrir **@BotFather** → `/newbot` → choisir un nom. Il donne un **jeton** (`123456:ABC…`).
2. Créer un **groupe** (ex. « Alertes Delta »), y ajouter le bot et les destinataires, puis écrire un message dans le groupe.
3. Récupérer l'identifiant du groupe, un nombre négatif comme `-1001234567890` (le jeton est demandé au clavier) :
   ```bash
   .venv/bin/python alerts.py telegram-id
   ```

### 2. Liste chiffrée
Importer la composition. Le mot de passe du tableau de bord est demandé au clavier : il n'apparaît nulle part.
```bash
.venv/bin/python alerts.py import ~/Downloads/composition.csv
```

### 3. GitHub
1. Créer un dépôt **public** et y envoyer ce dossier.
2. **Settings → Secrets and variables → Actions → New repository secret** :
   - `DASHBOARD_PASSWORD` : le mot de passe choisi à l'étape 2 (exactement le même)
   - `TELEGRAM_BOT_TOKEN` : le jeton du bot
   - `TELEGRAM_CHAT_ID` : l'identifiant du groupe
3. **Settings → Pages → Source : GitHub Actions**.
4. **Actions → Surveillance des limites → Run workflow** pour un premier passage.
5. Optionnel : variable `DASHBOARD_URL` (onglet *Variables*) avec l'adresse du tableau de bord, pour l'ajouter en bas de chaque message.

### 4. Modifier la liste depuis le tableau de bord
Le bouton **Modifier la liste** déchiffre la liste, permet d'ajouter, retirer ou modifier les titres, puis la rechiffre et l'enregistre. Il demande une fois un jeton GitHub :
*GitHub → Settings → Developer settings → Fine-grained tokens* : accès à ce dépôt seulement, **Contents : Read and write** et **Actions : Read and write**.
Les personnes qui consultent seulement n'ont besoin que du mot de passe.

Autre possibilité, avec Excel :
```bash
.venv/bin/python alerts.py export liste.csv
.venv/bin/python alerts.py load liste.csv
```
La première commande déchiffre la liste dans `liste.csv`. On la modifie dans Excel, puis la seconde la rechiffre dans `watchlist.enc.json`.

## Dupliquer pour un autre portefeuille
1. Sur GitHub : **Settings → cocher « Template repository »**, une seule fois.
2. **Use this template → Create a new repository** (public).
3. En local : `import` de la nouvelle composition avec un **nouveau mot de passe**, et changer le nom dans `config.json`.
4. Refaire l'étape 3 (secrets + Pages). Le même bot Telegram peut servir pour tous les portefeuilles, avec un groupe par portefeuille.

## Changer le mot de passe
`export`, puis `load` avec le nouveau mot de passe, mise à jour du secret `DASHBOARD_PASSWORD`, puis *Run workflow*. L'historique des alertes repart de zéro.
