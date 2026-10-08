# Revue croisée pour Claude Code

Deux skills Claude Code, `/review-plan` et `/review-code`, qui font relire un plan approuvé ou un lot de code terminé par trois relecteurs en parallèle :

- un **Claude Opus en contexte vierge** (sous-agent `fresh-reviewer`), qui n'a pas vu la conversation ;
- **deux modèles tiers via OpenRouter**, choisis par mode, avec une liste blanche fermée d'hébergeurs, zéro conservation des données (`zdr`) et refus des hébergeurs qui entraînent sur les données ;
- en mode code, les **contrôles automatiques** que le dépôt fournit (`php -l`, PHPCS, PHPStan, ESLint, `bash -n`, shellcheck s'il est installé) ; les tests du dépôt servent à prouver les constats retenus.

Les relecteurs rendent des constats (sévérité, où, problème, pourquoi), jamais de code. Le Claude principal de la session consolide, marque les constats convergents, propose un verdict par constat, et rien n'est appliqué sans votre décision. Chaque revue est journalisée (relecteur, modèle, hébergeur, constat, verdict, coût), ce qui permet de mesurer dans le temps quels relecteurs valent leur prix.

Tout est en français : prompts, format des constats, skills, rapport.

## Contenu du dépôt

```
tools/cross-review/cross-review.py     script (Python 3, bibliothèque standard seulement)
tools/cross-review/cross-review.json   configuration : modèles, hébergeurs, budgets, journal
tools/cross-review/prompts/            format.md (gabarit des constats), plan.md, code.md
tools/cross-review/tests/              tests unitaires (aucun appel réseau) et fixtures
skills/review-plan/SKILL.md            skill /review-plan
skills/review-code/SKILL.md            skill /review-code
agents/fresh-reviewer.md               sous-agent Claude vierge
LICENSE                                licence MIT
```

## Prérequis

- Claude Code (les skills utilisent `AskUserQuestion`, les sous-agents en arrière-plan et le sandbox Bash).
- Python 3 (aucune dépendance à installer) et `git`.
- Un compte OpenRouter avec du crédit.

## Installation

### 1. Copier les fichiers

```bash
mkdir -p ~/.claude/tools ~/.claude/skills ~/.claude/agents
cp -R tools/cross-review ~/.claude/tools/
cp -R skills/review-plan skills/review-code ~/.claude/skills/
cp agents/fresh-reviewer.md ~/.claude/agents/
chmod +x ~/.claude/tools/cross-review/cross-review.py
```

### 2. Autoriser le script dans `~/.claude/settings.json`

Deux entrées :

```json
{
  "permissions": {
    "allow": [
      "Bash(~/.claude/tools/cross-review/cross-review.py:*)"
    ]
  },
  "sandbox": {
    "excludedCommands": [
      "~/.claude/tools/cross-review/cross-review.py *"
    ]
  }
}
```

- La règle `allow` évite une confirmation à chaque appel.
- L'exclusion du sandbox est **indispensable** : dans le sandbox, le script ne peut ni joindre OpenRouter ni écrire le journal.
- Les skills écrivent le chemin exactement ainsi, le tilde en tête (jamais développé en chemin absolu, jamais via `python3`), et la règle comme l'exclusion se comparent à cette forme écrite. C'est pour cela que chaque appel doit être seul dans sa commande Bash, sans `&&`, `|` ni `;` (les skills le rappellent).

**Mise à jour d'une installation existante** : les versions précédentes du dépôt faisaient écrire le chemin absolu (un marqueur remplacé par `sed` dans les skills et l'agent, et des entrées `settings.json` avec le chemin développé). En mettant à jour, recopiez les skills et l'agent, puis remplacez ces deux entrées de `settings.json` par la forme tilde ci-dessus ; sinon chaque appel demande une confirmation et tourne dans le sandbox, sans accès à OpenRouter ni au journal.

### 3. Créer une clé OpenRouter

1. Sur https://openrouter.ai, créez une clé d'API et créditez le compte. OpenRouter **réserve** `max_tokens × prix du modèle` au moment de chaque requête et refuse l'appel (erreur 402) si le crédit ne couvre pas cette réservation, même si l'appel n'aurait consommé que peu de tokens : avec `max_tokens` à 48 000 et un modèle à 6 $/M en sortie (48 000 × 6 $/M ≈ 0,29 $), prévoyez au moins 0,30 $ de crédit disponible par appel.
2. Mettez la clé dans la variable d'environnement `OPENROUTER_API_KEY`, dans un fichier lu par les shells non interactifs (`~/.zshenv` sous zsh, pas seulement `~/.zshrc`), puis relancez Claude Code :

```bash
echo 'export OPENROUTER_API_KEY="votre-clé"' >> ~/.zshenv
```

Le script ne lit la clé que dans cette variable, ne l'écrit nulle part et masque toute clé qui traînerait dans le contenu envoyé.

### 4. Choisir vos modèles

Tout se règle dans `~/.claude/tools/cross-review/cross-review.json` :

- `modes.plan` et `modes.code` : la liste des modèles tiers de chaque mode (slugs OpenRouter). Deux par mode est un bon équilibre entre diversité et coût.
- `models.<slug>` : chaque modèle utilisé doit y être déclaré, avec son `label` (qui donne le préfixe de ses constats : GL1, GR2…), ses `hebergeurs` dans l'ordre d'essai, et éventuellement son `reasoning`. La liste d'hébergeurs est **fermée** : OpenRouter n'essaiera que ceux-là (`allow_fallbacks: false`), et le script renvoie le code 4 si un hébergeur hors liste a servi. Vérifiez les hébergeurs disponibles sur `https://openrouter.ai/api/v1/models/<slug>/endpoints`.
- `reasoning` à la racine : l'effort par défaut (`medium`). Un `reasoning` dans un modèle remplace entièrement celui de la racine. Deux pièges rencontrés : GLM-5.3 n'accepte que `low`, `high` ou `max` ; chez xAI (Grok) le raisonnement n'est pas compté dans `max_tokens`.
- `provider_defaults` : `zdr: true` et `data_collection: "deny"` par défaut. À adapter si vous acceptez plus d'hébergeurs.
- `ignore_chine` : liste d'hébergeurs à exclure quoi qu'il arrive (dans la config livrée, les hébergeurs dont la maison mère est chinoise).
- `max_tokens`, `temperature`, `timeout_s`, `deadline_s` (durée totale maximale d'une revue, 900 s), `max_input_chars` (au-delà, le contenu est refusé plutôt que tronqué), `code_review_min_lines` (100 ; ne vaut que pour un lot de front de présentation seul : en dessous, `/review-code` propose la revue au lieu de la lancer ; le script ne lit pas cette clé, c'est la skill qui l'applique).
- `sensitive_globs` et `extra_secret_patterns` : fichiers retirés du diff et motifs de secrets masqués.
- `log_path` : le journal (`~/.claude/cross-review-log.jsonl` par défaut). Variables `CROSS_REVIEW_CONFIG` et `CROSS_REVIEW_LOG` pour surcharger la config et le journal.
- `rappel_autocorrection` : après N revues de code, le rapport affiche un rappel de relire le journal. Passez `actif` à `false` si vous n'en voulez pas.

Configuration livrée, retenue après bancs d'essai sur des revues réelles (septembre 2026, voir plus bas) :

| Mode | Modèles tiers | Coût par revue |
|---|---|---|
| plan | `z-ai/glm-5.3` + `x-ai/grok-4.7` | ≈ 0,17 $ |
| code | `z-ai/glm-5.3` + `z-ai/glm-5.3-flash` | ≈ 0,04 $ |

Pour vérifier une configuration sans dépenser :

```bash
echo "plan de test" | ~/.claude/tools/cross-review/cross-review.py review --mode plan --dry-run
```

affiche le corps de chaque requête (modèle, hébergeurs, réglages), sans appel réseau.

### 5. Adapter les prompts

`prompts/plan.md` et `prompts/code.md` disent aux relecteurs quoi chercher. Ils sont écrits pour du développement web WordPress (PHP, JS, ACF, Gutenberg) : adaptez la liste des priorités à votre stack. `prompts/format.md` impose le format des constats et la réponse `RIEN À SIGNALER` ; le script s'en sert pour lire les réponses, changez-le avec prudence (les tests couvrent l'analyse du format).

## Utilisation

- **`/review-plan [chemin]`** : juste après avoir approuvé un plan, avant de l'exécuter. Sans argument, le plan de la session (dossier `~/.claude/plans/`).
- **`/review-code [--base REF] [--with-files]`** : lot terminé, avant commit ou livraison. Par défaut, tout ce qui n'est pas commité ; `--base main` pour une branche déjà commitée ; `--with-files` ajoute le contenu complet des fichiers touchés.

Quand c'est Claude qui envisage `/review-code` de lui-même (et non vous qui la tapez, auquel cas elle tourne quelle que soit la taille), la skill décide selon le risque du lot :

- le lot touche la prod ou un déploiement, des hooks, scripts d'automatisation ou la config Claude, des secrets ou des permissions, des données (migration, SQL, search-replace), du PHP exécuté côté serveur sur un site client, un formulaire ou un paiement : la revue se lance, quelle que soit la taille (un fichier sensible écarté de l'envoi, comme un `.env`, un `wp-config.php` ou un dump SQL, suffit à classer le lot dans cette catégorie) ;
- front de présentation seul (CSS, JS d'affichage, gabarits) : elle se lance si le lot atteint `code_review_min_lines` lignes, sinon elle vous la propose en une ligne ;
- contenu, doc, notes seuls : rien n'est lancé.

Une re-revue après corrections est limitée : au plus une deuxième revue du même lot, et seulement s'il reste des constats importants non prouvés ou si la logique a changé ; sinon les corrections se prouvent par l'exécution. Un très gros lot (au-delà d'environ 1 500 lignes ou 100 000 caractères) se découpe par sous-ensemble cohérent avant la revue : au-delà, les modèles tiers épuisent leur budget de raisonnement sans répondre.

Le rapport liste les constats convergents puis les uniques, avec pour chacun le verdict proposé (retenu, ou rejeté avec la raison, vérifiée dans le code). En mode code, chaque constat bloquant ou important retenu porte une preuve par l'exécution (`[VÉRIFIÉ]`, `[INFIRMÉ]` ou `[NON VÉRIFIÉ]` avec la raison). Un formulaire vous demande ensuite votre décision : suivre les verdicts, cocher constat par constat, ou remettre à plus tard. Rien n'est modifié avant cette réponse, et les corrections ne viennent jamais des relecteurs.

Les fichiers de chaque revue sont dans `$TMPDIR/cross-review/<run_id>/` (`payload.md` envoyé aux tiers, `tiers.md` reçu, `verdicts.json`). Une revue remise à plus tard se décide avec :

```bash
~/.claude/tools/cross-review/cross-review.py decide --run-id <run_id> --accept
```

`watch` compare l'état d'OpenRouter (prix, hébergeurs, nouveaux modèles des familles suivies) au dernier instantané ; à lancer de temps en temps ou par tâche planifiée.

## Ce que valent les relecteurs (bancs d'essai de septembre 2026)

Mesures sur des revues réelles avec verdicts de référence : un lot de code WordPress de 52 000 caractères (5 constats retenus en référence) et deux plans (un WordPress court, un infra nginx/QUIC de 14 constats). Constats de référence retrouvés, faux positifs déjà écartés repris, bruit, coût par passage :

| Modèle | Code / 5 | Plan infra / 14 | Coût code | Coût plan | À retenir |
|---|---|---|---|---|---|
| Claude Opus vierge | 5 | 7 | inclus | inclus | Le plus complet partout. |
| GLM-5.3 (Inceptron, FI) | 2, 3 rejetés repris | 7 | 0,05 $ | 0,02 $ | Tiers de base : 64 % de constats retenus sur 19 revues de code réelles. |
| GLM-5.3-Flash (Inceptron) | 4, 0 bruit | 6 | 0,006 $ | 0,008 $ | Meilleur second relecteur de code. Lent (4 à 7 min), même famille que GLM-5.3. |
| Grok 4.7 (xAI) | 0 | **11**, 0 faux positif, 2 angles neufs | 0,33 $ | 0,16 $ | Bon sur un plan, mauvais sur un gros diff. |
| Gemini 3.8 Flash (Google) | 0, « rien à signaler » | 3, un « bloquant » faux | 0,04 $ | 0,04 $ | Se tait sur le code subtil, deux erreurs 502 en deux jours. |
| GPT-5.1-Codex-Mini (Azure) | 2, 3 bruits | 2, 7 bruits | 0,05 $ | 0,03 $ | Trouve les défauts plantés, pas les subtils. |
| Grok 4.3 (xAI) | 0, « rien à signaler » | 1 | 0,03 $ | 0,01 $ | Silence rapide. |
| DeepSeek V4.1 Flash (DeepInfra) | boucle, réponse vide | 5 | 0,02 $ | 0,005 $ | Épuise le raisonnement sur un long contenu ; correct sur un plan court. |
| Mistral Small 2603 (Mistral UE) | 0, 4 bruits | 1, 7 bruits | 0,005 $ | 0,004 $ | Paraphrase, « bloquant » faux. |

Deux leçons de méthode : un diff à défauts plantés (nonce absent, injection SQL, `unserialize` d'un cookie…) ne départage personne, tous les trouvent ; seul un lot réel subtil avec des verdicts de référence sépare les relecteurs. Et une réponse « rien à signaler » rendue en vingt secondes est un mauvais signe, pas une bonne nouvelle.

## Tests

```bash
python3 -m unittest discover -s ~/.claude/tools/cross-review/tests -v
```

Aucun appel réseau. `tests/make-repo-exemple.sh` crée un dépôt git jetable avec des défauts plantés pour essayer `collect --mode code` ; `tests/plan-exemple.md` est un plan à problèmes pour `collect --mode plan`.

## Codes de sortie du script

| Code | Sens |
|---|---|
| 0 | au moins un relecteur tiers a répondu |
| 2 | erreur d'usage, config invalide ou clé absente |
| 3 | aucun tiers n'a répondu (la revue continue avec Claude seul) |
| 4 | un hébergeur hors liste blanche a été utilisé |
| 5 | contenu trop volumineux (`max_input_chars`) |
| 10 | `watch` : des changements ont été détectés |

## Contribuer

Avant votre premier commit dans un clone, réglez l'identité git du dépôt (adresse noreply GitHub, pour ne pas publier votre adresse personnelle) :

```bash
git config user.email "<identifiant>+<pseudo>@users.noreply.github.com"
```
