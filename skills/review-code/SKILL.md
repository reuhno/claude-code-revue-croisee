---
name: review-code
description: Revue croisée d'un lot de code terminé, avant commit, PR ou livraison. Lance en parallèle un relecteur Claude vierge (fresh-reviewer) et le modèle tiers OpenRouter du mode code sur le diff filtré (fichiers sensibles retirés, secrets masqués), plus les contrôles automatiques du projet (php -l, PHPCS, PHPStan, ESLint, bash -n et shellcheck), consolide les constats avec un verdict par constat, prouve par l'exécution les constats bloquants et importants retenus ([VÉRIFIÉ] / [INFIRMÉ] / [NON VÉRIFIÉ]), écrit le journal, puis attend la décision de l'utilisateur sans rien modifier. À utiliser uniquement à la fin d'un lot de code, ou quand l'utilisateur tape /review-code.
argument-hint: "[--base REF] [--plan FICHIER] [--with-files]"
allowed-tools: Bash(~/.claude/tools/cross-review/cross-review.py:*), Read, Write, AskUserQuestion
---

# Revue croisée d'un lot de code

Script : `~/.claude/tools/cross-review/cross-review.py`, toujours écrit ainsi (le tilde en tête, jamais développé en chemin absolu, jamais via `python3`) pour que la règle d'autorisation et l'exclusion du sandbox s'appliquent. Chaque appel est seul dans sa commande Bash : ni `&&`, ni `|`, ni `;`, sinon il tourne dans le sandbox et ne peut ni joindre OpenRouter ni écrire le journal. Il ne sert qu'à relire : les relecteurs rendent des constats, jamais de code.

## 1. Préparer le contenu

Depuis la racine du dépôt du projet :

```
~/.claude/tools/cross-review/cross-review.py collect --mode code [--base REF] [--plan <plan>] [--with-files]
```

- Par défaut, le lot est tout ce qui n'est pas commité (`git diff HEAD` et les fichiers non suivis). `--base REF` pour un lot déjà commité sur une branche (par exemple `--base main`). Options passées par l'utilisateur : `$ARGUMENTS`.
- `--plan` : le plan approuvé de la session s'il existe (dans `~/.claude/plans/`), pour contrôler la cohérence.
- `--with-files` : seulement si le diff seul manque de contexte (petits morceaux dans de gros fichiers).
- Hors dépôt git : `--files <fichiers touchés>`.

Garder du résumé JSON : `run_id`, `run_dir`, `payload`, `projet`, `repo_root`, `claude_md`, `chars`, `lines_changed`, `files_included`, `files_excluded`, `secrets_masked`, `over_limit`.

- **Déclenchement selon le risque** : tapée par l'utilisateur, `/review-code` tourne quelle que soit la taille. Sinon, d'après `files_included` **et** `files_excluded` (`collect` retire les fichiers sensibles : `.env*`, `wp-config*.php`, `*.sql`, clés… ; un fichier sensible exclu, qu'il s'agisse de config, de secrets ou d'un dump SQL, classe à lui seul le lot dans la catégorie à risque ci-dessous) :
  - le lot touche la prod ou un déploiement, des hooks, scripts d'automatisation ou la config Claude, des secrets ou des permissions, des données (migration, SQL, search-replace), du PHP exécuté côté serveur sur un site client, un formulaire ou un paiement : lancer, quelle que soit la taille ;
  - front de présentation seul (CSS, JS d'affichage, gabarits) : lancer si `lines_changed` atteint `code_review_min_lines` de la config (100) ; sinon proposer en une ligne (« Lot de N lignes : revue croisée ? ») et s'arrêter ;
  - contenu, doc, notes seuls : ne rien lancer.
- **Re-revue après corrections** : si ce lot a déjà eu une revue dans la session (même chantier, corrections des constats), au plus une deuxième revue, et seulement s'il reste des constats importants non prouvés ou si la logique a changé. Sinon, et au-delà, ne pas relancer : prouver les corrections par l'exécution et le dire.
- **Très gros lot** : `lines_changed` au-delà d'environ 1 500 ou `chars` au-delà d'environ 100 000 : proposer à l'utilisateur un découpage par sous-ensemble cohérent avant de lancer (au-delà, les modèles tiers épuisent leur budget de raisonnement sans répondre).
- Si `over_limit` est vrai (code 5), relancer sans `--with-files` ; si c'est toujours trop gros, proposer à l'utilisateur de découper le lot et s'arrêter.
- Si `secrets_masked` n'est pas vide, un secret est écrit en dur dans le code : le signaler en tête du rapport, avec le fichier.

## 2. Lancer les relecteurs, dans un seul message

- Agent : `subagent_type: fresh-reviewer`, `model: opus`, `run_in_background: true`, avec pour prompt :
  « Mode : code. Contenu à relire : `<payload>`. Racine du projet : `<repo_root>`. CLAUDE.md du projet : `<claude_md, sinon "aucun">`. »
- Bash, `run_in_background: true`, `timeout: 600000`, lancé depuis la conversation principale, jamais par un sous-agent. En arrière-plan, ce timeout ne coupe pas la commande : le script s'arrête de lui-même à `deadline_s` de la config (900 s).

  ```
  ~/.claude/tools/cross-review/cross-review.py review --mode code --input <payload> --run-dir <run_dir>
  ```

Dans le même message, les **contrôles automatiques**, en Bash ordinaire (sandbox), depuis `repo_root`, sur les seuls fichiers de `files_included`. Ils ne se trompent pas et ne coûtent rien :

- `.php` : `php -l` sur chaque fichier. Le PHP local peut différer de celui du site : un échec de syntaxe est sûr, une réussite ne garantit pas la compatibilité avec la version en prod.
- PHPCS si le projet a `vendor/bin/phpcs` et un fichier `phpcs.xml`, `.phpcs.xml`, `phpcs.xml.dist` ou `.phpcs.xml.dist` : `vendor/bin/phpcs --report=emacs <fichiers>`.
- PHPStan si le projet a `vendor/bin/phpstan` et un `phpstan.neon` ou `phpstan.neon.dist` : `vendor/bin/phpstan analyse --no-progress --error-format=raw <fichiers>`.
- `.js` : ESLint si le projet a `node_modules/.bin/eslint` et une config ESLint : `node_modules/.bin/eslint --format unix <fichiers>`.
- Scripts shell (`.sh`, `.bash`, ou fichier sans extension dont la première ligne est un shebang `bash` ou `sh`) : `bash -n` sur chaque fichier, puis shellcheck s'il est installé (`command -v shellcheck`) : `shellcheck -f gcc <fichiers>`. Ne lancer ni `bash -n` ni shellcheck sur un script dont le shebang est `zsh`, même avec l'extension `.sh` : ils ne savent pas le lire et donneraient de fausses erreurs.

Ne rien installer (ni `composer install`, ni `npm install`), ne rien corriger (pas de `phpcbf`, pas de `--fix`). Un outil absent donne une ligne « non disponible », pas une erreur. Des linters, ne garder que les messages qui tombent sur des lignes modifiées du lot ; les autres, un total en une ligne (« 12 avertissements préexistants »).

Attendre les deux notifications sans faire le travail des relecteurs entre-temps.

Code de sortie du script : 0 = au moins un tiers a répondu ; 3 = aucun (la revue continue avec Claude seul) ; 4 = **un hébergeur hors liste blanche a été utilisé** : le signaler en gras en tête du rapport ; 2 = config invalide ou clé absente : le signaler.

## 3. Consolider

Lire `<run_dir>/tiers.md`. Les constats du relecteur Claude prennent le préfixe `C` (C1, C2…), ceux des tiers ont déjà le leur (GL1…), ceux des contrôles automatiques le préfixe `T` (T1, T2…). Un contrôle automatique compte comme un relecteur pour la convergence.

- **Convergents** : même problème soulevé par au moins deux relecteurs, même formulé autrement. Une ligne par problème, avec tous les identifiants.
- **Uniques** : tous les autres.
- Pour chaque constat, mon verdict : **retenu**, ou **rejeté** avec la raison en une phrase (faux positif, déjà géré ailleurs dans le code, hors périmètre, risque négligeable…). Vérifier dans le code avant de trancher, sans rien modifier.

### Preuve par l'exécution

Un constat vaut par ce qu'on a observé, pas par le nombre de relecteurs qui le croient. Chaque constat **bloquant ou important** que je retiens reçoit une preuve, avant d'être présenté :

- **[VÉRIFIÉ]** : j'ai exécuté quelque chose et observé le défaut. La preuve tient en une ligne : la commande et ce qu'elle a montré (« `php -l` : erreur ligne 42 », « test `test_save_meta` en échec », « `curl` sans nonce sur admin-ajax du site local : 200 et option modifiée »).
- **[INFIRMÉ]** : l'exécution montre que le défaut n'existe pas. Le constat passe en **rejeté**, avec la preuve comme raison.
- **[NON VÉRIFIÉ]** : aucune exécution n'est possible ou sûre. La raison tient en quelques mots (« pas de site local », « demanderait d'écrire en prod », « dépend d'un service tiers »). Le verdict repose alors sur la lecture du code, et le rapport le dit.

Un contrôle automatique (T) est [VÉRIFIÉ] d'office. Un constat mineur n'a pas besoin de preuve.

Moyens de preuve, du moins coûteux au plus coûteux :
1. un contrôle automatique déjà lancé qui signale la même ligne ;
2. les tests existants du projet (`composer test`, `vendor/bin/phpunit`, `npm test`…), limités si possible aux tests des fichiers touchés ;
3. une reproduction sur l'environnement **local** : `wp eval`, `wp` CLI, `curl` sur le site local, ou un petit script jetable dans `$TMPDIR` qui inclut le fichier et appelle la fonction.

Limites :
- Jamais sur la prod, ni en lecture active qui déclencherait le défaut ; une reproduction sur staging demande l'accord de l'utilisateur.
- Aucun fichier du projet n'est modifié pour prouver quoi que ce soit : ni code, ni test ajouté dans le dépôt. Les fichiers jetables vont dans `$TMPDIR`. Une reproduction qui écrit en base locale se signale dans le rapport.
- Budget : au plus cinq minutes par constat. Au-delà, [NON VÉRIFIÉ] (« reproduction trop longue »).
- Délégation : une ou deux preuves d'une commande chacune, je les fais moi-même. Au-delà, un sous-agent `model: sonnet` reçoit la liste des constats retenus (identifiant, où, problème), les limites ci-dessus, la consigne de rendre pour chacun le statut et la preuve en une ligne, et la phrase « n'utilise pas l'outil Agent ». Il prouve, il ne corrige pas. Le verdict reste le mien.

## 4. Journal

Écrire `<run_dir>/verdicts.json` : une entrée par constat et par relecteur (un constat convergent donne une entrée pour chaque relecteur qui l'a soulevé, avec `convergent: true`).

```json
[
  {"relecteur": "Claude (fresh-reviewer)", "modele": "claude-opus-5-5", "hebergeur": "Anthropic",
   "finding_id": "C1", "severite": "bloquant", "resume": "une ligne, sans code",
   "convergent": true, "verdict": "retenu", "raison": "…"},
  {"relecteur": "GLM-5.3", "finding_id": "GL1", "severite": "bloquant", "resume": "…",
   "convergent": true, "verdict": "retenu", "raison": "…",
   "preuve_statut": "verifie", "preuve": "php -l : erreur de syntaxe ligne 42"},
  {"relecteur": "Contrôles automatiques", "modele": "php -l", "hebergeur": "local",
   "finding_id": "T1", "severite": "bloquant", "resume": "…",
   "convergent": true, "verdict": "retenu", "raison": "…",
   "preuve_statut": "verifie", "preuve": "…"}
]
```

`preuve_statut` vaut `verifie`, `infirme`, `non_verifie`, ou `null` pour un constat mineur ou rejeté sans exécution. Chaque constat convergent porte le même statut et la même preuve sur toutes ses entrées. Les contrôles automatiques sans message donnent une entrée `{"relecteur": "Contrôles automatiques", "modele": "<outils lancés>", "hebergeur": "local", "finding_id": null, "severite": "aucune", "resume": "rien à signaler", …}`.

Si Claude n'a rien signalé, une entrée `{"relecteur": "Claude (fresh-reviewer)", "modele": "claude-opus-5-5", "hebergeur": "Anthropic", "finding_id": null, "severite": "aucune", "resume": "rien à signaler", "convergent": false, "verdict": null, "raison": null}`. Le script ajoute lui-même les tiers sans constat ou indisponibles.

```
~/.claude/tools/cross-review/cross-review.py log --run-dir <run_dir> --verdicts <run_dir>/verdicts.json
```

Si la sortie contient une ligne `RAPPEL :`, la reprendre telle quelle, en gras, tout en haut du rapport.

## 5. Rapport, puis attente

```
## Revue croisée · code · <projet> · <date>
Relecteurs : Claude vierge (Opus) ✅ · GLM-5.3 via <hébergeur> ✅ <coût>
Contrôles automatiques : php -l ✅ <n> fichiers · PHPCS <n> messages sur le lot (<n> préexistants) · PHPStan non disponible · bash -n ✅ <n> fichiers · shellcheck <n> messages (ou non disponible)
Envoyé aux tiers : diff de <n> fichiers (<lines_changed> lignes) [+ plan] · exclus : <fichiers> · secrets masqués : <n>

### Convergents
| # | Sévérité | Où | Problème | Vu par | Preuve | Mon verdict |

### Uniques
| # | Sévérité | Où | Problème | Vu par | Preuve | Mon verdict |

(Preuve : [VÉRIFIÉ] ou [INFIRMÉ] suivi de la commande et du résultat, ou [NON VÉRIFIÉ] suivi de la raison ; vide pour un mineur.)

### Rien à signaler / indisponibles
- …

Rien n'a été modifié.
```

Puis, dans le même tour, le formulaire de décision avec l'outil AskUserQuestion. Un appel contient 4 questions au plus et chaque question 2 à 4 choix : c'est l'outil qui l'impose.

**Premier appel.** Question 1 « Décision » (choix unique) : « Go : mes verdicts (Recommended) », « Je coche constat par constat », « Rien pour l'instant ». Puis les questions de constats, par sévérité, dans l'ordre « Bloquants », « Importants », « Mineurs » (`multiSelect: true`), convergents en tête de chaque groupe (un constat convergent = un seul choix qui porte tous ses identifiants) : libellé `C1+GL1 · <problème en 5 mots>`, description = mon verdict (retenu / rejeté) et sa raison en une phrase, avec la preuve [VÉRIFIÉ] / [INFIRMÉ] quand il y en a une. Les constats d'une sévérité se découpent en questions de 2 à 4 choix (« Importants 1/2 », « Importants 2/2 » ; 5 constats donnent 3 + 2, jamais 4 + 1) ; une sévérité qui n'a qu'un constat reçoit le choix supplémentaire « Aucun de cette sévérité ». Les questions qui ne tiennent pas dans les 3 places restantes (ou une sévérité qui ne tient pas entière) sont remises à un second appel.

**Après le premier appel.** « Go » : mes verdicts s'appliquent, les coches sont ignorées, aucun second appel. « Rien pour l'instant » : les verdicts sont déjà au journal (étape 4) ; aucun appel à `decide`, le run reste « en attente de décision » et se décide plus tard avec les commandes ci-dessous ; aucune correction, s'arrêter là en rappelant le `run_id`. « Je coche » : les coches font foi (coché = retenu, non coché = rejeté, raison « écarté par l'utilisateur ») ; s'il reste des constats non présentés, un second appel avec ces seules questions. Une réponse « Autre » en texte libre prime sur tout ; le mot « go » seul en texte libre vaut « Go : mes verdicts ».

Ne rien modifier, ne pas commiter avant cette réponse. Ensuite :

```
~/.claude/tools/cross-review/cross-review.py decide --run-id <run_id> --accept
~/.claude/tools/cross-review/cross-review.py decide --run-id <run_id> retenu:C1,GL2 rejete:GL3
```

(la première pour « Go » et pour des coches identiques à mes verdicts ; la seconde pour des coches différentes, avec tous les identifiants du run ; aucune des deux pour « Rien pour l'instant »), puis, sauf « Rien pour l'instant », corriger les constats retenus selon les règles habituelles de délégation. Les corrections ne viennent jamais des relecteurs.

**Re-preuve, une seule fois.** Après la correction, chaque constat [VÉRIFIÉ] retenu reçoit une re-preuve : rejouer la commande de sa preuve, une fois, et constater que le défaut a disparu. Si le défaut persiste, s'arrêter et le dire à l'utilisateur. Pas de nouvelle correction dans la foulée, pas de nouvelle revue de la correction, hors le cas de re-revue prévu à l'étape 1 (au plus une, sous condition) : jamais de boucle relecture-correction. Le compte rendu de correction donne, par constat, la re-preuve en une ligne (« re-preuve : défaut disparu » avec la commande, ou « défaut persistant »).
