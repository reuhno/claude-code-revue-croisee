---
name: review-plan
description: Revue croisée d'un plan d'implémentation approuvé, avant de l'exécuter. Lance en parallèle un relecteur Claude vierge (fresh-reviewer) et les modèles tiers OpenRouter du mode plan, consolide les constats avec un verdict par constat, écrit le journal, puis attend la décision de l'utilisateur sans rien modifier. À utiliser uniquement juste après l'approbation d'un plan (sortie du plan mode), ou quand l'utilisateur tape /review-plan.
argument-hint: "[chemin du plan]"
allowed-tools: Bash(__CLAUDE_HOME__/tools/cross-review/cross-review.py:*), Read, Write, AskUserQuestion
---

# Revue croisée d'un plan

Script : `__CLAUDE_HOME__/tools/cross-review/cross-review.py`, toujours appelé par ce chemin exact (jamais via `python3`) pour que la règle d'autorisation et l'exclusion du sandbox s'appliquent. Chaque appel est seul dans sa commande Bash : ni `&&`, ni `|`, ni `;`, sinon il tourne dans le sandbox et ne peut ni joindre OpenRouter ni écrire le journal. Il ne sert qu'à relire : les relecteurs rendent des constats, jamais de code.

## 1. Préparer le contenu

Plan à relire : `$ARGUMENTS` s'il est fourni ; sinon le fichier de plan de la session (celui indiqué par le plan mode, dans `~/.claude/plans/`). Si aucun plan n'est identifiable, demander le chemin à l'utilisateur et s'arrêter.

```
__CLAUDE_HOME__/tools/cross-review/cross-review.py collect --mode plan --plan <plan>
```

Garder du résumé JSON : `run_id`, `run_dir`, `payload`, `projet`, `repo_root`, `claude_md`, `chars`, `secrets_masked`, `over_limit`. Si `over_limit` est vrai (code 5), le dire à l'utilisateur et s'arrêter : on ne tronque pas.

## 2. Lancer les relecteurs, dans un seul message

- Agent : `subagent_type: fresh-reviewer`, `model: opus`, `run_in_background: true`, avec pour prompt :
  « Mode : plan. Contenu à relire : `<payload>`. Racine du projet : `<repo_root, sinon le cwd>`. CLAUDE.md du projet : `<claude_md, sinon "aucun">`. »
- Bash, `run_in_background: true`, `timeout: 600000`, lancé depuis la conversation principale, jamais par un sous-agent. En arrière-plan, ce timeout ne coupe pas la commande : le script s'arrête de lui-même à `deadline_s` de la config (900 s).

  ```
  __CLAUDE_HOME__/tools/cross-review/cross-review.py review --mode plan --input <payload> --run-dir <run_dir>
  ```

Attendre les deux notifications sans faire le travail des relecteurs entre-temps.

Code de sortie du script : 0 = au moins un tiers a répondu ; 3 = aucun (la revue continue avec Claude seul) ; 4 = **un hébergeur hors liste blanche a été utilisé** : le signaler en gras en tête du rapport ; 2 = config invalide ou clé absente : le signaler.

## 3. Consolider

Lire `<run_dir>/tiers.md`. Les constats du relecteur Claude prennent le préfixe `C` (C1, C2…), ceux des tiers ont déjà le leur (GL1, GR2…).

- **Convergents** : même problème soulevé par au moins deux relecteurs, même formulé autrement. Une ligne par problème, avec tous les identifiants.
- **Uniques** : tous les autres.
- Pour chaque constat, mon verdict : **retenu**, ou **rejeté** avec la raison en une phrase (faux positif, déjà couvert par le plan, hors périmètre, risque négligeable…). Vérifier dans le plan ou le code avant de trancher, sans rien modifier.

## 4. Journal

Écrire `<run_dir>/verdicts.json` : une entrée par constat et par relecteur (un constat convergent donne une entrée pour chaque relecteur qui l'a soulevé, avec `convergent: true`).

```json
[
  {"relecteur": "Claude (fresh-reviewer)", "modele": "claude-opus-5-5", "hebergeur": "Anthropic",
   "finding_id": "C1", "severite": "important", "resume": "une ligne, sans code",
   "convergent": true, "verdict": "retenu", "raison": "…"},
  {"relecteur": "GLM-5.3", "finding_id": "GL2", "severite": "important", "resume": "…",
   "convergent": true, "verdict": "rejete", "raison": "déjà couvert par l'étape 2"}
]
```

Si Claude n'a rien signalé, une entrée `{"relecteur": "Claude (fresh-reviewer)", "modele": "claude-opus-5-5", "hebergeur": "Anthropic", "finding_id": null, "severite": "aucune", "resume": "rien à signaler", "convergent": false, "verdict": null, "raison": null}`. Le script ajoute lui-même les tiers sans constat ou indisponibles.

```
__CLAUDE_HOME__/tools/cross-review/cross-review.py log --run-dir <run_dir> --verdicts <run_dir>/verdicts.json
```

## 5. Rapport, puis attente

```
## Revue croisée · plan · <projet> · <date>
Relecteurs : Claude vierge (Opus) ✅ · GLM-5.3 via <hébergeur> ✅ <coût> · Grok 4.7 ⚠ indisponible (<raison>)
Envoyé aux tiers : plan (<chars> caractères) · secrets masqués : <n>

### Convergents
| # | Sévérité | Où | Problème | Vu par | Mon verdict |

### Uniques
| # | Sévérité | Où | Problème | Vu par | Mon verdict |

### Rien à signaler / indisponibles
- …

Rien n'a été modifié.
```

Puis, dans le même tour, le formulaire de décision avec l'outil AskUserQuestion. Un appel contient 4 questions au plus et chaque question 2 à 4 choix : c'est l'outil qui l'impose.

**Premier appel.** Question 1 « Décision » (choix unique) : « Go : mes verdicts (Recommended) », « Je coche constat par constat », « Rien pour l'instant ». Puis les questions de constats, par sévérité, dans l'ordre « Bloquants », « Importants », « Mineurs » (`multiSelect: true`), convergents en tête de chaque groupe (un constat convergent = un seul choix qui porte tous ses identifiants) : libellé `C1+GL1 · <problème en 5 mots>`, description = mon verdict (retenu / rejeté) et sa raison en une phrase. Les constats d'une sévérité se découpent en questions de 2 à 4 choix (« Importants 1/2 », « Importants 2/2 » ; 5 constats donnent 3 + 2, jamais 4 + 1) ; une sévérité qui n'a qu'un constat reçoit le choix supplémentaire « Aucun de cette sévérité ». Les questions qui ne tiennent pas dans les 3 places restantes (ou une sévérité qui ne tient pas entière) sont remises à un second appel.

**Après le premier appel.** « Go » : mes verdicts s'appliquent, les coches sont ignorées, aucun second appel. « Rien pour l'instant » : les verdicts sont déjà au journal (étape 4) ; aucun appel à `decide`, le run reste « en attente de décision » et se décide plus tard avec les commandes ci-dessous ; le plan n'est ni amendé ni exécuté, s'arrêter là en rappelant le `run_id`. « Je coche » : les coches font foi (coché = retenu, non coché = rejeté, raison « écarté par l'utilisateur ») ; s'il reste des constats non présentés, un second appel avec ces seules questions. Une réponse « Autre » en texte libre prime sur tout ; le mot « go » seul en texte libre vaut « Go : mes verdicts ».

Ne rien modifier et ne rien exécuter du plan avant cette réponse. Ensuite :

```
__CLAUDE_HOME__/tools/cross-review/cross-review.py decide --run-id <run_id> --accept
__CLAUDE_HOME__/tools/cross-review/cross-review.py decide --run-id <run_id> retenu:C1,GL2 rejete:GR1
```

(la première pour « Go » et pour des coches identiques à mes verdicts ; la seconde pour des coches différentes, avec tous les identifiants du run ; aucune des deux pour « Rien pour l'instant »), puis, sauf « Rien pour l'instant », amender le plan avec les constats retenus, et seulement alors l'exécuter.
