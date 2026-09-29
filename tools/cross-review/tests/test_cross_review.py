#!/usr/bin/env python3
"""Tests unitaires hors ligne pour cross-review.py.

Aucun appel réseau. Le module est importé dynamiquement via
importlib (le nom du fichier contient un tiret, donc pas
importable avec un simple `import`).

Lancer : python3 -m unittest discover -s <ce dossier> -v
"""

import contextlib
import gzip
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "cross-review.py"

_spec = importlib.util.spec_from_file_location("cross_review_module", SCRIPT_PATH)
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

# Point 9 (revue croisée du 2026-09-28) : les en-têtes PEM complets utilisés
# dans les tests ci-dessous sont construits par concaténation, jamais comme
# une chaîne littérale contiguë « -----BEGIN ... PRIVATE KEY----- » /
# « -----END ... PRIVATE KEY----- ». Sinon, `collect` masque le fichier de
# tests lui-même (comme n'importe quelle vraie clé privée) quand ce fichier
# est relu par cross-review.
PEM_BEGIN_RSA = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END_RSA = "-----END " + "RSA PRIVATE KEY-----"
PEM_BEGIN_EC = "-----BEGIN " + "EC PRIVATE KEY-----"
PEM_END_EC = "-----END " + "EC PRIVATE KEY-----"
PEM_END_GENERIC = "-----END " + "PRIVATE KEY-----"


def base_config():
    """Config de test, structurellement proche de cross-review.json mais
    réduite, pour ne pas dépendre du fichier réel du dépôt."""
    return {
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "timeout_s": 5,
        "max_input_chars": 2000,
        "max_tokens": 1000,
        "temperature": 0.2,
        "reasoning": {"effort": "medium"},
        "provider_defaults": {"allow_fallbacks": False, "data_collection": "deny"},
        "log_path": "~/cross-review-test-log.jsonl",
        "code_review_min_lines": 40,
        "modes": {
            "plan": ["z-ai/glm-5.3", "google/gemini-3.8-flash"],
            "code": ["z-ai/glm-5.3"],
        },
        "models": {
            "z-ai/glm-5.3": {
                "label": "GLM-5.3",
                "hebergeurs": [
                    {"slug": "inceptron", "name": "Inceptron", "pays": "SE", "ue": True},
                    {"slug": "mistral", "name": "Mistral", "pays": "FR", "ue": None},
                    {"slug": "together", "name": "Together", "pays": "US", "ue": False},
                ],
            },
            "google/gemini-3.8-flash": {
                "label": "Gemini 3.8 Flash",
                "hebergeurs": [
                    {"slug": "google-vertex/global", "name": "Google", "pays": "US", "ue": False},
                    {"slug": "google-ai-studio", "name": "Google AI Studio", "pays": "US", "ue": False},
                ],
            },
        },
        "ignore_chine": [
            "baidu", "deepseek", "tencent", "xiaomi", "streamlake", "nex-agi",
            "alibaba", "siliconflow", "z-ai", "moonshotai", "minimax", "stepfun",
        ],
        "sensitive_globs": [
            ".env", ".env.*", "*.env", "wp-config.php", "wp-config-*.php",
            "*.sql", "*.sql.gz", "*.dump", "*.sqlite", "*.sqlite3", "*.db",
            "*.pem", "*.key", "*.p12", "*.pfx", "*.crt", "id_rsa*", "id_ed25519*",
            "*.kdbx", "auth.json", ".htpasswd", ".npmrc", ".pgpass", ".netrc",
            "*credentials*", "*secret*", "*.log",
            "*.zip", "*.tar", "*.tar.*", "*.tgz", "*.gz", "*.7z", "*.rar",
            "wp-content/uploads/**", "node_modules/**", "vendor/**",
        ],
        "extra_secret_patterns": [],
    }


@contextlib.contextmanager
def captured_stdout():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


@contextlib.contextmanager
def captured_stderr():
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        yield buf


# ---------------------------------------------------------------------------
# Diff : découpage et filtrage
# ---------------------------------------------------------------------------

class TestDiffSplitFilter(unittest.TestCase):
    def test_split_two_sections(self):
        diff = (
            "diff --git a/foo.php b/foo.php\n"
            "index 111..222 100644\n"
            "--- a/foo.php\n"
            "+++ b/foo.php\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
            "diff --git a/bar.js b/bar.js\n"
            "--- a/bar.js\n"
            "+++ b/bar.js\n"
            "@@ -1 +1 @@\n"
            "-a\n"
            "+b\n"
        )
        sections = cr.split_diff_sections(diff)
        self.assertEqual(len(sections), 2)
        self.assertTrue(sections[0].startswith("diff --git a/foo.php"))
        self.assertTrue(sections[1].startswith("diff --git a/bar.js"))

    def test_extract_path_normal(self):
        section = "diff --git a/x/foo.php b/x/foo.php\n--- a/x/foo.php\n+++ b/x/foo.php\n@@ -1 +1 @@\n-a\n+b\n"
        self.assertEqual(cr.extract_path_from_section(section), "x/foo.php")

    def test_extract_path_deletion(self):
        section = "diff --git a/old.php b/old.php\n--- a/old.php\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n"
        self.assertEqual(cr.extract_path_from_section(section), "old.php")

    def test_sensitive_glob_simple(self):
        self.assertTrue(cr.matches_sensitive("wp-config.php", ["wp-config.php"])[0])
        self.assertTrue(cr.matches_sensitive("dump.sql", ["*.sql"])[0])
        self.assertFalse(cr.matches_sensitive("readme.md", ["*.sql"])[0])

    def test_sensitive_glob_double_star(self):
        globs = ["wp-content/uploads/**"]
        self.assertTrue(cr.matches_sensitive("wp-content/uploads/2024/img.jpg", globs)[0])
        self.assertTrue(cr.matches_sensitive("site/wp-content/uploads/img.jpg", globs)[0])
        self.assertFalse(cr.matches_sensitive("wp-content/plugins/foo.php", globs)[0])

    def test_binary_section_detected(self):
        section = "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n"
        self.assertTrue(cr.is_binary_section(section))
        section2 = "diff --git a/img.png b/img.png\nGIT binary patch\nliteral 10\n"
        self.assertTrue(cr.is_binary_section(section2))

    def test_binary_mention_in_hunk_body_not_binary_section(self):
        # Point 1 (revue croisée du 2026-09-28) : « Binary files ... differ »
        # cité dans le CORPS d'un hunk (tests, documentation) ne rend pas la
        # section binaire ; seule une mention dans l'en-tête (avant le
        # premier « @@ ») compte.
        section = (
            "diff --git a/tests/test_x.py b/tests/test_x.py\n"
            "--- a/tests/test_x.py\n+++ b/tests/test_x.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-old\n"
            "+self.assertIn(\"Binary files a/x and b/x differ\", out)\n"
        )
        self.assertFalse(cr.is_binary_section(section))

    def test_binary_mention_in_header_is_binary_section(self):
        section = (
            "diff --git a/img.png b/img.png\n"
            "index 111..222 100644\n"
            "Binary files a/img.png and b/img.png differ\n"
        )
        self.assertTrue(cr.is_binary_section(section))

    def test_filter_diff_sections_removes_sensitive_and_binary(self):
        diff = (
            "diff --git a/foo.php b/foo.php\n--- a/foo.php\n+++ b/foo.php\n@@ -1 +1 @@\n-a\n+b\n"
            "diff --git a/wp-config.php b/wp-config.php\n--- a/wp-config.php\n+++ b/wp-config.php\n"
            "@@ -1 +1 @@\n-x\n+y\n"
            "diff --git a/logo.png b/logo.png\nBinary files a/logo.png and b/logo.png differ\n"
        )
        globs = ["wp-config.php"]
        filtered, kept_paths, excluded = cr.filter_diff_sections(diff, globs)
        self.assertEqual(kept_paths, ["foo.php"])
        reasons = {e["fichier"]: e["raison"] for e in excluded}
        self.assertEqual(reasons.get("wp-config.php"), "sensible")
        self.assertEqual(reasons.get("logo.png"), "binaire")
        self.assertIn("foo.php", filtered)
        self.assertNotIn("wp-config.php", filtered)

    def test_count_lines_changed_excludes_headers(self):
        diff = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n-old1\n-old2\n+new1\n+new2\n"
        self.assertEqual(cr.count_lines_changed(diff), 4)

    def test_is_probably_text(self):
        self.assertTrue(cr.is_probably_text(b"hello world\n"))
        self.assertFalse(cr.is_probably_text(b"\x00\x01\x02binary"))


# ---------------------------------------------------------------------------
# Masquage des secrets
# ---------------------------------------------------------------------------

class TestMasking(unittest.TestCase):
    def test_define_wp_constant(self):
        line = "define( 'DB_PASSWORD', 'FAUX-SECRET-TEST-abcdef' );"
        out, types = cr.mask_line(line)
        self.assertNotIn("FAUX-SECRET-TEST-abcdef", out)
        self.assertIn("[MASQUÉ]", out)
        self.assertIn("define_constant", types)

    def test_define_keyword_token(self):
        line = "define( 'DEMO_API_TOKEN', 'FAUX-SECRET-TEST-plan-123456' );"
        out, types = cr.mask_line(line)
        self.assertNotIn("FAUX-SECRET-TEST-plan-123456", out)
        self.assertIn("define_constant", types)

    def test_define_unrelated_constant_not_masked(self):
        line = "define( 'WP_DEBUG', true );"
        out, types = cr.mask_line(line)
        self.assertEqual(out, line)
        self.assertEqual(types, [])

    def test_assignment_quoted(self):
        line = "$wpdb_password = 'un-secret-assez-long';"
        out, types = cr.mask_line(line)
        self.assertNotIn("un-secret-assez-long", out)
        self.assertIn("assignment", types)

    def test_assignment_bare_php_array(self):
        line = "$openrouter_token = ABCDEFGHIJKL1234567890;"
        out, types = cr.mask_line(line)
        self.assertNotIn("ABCDEFGHIJKL1234567890", out)

    def test_assignment_does_not_mask_function_call(self):
        line = "$token = get_token();"
        out, types = cr.mask_line(line)
        self.assertEqual(out, line)

    def test_private_key_block(self):
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + "\n"
            + "MIIEpAIBAAKCAQEA1234567890abcdefgh\n"
            "morekeydataherexxxxxxxxxxxxxxxxxxx\n"
            + PEM_END_RSA + "\n"
            + "apres\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertNotIn("MIIEpAIBAAKCAQEA1234567890abcdefgh", joined)
        self.assertIn("avant", joined)
        self.assertIn("apres", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key", types)

    def test_private_key_mismatched_begin_end_types(self):
        # Point 4a : BEGIN + RSA PRIVATE KEY / END + PRIVATE KEY (types
        # différents) doit quand même être reconnu comme un bloc complet.
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + "\n"
            + "MIIEpAIBAAKCAQEA1234567890abcdefgh\n"
            + PEM_END_GENERIC + "\n"
            + "apres\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertNotIn("MIIEpAIBAAKCAQEA1234567890abcdefgh", joined)
        self.assertIn("avant", joined)
        self.assertIn("apres", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key", types)

    def test_private_key_truncated_plain_text_masked_until_end(self):
        # Règle prudente et simple (revue croisée du 2026-09-28, retour
        # arrière sur la fuite K1 d'un lot précédent) : pas de ligne END
        # dans le même contexte (texte brut, sans préfixe de diff) -> tout
        # est masqué jusqu'à la fin du contexte, en un seul [MASQUÉ], y
        # compris « fin du fichier. » qui ne ressemble pourtant pas à du
        # corps de clé : mieux vaut sur-masquer que risquer de laisser fuir
        # un morceau de clé.
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + "\n"
            + "MIIEpAIBAAKCAQEA1234567890abcdefgh\n"
            "morekeydataherexxxxxxxxxxxxxxxxxxx\n"
            "fin du fichier.\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        for fragment in (
            "MIIEpAIBAAKCAQEA1234567890abcdefgh",
            "morekeydataherexxxxxxxxxxxxxxxxxxx",
            "fin du fichier.",
        ):
            self.assertNotIn(fragment, joined)
        self.assertIn("avant", joined)
        self.assertEqual(joined.count(cr.MASK), 1)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    def test_private_key_truncated_encrypted_pem_body_absent(self):
        # K1 (revue croisée du 2026-09-28) : une clé PEM chiffrée tronquée
        # (BEGIN, Proc-Type, DEK-Info, ligne vide, corps sans END) ne doit
        # plus laisser passer le corps en clair (avant, le masquage
        # s'arrêtait à la ligne vide qui sépare les en-têtes PEM du corps).
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + "\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,1234567890ABCDEF\n"
            "\n"
            "MIIEpAIBAAKCAQEA1234567890abcdefgh\n"
            "morekeydataherexxxxxxxxxxxxxxxxxxx\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        for fragment in (
            "Proc-Type",
            "DEK-Info",
            "MIIEpAIBAAKCAQEA1234567890abcdefgh",
            "morekeydataherexxxxxxxxxxxxxxxxxxx",
        ):
            self.assertNotIn(fragment, joined)
        self.assertIn("avant", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    def test_private_key_end_before_begin_on_same_line_body_after_masked(self):
        # G2, cas inversé : END et BEGIN sur la même ligne, mais le END
        # précède le BEGIN au lieu de le suivre. Le END n'est donc pas
        # trouvé après m.end() -> la ligne est traitée comme un BEGIN
        # normal, ici tronqué (pas d'autre END dans le contexte), et le
        # corps qui suit est masqué.
        text = (
            "avant\n"
            + PEM_END_RSA + " " + PEM_BEGIN_RSA + "\n"
            + "MIIEpAIBAAKCAQEA1234567890abcdefgh\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertIn("avant", joined)
        self.assertNotIn("MIIEpAIBAAKCAQEA1234567890abcdefgh", joined)
        self.assertNotIn("BEGIN " + "RSA PRIVATE KEY", joined)
        self.assertNotIn("END " + "RSA PRIVATE KEY", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    def test_private_key_truncated_does_not_leak_into_next_file(self):
        # Masquage limité au même contexte (c'était déjà le cas avant le lot
        # qui a introduit les fuites K1/K2) : clé tronquée dans un fichier
        # (a.py), suivie d'une autre section de diff (tests/fixture.py) avec
        # une clé EC complète. La règle prudente masque TOUT le contexte
        # a.py jusqu'à sa fin, y compris « +def foo():» qui ne ressemble
        # pourtant pas à du corps de clé (mieux vaut sur-masquer) ; mais ce
        # masquage ne déborde pas sur le fichier suivant du diff, qui reste
        # traité normalement (clé complète masquée, « +x = 1 » après le END
        # visible).
        pairs = [
            ("diff --git a/a.py b/a.py", "a.py"),
            ("--- a/a.py", "a.py"),
            ("+++ b/a.py", "a.py"),
            ("@@ -1,3 +1,6 @@", "a.py"),
            ("+avant", "a.py"),
            ("+" + PEM_BEGIN_RSA, "a.py"),
            ("+MIIEpAIBAAKCAQEA1234567890abcdefgh", "a.py"),
            ("+morekeydataherexxxxxxxxxxxxxxxxxxx", "a.py"),
            ("+def foo():", "a.py"),
            ("diff --git a/tests/fixture.py b/tests/fixture.py", "tests/fixture.py"),
            ("--- a/tests/fixture.py", "tests/fixture.py"),
            ("+++ b/tests/fixture.py", "tests/fixture.py"),
            ("@@ -1,3 +1,8 @@", "tests/fixture.py"),
            ("+" + PEM_BEGIN_EC, "tests/fixture.py"),
            ("+MIGkAgEBBDAECKEYBODYHERE1234567890", "tests/fixture.py"),
            ("+" + PEM_END_EC, "tests/fixture.py"),
            ("+x = 1", "tests/fixture.py"),
        ]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertIn("diff --git a/tests/fixture.py", joined)
        self.assertIn("+x = 1", joined)
        self.assertIn("+avant", joined)
        for fragment in (
            "MIIEpAIBAAKCAQEA1234567890abcdefgh",
            "morekeydataherexxxxxxxxxxxxxxxxxxx",
            "+def foo():",
            "MIGkAgEBBDAECKEYBODYHERE1234567890",
        ):
            self.assertNotIn(fragment, joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)
        self.assertIn("private_key", types)

    def test_private_key_truncated_indented_body_plain_text(self):
        # Corps de clé tronquée indenté de 4 espaces en texte brut : la
        # règle prudente masque tout ce qui suit le BEGIN dans le même
        # contexte, quelle que soit l'indentation.
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + "\n"
            + "    MIIEpAIBAAKCAQEA1234567890abcdefgh\n"
            "    morekeydataherexxxxxxxxxxxxxxxxxxx\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertNotIn("MIIEpAIBAAKCAQEA1234567890abcdefgh", joined)
        self.assertNotIn("morekeydataherexxxxxxxxxxxxxxxxxxx", joined)
        self.assertIn("avant", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    def test_private_key_truncated_two_hunks_second_hunk_masked(self):
        # K2 (revue croisée du 2026-09-28) : une clé tronquée modifiée en
        # deux hunks d'un même fichier ne doit plus laisser passer le
        # second hunk en clair (avant, le masquage s'arrêtait à la ligne
        # d'en-tête de hunk « @@ -10,5 +10,5 @@ »).
        pairs = [
            ("+avant", "fichier.py"),
            ("+" + PEM_BEGIN_RSA, "fichier.py"),
            ("+MIIEpAIBAAKCAQEA1234567890abcdefgh", "fichier.py"),
            ("@@ -10,5 +10,5 @@", "fichier.py"),
            ("+encoreapreshunkAAAAAAAAAAAAAAAAAAAA", "fichier.py"),
        ]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertNotIn("MIIEpAIBAAKCAQEA1234567890abcdefgh", joined)
        self.assertNotIn("encoreapreshunkAAAAAAAAAAAAAAAAAAAA", joined)
        self.assertIn("+avant", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    def test_private_key_two_begins_same_file_search_does_not_stop_at_begin(self):
        # Deux BEGIN successifs dans le même fichier, le premier sans END
        # avant le second BEGIN : la recherche de END ne s'arrête plus au
        # second BEGIN rencontré en chemin (règle prudente et simple), donc
        # le END du second bloc compte aussi pour le premier -> tout est
        # masqué en un seul bloc « private_key » (pas « tronquée », un END a
        # bien été trouvé dans le contexte), et la ligne qui suit le END
        # reste visible.
        pairs = [
            ("+avant", "fichier.py"),
            ("+" + PEM_BEGIN_RSA, "fichier.py"),
            ("+premierMORCEAUAAAAAAAAAAAAAAAAAAAA", "fichier.py"),
            ("+" + PEM_BEGIN_EC, "fichier.py"),
            ("+deuxiemeMORCEAUBBBBBBBBBBBBBBBBBBB", "fichier.py"),
            ("+" + PEM_END_EC, "fichier.py"),
            ("+apres", "fichier.py"),
        ]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        for fragment in (
            "premierMORCEAUAAAAAAAAAAAAAAAAAAAA",
            "deuxiemeMORCEAUBBBBBBBBBBBBBBBBBBB",
            "BEGIN " + "EC PRIVATE KEY",
            "END " + "EC PRIVATE KEY",
        ):
            self.assertNotIn(fragment, joined)
        self.assertIn("+avant", joined)
        self.assertIn("+apres", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key", types)

    def test_private_key_begin_end_same_line(self):
        # Point G2 (revue croisée du 2026-09-28) : BEGIN et END sur la même
        # ligne (clé vide ou d'un seul tenant) ne doivent masquer que cette
        # ligne, pas ce qui suit.
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + " " + PEM_END_RSA + "\n"
            + "apres\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertIn("avant", joined)
        self.assertIn("apres", joined)
        self.assertNotIn("BEGIN " + "RSA PRIVATE KEY", joined)
        # Une seule ligne masquée pour le bloc BEGIN/END : "avant",
        # "[MASQUÉ]" et "apres" -> 3 lignes en tout.
        self.assertEqual(len(out_lines), 3)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key", types)

    def test_private_key_begin_end_begin_same_line_treated_as_truncated(self):
        # Point 4 (revue croisée du 2026-09-28) : un second BEGIN suit le
        # END sur la même ligne, sans END après lui sur cette ligne -> ce
        # n'est plus le cas simple G2, la ligne démarre une clé tronquée et
        # les lignes suivantes du même contexte sont masquées (jusqu'à la
        # fin du contexte, faute de END).
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + " " + PEM_END_RSA + " " + PEM_BEGIN_RSA + "\n"
            + "corps_de_cle_qui_suit\n"
            "encore_du_corps\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertIn("avant", joined)
        self.assertNotIn("corps_de_cle_qui_suit", joined)
        self.assertNotIn("encore_du_corps", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    # L'ancien test « survit à la relecture du vrai fichier de tests »
    # (test_private_key_masking_survives_most_of_real_test_file) n'a plus de
    # sens avec la règle prudente : dès qu'un BEGIN tronqué apparaît (ce
    # fichier en contient plusieurs, utilisés par les tests ci-dessus), tout
    # le contexte qui suit est masqué jusqu'à sa fin, donc l'essentiel du
    # fichier disparaîtrait. La garantie « le masquage s'arrête bien à la
    # fin du contexte, sans déborder » est désormais vérifiée par
    # test_private_key_truncated_does_not_leak_into_next_file ci-dessus.

    def test_token_patterns(self):
        cases = {
            "openrouter_key": "sk-or-v1-abcdefghijklmnopqrstuvwxyz123456",
            "anthropic_key": "sk-ant-abcdefghijklmnopqrstuvwxyz1234",
            "aws_access_key": "AKIAABCDEFGHIJKLMNOP",
            "github_token": "ghp_" + "a" * 40,
            "github_pat": "github_pat_" + "a" * 30,
            "slack_token": "xoxb-1234567890-abcdefghij",
            "google_api_key": "AIza" + "a" * 35,
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwx",
        }
        for expected_type, token in cases.items():
            with self.subTest(expected_type=expected_type):
                line = f"const X = \"{token}\";"
                out, types = cr.mask_line(line)
                self.assertNotIn(token, out, f"{expected_type} pas masqué")
                self.assertIn(expected_type, types)

    def test_url_credentials(self):
        line = "DATABASE_URL=postgres://dbuser:FAUX-motdepasse-URL@host:5432/db"
        out, types = cr.mask_line(line)
        self.assertNotIn("FAUX-motdepasse-URL", out)
        self.assertIn("dbuser", out)
        self.assertIn("url_credentials", types)

    def test_env_var_value_masked(self):
        os.environ["CROSS_REVIEW_TEST_SECRET_TOKEN"] = "valeurSecreteDeTest123456"
        try:
            value = os.environ["CROSS_REVIEW_TEST_SECRET_TOKEN"]
            line = f"CROSS_REVIEW_TEST_SECRET_TOKEN={value}"
            out, types = cr.mask_line(line)
            self.assertNotIn(value, out)
            self.assertTrue(any(t.startswith("env:") for t in types))
            self.assertIn("env:CROSS_REVIEW_TEST_SECRET_TOKEN", types)
        finally:
            del os.environ["CROSS_REVIEW_TEST_SECRET_TOKEN"]

    def test_env_var_name_without_keyword_not_masked_by_family5(self):
        line = "SOME_PLAIN_VALUE=abcdefghijklmnopqrstuvwxyz"
        out, types = cr.mask_line(line)
        self.assertEqual(out, line)

    def test_extra_secret_patterns(self):
        line = "id_interne = XYZ-000111222"
        out, types = cr.mask_line(line, extra_patterns=[r"XYZ-\d{9}"])
        self.assertNotIn("XYZ-000111222", out)
        self.assertTrue(any(t.startswith("config_extra") for t in types))

    def test_idempotent(self):
        line = "define( 'DB_PASSWORD', 'FAUX-SECRET-TEST-abcdef' );"
        out1, _ = cr.mask_line(line)
        out2, _ = cr.mask_line(out1)
        self.assertEqual(out1, out2)

    def test_idempotent_full_text_with_context(self):
        text = (
            "define( 'DB_PASSWORD', 'FAUX-SECRET-TEST-abcdef' );\n"
            "$token = 'un-secret-assez-long';\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out1, _ = cr.mask_text_with_context(pairs)
        pairs2 = [(l, "contenu") for l in out1]
        out2, secrets2 = cr.mask_text_with_context(pairs2)
        self.assertEqual(out1, out2)
        self.assertEqual(secrets2, [])

    def test_mask_diff_with_file_context_tracks_path(self):
        diff = (
            "diff --git a/wp-content/plugins/x.php b/wp-content/plugins/x.php\n"
            "--- a/wp-content/plugins/x.php\n"
            "+++ b/wp-content/plugins/x.php\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+$secret_token = 'un-secret-assez-long-ici';\n"
        )
        masked, secrets_masked = cr.mask_diff_with_file_context(diff)
        self.assertNotIn("un-secret-assez-long-ici", masked)
        self.assertTrue(any(s["fichier"] == "wp-content/plugins/x.php" for s in secrets_masked))


# ---------------------------------------------------------------------------
# Nettoyage des blocs de code et analyse des findings
# ---------------------------------------------------------------------------

class TestCodeBlockStripping(unittest.TestCase):
    def test_strip_closed_block(self):
        text = "avant\n```php\necho 'x';\n```\napres"
        clean, n = cr.strip_code_blocks(text)
        self.assertEqual(n, 1)
        self.assertNotIn("echo 'x';", clean)
        self.assertIn("bloc de code retiré", clean)

    def test_strip_unterminated_block(self):
        text = "avant\n```php\necho 'x';\nsuite sans fermeture"
        clean, n = cr.strip_code_blocks(text)
        self.assertEqual(n, 1)
        self.assertNotIn("sans fermeture", clean)

    def test_strip_tilde_block(self):
        text = "a\n~~~\ncode\n~~~\nb"
        clean, n = cr.strip_code_blocks(text)
        self.assertEqual(n, 1)


class TestFindingsParsing(unittest.TestCase):
    def test_clean_format(self):
        text = (
            "### [BLOQUANT] Migration en prod sans sauvegarde\n"
            "- **Où** : Plan, § Migration\n"
            "- **Problème** : aucune sauvegarde avant migration.\n"
            "- **Pourquoi** : perte de données possible.\n"
        )
        findings, rien = cr.parse_findings(text)
        self.assertFalse(rien)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severite"], "BLOQUANT")
        self.assertEqual(f["titre"], "Migration en prod sans sauvegarde")
        self.assertIn("Migration", f["ou"])
        self.assertTrue(f["probleme"])
        self.assertTrue(f["pourquoi"])

    def test_tolerant_format_no_bold_no_accents(self):
        text = (
            "## IMPORTANT - Nonce absent\n"
            "- Ou: wp-content/plugins/x.php:42\n"
            "- Probleme: pas de verification du nonce.\n"
            "- Pourquoi : appel AJAX exploitable.\n"
        )
        findings, rien = cr.parse_findings(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severite"], "IMPORTANT")
        self.assertTrue(findings[0]["ou"])
        self.assertTrue(findings[0]["probleme"])
        self.assertTrue(findings[0]["pourquoi"])

    def test_rien_a_signaler(self):
        findings, rien = cr.parse_findings("RIEN À SIGNALER")
        self.assertEqual(findings, [])
        self.assertTrue(rien)

    def test_rien_a_signaler_without_accent(self):
        findings, rien = cr.parse_findings("RIEN A SIGNALER\n")
        self.assertTrue(rien)

    def test_multiple_findings_order(self):
        text = (
            "### [BLOQUANT] Premier\n"
            "- **Où** : a\n- **Problème** : b\n- **Pourquoi** : c\n"
            "### [MINEUR] Deuxieme\n"
            "- **Où** : d\n- **Problème** : e\n- **Pourquoi** : f\n"
        )
        findings, rien = cr.parse_findings(text)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severite"], "BLOQUANT")
        self.assertEqual(findings[1]["severite"], "MINEUR")

    def test_compute_prefixes_collision(self):
        prefixes = cr.compute_prefixes(["GLM-5.3", "Gemini 3.8 Flash"])
        self.assertEqual(prefixes["GLM-5.3"], "GL")
        self.assertEqual(prefixes["Gemini 3.8 Flash"], "GE")

    def test_compute_prefixes_no_collision(self):
        prefixes = cr.compute_prefixes(["GLM-5.3"])
        self.assertEqual(prefixes["GLM-5.3"], "G")

    def test_compute_prefixes_two_letter_collision_suffixed(self):
        # Point 6b : "Gemini" et "Gemma" produisent tous les deux "GE" avec
        # le calcul à deux lettres ; il faut les distinguer.
        # Point C8 : le suffixe de désambiguïsation est une lettre (pas un
        # chiffre), pour ne pas produire d'identifiant ambigu après
        # assign_ids (ex. "GE2" + "1" = "GE21").
        prefixes = cr.compute_prefixes(["Gemini", "Gemma"])
        self.assertEqual(len(set(prefixes.values())), 2)
        self.assertEqual(prefixes["Gemini"], "GE")
        self.assertEqual(prefixes["Gemma"], "GEB")
        for p in prefixes.values():
            self.assertFalse(any(c.isdigit() for c in p))

    def test_compute_prefixes_labels_without_letters_no_exception(self):
        # Point 6a : un label sans aucune lettre ne doit plus lever
        # d'IndexError (alphas vide dans la branche collision).
        # Point C8 : toujours pas de chiffre dans le suffixe de
        # désambiguïsation.
        prefixes = cr.compute_prefixes(["123", "456"])
        self.assertEqual(len(prefixes), 2)
        self.assertEqual(len(set(prefixes.values())), 2)
        for p in prefixes.values():
            self.assertFalse(any(c.isdigit() for c in p))

    def test_assign_ids(self):
        findings = [{"severite": "BLOQUANT", "titre": "a", "ou": "x", "probleme": "y", "pourquoi": "z"}] * 2
        findings = [dict(f) for f in findings]
        cr.assign_ids(findings, "GL")
        self.assertEqual(findings[0]["id"], "GL1")
        self.assertEqual(findings[1]["id"], "GL2")


# ---------------------------------------------------------------------------
# Normalisation et contrôle d'hébergeur
# ---------------------------------------------------------------------------

class TestHosterCheck(unittest.TestCase):
    def setUp(self):
        self.hosters = [
            {"slug": "google-vertex/global", "name": "Google", "pays": "US", "ue": False},
            {"slug": "google-ai-studio", "name": "Google AI Studio", "pays": "US", "ue": False},
        ]

    def test_normalize(self):
        self.assertEqual(cr.normalize_hoster_token("Google AI Studio"), "googleaistudio")
        self.assertEqual(cr.normalize_hoster_token("google-ai-studio"), "googleaistudio")
        self.assertEqual(cr.normalize_hoster_token("Inceptron"), "inceptron")

    def test_match_by_name(self):
        ok, matched = cr.hoster_matches("Google AI Studio", self.hosters)
        self.assertTrue(ok)
        self.assertEqual(matched["slug"], "google-ai-studio")

    def test_match_by_slug_base(self):
        ok, matched = cr.hoster_matches("google-ai-studio", self.hosters)
        self.assertTrue(ok)

    def test_inceptron_match(self):
        hosters = [{"slug": "inceptron", "name": "Inceptron", "pays": "SE", "ue": True}]
        ok, matched = cr.hoster_matches("Inceptron", hosters)
        self.assertTrue(ok)
        ok2, _ = cr.hoster_matches("inceptron", hosters)
        self.assertTrue(ok2)

    def test_no_match(self):
        ok, matched = cr.hoster_matches("DeepInfra", self.hosters)
        self.assertFalse(ok)

    def test_validate_no_chinese_hosters_passes_on_clean_config(self):
        config = base_config()
        err = cr.validate_no_chinese_hosters(["z-ai/glm-5.3"], config)
        self.assertIsNone(err)

    def test_validate_no_chinese_hosters_rejects(self):
        config = base_config()
        config["models"]["bad/model"] = {
            "label": "Bad Model",
            "hebergeurs": [{"slug": "siliconflow", "name": "SiliconFlow", "pays": "CN", "ue": False}],
        }
        err = cr.validate_no_chinese_hosters(["bad/model"], config)
        self.assertIsNotNone(err)
        self.assertIn("siliconflow", err)


# ---------------------------------------------------------------------------
# Corps de requête (dry-run)
# ---------------------------------------------------------------------------

class TestRequestBody(unittest.TestCase):
    def test_build_request_body_provider_block(self):
        config = base_config()
        model_slug = "z-ai/glm-5.3"
        model_cfg = config["models"][model_slug]
        body = cr.build_request_body(model_slug, model_cfg, "system", "user", config)
        self.assertEqual(body["provider"]["only"], ["inceptron", "mistral", "together"])
        self.assertEqual(body["provider"]["order"], ["inceptron", "mistral", "together"])
        self.assertEqual(body["provider"]["ignore"], config["ignore_chine"])
        self.assertEqual(body["provider"]["allow_fallbacks"], False)
        self.assertEqual(body["provider"]["data_collection"], "deny")
        self.assertEqual(body["reasoning"], config["reasoning"])
        self.assertEqual(body["model"], model_slug)

    def test_reasoning_model_override_replaces_global_without_merge(self):
        # Un modèle avec son propre 'reasoning' (ex. GLM-5.3 : effort high,
        # incompatible avec max_tokens) remplace entièrement celui de la
        # racine, sans fusion.
        config = base_config()
        model_slug = "z-ai/glm-5.3"
        model_cfg = dict(config["models"][model_slug])
        model_cfg["reasoning"] = {"effort": "high"}
        body = cr.build_request_body(model_slug, model_cfg, "system", "user", config)
        self.assertEqual(body["reasoning"], {"effort": "high"})
        self.assertNotIn("max_tokens", body["reasoning"])

    def test_reasoning_global_used_when_model_has_none(self):
        config = base_config()
        model_slug = "google/gemini-3.8-flash"
        model_cfg = config["models"][model_slug]
        self.assertNotIn("reasoning", model_cfg)
        body = cr.build_request_body(model_slug, model_cfg, "system", "user", config)
        self.assertEqual(body["reasoning"], config["reasoning"])

    def test_redacted_body_replaces_content(self):
        config = base_config()
        model_slug = "z-ai/glm-5.3"
        body = cr.build_request_body(model_slug, config["models"][model_slug], "system prompt", "contenu utilisateur", config)
        redacted = cr.redacted_body_for_dry_run(body)
        self.assertTrue(redacted["messages"][0]["content"].startswith("<"))
        self.assertTrue(redacted["messages"][0]["content"].endswith("caractères>"))
        self.assertNotIn("system prompt", redacted["messages"][0]["content"])

    def test_dry_run_no_attribution_headers(self):
        # Le corps de requête ne doit contenir ni HTTP-Referer ni X-Title.
        config = base_config()
        model_slug = "z-ai/glm-5.3"
        body = cr.build_request_body(model_slug, config["models"][model_slug], "s", "u", config)
        self.assertNotIn("HTTP-Referer", json.dumps(body))
        self.assertNotIn("X-Title", json.dumps(body))

    def test_cmd_review_dry_run_output(self):
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text("# Plan\nContenu de test sans secret.\n", encoding="utf-8")
            args = Namespace(
                mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=None, run_id=None, dry_run=True, timeout=None,
            )
            with captured_stdout() as out:
                code = cr.cmd_review(args, config)
            self.assertEqual(code, 0)
            printed = out.getvalue()
            self.assertIn('"only": [', printed)
            self.assertIn("inceptron", printed)
            self.assertIn('"allow_fallbacks": false', printed)
            self.assertIn('"data_collection": "deny"', printed)


# ---------------------------------------------------------------------------
# process_model_response (simulation de réponse OpenRouter)
# ---------------------------------------------------------------------------

class TestProcessModelResponse(unittest.TestCase):
    def setUp(self):
        self.config = base_config()
        self.model_slug = "z-ai/glm-5.3"
        self.model_cfg = self.config["models"][self.model_slug]

    def fake_ok_result(self, content, provider="Inceptron", finish_reason="stop"):
        return {
            "ok": True,
            "data": {
                "id": "gen-abc123",
                "model": self.model_slug,
                "provider": provider,
                "usage": {
                    "prompt_tokens": 12345,
                    "completion_tokens": 2345,
                    "completion_tokens_details": {"reasoning_tokens": 1200},
                    "cost": 0.0123,
                },
                "choices": [{"message": {"content": content}, "finish_reason": finish_reason}],
            },
        }

    def test_ok_response_with_findings(self):
        content = (
            "### [BLOQUANT] Un souci\n"
            "- **Où** : plugin.php:10\n- **Problème** : bug.\n- **Pourquoi** : casse tout.\n"
        )
        result = cr.process_model_response(
            self.fake_ok_result(content), self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 1.2, self.config
        )
        self.assertEqual(result["statut"], "ok")
        self.assertTrue(result["hebergeur_ok"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["id"], "G1")
        self.assertTrue(result["format_ok"])
        self.assertEqual(result["cout_usd"], 0.0123)
        self.assertEqual(result["tokens"]["reasoning"], 1200)

    def test_hors_liste_blanche(self):
        content = "RIEN À SIGNALER"
        result = cr.process_model_response(
            self.fake_ok_result(content, provider="DeepInfra"),
            self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 1.0, self.config,
        )
        self.assertEqual(result["statut"], "hors_liste_blanche")
        self.assertFalse(result["hebergeur_ok"])

    def test_echec_result(self):
        result = cr.process_model_response(
            {"ok": False, "error": "HTTP 502"}, self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 0.5, self.config
        )
        self.assertEqual(result["statut"], "echec")
        self.assertEqual(result["erreur"], "HTTP 502")

    def test_empty_content_length_finish_reason(self):
        result = cr.process_model_response(
            self.fake_ok_result("", finish_reason="length"),
            self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 3.0, self.config,
        )
        self.assertEqual(result["statut"], "echec")
        self.assertIn("raisonnement", result["erreur"])

    def test_code_block_removed_breaks_format_ok(self):
        content = "```php\necho 1;\n```\n### [MINEUR] x\n- **Où** : a\n- **Problème** : b\n- **Pourquoi** : c\n"
        result = cr.process_model_response(
            self.fake_ok_result(content), self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 1.0, self.config
        )
        self.assertEqual(result["blocs_retires"], 1)
        self.assertFalse(result["format_ok"])

    def test_rien_a_signaler_result(self):
        result = cr.process_model_response(
            self.fake_ok_result("RIEN À SIGNALER"), self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 1.0, self.config
        )
        self.assertTrue(result["rien_a_signaler"])
        self.assertTrue(result["format_ok"])

    def test_budget_epuise_hoster_liste_blanche_echec(self):
        # Hébergeur (Inceptron) dans la liste blanche du modèle : budget de
        # raisonnement épuisé reste un simple échec, mais l'hébergeur et le
        # coût restent renseignés (pas de relance : retirée le 2026-09-28).
        result = cr.process_model_response(
            self.fake_ok_result("", provider="Inceptron", finish_reason="length"),
            self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 3.0, self.config,
        )
        self.assertEqual(result["statut"], "echec")
        self.assertIn("raisonnement", result["erreur"])
        self.assertEqual(result["hebergeur"], "Inceptron")
        self.assertTrue(result["hebergeur_ok"])
        self.assertEqual(result["cout_usd"], 0.0123)

    def test_budget_epuise_hoster_hors_liste_blanche(self):
        # Hébergeur (DeepInfra) absent de la liste blanche du modèle de
        # test : même en cas de budget épuisé, le statut doit être
        # 'hors_liste_blanche' (code de sortie 4), pas un simple échec,
        # l'info « budget épuisé » restant dans 'erreur'.
        result = cr.process_model_response(
            self.fake_ok_result("", provider="DeepInfra", finish_reason="length"),
            self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 3.0, self.config,
        )
        self.assertEqual(result["statut"], "hors_liste_blanche")
        self.assertFalse(result["hebergeur_ok"])
        self.assertIn("raisonnement", result["erreur"])

    def test_reponse_tronquee_garde_statut_ok(self):
        content = "### [MINEUR] x\n- **Où** : a\n- **Problème** : b\n- **Pourquoi** : c\n"
        result = cr.process_model_response(
            self.fake_ok_result(content, finish_reason="length"),
            self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 1.0, self.config,
        )
        self.assertEqual(result["statut"], "ok")
        self.assertTrue(result["tronque"])
        md = cr.render_reviewer_markdown(result, self.model_cfg)
        self.assertIn("tronquée", md)

    def test_reponse_complete_non_tronquee(self):
        result = cr.process_model_response(
            self.fake_ok_result("RIEN À SIGNALER", finish_reason="stop"),
            self.model_slug, self.model_cfg, "GLM-5.3", "G", 100, 0, 1.0, self.config,
        )
        self.assertFalse(result["tronque"])


# ---------------------------------------------------------------------------
# collect : refus de taille (exit 5) et review : refus de taille (exit 3)
# ---------------------------------------------------------------------------

class TestSizeRefusal(unittest.TestCase):
    def test_collect_plan_over_limit_exit_5(self):
        config = base_config()
        config["max_input_chars"] = 50
        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.md"
            plan_path.write_text("x" * 500, encoding="utf-8")
            run_dir = Path(tmp) / "run"
            args = Namespace(mode="plan", plan=str(plan_path), base=None, with_files=False,
                              files=None, repo=None, run_dir=str(run_dir), run_id=None)
            with captured_stdout(), captured_stderr() as err:
                code = cr.cmd_collect(args, config)
            self.assertEqual(code, 5)
            self.assertIn("dépasse", err.getvalue())
            self.assertTrue((run_dir / "payload.md").is_file())

    def test_review_over_limit_exit_3(self):
        config = base_config()
        config["max_input_chars"] = 20
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text("x" * 500, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=False, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
            self.assertEqual(code, 3)
            self.assertIn("volumineux", err.getvalue())

    def test_review_unknown_model_exit_2(self):
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text("contenu", encoding="utf-8")
            args = Namespace(mode="plan", model=["inconnu/modele"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
            self.assertEqual(code, 2)
            self.assertIn("inconnu", err.getvalue())

    def test_review_chinese_hoster_refused(self):
        config = base_config()
        config["models"]["bad/model"] = {
            "label": "Bad",
            "hebergeurs": [{"slug": "siliconflow", "name": "SiliconFlow", "pays": "CN", "ue": False}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text("contenu", encoding="utf-8")
            args = Namespace(mode="plan", model=["bad/model"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
            self.assertEqual(code, 2)
            self.assertIn("ignore_chine", err.getvalue())


class TestReviewEmptyAfterFiltering(unittest.TestCase):
    """Point 1 (revue croisée) : cmd_review ne doit plus jamais envoyer un
    contenu vide (ou uniquement des sections retirées) au relecteur payant."""

    def test_only_section_is_sensitive_exit_3_no_call(self):
        config = base_config()
        diff = "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(diff, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=False, timeout=None)
            with mock.patch.object(cr, "call_openrouter") as fake_call:
                with captured_stderr() as err:
                    code = cr.cmd_review(args, config)
            self.assertEqual(code, 3)
            self.assertIn("rien à relire après filtrage", err.getvalue())
            fake_call.assert_not_called()

    def test_only_section_is_binary_exit_3(self):
        config = base_config()
        diff = "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n"
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(diff, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=False, timeout=None)
            with mock.patch.object(cr, "call_openrouter") as fake_call:
                with captured_stderr() as err:
                    code = cr.cmd_review(args, config)
            self.assertEqual(code, 3)
            self.assertIn("rien à relire après filtrage", err.getvalue())
            fake_call.assert_not_called()

    def test_dry_run_also_refused_when_empty_after_filtering(self):
        config = base_config()
        diff = "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(diff, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
            self.assertEqual(code, 3)
            self.assertIn("rien à relire après filtrage", err.getvalue())

    def test_normal_section_kept_env_section_excluded_from_sent_message(self):
        config = base_config()
        diff = (
            "diff --git a/foo.php b/foo.php\n--- a/foo.php\n+++ b/foo.php\n"
            "@@ -1 +1 @@\n-old\n+contenu_normal_visible\n"
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n"
            "@@ -1 +1 @@\n-A=1\n+SECRET_DOTENV=azerty\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(diff, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            captured = {}
            orig_build_request_body = cr.build_request_body

            def spy(model_slug, model_cfg, system_msg, user_msg, config_arg):
                captured["user_msg"] = user_msg
                return orig_build_request_body(model_slug, model_cfg, system_msg, user_msg, config_arg)

            with mock.patch.object(cr, "build_request_body", side_effect=spy):
                with captured_stdout():
                    code = cr.cmd_review(args, config)
            self.assertEqual(code, 0)
            self.assertIn("contenu_normal_visible", captured["user_msg"])
            self.assertNotIn("SECRET_DOTENV", captured["user_msg"])
            self.assertNotIn(".env", captured["user_msg"])


class TestReviewRefilterScopedToDiffBlock(unittest.TestCase):
    """Point C2 (revue croisée du 2026-09-28) : le re-filtrage de
    cmd_review (sections sensibles/binaires) ne doit s'appliquer qu'à
    l'intérieur du bloc « Diff du lot » produit par collect (wrap_block),
    pas au texte hors diff (plan, fichiers complets) qui citerait par
    erreur des motifs comme « diff --git » ou « Binary files ... differ »."""

    def _capture_user_msg(self, args, config):
        captured = {}
        orig_build_request_body = cr.build_request_body

        def spy(model_slug, model_cfg, system_msg, user_msg, config_arg):
            captured["user_msg"] = user_msg
            return orig_build_request_body(model_slug, model_cfg, system_msg, user_msg, config_arg)

        with mock.patch.object(cr, "build_request_body", side_effect=spy):
            with captured_stdout():
                code = cr.cmd_review(args, config)
        return code, captured.get("user_msg")

    def test_a_plan_citing_diff_markers_passes_in_full(self):
        # Sans bloc « Diff du lot », un plan qui cite ces chaînes en exemple
        # ne doit pas être amputé : envoyé en entier.
        config = base_config()
        plan_text = (
            'Le plan mentionne "diff --git a/x b/x" et '
            '"Binary files a/y b/y differ" comme exemples de sortie attendue.\n'
        )
        payload = "# Contenu à relire (mode plan)\n\n" + cr.wrap_block("Plan d'origine", plan_text)
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            code, user_msg = self._capture_user_msg(args, config)
        self.assertEqual(code, 0)
        self.assertIn("diff --git a/x b/x", user_msg)
        self.assertIn("Binary files a/y b/y differ", user_msg)

    def test_b_diff_block_refiltered_full_files_kept_intact(self):
        # Avec un bloc « Diff du lot » (section .env sensible à retirer) et
        # des fichiers complets après, qui citent les mêmes motifs sans
        # rapport avec un vrai diff : la section sensible du diff disparaît,
        # les fichiers complets restent intacts.
        config = base_config()
        diff_content = (
            "diff --git a/foo.php b/foo.php\n--- a/foo.php\n+++ b/foo.php\n"
            "@@ -1 +1 @@\n-old\n+contenu_diff_visible\n"
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n"
            "@@ -1 +1 @@\n-A=1\n+SECRET_DOTENV=azerty\n"
        )
        fichier_complet = (
            'Fichier complet qui cite "diff --git a/z b/z" et '
            '"Binary files a/w b/w differ" sans rapport avec un vrai diff, '
            "et doit rester intact.\n"
        )
        payload = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Diff du lot", diff_content)
            + "\n## Fichiers complets\n\n"
            + cr.wrap_block("Fichier : notes.md", fichier_complet)
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            code, user_msg = self._capture_user_msg(args, config)
        self.assertEqual(code, 0)
        self.assertIn("contenu_diff_visible", user_msg)
        self.assertNotIn(".env", user_msg)
        self.assertNotIn("SECRET_DOTENV", user_msg)
        self.assertIn("diff --git a/z b/z", user_msg)
        self.assertIn("Binary files a/w b/w differ", user_msg)
        self.assertIn("et doit rester intact", user_msg)

    def test_c_refusal_stays_when_all_real_diff_sections_are_sensitive(self):
        # Le refus « rien à relire » reste en place quand toutes les vraies
        # sections du bloc « Diff du lot » sont sensibles.
        config = base_config()
        diff_content = "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        payload = "# Contenu à relire (mode code)\n\n" + cr.wrap_block("Diff du lot", diff_content)
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
        self.assertEqual(code, 3)
        self.assertIn("aucune section de diff ni fichier complet à relire", err.getvalue())

    def test_f_mode_code_refuses_when_only_plan_block_remains(self):
        # Point 3 : en mode code, même avec un bloc « Plan d'origine »
        # présent et non vide, l'absence de toute section diff et de tout
        # bloc « Fichier : ... » entraîne le refus.
        config = base_config()
        diff_content = "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        payload = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Plan d'origine", "Le plan d'origine, non vide.\n")
            + cr.wrap_block("Diff du lot", diff_content)
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
        self.assertEqual(code, 3)
        self.assertIn("aucune section de diff ni fichier complet à relire", err.getvalue())

    def test_k3_marker_substring_mid_added_line_does_not_disable_filtering(self):
        # K3 (revue croisée du 2026-09-28) : refilter_diff_block_in_content
        # renonçait à tout filtrage dès que la sous-chaîne « ----- DÉBUT »
        # apparaissait n'importe où dans le contenu, y compris au milieu
        # d'une ligne ajoutée par un vrai diff (« +----- DÉBUT Exemple
        # ----- », donc pas en début de ligne). Un diff brut avec une
        # section .env sensible et une section doc.md qui ajoute une telle
        # ligne doit quand même retirer la section .env.
        config = base_config()
        diff = (
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n"
            "@@ -1 +1 @@\n-A=1\n+SECRET_DOTENV=azerty\n"
            "diff --git a/doc.md b/doc.md\n--- a/doc.md\n+++ b/doc.md\n"
            "@@ -1 +1 @@\n-old\n+----- DÉBUT Exemple -----\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(diff, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            code, user_msg = self._capture_user_msg(args, config)
        self.assertEqual(code, 0)
        self.assertNotIn("SECRET_DOTENV", user_msg)
        self.assertNotIn(".env", user_msg)
        self.assertIn("doc.md", user_msg)
        self.assertIn("+----- DÉBUT Exemple -----", user_msg)

    def test_all_diff_sections_sensitive_but_full_files_kept_not_refused(self):
        # Toutes les sections « diff --git » sont sensibles, mais un bloc de
        # fichiers complets suit : pas de refus, les fichiers complets
        # restent.
        config = base_config()
        diff_content = "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        fichier_complet = "Contenu du fichier complet, sans rapport avec le diff.\n"
        payload = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Diff du lot", diff_content)
            + "\n## Fichiers complets\n\n"
            + cr.wrap_block("Fichier : notes.md", fichier_complet)
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            code, user_msg = self._capture_user_msg(args, config)
        self.assertEqual(code, 0)
        self.assertNotIn(".env", user_msg)
        self.assertIn("Contenu du fichier complet", user_msg)

    def test_full_file_with_binary_marker_after_diff_stays_intact(self):
        # Un fichier complet placé après le diff et qui contient « Binary
        # files ... differ » ne doit faire disparaître ni lui-même, ni la
        # section de diff qui précède.
        config = base_config()
        diff_content = (
            "diff --git a/foo.php b/foo.php\n--- a/foo.php\n+++ b/foo.php\n"
            "@@ -1 +1 @@\n-old\n+contenu_diff_visible\n"
        )
        fichier_complet = (
            "Ce fichier documente un cas : « Binary files a/img.png and "
            "b/img.png differ » est le message que git affiche pour un binaire.\n"
        )
        payload = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Diff du lot", diff_content)
            + "\n## Fichiers complets\n\n"
            + cr.wrap_block("Fichier : notes.md", fichier_complet)
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            code, user_msg = self._capture_user_msg(args, config)
        self.assertEqual(code, 0)
        self.assertIn("contenu_diff_visible", user_msg)
        self.assertIn("Binary files a/img.png and b/img.png differ", user_msg)

    def test_e_truncated_key_in_one_fichier_block_does_not_mask_next_fichier_block(self):
        # Point 2 (masquage guidé par les blocs) : un BEGIN sans END dans le
        # bloc « Fichier : a.py » ne doit masquer que ce bloc, jamais le
        # bloc « Fichier : b.py » qui suit.
        config = base_config()
        fichier_a = PEM_BEGIN_RSA + "\nMIIB...tronque_sans_fin\n"
        fichier_b = "contenu_normal_de_b_visible\n"
        payload = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Diff du lot", "diff --git a/x.php b/x.php\n--- a/x.php\n+++ b/x.php\n@@ -1 +1 @@\n-a\n+b\n")
            + "\n## Fichiers complets\n\n"
            + cr.wrap_block("Fichier : a.py", fichier_a)
            + cr.wrap_block("Fichier : b.py", fichier_b)
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            code, user_msg = self._capture_user_msg(args, config)
        self.assertEqual(code, 0)
        self.assertIn("contenu_normal_de_b_visible", user_msg)
        self.assertNotIn("MIIB...tronque_sans_fin", user_msg)

    def test_e_truncated_key_in_one_diff_section_does_not_mask_next_section(self):
        # Même garantie, entre deux sections `diff --git` du bloc « Diff du
        # lot ».
        config = base_config()
        diff_content = (
            "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n"
            "-old\n+" + PEM_BEGIN_RSA + "\n"
            + "diff --git a/b.php b/b.php\n--- a/b.php\n+++ b/b.php\n@@ -1 +1 @@\n"
            "-old\n+contenu_normal_b_visible\n"
        )
        payload = "# Contenu à relire (mode code)\n\n" + cr.wrap_block("Diff du lot", diff_content)
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            code, user_msg = self._capture_user_msg(args, config)
        self.assertEqual(code, 0)
        self.assertIn("contenu_normal_b_visible", user_msg)

    def test_h_diff_line_fin_without_trailing_dashes_stays_inside_sensitive_section(self):
        # Point 2 : une ligne de diff « ----- FIN truc » (sans le « ----- »
        # final) au milieu d'une section sensible n'est pas un marqueur de
        # bloc valide (BLOCK_MARKER_RE exige la ligne entière) : la section
        # reste retirée en entier.
        config = base_config()
        diff_content = (
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1,2 +1,2 @@\n"
            "-A=1\n+----- FIN truc\n+SECRET_DOTENV=azerty\n"
        )
        payload = "# Contenu à relire (mode code)\n\n" + cr.wrap_block("Diff du lot", diff_content)
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(payload, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
        self.assertEqual(code, 3)
        self.assertIn("aucune section de diff ni fichier complet à relire", err.getvalue())


# ---------------------------------------------------------------------------
# collect : intégration légère (mode code, dépôt git réel jetable)
# ---------------------------------------------------------------------------

class TestCollectCodeIntegration(unittest.TestCase):
    def test_collect_code_basic_repo(self):
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            _run(["git", "init", "-q"], repo)
            _run(["git", "config", "user.email", "test@example.com"], repo)
            _run(["git", "config", "user.name", "Test"], repo)
            (repo / "foo.php").write_text("<?php\necho 'a';\n", encoding="utf-8")
            (repo / "wp-config.php").write_text(
                "<?php\ndefine( 'DB_PASSWORD', 'FAUX-SECRET-TEST-1' );\n", encoding="utf-8"
            )
            _run(["git", "add", "."], repo)
            _run(["git", "commit", "-q", "-m", "init"], repo)
            (repo / "foo.php").write_text("<?php\necho 'b';\n", encoding="utf-8")
            (repo / "wp-config.php").write_text(
                "<?php\ndefine( 'DB_PASSWORD', 'FAUX-SECRET-TEST-2' );\n", encoding="utf-8"
            )

            run_dir = Path(tmp) / "run"
            args = Namespace(mode="code", plan=None, base=None, with_files=False,
                              files=None, repo=str(repo), run_dir=str(run_dir), run_id=None)
            with captured_stdout() as out:
                code = cr.cmd_collect(args, config)
            self.assertEqual(code, 0)
            payload = (run_dir / "payload.md").read_text(encoding="utf-8")
            self.assertIn("foo.php", payload)
            self.assertNotIn("wp-config.php", payload)
            summary = json.loads(out.getvalue())
            self.assertIn("foo.php", summary["files_included"])
            reasons = {e["fichier"]: e["raison"] for e in summary["files_excluded"]}
            self.assertEqual(reasons.get("wp-config.php"), "sensible")

    def test_collect_code_invalid_base_ref_exit_2_no_payload(self):
        # Point 3 (revue croisée) : --base pointant vers une révision
        # inexistante doit être signalé proprement, pas planter ou écrire
        # un payload vide/tronqué.
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            _run(["git", "init", "-q"], repo)
            _run(["git", "config", "user.email", "test@example.com"], repo)
            _run(["git", "config", "user.name", "Test"], repo)
            (repo / "foo.php").write_text("<?php\necho 'a';\n", encoding="utf-8")
            _run(["git", "add", "."], repo)
            _run(["git", "commit", "-q", "-m", "init"], repo)

            run_dir = Path(tmp) / "run"
            args = Namespace(mode="code", plan=None, base="ref-inexistante-xyz", with_files=False,
                              files=None, repo=str(repo), run_dir=str(run_dir), run_id=None)
            with captured_stderr() as err:
                code = cr.cmd_collect(args, config)
            self.assertEqual(code, 2)
            self.assertIn("git diff a échoué", err.getvalue())
            self.assertFalse((run_dir / "payload.md").exists())

    def test_collect_code_non_git_dir_without_files_exit_2(self):
        # Point 3 : mode code sans --files sur un dossier hors dépôt git.
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            not_a_repo = Path(tmp) / "pas-un-repo"
            not_a_repo.mkdir()
            run_dir = Path(tmp) / "run"
            args = Namespace(mode="code", plan=None, base=None, with_files=False,
                              files=None, repo=str(not_a_repo), run_dir=str(run_dir), run_id=None)
            with captured_stderr() as err:
                code = cr.cmd_collect(args, config)
            self.assertEqual(code, 2)
            self.assertIn("n'est pas un dépôt git", err.getvalue())
            self.assertIn("--files", err.getvalue())
            self.assertFalse((run_dir / "payload.md").exists())

    def test_collect_code_files_unreadable_file_excluded(self):
        # Point 5 : un fichier illisible (permissions) dans --files ne doit
        # pas faire planter collect_code (OSError non gardé sur read_bytes).
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("chmod 000 est ignoré en root")
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            unreadable = Path(tmp) / "fichier_illisible.php"
            unreadable.write_text("<?php echo 'x';\n", encoding="utf-8")
            unreadable.chmod(0o000)
            run_dir = Path(tmp) / "run"
            try:
                args = Namespace(mode="code", plan=None, base=None, with_files=False,
                                  files=[str(unreadable)], repo=None, run_dir=str(run_dir), run_id=None)
                with captured_stdout() as out:
                    code = cr.cmd_collect(args, config)
            finally:
                unreadable.chmod(0o644)
            self.assertEqual(code, 0)
            summary = json.loads(out.getvalue())
            reasons = {e["fichier"]: e["raison"] for e in summary["files_excluded"]}
            self.assertEqual(reasons.get(str(unreadable)), "illisible")

    def test_collect_code_files_directory_excluded_as_pas_un_fichier(self):
        # Point 5 : un dossier passé dans --files doit être distingué d'un
        # fichier absent.
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            a_dir = Path(tmp) / "un-dossier"
            a_dir.mkdir()
            run_dir = Path(tmp) / "run"
            args = Namespace(mode="code", plan=None, base=None, with_files=False,
                              files=[str(a_dir)], repo=None, run_dir=str(run_dir), run_id=None)
            with captured_stdout() as out:
                code = cr.cmd_collect(args, config)
            self.assertEqual(code, 0)
            summary = json.loads(out.getvalue())
            reasons = {e["fichier"]: e["raison"] for e in summary["files_excluded"]}
            self.assertEqual(reasons.get(str(a_dir)), "pas un fichier")


def _run(cmd, cwd):
    import subprocess
    subprocess.run(cmd, cwd=str(cwd), check=True, capture_output=True)


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------

class TestLogCommand(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.log_path = self.tmp / "log.jsonl"
        os.environ["CROSS_REVIEW_LOG"] = str(self.log_path)
        self.config = base_config()

    def tearDown(self):
        del os.environ["CROSS_REVIEW_LOG"]
        self.tmpdir.cleanup()

    def _make_run_dir_with_tiers(self):
        run_dir = self.tmp / "run1"
        run_dir.mkdir()
        (run_dir / "collect.json").write_text(json.dumps({"projet": "site-test", "mode": "code"}), encoding="utf-8")
        tiers_ok = {
            "label": "GLM-5.3", "prefixe": "G", "modele_demande": "z-ai/glm-5.3",
            "modele_renvoye": "z-ai/glm-5.3", "hebergeur": "Inceptron", "hebergeur_ok": True,
            "statut": "ok", "erreur": None, "appel_id": "gen-1", "cout_usd": 0.01,
            "tokens": {"prompt": 10, "completion": 5, "reasoning": 0}, "duree_s": 1.0,
            "finish_reason": "stop", "blocs_retires": 0, "format_ok": True,
            "rien_a_signaler": False, "findings": [{"id": "G1", "severite": "BLOQUANT", "titre": "x",
                                                      "ou": "a", "probleme": "b", "pourquoi": "c"}],
        }
        tiers_rien = {
            "label": "Gemini 3.8 Flash", "prefixe": "GE", "modele_demande": "google/gemini-3.8-flash",
            "modele_renvoye": "google/gemini-3.8-flash", "hebergeur": "Google AI Studio", "hebergeur_ok": True,
            "statut": "ok", "erreur": None, "appel_id": "gen-2", "cout_usd": 0.02,
            "tokens": {"prompt": 8, "completion": 2, "reasoning": 0}, "duree_s": 0.8,
            "finish_reason": "stop", "blocs_retires": 0, "format_ok": True,
            "rien_a_signaler": True, "findings": [],
        }
        tiers_echec = {
            "label": "Grok 4.7", "prefixe": "GR", "modele_demande": "x-ai/grok-4.7",
            "modele_renvoye": None, "hebergeur": None, "hebergeur_ok": None,
            "statut": "echec", "erreur": "délai dépassé", "appel_id": None, "cout_usd": None,
            "tokens": {"prompt": None, "completion": None, "reasoning": None}, "duree_s": None,
            "finish_reason": None, "blocs_retires": 0, "format_ok": False,
            "rien_a_signaler": False, "findings": [],
        }
        (run_dir / "tiers-glm-53.json").write_text(json.dumps(tiers_ok), encoding="utf-8")
        (run_dir / "tiers-gemini-38-flash.json").write_text(json.dumps(tiers_rien), encoding="utf-8")
        (run_dir / "tiers-grok-47.json").write_text(json.dumps(tiers_echec), encoding="utf-8")
        return run_dir

    def test_log_enrichment_and_auto_lines(self):
        run_dir = self._make_run_dir_with_tiers()
        verdicts = [
            {"relecteur": "GLM-5.3", "finding_id": "G1", "severite": "bloquant",
             "resume": "vrai souci", "convergent": True, "verdict": "retenu", "raison": "confirmé"},
        ]
        verdicts_path = self.tmp / "verdicts.json"
        verdicts_path.write_text(json.dumps(verdicts), encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet=None)
        with captured_stdout() as out:
            code = cr.cmd_log(args, self.config)
        self.assertEqual(code, 0)
        self.assertIn("lignes ajoutées", out.getvalue())

        lines = [json.loads(l) for l in self.log_path.read_text(encoding="utf-8").splitlines()]
        # 1 ligne fournie + 1 auto (rien à signaler) + 1 auto (échec) = 3
        self.assertEqual(len(lines), 3)
        by_relecteur = {l["relecteur"]: l for l in lines}
        self.assertEqual(by_relecteur["GLM-5.3"]["modele"], "z-ai/glm-5.3")
        self.assertEqual(by_relecteur["GLM-5.3"]["hebergeur"], "Inceptron")
        self.assertEqual(by_relecteur["GLM-5.3"]["projet"], "site-test")
        self.assertIsNone(by_relecteur["GLM-5.3"]["decision"])
        self.assertEqual(by_relecteur["Gemini 3.8 Flash"]["severite"], "aucune")
        self.assertEqual(by_relecteur["Gemini 3.8 Flash"]["resume"], "rien à signaler")
        self.assertEqual(by_relecteur["Grok 4.7"]["statut"], "echec")

    def test_log_auto_line_for_hors_liste_blanche_without_finding(self):
        # Point C4 (revue croisée du 2026-09-28) : un relecteur de statut
        # hors_liste_blanche sans constat (pas de ligne fournie pour lui
        # dans les verdicts) doit donner une ligne automatique, comme un
        # échec, avec coût, appel_id, hébergeur et erreur.
        run_dir = self.tmp / "run_offlist"
        run_dir.mkdir()
        (run_dir / "collect.json").write_text(json.dumps({"projet": "site-test", "mode": "code"}), encoding="utf-8")
        tiers_offlist = {
            "label": "MiMo-V2.6-Pro", "prefixe": "M", "modele_demande": "xiaomi/mimo-v2.6-pro",
            "modele_renvoye": "xiaomi/mimo-v2.6-pro", "hebergeur": "SiliconFlow", "hebergeur_ok": False,
            "statut": "hors_liste_blanche", "erreur": "hébergeur hors liste blanche : SiliconFlow",
            "appel_id": "gen-3", "cout_usd": 0.03,
            "tokens": {"prompt": 12, "completion": 0, "reasoning": 0}, "duree_s": 0.5,
            "finish_reason": "length", "blocs_retires": 0, "format_ok": False,
            "rien_a_signaler": False, "findings": [],
        }
        (run_dir / "tiers-mimo-v26-pro.json").write_text(json.dumps(tiers_offlist), encoding="utf-8")
        verdicts_path = self.tmp / "verdicts_offlist.json"
        verdicts_path.write_text(json.dumps([]), encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet=None)
        with captured_stdout() as out:
            code = cr.cmd_log(args, self.config)
        self.assertEqual(code, 0)
        lines = [json.loads(l) for l in self.log_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), 1)
        entry = lines[0]
        self.assertEqual(entry["relecteur"], "MiMo-V2.6-Pro")
        self.assertEqual(entry["statut"], "hors_liste_blanche")
        self.assertEqual(entry["hebergeur"], "SiliconFlow")
        self.assertEqual(entry["appel_id"], "gen-3")
        self.assertEqual(entry["cout_appel_usd"], 0.03)
        self.assertIn("hors liste blanche", entry["resume"])

    def test_log_validation_rejects_bad_severite_and_writes_nothing(self):
        run_dir = self._make_run_dir_with_tiers()
        verdicts = [{"relecteur": "GLM-5.3", "finding_id": "G1", "severite": "grave",
                     "resume": "x", "convergent": True, "verdict": None, "raison": None}]
        verdicts_path = self.tmp / "verdicts.json"
        verdicts_path.write_text(json.dumps(verdicts), encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet=None)
        with captured_stderr() as err:
            code = cr.cmd_log(args, self.config)
        self.assertEqual(code, 2)
        self.assertFalse(self.log_path.exists())

    def test_log_validation_rejects_long_resume(self):
        run_dir = self._make_run_dir_with_tiers()
        verdicts = [{"relecteur": "GLM-5.3", "finding_id": "G1", "severite": "bloquant",
                     "resume": "x" * 301, "convergent": True, "verdict": "retenu", "raison": None}]
        verdicts_path = self.tmp / "verdicts.json"
        verdicts_path.write_text(json.dumps(verdicts), encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet=None)
        code = cr.cmd_log(args, self.config)
        self.assertEqual(code, 2)
        self.assertFalse(self.log_path.exists())

    def test_log_validation_rejects_verdict_value(self):
        run_dir = self._make_run_dir_with_tiers()
        verdicts = [{"relecteur": "GLM-5.3", "finding_id": "G1", "severite": "bloquant",
                     "resume": "x", "convergent": True, "verdict": "peut-etre", "raison": None}]
        verdicts_path = self.tmp / "verdicts.json"
        verdicts_path.write_text(json.dumps(verdicts), encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet=None)
        code = cr.cmd_log(args, self.config)
        self.assertEqual(code, 2)

    def test_log_validation_rejects_non_dict_entries_no_traceback(self):
        # Point 8 (revue croisée) : verdicts.json = [1, "x"] ne doit pas
        # planter (AttributeError sur entry.get) mais renvoyer une erreur
        # propre, sans écrire le journal.
        run_dir = self._make_run_dir_with_tiers()
        verdicts_path = self.tmp / "verdicts.json"
        verdicts_path.write_text(json.dumps([1, "x"]), encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet=None)
        with captured_stderr() as err:
            code = cr.cmd_log(args, self.config)
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("objet JSON attendu", err.getvalue())
        self.assertFalse(self.log_path.exists())

    def test_log_accepts_rejete_with_accent(self):
        run_dir = self._make_run_dir_with_tiers()
        verdicts = [{"relecteur": "GLM-5.3", "finding_id": "G1", "severite": "important",
                     "resume": "x", "convergent": False, "verdict": "rejeté", "raison": "faux positif"}]
        verdicts_path = self.tmp / "verdicts.json"
        verdicts_path.write_text(json.dumps(verdicts), encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet="MonProjet")
        code = cr.cmd_log(args, self.config)
        self.assertEqual(code, 0)
        lines = [json.loads(l) for l in self.log_path.read_text(encoding="utf-8").splitlines()]
        entry = [l for l in lines if l["relecteur"] == "GLM-5.3" and l.get("finding_id") == "G1"][0]
        self.assertEqual(entry["verdict"], "rejete")
        self.assertEqual(entry["projet"], "MonProjet")


# ---------------------------------------------------------------------------
# rappel_autocorrection (fonction pure)
# ---------------------------------------------------------------------------

class TestComputeRappelAutocorrection(unittest.TestCase):
    def _rappel_config(self, **overrides):
        cfg = {
            "actif": True,
            "seuil": 3,
            "depuis": "2026-01-01T00:00:00+01:00",
            "exclure_projets": ["projet-exclu"],
            "message": "message de rappel",
        }
        cfg.update(overrides)
        return cfg

    def _entry(self, run_id, projet="site-test", mode="code", date="2026-02-01T10:00:00+01:00"):
        return {"run_id": run_id, "projet": projet, "mode": mode, "date": date}

    def test_sous_le_seuil_rien(self):
        entries = [self._entry("r1"), self._entry("r2")]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNone(result)

    def test_au_seuil_la_ligne(self):
        entries = [self._entry("r1"), self._entry("r2"), self._entry("r3")]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("RAPPEL : message de rappel"))
        self.assertIn("(3 revues de code depuis le 01/01/2026)", result)

    def test_actif_false_rien(self):
        entries = [self._entry("r1"), self._entry("r2"), self._entry("r3")]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3, actif=False))
        self.assertIsNone(result)

    def test_projet_exclu_non_compte(self):
        entries = [
            self._entry("r1"),
            self._entry("r2"),
            self._entry("r3", projet="projet-exclu"),
        ]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNone(result)

    def test_run_anterieur_a_depuis_non_compte(self):
        entries = [
            self._entry("r1"),
            self._entry("r2"),
            self._entry("r3", date="2025-06-01T10:00:00+01:00"),
        ]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNone(result)

    def test_mode_plan_non_compte(self):
        entries = [
            self._entry("r1"),
            self._entry("r2"),
            self._entry("r3", mode="plan"),
        ]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNone(result)

    def test_plusieurs_entrees_meme_run_comptees_une_fois(self):
        entries = [
            self._entry("r1"),
            self._entry("r1"),
            self._entry("r1"),
            self._entry("r2"),
        ]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNone(result)
        entries.append(self._entry("r3"))
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNotNone(result)
        self.assertIn("(3 revues de code depuis le 01/01/2026)", result)

    def test_config_absente_rien(self):
        entries = [self._entry("r1"), self._entry("r2"), self._entry("r3")]
        self.assertIsNone(cr.compute_rappel_autocorrection(entries, None))
        self.assertIsNone(cr.compute_rappel_autocorrection(entries, {}))

    def test_lignes_illisibles_ignorees(self):
        entries = [self._entry("r1"), self._entry("r2"), self._entry("r3"), None, "pas un dict"]
        result = cr.compute_rappel_autocorrection(entries, self._rappel_config(seuil=3))
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# decide
# ---------------------------------------------------------------------------

class TestDecideCommand(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.log_path = self.tmp / "log.jsonl"
        os.environ["CROSS_REVIEW_LOG"] = str(self.log_path)
        self.config = base_config()
        entries = [
            {"relecteur": "GLM-5.3", "finding_id": "G1", "verdict": "retenu", "run_id": "run1", "decision": None},
            {"relecteur": "GLM-5.3", "finding_id": "G2", "verdict": "rejete", "run_id": "run1", "decision": None},
            {"relecteur": "Gemini", "finding_id": "GE1", "verdict": None, "run_id": "run1", "decision": None},
            {"relecteur": "GLM-5.3", "finding_id": "X1", "verdict": "retenu", "run_id": "run2", "decision": None},
        ]
        with open(self.log_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def tearDown(self):
        del os.environ["CROSS_REVIEW_LOG"]
        self.tmpdir.cleanup()

    def test_decide_accept(self):
        args = Namespace(run_id="run1", accept=True, assignments=[])
        with captured_stdout() as out:
            code = cr.cmd_decide(args, self.config)
        self.assertEqual(code, 0)
        self.assertIn("2 lignes mises à jour", out.getvalue())
        lines = [json.loads(l) for l in self.log_path.read_text(encoding="utf-8").splitlines()]
        by_id = {l["finding_id"]: l for l in lines}
        self.assertEqual(by_id["G1"]["decision"], "retenu")
        self.assertEqual(by_id["G2"]["decision"], "rejete")
        self.assertIsNone(by_id["GE1"]["decision"])
        self.assertIsNone(by_id["X1"]["decision"])  # autre run, non touché

    def test_decide_pairs(self):
        args = Namespace(run_id="run1", accept=False, assignments=["retenu:G1", "rejete:G2,GE1"])
        with captured_stdout() as out:
            code = cr.cmd_decide(args, self.config)
        self.assertEqual(code, 0)
        lines = [json.loads(l) for l in self.log_path.read_text(encoding="utf-8").splitlines()]
        by_id = {l["finding_id"]: l for l in lines}
        self.assertEqual(by_id["G1"]["decision"], "retenu")
        self.assertEqual(by_id["G2"]["decision"], "rejete")
        self.assertEqual(by_id["GE1"]["decision"], "rejete")

    def test_decide_pairs_with_accent(self):
        args = Namespace(run_id="run1", accept=False, assignments=["rejeté:G1"])
        code = cr.cmd_decide(args, self.config)
        self.assertEqual(code, 0)
        lines = [json.loads(l) for l in self.log_path.read_text(encoding="utf-8").splitlines()]
        by_id = {l["finding_id"]: l for l in lines}
        self.assertEqual(by_id["G1"]["decision"], "rejete")

    def test_decide_unknown_id_warns(self):
        args = Namespace(run_id="run1", accept=False, assignments=["retenu:INCONNU1"])
        with captured_stderr() as err:
            code = cr.cmd_decide(args, self.config)
        self.assertEqual(code, 0)
        self.assertIn("INCONNU1", err.getvalue())

    def test_decide_preserves_blank_and_unreadable_lines_in_place(self):
        # Point 2 (revue croisée) : une ligne vide suivie d'une ligne
        # illisible ne doit plus décaler les lignes JSON suivantes lors de
        # la réécriture (zip(entries, lines) perdait l'alignement).
        entries = [
            {"relecteur": "GLM-5.3", "finding_id": "E1", "verdict": "retenu", "run_id": "runX", "decision": None},
            {"relecteur": "GLM-5.3", "finding_id": "E3", "verdict": "rejete", "run_id": "runX", "decision": None},
        ]
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(entries[0]) + "\n")
            f.write("\n")
            f.write("{illisible\n")
            f.write(json.dumps(entries[1]) + "\n")

        args = Namespace(run_id="runX", accept=False, assignments=["retenu:E1", "rejete:E3"])
        code = cr.cmd_decide(args, self.config)
        self.assertEqual(code, 0)

        raw_lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(raw_lines), 4)
        self.assertEqual(raw_lines[1], "")
        self.assertEqual(raw_lines[2], "{illisible")
        e1 = json.loads(raw_lines[0])
        e3 = json.loads(raw_lines[3])
        self.assertEqual(e1["finding_id"], "E1")
        self.assertEqual(e1["decision"], "retenu")
        self.assertEqual(e3["finding_id"], "E3")
        self.assertEqual(e3["decision"], "rejete")


# ---------------------------------------------------------------------------
# log / decide : écriture impossible (sandbox, dossier en lecture seule...)
# ---------------------------------------------------------------------------

class TestLogWriteFailure(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.log_path = self.tmp / "log.jsonl"
        os.environ["CROSS_REVIEW_LOG"] = str(self.log_path)
        self.config = base_config()

    def tearDown(self):
        del os.environ["CROSS_REVIEW_LOG"]
        self.tmpdir.cleanup()

    def test_cmd_log_oserror_on_write_exits_2_with_clear_message(self):
        run_dir = self.tmp / "run1"
        run_dir.mkdir()
        verdicts_path = self.tmp / "verdicts.json"
        verdicts_path.write_text("[]", encoding="utf-8")
        args = Namespace(run_dir=str(run_dir), verdicts=str(verdicts_path), projet=None)

        # Simule l'échec constaté en pratique : PermissionError (Errno 1)
        # sur l'écriture du journal, par exemple parce que le script tourne
        # dans le sandbox Bash. On ne patche que le `open` vu par le module
        # (pas `Path.read_text`/`write_text`, qui passent par `io.open`),
        # donc les lectures faites plus haut dans cmd_log restent normales.
        with mock.patch.object(
            cr, "open", create=True,
            side_effect=PermissionError(1, "Operation not permitted"),
        ):
            with captured_stderr() as err:
                code = cr.cmd_log(args, self.config)

        self.assertEqual(code, 2)
        message = err.getvalue()
        self.assertIn("cross-review", message)
        self.assertIn(str(self.log_path), message)
        self.assertIn("chemin complet", message)
        self.assertIn("hors sandbox", message)
        # Aucune trace Python brute (pas de traceback) : le message est la
        # seule chose écrite sur stderr, et le journal n'a pas été créé.
        self.assertNotIn("Traceback", message)
        self.assertFalse(self.log_path.exists())


class TestDecideWriteFailure(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.log_path = self.tmp / "log.jsonl"
        os.environ["CROSS_REVIEW_LOG"] = str(self.log_path)
        self.config = base_config()
        entries = [
            {"relecteur": "GLM-5.3", "finding_id": "G1", "verdict": "retenu", "run_id": "run1", "decision": None},
        ]
        with open(self.log_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        self.original_content = self.log_path.read_text(encoding="utf-8")

    def tearDown(self):
        del os.environ["CROSS_REVIEW_LOG"]
        self.tmpdir.cleanup()

    def test_cmd_decide_replace_failure_leaves_log_intact_and_cleans_tmp(self):
        args = Namespace(run_id="run1", accept=True, assignments=[])

        # Le fichier temporaire s'écrit normalement (open() n'est pas
        # touché) ; seul le remplacement final échoue, comme il le ferait si
        # le dossier du journal devenait inaccessible en cours de route.
        with mock.patch.object(
            cr.os, "replace",
            side_effect=OSError(1, "Operation not permitted"),
        ):
            with captured_stderr() as err:
                code = cr.cmd_decide(args, self.config)

        self.assertEqual(code, 2)
        message = err.getvalue()
        self.assertIn("cross-review", message)
        self.assertIn(str(self.log_path), message)
        self.assertIn("chemin complet", message)
        self.assertNotIn("Traceback", message)
        # Le journal d'origine n'a pas bougé.
        self.assertEqual(self.log_path.read_text(encoding="utf-8"), self.original_content)
        # Le fichier temporaire a été nettoyé, pas laissé à côté du journal.
        leftovers = list(self.tmp.glob("log.jsonl.tmp-*"))
        self.assertEqual(leftovers, [])

    def test_cmd_decide_open_failure_leaves_log_intact(self):
        args = Namespace(run_id="run1", accept=True, assignments=[])

        with mock.patch.object(
            cr, "open", create=True,
            side_effect=PermissionError(1, "Operation not permitted"),
        ):
            with captured_stderr() as err:
                code = cr.cmd_decide(args, self.config)

        self.assertEqual(code, 2)
        self.assertIn("cross-review", err.getvalue())
        self.assertEqual(self.log_path.read_text(encoding="utf-8"), self.original_content)
        leftovers = list(self.tmp.glob("log.jsonl.tmp-*"))
        self.assertEqual(leftovers, [])


# ---------------------------------------------------------------------------
# watch : veille mensuelle des modèles OpenRouter
# ---------------------------------------------------------------------------


def veille_config():
    """Config de test avec une section 'veille' minimale, en plus de
    base_config() (deux modèles suivis : GLM-5.3 et Gemini 3.8 Flash)."""
    config = base_config()
    config["veille"] = {
        "snapshot_path": "~/cross-review-veille-test-inutilise.json",
        "familles": [
            {"nom": "GLM", "motif": "^z-ai/glm-"},
            {"nom": "Gemini", "motif": "^google/gemini-"},
        ],
        "exclure_motif": "(:free$|image|audio)",
        "variation_prix_pct": 20,
    }
    return config


def sample_models(extra=None):
    models = [
        {"id": "z-ai/glm-5.3", "name": "GLM-5.3", "created": 1750000000, "context_length": 200000,
         "pricing": {"prompt": "0.000002", "completion": "0.000006"}},
        {"id": "google/gemini-3.8-flash", "name": "Gemini 3.8 Flash", "created": 1751000000,
         "context_length": 1000000, "pricing": {"prompt": "0.0000005", "completion": "0.0000015"}},
    ]
    if extra:
        models.extend(extra)
    return models


def sample_providers(extra=None):
    providers = [
        {"slug": "inceptron", "name": "Inceptron", "headquarters": "SE", "datacenters": ["FI"]},
        {"slug": "mistral", "name": "Mistral", "headquarters": "FR", "datacenters": None},
        {"slug": "together", "name": "Together", "headquarters": "US", "datacenters": ["US"]},
        {"slug": "google-vertex", "name": "Google", "headquarters": "US", "datacenters": ["US"]},
        {"slug": "google-ai-studio", "name": "Google AI Studio", "headquarters": "US", "datacenters": None},
    ]
    if extra:
        providers.extend(extra)
    return providers


def sample_endpoints():
    return {
        "z-ai/glm-5.3": [
            {"tag": "inceptron/fp4", "provider_name": "Inceptron", "quantization": "fp4", "status": "active"},
            {"tag": "mistral", "provider_name": "Mistral", "quantization": "nvfp4", "status": "active"},
        ],
        "google/gemini-3.8-flash": [
            {"tag": "google-vertex/global", "provider_name": "Google", "quantization": None, "status": "active"},
        ],
    }


def make_fetch_json(models_data, providers_data, endpoints_by_id=None, endpoint_errors=None):
    """Simule fetch_json(url) : dispatche selon l'URL demandée (/models,
    /providers, ou /models/<id>/endpoints), sans aucun appel réseau."""
    endpoints_by_id = endpoints_by_id or {}
    endpoint_errors = endpoint_errors or {}

    def _fetch(url, timeout_s=30, retry_log=None):
        if url == cr.OPENROUTER_MODELS_URL:
            return {"data": models_data}
        if url == cr.OPENROUTER_PROVIDERS_URL:
            return {"data": providers_data}
        for mid, err in endpoint_errors.items():
            if url == cr.OPENROUTER_ENDPOINTS_URL_TMPL.format(model_id=mid):
                raise RuntimeError(err)
        for mid, eps in endpoints_by_id.items():
            if url == cr.OPENROUTER_ENDPOINTS_URL_TMPL.format(model_id=mid):
                return {"data": {"endpoints": eps}}
        return {"data": {"endpoints": []}}

    return _fetch


def write_previous_snapshot(path, modeles, endpoints, hebergeurs, date="2026-08-25T09:00:00+02:00"):
    snapshot = {"date": date, "modeles": modeles, "endpoints": endpoints, "hebergeurs": hebergeurs}
    path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    return snapshot


def base_previous_modeles():
    return {
        "z-ai/glm-5.3": {"name": "GLM-5.3", "created": 1750000000, "context_length": 200000,
                          "prix_entree": 0.000002, "prix_sortie": 0.000006, "expiration_date": None},
        "google/gemini-3.8-flash": {"name": "Gemini 3.8 Flash", "created": 1751000000,
                                     "context_length": 1000000, "prix_entree": 0.0000005,
                                     "prix_sortie": 0.0000015, "expiration_date": None},
    }


def base_previous_hebergeurs():
    return {
        "inceptron": {"name": "Inceptron", "headquarters": "SE", "datacenters": ["FI"]},
        "mistral": {"name": "Mistral", "headquarters": "FR", "datacenters": None},
        "together": {"name": "Together", "headquarters": "US", "datacenters": ["US"]},
        "google-vertex": {"name": "Google", "headquarters": "US", "datacenters": ["US"]},
        "google-ai-studio": {"name": "Google AI Studio", "headquarters": "US", "datacenters": None},
    }


def watch_args(snapshot, no_save=False, as_json=False):
    return Namespace(snapshot=str(snapshot), no_save=no_save, json=as_json)


class TestWatchFirstPass(unittest.TestCase):
    def test_first_pass_creates_reference_exit_0(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 0)
            self.assertIn("Référence créée le", out.getvalue())
            self.assertTrue(snapshot_path.is_file())
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertIn("z-ai/glm-5.3", data["modeles"])
            self.assertIn("google/gemini-3.8-flash", data["modeles"])
            self.assertIn("inceptron", data["hebergeurs"])
            self.assertEqual(
                data["endpoints"]["z-ai/glm-5.3"][0]["tag"], "inceptron/fp4"
            )

    def test_no_save_writes_nothing(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout():
                    code = cr.cmd_watch(watch_args(snapshot_path, no_save=True), config)
            self.assertEqual(code, 0)
            self.assertFalse(snapshot_path.exists())


class TestWatchNoChanges(unittest.TestCase):
    def test_no_changes_exit_0(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 0)
            self.assertIn("Rien de nouveau depuis le 2026-08-25", out.getvalue())


class TestWatchConfigModels(unittest.TestCase):
    def test_disappeared_and_expiration_appeared(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            # GLM-5.3 disparaît de /models ; Gemini reste mais gagne une
            # date d'expiration qu'il n'avait pas avant.
            models = [
                {"id": "google/gemini-3.8-flash", "name": "Gemini 3.8 Flash", "created": 1751000000,
                 "context_length": 1000000, "pricing": {"prompt": "0.0000005", "completion": "0.0000015"},
                 "expiration_date": "2026-12-01"},
            ]
            fetch = make_fetch_json(models, sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("## 1. Modèles de la config", output)
            self.assertIn("GLM-5.3", output)
            self.assertIn("disparu de `/models`", output)
            self.assertIn("Gemini 3.8 Flash", output)
            self.assertIn("date d'expiration nouvellement renseignée : 2026-12-01", output)

    def test_price_variation_above_and_below_threshold(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            models = [
                # GLM-5.3 : prix d'entrée +50 % (> seuil 20 %)
                {"id": "z-ai/glm-5.3", "name": "GLM-5.3", "created": 1750000000, "context_length": 200000,
                 "pricing": {"prompt": "0.000003", "completion": "0.000006"}},
                # Gemini : prix de sortie +5 % (< seuil 20 %), pas de signal attendu
                {"id": "google/gemini-3.8-flash", "name": "Gemini 3.8 Flash", "created": 1751000000,
                 "context_length": 1000000,
                 "pricing": {"prompt": "0.0000005", "completion": "0.000001575"}},
            ]
            fetch = make_fetch_json(models, sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("prix d'entrée", output)
            self.assertIn("GLM-5.3", output)
            # Gemini ne doit pas apparaître dans la section 1 (aucun changement retenu)
            self.assertNotIn("Gemini 3.8 Flash** (`google/gemini-3.8-flash`)", output)


class TestWatchHebergeursConfig(unittest.TestCase):
    def test_eu_hoster_appeared_by_datacenter_and_by_tag(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            providers = sample_providers(extra=[
                {"slug": "novita", "name": "Novita", "headquarters": "US", "datacenters": ["DE"]},
            ])
            endpoints = dict(sample_endpoints())
            endpoints["z-ai/glm-5.3"] = endpoints["z-ai/glm-5.3"] + [
                {"tag": "novita/fp8", "provider_name": "Novita", "quantization": "fp8", "status": "active"},
                {"tag": "mistral/eu", "provider_name": "Mistral", "quantization": "fp8", "status": "active"},
            ]
            fetch = make_fetch_json(sample_models(), providers, endpoints)
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("## 2. Hébergeurs des modèles de la config", output)
            self.assertIn("novita/fp8", output)
            self.assertIn("datacenter DE", output)
            self.assertIn("mistral/eu", output)
            self.assertIn("tag /eu", output)

    def test_chinese_hoster_appeared(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            providers = sample_providers(extra=[
                {"slug": "siliconflow", "name": "SiliconFlow", "headquarters": "CN", "datacenters": ["CN"]},
            ])
            endpoints = dict(sample_endpoints())
            endpoints["z-ai/glm-5.3"] = endpoints["z-ai/glm-5.3"] + [
                {"tag": "siliconflow/fp8", "provider_name": "SiliconFlow", "quantization": "fp8", "status": "active"},
            ]
            fetch = make_fetch_json(sample_models(), providers, endpoints)
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("siliconflow/fp8", output)
            self.assertIn("CHINE (ignore_chine)", output)

    def test_whitelisted_hoster_disappeared_is_bolded(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            # "inceptron/fp4" disparaît (il était dans la liste blanche de
            # z-ai/glm-5.3, slug "inceptron", dans base_config()).
            endpoints = {
                "z-ai/glm-5.3": [
                    {"tag": "mistral", "provider_name": "Mistral", "quantization": "nvfp4", "status": "active"},
                ],
                "google/gemini-3.8-flash": sample_endpoints()["google/gemini-3.8-flash"],
            }
            fetch = make_fetch_json(sample_models(), sample_providers(), endpoints)
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("**disparu : `inceptron/fp4`", output)
            self.assertIn("était dans la liste blanche", output)


class TestWatchNewModels(unittest.TestCase):
    def test_new_model_in_family_respects_exclusion(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            extra_models = [
                {"id": "z-ai/glm-5.4", "name": "GLM-5.4", "created": 1760000000, "context_length": 256000,
                 "pricing": {"prompt": "0.0000025", "completion": "0.0000065"}},
                {"id": "z-ai/glm-5.4-image", "name": "GLM-5.4 Image", "created": 1760000000,
                 "context_length": 32000, "pricing": {"prompt": "0.000001", "completion": "0.000001"}},
            ]
            models = sample_models(extra=extra_models)
            endpoints = dict(sample_endpoints())
            endpoints["z-ai/glm-5.4"] = [
                {"tag": "together/fp8", "provider_name": "Together", "quantization": "fp8", "status": "active"},
                {"tag": "mistral/eu", "provider_name": "Mistral", "quantization": "fp8", "status": "active"},
            ]
            fetch = make_fetch_json(models, sample_providers(), endpoints)
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("## 3. Nouveaux modèles des familles suivies", output)
            self.assertIn("GLM-5.4", output)
            self.assertIn("famille GLM", output)
            # Le motif d'exclusion ("image") doit écarter le second modèle
            self.assertNotIn("glm-5.4-image", output)
            self.assertNotIn("GLM-5.4 Image", output)
            # Un hébergeur UE (mistral/eu) doit être listé
            self.assertIn("UE :", output)


class TestWatchNewHosters(unittest.TestCase):
    def test_new_openrouter_hoster_cn_sg_and_null(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            providers = sample_providers(extra=[
                {"slug": "baidu-cloud", "name": "Baidu Cloud", "headquarters": "CN", "datacenters": ["CN"]},
                {"slug": "sg-host", "name": "SG Host", "headquarters": "SG", "datacenters": ["SG"]},
                {"slug": "mystery-host", "name": "Mystery Host", "headquarters": None, "datacenters": None},
            ])
            fetch = make_fetch_json(sample_models(), providers, sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("## 4. Nouveaux hébergeurs OpenRouter", output)
            self.assertIn("baidu-cloud", output)
            self.assertIn("siège CN", output)
            self.assertIn("sg-host", output)
            self.assertIn("mystery-host", output)
            self.assertIn("origine à vérifier", output)


class TestWatchNetworkAndEndpointFailures(unittest.TestCase):
    def test_network_error_on_models_exits_2_snapshot_intact(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            previous = write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            original_content = snapshot_path.read_text(encoding="utf-8")

            def _fetch(url, timeout_s=30, retry_log=None):
                raise cr.urllib.error.URLError("connexion refusée")

            with mock.patch.object(cr, "fetch_json", side_effect=_fetch):
                with captured_stderr() as err:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 2)
            self.assertIn("cross-review", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())
            self.assertEqual(snapshot_path.read_text(encoding="utf-8"), original_content)
            self.assertEqual(json.loads(original_content)["date"], previous["date"])

    def test_single_endpoint_failure_is_not_fatal(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            errors = {"z-ai/glm-5.3": "délai dépassé"}
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints(), endpoint_errors=errors)
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            # Rien d'autre n'a changé : l'échec /endpoints n'est pas fatal,
            # et les hébergeurs de l'instantané précédent sont conservés
            # pour ce modèle, donc aucune différence détectée -> code 0.
            self.assertEqual(code, 0)
            output = out.getvalue()
            self.assertIn("Rien de nouveau", output)
            self.assertIn("Échecs de vérification (non fatal)", output)
            self.assertIn("z-ai/glm-5.3", output)
            self.assertIn("délai dépassé", output)
            # L'instantané réécrit doit conserver les endpoints précédents
            # pour ce modèle (pas d'écrasement par une liste vide).
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data["endpoints"]["z-ai/glm-5.3"]), 2)


class TestWatchJsonOutput(unittest.TestCase):
    def test_json_report_has_expected_keys(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            providers = sample_providers(extra=[
                {"slug": "novita", "name": "Novita", "headquarters": "US", "datacenters": ["DE"]},
            ])
            fetch = make_fetch_json(sample_models(), providers, sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path, as_json=True), config)
            self.assertEqual(code, 10)
            report = json.loads(out.getvalue())
            self.assertEqual(report["resume"]["nouveaux_hebergeurs"], 1)
            self.assertEqual(report["nouveaux_hebergeurs"][0]["slug"], "novita")
            self.assertFalse(report["rien_de_nouveau"])


class TestWatchSnapshotWriteFailure(unittest.TestCase):
    def test_write_failure_on_first_pass_exits_2(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with mock.patch.object(cr, "open", create=True,
                                        side_effect=PermissionError(1, "Operation not permitted")):
                    with captured_stderr() as err:
                        code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 2)
            self.assertIn("cross-review", err.getvalue())
            self.assertIn("chemin complet", err.getvalue())
            self.assertFalse(snapshot_path.exists())


# ---------------------------------------------------------------------------
# Corrections de revue croisée du 2026-09-25 (sous-commande watch)
# ---------------------------------------------------------------------------

# Point 1 : instantané illisible (JSON invalide, ou JSON valide qui n'est
# pas un objet) distingué de l'absence pure et simple.
class TestSnapshotUnreadable(unittest.TestCase):
    def test_invalid_json_exits_2_and_leaves_file_untouched(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            snapshot_path.write_text("{ceci n'est pas du JSON", encoding="utf-8")
            original = snapshot_path.read_text(encoding="utf-8")
            with captured_stderr() as err:
                code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 2)
            self.assertIn("illisible", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())
            self.assertEqual(snapshot_path.read_text(encoding="utf-8"), original)

    def test_json_list_instead_of_object_exits_2_and_leaves_file_untouched(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            snapshot_path.write_text(json.dumps(["pas", "un", "objet"]), encoding="utf-8")
            original = snapshot_path.read_text(encoding="utf-8")
            with captured_stderr() as err:
                code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 2)
            self.assertIn("illisible", err.getvalue())
            self.assertEqual(snapshot_path.read_text(encoding="utf-8"), original)

    def test_absent_file_is_not_unreadable_first_pass_proceeds(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 0)
            self.assertIn("Référence créée", out.getvalue())


# Point 2 : un modèle ajouté à la config depuis le dernier passage ne doit
# pas être signalé comme « apparu » / expiration nouvellement renseignée.
class TestWatchNewModelInConfig(unittest.TestCase):
    def test_new_config_model_is_noted_not_reported_as_change(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            # Instantané précédent : seul GLM-5.3 était suivi (Gemini vient
            # d'être ajouté à la config).
            previous_modeles = {"z-ai/glm-5.3": base_previous_modeles()["z-ai/glm-5.3"]}
            previous_endpoints = {"z-ai/glm-5.3": sample_endpoints()["z-ai/glm-5.3"]}
            write_previous_snapshot(snapshot_path, previous_modeles, previous_endpoints, base_previous_hebergeurs())
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            output = out.getvalue()
            self.assertEqual(code, 0)
            self.assertIn("Nouveau dans la config", output)
            self.assertIn("Gemini 3.8 Flash", output)
            self.assertNotIn("apparu", output)
            self.assertNotIn("nouvellement renseignée", output)
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertIn("google/gemini-3.8-flash", data["modeles"])


# Point 3 : détection UE par segment exact de tag, deux niveaux.
class TestEuStatusLevels(unittest.TestCase):
    def test_tag_substring_europe_does_not_match_eu_segment(self):
        # "google-vertex/europe" ne doit pas être pris pour un tag /eu
        # (l'ancien test contenait "eu" comme sous-chaîne de "europe").
        result = cr.eu_status("google-vertex/europe", {"headquarters": "US", "datacenters": ["US"]})
        self.assertIsNone(result)

    def test_exact_eu_segment_is_confirme(self):
        result = cr.eu_status("mistral/eu", {"headquarters": "FR", "datacenters": None})
        self.assertEqual(result["niveau"], "confirme")
        self.assertIn("tag /eu", result["raisons"])

    def test_all_datacenters_eu_is_confirme(self):
        result = cr.eu_status("novita/fp8", {"headquarters": "US", "datacenters": ["DE", "FR"]})
        self.assertEqual(result["niveau"], "confirme")

    def test_partial_eu_datacenters_is_possible(self):
        result = cr.eu_status("novita/fp8", {"headquarters": "US", "datacenters": ["DE", "US"]})
        self.assertEqual(result["niveau"], "possible")

    def test_eu_headquarters_without_datacenters_is_possible(self):
        result = cr.eu_status("mistral", {"headquarters": "FR", "datacenters": None})
        self.assertEqual(result["niveau"], "possible")

    def test_no_signal_returns_none(self):
        result = cr.eu_status("together/fp8", {"headquarters": "US", "datacenters": ["US"]})
        self.assertIsNone(result)


# Point 4 : correspondance exacte de la liste blanche.
class TestHosterInWhitelistExact(unittest.TestCase):
    def test_base_slug_covers_its_variants_only(self):
        model_cfg = {"hebergeurs": [{"slug": "inceptron"}]}
        self.assertTrue(cr.hoster_in_whitelist("inceptron", model_cfg))
        self.assertTrue(cr.hoster_in_whitelist("inceptron/fp4", model_cfg))
        self.assertFalse(cr.hoster_in_whitelist("inceptron-autre", model_cfg))

    def test_variant_entry_does_not_cover_sibling_variant(self):
        model_cfg = {"hebergeurs": [{"slug": "google-vertex/global"}]}
        self.assertTrue(cr.hoster_in_whitelist("google-vertex/global", model_cfg))
        self.assertTrue(cr.hoster_in_whitelist("google-vertex/global/asia", model_cfg))
        self.assertFalse(cr.hoster_in_whitelist("google-vertex/europe", model_cfg))

    def test_variant_entry_does_not_cover_bare_base(self):
        model_cfg = {"hebergeurs": [{"slug": "mistral/eu"}]}
        self.assertFalse(cr.hoster_in_whitelist("mistral", model_cfg))
        self.assertTrue(cr.hoster_in_whitelist("mistral/eu", model_cfg))


# Point 5 : un modèle disparu puis revenu est comparé à ses dernières
# valeurs connues, retenues dans l'instantané (absent_depuis).
class TestWatchModelDisappearedThenReturned(unittest.TestCase):
    def test_disappears_then_returns_with_price_change(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )

            # Passage 1 : Gemini disparaît de /models.
            models_pass1 = [m for m in sample_models() if m["id"] != "google/gemini-3.8-flash"]
            fetch1 = make_fetch_json(models_pass1, sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch1):
                with captured_stdout() as out1:
                    code1 = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code1, 10)
            self.assertIn("disparu de `/models`", out1.getvalue())
            self.assertIn("Gemini 3.8 Flash", out1.getvalue())
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            gemini_snap = data["modeles"]["google/gemini-3.8-flash"]
            self.assertIsNotNone(gemini_snap["absent_depuis"])
            # Les dernières valeurs connues sont conservées.
            self.assertEqual(gemini_snap["prix_entree"], 0.0000005)

            # Passage 2 : Gemini revient, avec un prix d'entrée en forte
            # hausse (+100 %, largement au-dessus du seuil de 20 %).
            models_pass2 = sample_models()
            for m in models_pass2:
                if m["id"] == "google/gemini-3.8-flash":
                    m["pricing"] = {"prompt": "0.000001", "completion": "0.0000015"}
            fetch2 = make_fetch_json(models_pass2, sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch2):
                with captured_stdout() as out2:
                    code2 = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code2, 10)
            output2 = out2.getvalue()
            self.assertIn("de retour dans `/models`", output2)
            self.assertIn("prix d'entrée", output2)
            data2 = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertIsNone(data2["modeles"]["google/gemini-3.8-flash"]["absent_depuis"])


# Point 6 : changement (ou retrait) d'une date d'expiration déjà connue.
class TestWatchExpirationChangedOrRemoved(unittest.TestCase):
    def test_expiration_date_changed_is_reported(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            previous_modeles = base_previous_modeles()
            previous_modeles["google/gemini-3.8-flash"]["expiration_date"] = "2026-10-01"
            write_previous_snapshot(snapshot_path, previous_modeles, sample_endpoints(), base_previous_hebergeurs())
            models = sample_models()
            for m in models:
                if m["id"] == "google/gemini-3.8-flash":
                    m["expiration_date"] = "2026-12-01"
            fetch = make_fetch_json(models, sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("date d'expiration modifiée", output)
            self.assertIn("2026-10-01", output)
            self.assertIn("2026-12-01", output)

    def test_expiration_date_removed_is_reported(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            previous_modeles = base_previous_modeles()
            previous_modeles["google/gemini-3.8-flash"]["expiration_date"] = "2026-10-01"
            write_previous_snapshot(snapshot_path, previous_modeles, sample_endpoints(), base_previous_hebergeurs())
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            self.assertIn("date d'expiration retirée", out.getvalue())


# Points 7 et 8 : nouveaux modèles jamais vérifiés (plafond d'appels ou
# échec) ne sont pas enregistrés dans l'instantané et restent « nouveaux ».
class TestWatchNewModelDeferredVerification(unittest.TestCase):
    def test_beyond_call_cap_not_recorded_and_reported_as_deferred(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            extra = [{"id": "z-ai/glm-5.4", "name": "GLM-5.4", "created": 1760000000,
                      "context_length": 256000, "pricing": {"prompt": "0.0000025", "completion": "0.0000065"}}]
            models = sample_models(extra=extra)
            fetch = make_fetch_json(models, sample_providers(), sample_endpoints())
            # Le plafond (2, la taille de config.models) est déjà atteint par
            # les modèles de la config : le nouveau modèle n'est jamais
            # interrogé sur /endpoints.
            with mock.patch.object(cr, "MAX_ENDPOINT_CALLS", 2):
                with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                    with captured_stdout() as out:
                        code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("GLM-5.4", output)
            self.assertIn("vérification reportée au prochain passage (plafond d'appels)", output)
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertNotIn("z-ai/glm-5.4", data["modeles"])

    def test_endpoint_failure_not_recorded_and_reported_with_error(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            extra = [{"id": "z-ai/glm-5.4", "name": "GLM-5.4", "created": 1760000000,
                      "context_length": 256000, "pricing": {"prompt": "0.0000025", "completion": "0.0000065"}}]
            models = sample_models(extra=extra)
            errors = {"z-ai/glm-5.4": "délai dépassé"}
            fetch = make_fetch_json(models, sample_providers(), sample_endpoints(), endpoint_errors=errors)
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 10)
            output = out.getvalue()
            self.assertIn("GLM-5.4", output)
            self.assertIn("hébergeurs non vérifiés : échec de l'appel (délai dépassé)", output)
            self.assertIn("vérification reportée au prochain passage", output)
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertNotIn("z-ai/glm-5.4", data["modeles"])
            # L'échec d'un nouveau modèle ne doit pas apparaître dans la
            # note générique « Échecs de vérification » (réservée aux
            # modèles de la config, avec rétention des hébergeurs).
            self.assertNotIn("Échecs de vérification (non fatal)", output)


# Point 9 : rendu complet en mémoire avant l'écriture de l'instantané ; si
# le rendu échoue, rien n'est écrit.
class TestWatchRenderFailureDoesNotWriteSnapshot(unittest.TestCase):
    def test_markdown_render_exception_exits_2_snapshot_untouched(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            write_previous_snapshot(
                snapshot_path, base_previous_modeles(), sample_endpoints(), base_previous_hebergeurs()
            )
            original_content = snapshot_path.read_text(encoding="utf-8")
            models = [m for m in sample_models() if m["id"] != "google/gemini-3.8-flash"]
            fetch = make_fetch_json(models, sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with mock.patch.object(cr, "render_watch_markdown", side_effect=RuntimeError("boum")):
                    with captured_stderr() as err:
                        code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 2)
            self.assertEqual(len(err.getvalue().splitlines()), 1)
            self.assertNotIn("Traceback", err.getvalue())
            self.assertEqual(snapshot_path.read_text(encoding="utf-8"), original_content)


# Point 10 : seconde tentative réseau après une coupure transitoire.
class FakeHttpResponse:
    def __init__(self, text=None, headers=None, raw=None):
        self._data = raw if raw is not None else text.encode("utf-8")
        # `.get()` comme sur un vrai `resp.headers` ; {} par défaut (pas de
        # Content-Encoding), pour ne rien changer aux tests existants qui ne
        # passent pas `headers`.
        self.headers = headers if headers is not None else {}

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestFetchJsonRetry(unittest.TestCase):
    def test_transient_error_then_success_retries_once(self):
        attempts = []

        def fake_urlopen(req, timeout=None):
            attempts.append(1)
            if len(attempts) == 1:
                raise cr.urllib.error.URLError("connexion refusée")
            return FakeHttpResponse(json.dumps({"data": []}))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.fetch_json("https://openrouter.ai/api/v1/models")
        self.assertEqual(result, {"data": []})
        self.assertEqual(len(attempts), 2)
        sleep_mock.assert_called_once_with(cr.RETRY_DELAY_S)

    def test_non_retryable_4xx_raises_without_retry(self):
        def fake_urlopen(req, timeout=None):
            raise cr.urllib.error.HTTPError("url", 404, "Not Found", {}, io.BytesIO(b"{}"))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                with self.assertRaises(cr.urllib.error.HTTPError):
                    cr.fetch_json("https://openrouter.ai/api/v1/models")
        sleep_mock.assert_not_called()

    def test_retry_appends_url_to_retry_log(self):
        attempts = []

        def fake_urlopen(req, timeout=None):
            attempts.append(1)
            if len(attempts) == 1:
                raise cr.http.client.IncompleteRead(b"")
            return FakeHttpResponse(json.dumps({"data": []}))

        retry_log = []
        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep"):
                cr.fetch_json("https://openrouter.ai/api/v1/models", retry_log=retry_log)
        self.assertEqual(retry_log, ["https://openrouter.ai/api/v1/models"])


class TestCallOpenrouterRetry(unittest.TestCase):
    def test_connection_error_before_response_then_success_retries_once(self):
        attempts = []

        def fake_urlopen(req, timeout=None):
            attempts.append(1)
            if len(attempts) == 1:
                raise cr.urllib.error.URLError("connexion réinitialisée")
            return FakeHttpResponse(json.dumps({"id": "gen-1", "choices": []}))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertTrue(result["ok"])
        self.assertEqual(result["tentatives"], 2)
        self.assertEqual(len(attempts), 2)
        sleep_mock.assert_called_once_with(cr.RETRY_DELAY_S)

    def test_incomplete_read_on_200_never_retried(self):
        attempts = []

        def fake_urlopen(req, timeout=None):
            attempts.append(1)
            raise cr.http.client.IncompleteRead(b"")

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertFalse(result["ok"])
        self.assertEqual(result["tentatives"], 1)
        self.assertEqual(len(attempts), 1)
        sleep_mock.assert_not_called()

    def test_503_no_available_provider_never_retried(self):
        attempts = []

        def fake_urlopen(req, timeout=None):
            attempts.append(1)
            body = json.dumps({"error": {"code": 503, "message": "no available provider"}}).encode("utf-8")
            raise cr.urllib.error.HTTPError("url", 503, "Service Unavailable", {}, io.BytesIO(body))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertFalse(result["ok"])
        self.assertEqual(result["tentatives"], 1)
        self.assertEqual(len(attempts), 1)
        sleep_mock.assert_not_called()

    def test_502_retried_once(self):
        attempts = []

        def fake_urlopen(req, timeout=None):
            attempts.append(1)
            if len(attempts) == 1:
                body = json.dumps({"error": {"code": 502, "message": "bad gateway"}}).encode("utf-8")
                raise cr.urllib.error.HTTPError("url", 502, "Bad Gateway", {}, io.BytesIO(body))
            return FakeHttpResponse(json.dumps({"id": "gen-2", "choices": []}))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertTrue(result["ok"])
        self.assertEqual(result["tentatives"], 2)
        sleep_mock.assert_called_once_with(cr.RETRY_DELAY_S)

    def test_tentatives_shown_in_reviewer_header(self):
        config = base_config()
        model_cfg = config["models"]["z-ai/glm-5.3"]
        result = cr.process_model_response(
            {"ok": False, "error": "connexion impossible : refusée", "tentatives": 2},
            "z-ai/glm-5.3", model_cfg, "GLM-5.3", "G", 100, 0, 4.0, config,
        )
        self.assertEqual(result["tentatives"], 2)
        md = cr.render_reviewer_markdown(result, model_cfg)
        self.assertIn("2 tentatives", md)


# ---------------------------------------------------------------------------
# call_openrouter : timeout et reprise réseau bornés par l'échéance globale
# ---------------------------------------------------------------------------

class TestCallOpenrouterDeadline(unittest.TestCase):
    def test_no_deadline_uses_timeout_as_is(self):
        calls = []

        def fake_once(endpoint, api_key, body, timeout_s):
            calls.append(timeout_s)
            return {"ok": True, "data": {"id": "x", "choices": []}, "retryable": False}

        with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
            cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertEqual(calls, [30])

    def test_timeout_bounded_by_remaining_deadline(self):
        calls = []

        def fake_once(endpoint, api_key, body, timeout_s):
            calls.append(timeout_s)
            return {"ok": True, "data": {"id": "x", "choices": []}, "retryable": False}

        # Il reste ~10 s avant l'échéance, marge CALL_TIMEOUT_MARGIN_S=5 s :
        # le timeout envoyé doit être ~5 s, pas les 480 s demandés.
        deadline = cr.time.time() + 10
        with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
            cr.call_openrouter(
                "https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 480, deadline=deadline
            )
        self.assertEqual(len(calls), 1)
        self.assertLess(calls[0], 480)
        self.assertTrue(3 <= calls[0] <= 6, f"timeout inattendu : {calls[0]}")

    def test_retry_skipped_when_not_enough_time_before_deadline(self):
        attempts = []

        def fake_once(endpoint, api_key, body, timeout_s):
            attempts.append(timeout_s)
            return {"ok": False, "error": "connexion impossible : x", "retryable": True}

        # Il ne reste que 10 s avant l'échéance : moins que
        # CALL_RETRY_MIN_REMAINING_S (30 s), donc pas de reprise réseau même
        # si l'échec est normalement rejouable.
        deadline = cr.time.time() + 10
        with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.call_openrouter(
                    "https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 480, deadline=deadline
                )
        self.assertEqual(len(attempts), 1)
        self.assertEqual(result["tentatives"], 1)
        sleep_mock.assert_not_called()

    def test_retry_attempted_when_enough_time_before_deadline(self):
        attempts = []

        def fake_once(endpoint, api_key, body, timeout_s):
            attempts.append(timeout_s)
            if len(attempts) == 1:
                return {"ok": False, "error": "connexion impossible : x", "retryable": True}
            return {"ok": True, "data": {"id": "x", "choices": []}, "retryable": False}

        deadline = cr.time.time() + 120  # largement assez de marge pour la reprise
        with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.call_openrouter(
                    "https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 480, deadline=deadline
                )
        self.assertEqual(len(attempts), 2)
        self.assertEqual(result["tentatives"], 2)
        sleep_mock.assert_called_once_with(cr.RETRY_DELAY_S)


# ---------------------------------------------------------------------------
# cmd_review : le garde-fou doit vraiment rendre la main (pas d'attente sur
# un thread encore occupé au-delà de l'échéance).
# ---------------------------------------------------------------------------

class TestReviewGuardRendsLaMain(unittest.TestCase):
    def test_guard_returns_promptly_without_waiting_for_blocked_worker(self):
        config = base_config()
        config["deadline_s"] = 0.2

        def fake_once(endpoint, api_key, body, timeout_s):
            # Bien plus long que le garde-fou patché ci-dessous (~0.5 s) :
            # simule un appel resté bloqué (réseau, hébergeur muet...).
            cr.time.sleep(1.5)
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": "Inceptron",
                    "usage": {},
                    "choices": [{"message": {"content": "RIEN À SIGNALER"}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            args = Namespace(
                mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )

            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with mock.patch.object(cr, "GUARD_EXTRA_MARGIN_S", 0.3):
                        start = cr.time.time()
                        code = cr.cmd_review(args, config)
                        elapsed = cr.time.time() - start

            # Le garde-fou (échéance 0.2 s + marge patchée 0.3 s) doit
            # rendre la main bien avant que le faux appel (1.5 s) ne se
            # termine : preuve que cmd_review ne bloque pas sur
            # future.result(timeout=...) et n'attend pas non plus
            # l'exécuteur (shutdown(wait=False)). Lu à l'intérieur du bloc
            # tempfile : celui-ci supprime run_dir à la sortie.
            self.assertLess(elapsed, 1.2)
            self.assertEqual(code, 3)  # aucun relecteur n'a répondu à temps
            tiers_md = (run_dir / "tiers.md").read_text(encoding="utf-8")
            self.assertIn("garde-fou dépassé", tiers_md)


class TestReviewGuardDeadlineIsAbsoluteNotCumulative(unittest.TestCase):
    def test_two_blocked_models_do_not_add_up_the_guard_margin(self):
        # Point C1 (revue croisée du 2026-09-28) : avant, le timeout de
        # future.result(...) était recalculé pour CHAQUE future comme
        # « temps restant + marge », donc la marge s'additionnait une fois
        # par modèle bloqué (2 modèles, échéance 2 s, marge 1 s -> retour
        # constaté à 4,02 s). Avec une échéance absolue unique
        # (guard_deadline = command_deadline + GUARD_EXTRA_MARGIN_S), le
        # retour doit rester borné par échéance + marge (+ une petite
        # tolérance), quel que soit le nombre de modèles bloqués.
        config = base_config()
        config["deadline_s"] = 0.2
        config["modes"]["code"] = ["z-ai/glm-5.3", "google/gemini-3.8-flash"]

        def fake_once(endpoint, api_key, body, timeout_s):
            cr.time.sleep(3.0)  # bien plus long que échéance + marge
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": "Inceptron",
                    "usage": {},
                    "choices": [{"message": {"content": "RIEN À SIGNALER"}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            args = Namespace(
                mode="code", model=["z-ai/glm-5.3", "google/gemini-3.8-flash"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )

            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with mock.patch.object(cr, "GUARD_EXTRA_MARGIN_S", 0.4):
                        start = cr.time.time()
                        code = cr.cmd_review(args, config)
                        elapsed = cr.time.time() - start

            # Échéance (0.2 s) + marge (0.4 s) + petite tolérance : un
            # garde-fou cumulé additionnerait la marge une deuxième fois
            # pour le second modèle (~1,0 s), donc 0.9 s discrimine bien
            # les deux comportements.
            self.assertLess(elapsed, 0.9)
            self.assertEqual(code, 3)  # aucun relecteur n'a répondu à temps
            tiers_md = (run_dir / "tiers.md").read_text(encoding="utf-8")
            self.assertEqual(tiers_md.count("garde-fou dépassé"), 2)

            # La durée affichée est le temps écoulé depuis le LANCEMENT des
            # appels, pas le temps restant d'attente de cette itération de
            # boucle : avant ce correctif, le second modèle traité dans la
            # boucle affichait « 0.0 s » (le temps restant avant
            # guard_deadline, déjà consommé par l'attente du premier), alors
            # qu'il avait attendu tout autant que le premier modèle.
            waits = [float(x) for x in cr.re.findall(r"pas de réponse après ([\d.]+) s", tiers_md)]
            self.assertEqual(len(waits), 2)
            for w in waits:
                self.assertGreater(w, 0.3)


class TestReviewGuardMessageDistinguishesTimeoutFromOtherError(unittest.TestCase):
    # Point C5 (revue croisée du 2026-09-28) : avant, le message du
    # garde-fou (« garde-fou dépassé : {e} ») était le même pour un vrai
    # dépassement de délai (concurrent.futures.TimeoutError) que pour une
    # autre exception levée par le worker, ce qui rendait le second cas
    # illisible.

    def test_real_timeout_gives_deadline_message(self):
        config = base_config()
        config["deadline_s"] = 0.1

        def fake_once(endpoint, api_key, body, timeout_s):
            cr.time.sleep(2.0)  # bien plus long que échéance + marge
            return {"ok": True, "data": {}, "retryable": False}

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            args = Namespace(
                mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with mock.patch.object(cr, "GUARD_EXTRA_MARGIN_S", 0.2):
                        code = cr.cmd_review(args, config)

            tiers_md = (run_dir / "tiers.md").read_text(encoding="utf-8")
            self.assertIn(
                "garde-fou dépassé : pas de réponse après", tiers_md,
            )
            self.assertIn("échéance globale deadline_s=0.1 s", tiers_md)
            self.assertNotIn("erreur interne", tiers_md)

            # La durée affichée doit être un temps écoulé plausible depuis
            # le lancement de l'appel (~ deadline_s + marge = 0.3 s), pas
            # « 0.0 s » ni la durée du sleep simulé (2.0 s).
            m = cr.re.search(r"pas de réponse après ([\d.]+) s", tiers_md)
            self.assertIsNotNone(m)
            waited = float(m.group(1))
            self.assertGreater(waited, 0.15)
            self.assertLess(waited, 1.0)

    def test_other_worker_exception_gives_erreur_interne_message(self):
        config = base_config()

        def fake_once(endpoint, api_key, body, timeout_s):
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": "Inceptron",
                    "usage": {},
                    "choices": [{"message": {"content": "RIEN À SIGNALER"}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        def boom(*args, **kwargs):
            raise ValueError("boum interne")

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            args = Namespace(
                mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with mock.patch.object(cr, "process_model_response", side_effect=boom):
                        code = cr.cmd_review(args, config)

            tiers_md = (run_dir / "tiers.md").read_text(encoding="utf-8")
            self.assertIn("erreur interne : ValueError : boum interne", tiers_md)
            self.assertNotIn("garde-fou dépassé", tiers_md)


class TestReviewWriteFailure(unittest.TestCase):
    def test_run_dir_read_only_does_not_lose_reviewer_output(self):
        # Point 7 (revue croisée) : les écritures tiers-*.json/.md,
        # tiers.md et review.json de cmd_review n'étaient pas protégées.
        # Un run_dir en lecture seule ne doit ni faire planter la commande,
        # ni perdre le rendu déjà payé du relecteur.
        #
        # Point 1 (revue croisée du 2026-09-28) : avant, tiers_md_parts se
        # remplissait dans la même boucle que les écritures ; si la
        # PREMIÈRE écriture échouait, seuls les rendus déjà calculés à ce
        # moment-là étaient affichés. Deux modèles ici pour le constater :
        # les rendus des DEUX relecteurs doivent être présents sur stdout
        # même si l'écriture échoue dès le premier tiers-*.json.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("chmod 555 est ignoré en root")

        config = base_config()

        def fake_once(endpoint, api_key, body, timeout_s):
            if body["model"] == "z-ai/glm-5.3":
                provider = "Inceptron"
                content = (
                    "### [BLOQUANT] Constat distinctif GLM 9f3e\n"
                    "- **Où** : a.php\n"
                    "- **Problème** : b.\n"
                    "- **Pourquoi** : c.\n"
                )
            else:
                provider = "Google"
                content = (
                    "### [IMPORTANT] Constat distinctif Gemini 4b7c\n"
                    "- **Où** : b.php\n"
                    "- **Problème** : b.\n"
                    "- **Pourquoi** : c.\n"
                )
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": provider,
                    "usage": {},
                    "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            run_dir.chmod(0o555)

            args = Namespace(
                mode="code", model=["z-ai/glm-5.3", "google/gemini-3.8-flash"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )
            try:
                with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                    with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                        with captured_stdout() as out, captured_stderr() as err:
                            code = cr.cmd_review(args, config)
            finally:
                run_dir.chmod(0o755)

            self.assertEqual(code, 2)
            self.assertNotIn("Traceback", err.getvalue())
            self.assertIn("Relecteur : GLM-5.3", out.getvalue())
            self.assertIn("Relecteur : Gemini 3.8 Flash", out.getvalue())
            self.assertIn("Format : conforme", out.getvalue())
            # Les DEUX rendus doivent être présents, pas seulement celui
            # dont l'écriture aurait été tentée en premier.
            self.assertIn("Constat distinctif GLM 9f3e", out.getvalue())
            self.assertIn("Constat distinctif Gemini 4b7c", out.getvalue())


# Point 1 (revue croisée du 2026-09-25) : au premier passage, TOUS les
# modèles suivis (config + familles hors exclure_motif) doivent entrer dans
# la référence, sans appel /endpoints pour les modèles de familles.
class TestWatchFirstPassRegistersAllFamilyModels(unittest.TestCase):
    def test_first_pass_records_all_family_models_without_endpoint_calls(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            extra_models = [
                {"id": f"z-ai/glm-test-{i}", "name": f"GLM Test {i}", "created": 1750000000 + i,
                 "context_length": 128000, "pricing": {"prompt": "0.000001", "completion": "0.000002"}}
                for i in range(40)
            ]
            models = sample_models(extra=extra_models)
            endpoint_calls = []

            def fetch(url, timeout_s=30, retry_log=None):
                if url == cr.OPENROUTER_MODELS_URL:
                    return {"data": models}
                if url == cr.OPENROUTER_PROVIDERS_URL:
                    return {"data": sample_providers()}
                endpoint_calls.append(url)
                for mid, eps in sample_endpoints().items():
                    if url == cr.OPENROUTER_ENDPOINTS_URL_TMPL.format(model_id=mid):
                        return {"data": {"endpoints": eps}}
                return {"data": {"endpoints": []}}

            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 0)
            self.assertIn("42 modèles suivis", out.getvalue())

            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data["modeles"]), 42)
            for i in range(40):
                self.assertIn(f"z-ai/glm-test-{i}", data["modeles"])
            # Seuls les modèles de la config ont leurs endpoints dans la référence.
            self.assertEqual(set(data["endpoints"].keys()), {"z-ai/glm-5.3", "google/gemini-3.8-flash"})
            # Aucun appel /endpoints pour les modèles de familles au premier passage.
            self.assertEqual(len(endpoint_calls), 2)

            # Passage suivant, sans changement : rien de nouveau, code 0 (et
            # non plus 10 avec ~40 « nouveaux modèles » à chaque fois).
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out2:
                    code2 = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code2, 0)
            self.assertIn("Rien de nouveau", out2.getvalue())


# Correction du 2026-09-25 (suite) : les modèles de familles déjà connus
# (ni de la config, ni nouveaux ce passage-ci) doivent être recopiés dans
# l'instantané à partir du deuxième passage, sinon ils disparaissaient
# silencieusement (pour ressurgir en masse comme « nouveaux » ensuite).
class TestWatchFamilyModelsStableAcrossPasses(unittest.TestCase):
    def test_three_passes_no_changes_stable_model_count(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            extra_models = [
                {"id": f"z-ai/glm-test-{i}", "name": f"GLM Test {i}", "created": 1750000000 + i,
                 "context_length": 128000, "pricing": {"prompt": "0.000001", "completion": "0.000002"}}
                for i in range(40)
            ]
            models = sample_models(extra=extra_models)
            fetch = make_fetch_json(models, sample_providers(), sample_endpoints())

            counts = []
            for i in range(3):
                with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                    with captured_stdout() as out:
                        code = cr.cmd_watch(watch_args(snapshot_path), config)
                self.assertEqual(code, 0)
                if i == 0:
                    self.assertIn("modèles suivis", out.getvalue())
                else:
                    self.assertIn("Rien de nouveau", out.getvalue())
                data = json.loads(snapshot_path.read_text(encoding="utf-8"))
                counts.append(len(data["modeles"]))
            # 2 modèles de config + 40 modèles de famille, stable sur les 3 passages.
            self.assertEqual(counts, [42, 42, 42])


class TestWatchFamilyModelRemovedFromModels(unittest.TestCase):
    def test_known_family_model_no_longer_in_models_drops_silently(self):
        config = veille_config()
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "veille.json"
            previous_modeles = dict(base_previous_modeles())
            previous_modeles["z-ai/glm-5.4"] = {
                "name": "GLM-5.4", "created": 1760000000, "context_length": 256000,
                "prix_entree": 0.0000025, "prix_sortie": 0.0000065, "expiration_date": None,
                "absent_depuis": None,
            }
            write_previous_snapshot(
                snapshot_path, previous_modeles, sample_endpoints(), base_previous_hebergeurs()
            )
            # z-ai/glm-5.4 (famille GLM, déjà connu) n'est plus dans /models
            # ce passage-ci ; les modèles de la config, eux, ne changent pas.
            fetch = make_fetch_json(sample_models(), sample_providers(), sample_endpoints())
            with mock.patch.object(cr, "fetch_json", side_effect=fetch):
                with captured_stdout() as out:
                    code = cr.cmd_watch(watch_args(snapshot_path), config)
            self.assertEqual(code, 0)
            self.assertIn("Rien de nouveau", out.getvalue())
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertNotIn("z-ai/glm-5.4", data["modeles"])
            # Les modèles de la config restent bien présents.
            self.assertIn("z-ai/glm-5.3", data["modeles"])
            self.assertIn("google/gemini-3.8-flash", data["modeles"])


# Point 2 (revue croisée du 2026-09-25) : Accept-Encoding: gzip envoyé par
# fetch_json et call_openrouter, avec décompression si le serveur répond en
# Content-Encoding: gzip (contournement d'un bug du proxy réseau de
# l'environnement, qui coupe ~1 réponse non compressée sur 2 pour les gros
# payloads comme /models).
class TestFetchJsonGzip(unittest.TestCase):
    def test_gzip_compressed_response_is_decompressed(self):
        payload = json.dumps({"data": [{"id": "x"}]}).encode("utf-8")
        compressed = gzip.compress(payload)
        sent_headers = {}

        def fake_urlopen(req, timeout=None):
            sent_headers["Accept-Encoding"] = req.get_header("Accept-encoding")
            return FakeHttpResponse(raw=compressed, headers={"Content-Encoding": "gzip"})

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = cr.fetch_json("https://openrouter.ai/api/v1/models")
        self.assertEqual(result, {"data": [{"id": "x"}]})
        self.assertEqual(sent_headers["Accept-Encoding"], "gzip")

    def test_non_compressed_response_still_works(self):
        def fake_urlopen(req, timeout=None):
            return FakeHttpResponse(text=json.dumps({"data": []}))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = cr.fetch_json("https://openrouter.ai/api/v1/models")
        self.assertEqual(result, {"data": []})


class TestCallOpenrouterGzip(unittest.TestCase):
    def test_gzip_compressed_response_is_decompressed(self):
        payload = json.dumps({"id": "gen-1", "choices": []}).encode("utf-8")
        compressed = gzip.compress(payload)
        sent_headers = {}

        def fake_urlopen(req, timeout=None):
            sent_headers["Accept-Encoding"] = req.get_header("Accept-encoding")
            return FakeHttpResponse(raw=compressed, headers={"Content-Encoding": "gzip"})

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["id"], "gen-1")
        self.assertEqual(sent_headers["Accept-Encoding"], "gzip")

    def test_non_compressed_response_still_works(self):
        def fake_urlopen(req, timeout=None):
            return FakeHttpResponse(text=json.dumps({"id": "gen-1", "choices": []}))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["id"], "gen-1")

    def test_gzip_compressed_http_error_body_is_decompressed(self):
        body = json.dumps({"error": {"code": 502, "message": "bad gateway"}}).encode("utf-8")
        compressed = gzip.compress(body)

        def fake_urlopen(req, timeout=None):
            raise cr.urllib.error.HTTPError(
                "url", 502, "Bad Gateway", {"Content-Encoding": "gzip"}, io.BytesIO(compressed)
            )

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep"):
                result = cr.call_openrouter("https://openrouter.ai/api/v1/chat/completions", "sk-x", {}, 30)
        self.assertFalse(result["ok"])
        self.assertIn("bad gateway", result["error"])
        self.assertEqual(result["tentatives"], 2)


class TestCallOpenrouter402InsufficientCredit(unittest.TestCase):
    # Point C6 (revue croisée du 2026-09-28) : un 402 OpenRouter (crédit
    # insuffisant pour réserver max_tokens × prix) donnait auparavant le
    # même message opaque que n'importe quelle autre erreur HTTP.
    def test_402_gives_readable_credit_message_and_is_not_retried(self):
        body_err = json.dumps({"error": {"code": 402, "message": "Insufficient credits"}}).encode("utf-8")

        def fake_urlopen(req, timeout=None):
            raise cr.urllib.error.HTTPError("url", 402, "Payment Required", {}, io.BytesIO(body_err))

        with mock.patch.object(cr.urllib.request, "urlopen", side_effect=fake_urlopen):
            with mock.patch.object(cr.time, "sleep") as sleep_mock:
                result = cr.call_openrouter(
                    "https://openrouter.ai/api/v1/chat/completions", "sk-x",
                    {"model": "z-ai/glm-5.3", "max_tokens": 32000}, 30,
                )
        self.assertFalse(result["ok"])
        self.assertIn("crédit OpenRouter insuffisant pour max_tokens=32000", result["error"])
        self.assertIn("max_tokens × prix", result["error"])
        self.assertIn("recharger le crédit ou baisser max_tokens", result["error"])
        self.assertIn("Insufficient credits", result["error"])  # message d'origine conservé
        self.assertEqual(result["tentatives"], 1)  # 402 n'est pas rejouable
        sleep_mock.assert_not_called()


# ---------------------------------------------------------------------------
# Revue croisée du 2026-09-28 (points 1 à 8) : GL1, GL2, C2, T1, C5, C6+GL5,
# GL3+GL4, GL6.
# ---------------------------------------------------------------------------

class TestCrossReview20260928Fixes(unittest.TestCase):
    def setUp(self):
        self.config = base_config()
        self.globs = self.config["sensitive_globs"]

    # Point 1 (GL1) : sections diff --git hors de tout bloc, et bloc « Diff
    # du lot » ouvert sans FIN, filtrées comme un bloc « Diff du lot » bien
    # fermé.
    def test_gl1_diff_outside_any_block_is_filtered(self):
        content = (
            cr.wrap_block("Fichier : a.py", "x = 1\n")
            + "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        )
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("A=2", new_content)
        self.assertIn("x = 1", new_content)
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))
        self.assertEqual(info["kept_diff_sections"], 0)

    def test_gl1_diff_du_lot_unclosed_is_filtered(self):
        content = (
            "----- DÉBUT Diff du lot -----\n"
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        )
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("A=2", new_content)
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))
        self.assertEqual(info["kept_diff_sections"], 0)

    # Point 2 (GL2) : dans la branche sans marqueur, meaningful_remains
    # écarte les lignes de titre et les lignes blanches, comme la branche
    # avec marqueurs.
    def test_gl2_meaningful_remains_ignores_title_line_without_markers(self):
        content = (
            "# Contenu à relire (mode plan)\n\n"
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        )
        _new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertTrue(removed)
        self.assertFalse(info["meaningful_remains"])

    # Point 3 (C2) : BEGIN et END sur la même ligne, examen du DERNIER BEGIN
    # de la ligne. Trois BEGIN/END sur la ligne, le troisième BEGIN sans END
    # -> la ligne démarre une clé tronquée, le corps qui suit est masqué.
    def test_c2_last_begin_on_line_without_end_starts_truncated_key(self):
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + " " + PEM_END_RSA + " "
            + PEM_BEGIN_EC + " " + PEM_END_EC + " "
            + PEM_BEGIN_RSA + "\n"
            + "CORPS\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertIn("avant", joined)
        self.assertNotIn("CORPS", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    # Point 4 (T1) : finish_reason == "error" ou contenu vide hors cas
    # "length" -> relecteur indisponible (statut "echec"), erreur lisible,
    # hébergeur et coût renseignés.
    def test_t1_finish_reason_error_marks_reviewer_unavailable(self):
        config = base_config()
        model_slug = "z-ai/glm-5.3"
        model_cfg = config["models"][model_slug]
        result = {
            "ok": True,
            "data": {
                "id": "gen-err1",
                "model": model_slug,
                "provider": "Inceptron",
                "usage": {"prompt_tokens": 10, "completion_tokens": 0, "cost": 0.001},
                "choices": [{
                    "message": {"content": ""},
                    "finish_reason": "error",
                    "error": {"code": 429, "message": "Rate limited upstream"},
                }],
            },
        }
        out = cr.process_model_response(
            result, model_slug, model_cfg, "GLM-5.3", "G", 100, 0, 1.0, config,
        )
        self.assertEqual(out["statut"], "echec")
        self.assertIn("Rate limited upstream", out["erreur"])
        self.assertEqual(out["hebergeur"], "Inceptron")
        self.assertEqual(out["cout_usd"], 0.001)

    def test_t1_empty_content_without_length_marks_reviewer_unavailable(self):
        config = base_config()
        model_slug = "z-ai/glm-5.3"
        model_cfg = config["models"][model_slug]
        result = {
            "ok": True,
            "data": {
                "id": "gen-err2",
                "model": model_slug,
                "provider": "Inceptron",
                "usage": {"prompt_tokens": 10, "completion_tokens": 0, "cost": 0.0},
                "choices": [{"message": {"content": "   "}, "finish_reason": "stop"}],
            },
        }
        out = cr.process_model_response(
            result, model_slug, model_cfg, "GLM-5.3", "G", 100, 0, 1.0, config,
        )
        self.assertEqual(out["statut"], "echec")
        self.assertIn("réponse vide", out["erreur"])
        self.assertIn("finish_reason=stop", out["erreur"])
        md = cr.render_reviewer_markdown(out, model_cfg)
        self.assertIn("⚠ Indisponible :", md)
        self.assertNotIn("format non respecté", md)

    # Point 5 (C5) : la ligne « Contenu envoyé » additionne ce que collect a
    # retiré/masqué à ce que review a retiré/masqué, en distinguant les deux.
    def test_c5_tiers_md_combines_collect_and_review_removals(self):
        config = base_config()
        model_cfg = config["models"]["z-ai/glm-5.3"]
        result = {
            "label": "GLM-5.3", "prefixe": "G", "modele_demande": "z-ai/glm-5.3",
            "hebergeur": "Inceptron", "hebergeur_ok": True, "statut": "ok",
            "erreur": None, "appel_id": "gen-1", "modele_renvoye": "z-ai/glm-5.3",
            "cout_usd": 0.01, "tokens": {"prompt": 10, "completion": 5, "reasoning": None},
            "duree_s": 1.0, "finish_reason": "stop", "max_tokens_utilise": 1000,
            "tronque": False, "blocs_retires": 0, "format_ok": True,
            "rien_a_signaler": True, "findings": [], "contenu_envoye_chars": 500,
            "original_chars": 600, "removed_sections": [{"fichier": "img.png", "raison": "binaire"}],
            "secrets_masked_count": 0, "ordre_essai": "inceptron",
        }
        collect_info = {
            "files_excluded": [{"fichier": ".env", "raison": "sensible"}],
            "secrets_masked": [{"fichier": "a.py", "ligne_payload": 1, "type": "assignment"}] * 5,
        }
        md = cr.render_reviewer_markdown(result, model_cfg, collect_info)
        self.assertIn(".env (sensible, collect)", md)
        self.assertIn("img.png (binaire, review)", md)
        self.assertIn("secrets masqués : 5 (collect) + 0 (review)", md)

    def test_c5_without_collect_json_shows_only_review_pass(self):
        config = base_config()
        model_cfg = config["models"]["z-ai/glm-5.3"]
        result = {
            "label": "GLM-5.3", "prefixe": "G", "modele_demande": "z-ai/glm-5.3",
            "hebergeur": "Inceptron", "hebergeur_ok": True, "statut": "ok",
            "erreur": None, "appel_id": "gen-1", "modele_renvoye": "z-ai/glm-5.3",
            "cout_usd": 0.01, "tokens": {"prompt": 10, "completion": 5, "reasoning": None},
            "duree_s": 1.0, "finish_reason": "stop", "max_tokens_utilise": 1000,
            "tronque": False, "blocs_retires": 0, "format_ok": True,
            "rien_a_signaler": True, "findings": [], "contenu_envoye_chars": 500,
            "original_chars": 600, "removed_sections": [{"fichier": "img.png", "raison": "binaire"}],
            "secrets_masked_count": 2, "ordre_essai": "inceptron",
        }
        md = cr.render_reviewer_markdown(result, model_cfg, None)
        self.assertIn("img.png (binaire)", md)
        self.assertNotIn("(review)", md)
        self.assertNotIn("(collect)", md)
        self.assertIn("secrets masqués : 2", md)

    # Point 6 (C6 + GL5) : has_fichier_block ne compte qu'un bloc non vide ;
    # un bloc sensible est retiré en entier et compté dans removed_sections.
    def test_c6_gl5_empty_fichier_block_does_not_count(self):
        content = cr.wrap_block("Fichier : vide.py", "")
        _new_content, _removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertFalse(info["has_fichier_block"])

    def test_c6_gl5_sensitive_fichier_block_removed_entirely(self):
        content = cr.wrap_block("Fichier : .env", "SECRET=azerty\n")
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET=azerty", new_content)
        self.assertFalse(info["has_fichier_block"])
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))

    def test_c6_gl5_unclosed_non_empty_fichier_block_counts(self):
        content = "----- DÉBUT Fichier : a.py -----\nx = 1\n"
        _new_content, _removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertTrue(info["has_fichier_block"])

    # Point 7 (GL3 + GL4) : les fins de ligne d'origine (\r\n) sont
    # préservées par split_content_into_contexts + mask_text_with_context,
    # recomposées avec "".join (pas de "\n".join sur des lignes sans fin de
    # ligne).
    def test_gl3_gl4_crlf_line_endings_preserved_through_masking(self):
        content = "avant\r\n$token = \"abcdefghijklmnopqrst\";\r\napres\r\n"
        pairs = cr.split_content_into_contexts(content)
        masked_lines, _secrets = cr.mask_text_with_context(pairs, None)
        recomposed = "".join(masked_lines)
        self.assertIn("avant\r\n", recomposed)
        self.assertIn("apres\r\n", recomposed)
        self.assertNotIn("abcdefghijklmnopqrst", recomposed)

    # Point 8 (GL6) : message de refus en mode code donnant la vraie cause.
    def test_gl6_code_mode_refusal_message_states_real_cause(self):
        config = base_config()
        diff = "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(diff, encoding="utf-8")
            args = Namespace(mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
        self.assertEqual(code, 3)
        msg = err.getvalue()
        self.assertIn("refusé : aucune section de diff ni fichier complet à relire", msg)
        # Point GL5 (revue croisée du 2026-09-28) : accord au singulier
        # quand une seule section est retirée.
        self.assertIn("1 section sensible ou binaire retirée", msg)


class TestCrossReview20260928SecondFixes(unittest.TestCase):
    """Nouvelle revue croisée du 2026-09-28 (deuxième lot) : points 1 à 8
    du filtrage par blocs, du masquage et de process_model_response."""

    def setUp(self):
        self.config = base_config()
        self.globs = self.config["sensitive_globs"]

    # Point 1 (GE1) : un bloc DÉBUT sans FIN se termine au prochain marqueur
    # DÉBUT (pas à la fin du contenu) -> les blocs fermés qui suivent sont
    # traités normalement.
    def test_ge1_unclosed_block_stops_at_next_debut_marker(self):
        content = (
            "----- DÉBUT Plan d'origine -----\n"
            "plan tronqué\n"
            "----- DÉBUT Fichier : .env -----\n"
            "SECRET_DOTENV=1\n"
            "----- FIN Fichier : .env -----\n"
        )
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET_DOTENV", new_content)
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))
        self.assertIn("plan tronqué", new_content)

    # Point 2 (GE4 + GL3) : has_fichier_block se calcule après filtrage du
    # contenu d'un bloc « Fichier : ... » sans FIN, pas avant : un bloc
    # ouvert qui ne contient plus rien une fois sa section sensible retirée
    # ne compte pas.
    def test_ge4_gl3_has_fichier_block_computed_after_filtering(self):
        content = (
            "----- DÉBUT Fichier : notes.md -----\n"
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        )
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("A=2", new_content)
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))
        self.assertFalse(info["has_fichier_block"])

    # Point 3 (C2) : le chemin d'un bloc « Fichier : ... » est aussi comparé
    # aux globs sensibles coupé avant la première parenthèse ouvrante (dernier
    # candidat) ; l'entrée `removed` porte le chemin réel, pas la coupe.
    def test_c2_fichier_path_truncated_before_parenthesis(self):
        content = cr.wrap_block("Fichier : .env (extrait)", "SECRET_DOTENV=azerty\n")
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET_DOTENV", new_content)
        self.assertTrue(any(r["fichier"] == ".env (extrait)" and r["raison"] == "sensible" for r in removed))

    # Point 4 (C1) : branche T1, même règle que le cas « budget épuisé » --
    # hébergeur hors liste blanche + réponse vide -> statut
    # hors_liste_blanche, erreur renseignée.
    def test_c1_t1_empty_response_with_unlisted_hoster(self):
        config = base_config()
        model_slug = "z-ai/glm-5.3"
        model_cfg = config["models"][model_slug]
        result = {
            "ok": True,
            "data": {
                "id": "gen-c1",
                "model": model_slug,
                "provider": "DeepInfra",
                "usage": {"prompt_tokens": 10, "completion_tokens": 0, "cost": 0.0},
                "choices": [{"message": {"content": "   "}, "finish_reason": "stop"}],
            },
        }
        out = cr.process_model_response(
            result, model_slug, model_cfg, "GLM-5.3", "G", 100, 0, 1.0, config,
        )
        self.assertEqual(out["statut"], "hors_liste_blanche")
        self.assertFalse(out["hebergeur_ok"])
        self.assertIn("réponse vide", out["erreur"])

    # Point 5 (GE2) : BEGIN et END sur la même ligne, mais un BEGIN
    # antérieur reste sans END avant le BEGIN suivant -> la ligne démarre
    # une clé tronquée, le corps qui suit doit être masqué.
    def test_ge2_earlier_unclosed_begin_starts_truncated_key(self):
        text = (
            "avant\n"
            + PEM_BEGIN_RSA + " " + PEM_BEGIN_EC + " " + PEM_END_EC + "\n"
            + "CORPS_SUIVANT\n"
        )
        pairs = [(l, "contenu") for l in text.splitlines()]
        out_lines, secrets_masked = cr.mask_text_with_context(pairs)
        joined = "\n".join(out_lines)
        self.assertIn("avant", joined)
        self.assertNotIn("CORPS_SUIVANT", joined)
        types = [s["type"] for s in secrets_masked]
        self.assertIn("private_key_tronquee", types)

    # Point 6 (C7) : les sections diff --git hors bloc forment chacune leur
    # propre contexte « diff:<chemin> », pas un contexte unique hors_bloc.
    def test_c7_out_of_block_diff_sections_get_own_contexts(self):
        # Point 5 (C4, revue croisée) : le contenu doit porter au moins un
        # marqueur de bloc pour passer par la branche avec marqueurs de
        # split_content_into_contexts (via split_blocks), pas la branche
        # "aucun marqueur" qui produit déjà des contextes diff:<chemin> par
        # un autre chemin de code.
        content = (
            cr.wrap_block("Plan d'origine", "le plan\n")
            + "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+newA\n"
            "diff --git a/b.php b/b.php\n--- a/b.php\n+++ a/b.php\n@@ -1 +1 @@\n-old\n+newB\n"
        )
        pairs = cr.split_content_into_contexts(content)
        contexts = {ctx for _line, ctx in pairs}
        self.assertIn("diff:a.php", contexts)
        self.assertIn("diff:b.php", contexts)
        self.assertNotIn("hors_bloc", contexts)

    # Point 7 (C6) : collect.json n'est utilisé que si son champ payload
    # désigne le même fichier que args.input (chemins résolus) ; sinon
    # collect_info reste None.
    def _run_with_collect_json(self, payload_matches):
        config = base_config()

        def fake_once(endpoint, api_key, body, timeout_s):
            content = (
                "### [BLOQUANT] Constat\n- **Où** : a.\n- **Problème** : b.\n- **Pourquoi** : c.\n"
            )
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": "Inceptron",
                    "usage": {},
                    "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(
                "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            other_payload = Path(tmp) / "autre-payload.md"
            other_payload.write_text("contenu sans rapport\n", encoding="utf-8")
            collect_summary = {
                "payload": str(input_path) if payload_matches else str(other_payload),
                "files_excluded": [{"fichier": "wp-config.php", "raison": "sensible"}],
                "secrets_masked": [{"fichier": "a.php", "ligne_payload": 1, "type": "assignment"}],
            }
            (run_dir / "collect.json").write_text(json.dumps(collect_summary), encoding="utf-8")

            args = Namespace(
                mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with captured_stdout() as out, captured_stderr() as err:
                        code = cr.cmd_review(args, config)
            self.assertEqual(code, 0, err.getvalue())
            return out.getvalue()

    def test_c6_collect_json_used_when_payload_matches_input(self):
        stdout = self._run_with_collect_json(payload_matches=True)
        self.assertIn("wp-config.php (sensible, collect)", stdout)
        self.assertIn(".env (sensible, review)", stdout)

    def test_c6_collect_json_ignored_when_payload_differs_from_input(self):
        stdout = self._run_with_collect_json(payload_matches=False)
        self.assertNotIn("wp-config.php", stdout)
        self.assertNotIn(", collect)", stdout)
        self.assertIn(".env (sensible)", stdout)


class TestCrossReviewSplitBlocksFixes(unittest.TestCase):
    """Revue croisée (points 1 à 5) : découpage en blocs unifié via
    split_blocks, chemin des blocs « Fichier : ... » testé en entier avant
    l'annotation, accord singulier du message de refus en mode plan, et
    collect.json malformé sans exception."""

    def setUp(self):
        self.config = base_config()
        self.globs = self.config["sensitive_globs"]

    # --- Point 1 : split_blocks, une seule notion de bloc pour le filtre et
    # le masquage (C2, GL3, GL5, C3). ---

    def test_c2_debut_marker_inside_closed_file_block_is_swallowed(self):
        # Reproduction C2 : un bloc « Fichier : app.log » fermé (glob
        # *.log) contient une ligne exactement « ----- DÉBUT Diff du lot
        # ----- » ; avant la correction, la recherche du FIN s'arrêtait sur
        # cette ligne et la suite du fichier était envoyée. Attendu : le
        # bloc entier est retiré, la ligne « après » (hors bloc, après le
        # vrai FIN) reste intacte.
        content = (
            "----- DÉBUT Fichier : app.log -----\n"
            "log line 1\n"
            "----- DÉBUT Diff du lot -----\n"
            "log line 2\n"
            "----- FIN Fichier : app.log -----\n"
            "après\n"
        )
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, ["*.log"])
        self.assertNotIn("log line 1", new_content)
        self.assertNotIn("log line 2", new_content)
        self.assertNotIn("DÉBUT Diff du lot", new_content)
        self.assertTrue(any(r["fichier"] == "app.log" and r["raison"] == "sensible" for r in removed))
        self.assertIn("après", new_content)

    def test_split_blocks_orphan_fin_is_dropped_from_every_segment(self):
        content = "----- FIN Quelquechose -----\ntexte\n"
        segments = cr.split_blocks(content.splitlines(keepends=True))
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0], ("hors_bloc", ["texte\n"]))

    def test_split_blocks_orphan_fin_dropped_even_after_a_closed_block(self):
        content = (
            cr.wrap_block("Fichier : a.py", "x = 1\n")
            + "----- FIN Autre chose -----\n"
            "texte\n"
        )
        segments = cr.split_blocks(content.splitlines(keepends=True))
        # Le bloc fermé, puis un segment hors_bloc qui ne contient PAS la
        # ligne FIN orpheline.
        self.assertEqual(segments[0][0], "bloc")
        self.assertEqual(segments[0][1], "Fichier : a.py")
        self.assertEqual(segments[-1], ("hors_bloc", ["texte\n"]))

    def test_open_fichier_block_disappears_with_its_debut_line_when_emptied(self):
        # Un bloc « Fichier : ... » ouvert (pas de FIN) dont tout le
        # contenu est retiré par le filtrage disparaît entièrement, y
        # compris sa ligne DÉBUT (pas de DÉBUT orphelin envoyé).
        content = (
            "----- DÉBUT Fichier : notes.md -----\n"
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        )
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("DÉBUT Fichier : notes.md", new_content)
        self.assertNotIn("A=2", new_content)
        self.assertFalse(info["has_fichier_block"])
        self.assertTrue(any(r["fichier"] == ".env" for r in removed))

    def test_filter_and_mask_see_the_same_blocks_unclosed_then_closed(self):
        # Un bloc sans FIN (« Plan d'origine ») suivi d'un bloc fermé
        # (« Fichier : .env ») : split_blocks doit produire exactement deux
        # segments, et refilter_diff_block_in_content /
        # split_content_into_contexts doivent s'accorder sur cette même
        # frontière.
        content = (
            "----- DÉBUT Plan d'origine -----\n"
            "plan tronqué\n"
            "----- DÉBUT Fichier : .env -----\n"
            "SECRET_DOTENV=1\n"
            "----- FIN Fichier : .env -----\n"
        )
        lines = content.splitlines(keepends=True)
        segments = cr.split_blocks(lines)
        self.assertEqual(len(segments), 2)
        kind0, name0, inner0, closed0, _debut0, fin0 = segments[0]
        self.assertEqual((kind0, name0, closed0, fin0), ("bloc", "Plan d'origine", False, None))
        self.assertEqual(inner0, ["plan tronqué\n"])
        kind1, name1, inner1, closed1, _debut1, _fin1 = segments[1]
        self.assertEqual((kind1, name1, closed1), ("bloc", "Fichier : .env", True))
        self.assertEqual(inner1, ["SECRET_DOTENV=1\n"])

        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertIn("plan tronqué", new_content)
        self.assertNotIn("SECRET_DOTENV", new_content)
        self.assertTrue(any(r["fichier"] == ".env" for r in removed))

        pairs = cr.split_content_into_contexts(content)
        contexts = [ctx for _line, ctx in pairs]
        self.assertIn("Fichier : .env", contexts)

    # --- Point 2 : chemin d'un bloc « Fichier : ... » testé en entier
    # avant toute annotation entre parenthèses (C1 + GL1). ---

    def test_c1_gl1_full_name_with_parenthesis_tested_before_stripping(self):
        # Reproduction : « Fichier : dump (1).sql » avec le glob « *.sql » ;
        # l'ancienne coupe à la première parenthèse produisait « dump »,
        # qui ne matche pas « *.sql » -> envoyé à tort. Le nom complet
        # matche directement.
        content = cr.wrap_block("Fichier : dump (1).sql", "SELECT 1;\n")
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, ["*.sql"])
        self.assertNotIn("SELECT 1;", new_content)
        self.assertTrue(any(r["fichier"] == "dump (1).sql" and r["raison"] == "sensible" for r in removed))

    def test_c1_gl1_trailing_annotation_stripped_only_as_fallback(self):
        content = cr.wrap_block("Fichier : .env (extrait)", "SECRET_DOTENV=azerty\n")
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET_DOTENV", new_content)
        self.assertTrue(any(r["fichier"] == ".env (extrait)" and r["raison"] == "sensible" for r in removed))

    # --- Point 3 : accord au singulier en mode plan (C5 + GE2). ---

    def test_c5_ge2_plan_mode_refusal_message_singular_agreement(self):
        config = base_config()
        diff = "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+A=2\n"
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(diff, encoding="utf-8")
            args = Namespace(mode="plan", model=["z-ai/glm-5.3"], input=str(input_path),
                              run_dir=None, run_id=None, dry_run=True, timeout=None)
            with captured_stderr() as err:
                code = cr.cmd_review(args, config)
        self.assertEqual(code, 3)
        msg = err.getvalue()
        self.assertIn("1 section sensible ou binaire retirée", msg)
        self.assertNotIn("1 sections sensibles ou binaires retirées", msg)

    # --- Point 4 : collect.json malformé ne lève jamais d'exception (GE1). ---

    def _run_review_with_collect_json_payload(self, collect_payload):
        config = base_config()

        def fake_once(endpoint, api_key, body, timeout_s):
            content = "### [BLOQUANT] Constat\n- **Où** : a.\n- **Problème** : b.\n- **Pourquoi** : c.\n"
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": "Inceptron",
                    "usage": {},
                    "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            (run_dir / "collect.json").write_text(json.dumps(collect_payload), encoding="utf-8")

            args = Namespace(
                mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with captured_stdout() as out, captured_stderr() as err:
                        code = cr.cmd_review(args, config)
            return code, out.getvalue(), err.getvalue()

    def test_ge1_collect_json_root_not_a_dict_does_not_raise(self):
        code, _out, err = self._run_review_with_collect_json_payload(["pas", "un", "dict"])
        self.assertEqual(code, 0, err)

    def test_ge1_collect_json_payload_missing_does_not_raise(self):
        code, _out, err = self._run_review_with_collect_json_payload({"files_excluded": []})
        self.assertEqual(code, 0, err)

    def test_ge1_collect_json_payload_not_a_non_empty_string_does_not_raise(self):
        code, _out, err = self._run_review_with_collect_json_payload({"payload": 123})
        self.assertEqual(code, 0, err)

    # Point C3 : os.path.realpath sur un payload contenant un octet NUL lève
    # ValueError, pas seulement OSError -> collect_info doit rester None
    # sans exception.
    def test_c3_realpath_valueerror_on_nul_byte_in_payload_does_not_raise(self):
        code, _out, err = self._run_review_with_collect_json_payload({"payload": "bad\x00path"})
        self.assertEqual(code, 0, err)

    def _run_review_with_matching_collect_payload(self, extra_fields):
        """Comme `_run_review_with_collect_json_payload`, mais avec un champ
        `payload` qui désigne le même fichier que `args.input` : collect_info
        n'est plus None, ce qui exerce le rendu de `render_reviewer_markdown`
        (files_excluded / secrets_masked) pour le point C3."""
        config = base_config()

        def fake_once(endpoint, api_key, body, timeout_s):
            content = "### [BLOQUANT] Constat\n- **Où** : a.\n- **Problème** : b.\n- **Pourquoi** : c.\n"
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": "Inceptron",
                    "usage": {},
                    "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.diff"
            input_path.write_text(
                "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            collect_payload = {"payload": str(input_path)}
            collect_payload.update(extra_fields)
            (run_dir / "collect.json").write_text(json.dumps(collect_payload), encoding="utf-8")

            args = Namespace(
                mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with captured_stdout() as out, captured_stderr() as err:
                        code = cr.cmd_review(args, config)
            return code, out.getvalue(), err.getvalue()

    def test_c3_files_excluded_not_a_list_does_not_raise(self):
        code, out, err = self._run_review_with_matching_collect_payload(
            {"files_excluded": "pas-une-liste"}
        )
        self.assertEqual(code, 0, err)
        self.assertIn("Contenu envoyé", out)

    def test_c3_files_excluded_non_dict_entries_are_ignored(self):
        code, out, err = self._run_review_with_matching_collect_payload(
            {
                "files_excluded": [{"fichier": ".env", "raison": "sensible"}, "pas-un-dict", 42, None],
                "secrets_masked": ["pas-un-dict", {"fichier": "a.py", "ligne_payload": 1, "type": "assignment"}],
            }
        )
        self.assertEqual(code, 0, err)
        self.assertIn(".env (sensible, collect)", out)

    # --- Points C1+GL1/GL2 : découpage asymétrique des blocs (bloc sensible
    # vs bloc non sensible) et Point C2 (fichier_block_path_candidates). ---

    def test_split_blocks_asymmetric_a_env_nested_in_closed_plan_origine(self):
        # Reproduction (a) : « Fichier : .env » fermé imbriqué dans un
        # « Plan d'origine » fermé -> .env retiré, le reste du plan
        # conservé (avant ET après le bloc imbriqué).
        content = (
            "----- DÉBUT Plan d'origine -----\n"
            "avant\n"
            "----- DÉBUT Fichier : .env -----\n"
            "SECRET=azerty\n"
            "----- FIN Fichier : .env -----\n"
            "apres\n"
            "----- FIN Plan d'origine -----\n"
        )
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET=azerty", new_content)
        self.assertIn("avant", new_content)
        self.assertIn("apres", new_content)
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))

    def test_split_blocks_asymmetric_b_env_nested_in_closed_fichier_block(self):
        # Reproduction (b) : même chose imbriqué dans un « Fichier :
        # notes.md » fermé.
        content = (
            "----- DÉBUT Fichier : notes.md -----\n"
            "avant\n"
            "----- DÉBUT Fichier : .env -----\n"
            "SECRET=azerty\n"
            "----- FIN Fichier : .env -----\n"
            "apres\n"
            "----- FIN Fichier : notes.md -----\n"
        )
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET=azerty", new_content)
        self.assertIn("avant", new_content)
        self.assertIn("apres", new_content)
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))

    def test_split_blocks_asymmetric_c_env_nested_in_closed_diff_du_lot(self):
        # Reproduction (c) : imbriqué dans un « Diff du lot » fermé, entre
        # deux sections diff --git -> .env retiré, les deux sections
        # conservées.
        content = (
            "----- DÉBUT Diff du lot -----\n"
            "diff --git a/a.php b/a.php\n--- a/a.php\n+++ a/a.php\n@@ -1 +1 @@\n-old\n+newA\n"
            "----- DÉBUT Fichier : .env -----\n"
            "SECRET=azerty\n"
            "----- FIN Fichier : .env -----\n"
            "diff --git a/b.php b/b.php\n--- a/b.php\n+++ a/b.php\n@@ -1 +1 @@\n-old\n+newB\n"
            "----- FIN Diff du lot -----\n"
        )
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET=azerty", new_content)
        self.assertIn("+newA", new_content)
        self.assertIn("+newB", new_content)
        self.assertTrue(any(r["fichier"] == ".env" and r["raison"] == "sensible" for r in removed))

    def test_split_blocks_asymmetric_e_gl2_duplicate_name_first_unclosed(self):
        # Reproduction (e) GL2 : deux blocs « Fichier : x.md » de même nom,
        # le premier sans FIN -> le premier s'arrête au second DÉBUT, le
        # second est fermé normalement, aucune ligne de marqueur ne finit
        # dans un contexte de contenu.
        content = (
            "----- DÉBUT Fichier : x.md -----\n"
            "content1\n"
            "----- DÉBUT Fichier : x.md -----\n"
            "content2\n"
            "----- FIN Fichier : x.md -----\n"
        )
        lines = content.splitlines(keepends=True)
        segments = cr.split_blocks(lines)
        self.assertEqual(len(segments), 2)
        kind0, name0, inner0, closed0, _debut0, fin0 = segments[0]
        self.assertEqual((kind0, name0, closed0, fin0), ("bloc", "Fichier : x.md", False, None))
        self.assertEqual(inner0, ["content1\n"])
        kind1, name1, inner1, closed1, _debut1, fin1 = segments[1]
        self.assertEqual((kind1, name1, closed1), ("bloc", "Fichier : x.md", True))
        self.assertEqual(inner1, ["content2\n"])
        for _k, _n, inner, _c, _d, _f in segments:
            for l in inner:
                self.assertNotIn("DÉBUT", l)
                self.assertNotIn("FIN", l)

        pairs = cr.split_content_into_contexts(content)
        for line, ctx in pairs:
            if ctx != "marqueurs":
                self.assertNotIn("DÉBUT", line)
                self.assertNotIn("FIN", line)

    def test_c2_candidates_double_trailing_annotation(self):
        candidates = cr.fichier_block_path_candidates(".env (extrait) (lignes 1-20)")
        self.assertEqual(candidates, [".env (extrait) (lignes 1-20)", ".env (extrait)", ".env"])

    def test_c2_candidates_nested_trailing_annotation(self):
        candidates = cr.fichier_block_path_candidates(".env (extrait (1-20))")
        self.assertEqual(candidates, [".env (extrait (1-20))", ".env"])

    def test_c2_candidates_before_first_parenthesis(self):
        candidates = cr.fichier_block_path_candidates("dump (1).sql")
        self.assertEqual(candidates, ["dump (1).sql", "dump"])

    def test_c2_removed_double_trailing_annotation(self):
        content = cr.wrap_block("Fichier : .env (extrait) (lignes 1-20)", "SECRET=x\n")
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET=x", new_content)
        self.assertEqual([r["fichier"] for r in removed], [".env (extrait) (lignes 1-20)"])

    def test_c2_removed_nested_trailing_annotation(self):
        content = cr.wrap_block("Fichier : .env (extrait (1-20))", "SECRET=x\n")
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET=x", new_content)
        self.assertEqual([r["fichier"] for r in removed], [".env (extrait (1-20))"])

    def test_c2_removed_numbered_dump_before_extension(self):
        content = cr.wrap_block("Fichier : dump (1).sql", "SELECT 1;\n")
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, ["*.sql"])
        self.assertNotIn("SELECT 1;", new_content)
        self.assertTrue(any(r["fichier"] == "dump (1).sql" for r in removed))

    def test_c2_kept_unmatched_annotated_name(self):
        # Points C5 + GL6 (GL5/GLB4) : liste explicite de globs, découplée de
        # cross-review.json (le test ne doit pas dépendre de la config réelle) ;
        # « notes (v2).md » est conservé alors que « dump (1).sql » est retiré
        # dans le même contenu.
        globs = [".env", "*.sql"]
        content = (
            cr.wrap_block("Fichier : notes (v2).md", "du texte normal\n")
            + cr.wrap_block("Fichier : dump (1).sql", "SELECT 1;\n")
        )
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, globs)
        self.assertIn("du texte normal", new_content)
        self.assertIn("Fichier : notes (v2).md", new_content)
        self.assertNotIn("SELECT 1;", new_content)
        self.assertEqual(removed, [{"fichier": "dump (1).sql", "raison": "sensible"}])


class TestCrossReview20260928ThirdFixes(unittest.TestCase):
    """Corrections de la revue croisée du 2026-09-28 (troisième lot) : C1
    (neutralisation des marqueurs dans wrap_block), C4+GL2+GL4 (règle unique
    de sensibilité), C3 (FIN étranger retiré), GLB2 (raison du bloc sensible
    sans FIN)."""

    DIFF_A = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
    # Raison unique de tout bloc « Fichier : ... » sensible non fermé (C2/GLB2).
    UNCLOSED_REASON = "sensible, sans FIN : retiré jusqu'à la fin du contenu"

    def setUp(self):
        self.config = base_config()
        self.globs = self.config["sensitive_globs"]

    # --- Point 1 (C1) : wrap_block neutralise les lignes qui ressemblent à
    # un marqueur. ---

    def test_c1_wrap_block_prefixes_marker_like_lines_with_a_space(self):
        """Le décalage d'une espace de ces lignes est une perte de fidélité
        acceptée (aucune neutralisation ne garde la ligne intacte), pas un
        comportement recherché en soi."""
        content = (
            "avant\n"
            "----- DÉBUT Fichier : .env -----\n"
            "----- FIN Fichier : .env -----\r\n"
            "----- DÉBUT pas un marqueur ----- suite\n"
            "apres"
        )
        wrapped = cr.wrap_block("Plan d'origine", content)
        self.assertEqual(
            wrapped,
            "----- DÉBUT Plan d'origine -----\n"
            "avant\n"
            " ----- DÉBUT Fichier : .env -----\n"
            " ----- FIN Fichier : .env -----\r\n"
            "----- DÉBUT pas un marqueur ----- suite\n"
            "apres\n"
            "----- FIN Plan d'origine -----\n",
        )

    def test_c1_plan_quoting_a_marker_without_fin_keeps_plan_and_diff(self):
        # Reproduction : un plan qui cite « ----- DÉBUT Fichier : .env ----- »
        # sans FIN, suivi d'un « Diff du lot ». Avant la correction, le bloc
        # « .env » sensible avalait le diff (retiré) ; le plan citait un
        # faux marqueur.
        plan = "Exemple de format :\n----- DÉBUT Fichier : .env -----\nSECRET=exemple\n"
        content = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Plan d'origine", plan)
            + "\n\n"
            + cr.wrap_block("Diff du lot", self.DIFF_A)
        )
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertEqual(removed, [])
        self.assertIn(" ----- DÉBUT Fichier : .env -----\n", new_content)
        self.assertIn("SECRET=exemple", new_content)  # texte du plan, intact
        self.assertIn(cr.wrap_block("Plan d'origine", plan), new_content)
        self.assertIn("diff --git a/a.py b/a.py", new_content)
        self.assertEqual(info["kept_diff_sections"], 1)

    def test_c1_removed_diff_line_that_looks_like_a_marker_keeps_diff_section(self):
        """La ligne supprimée du diff, décalée d'une espace et devenue ligne de
        contexte, est une perte de fidélité acceptée, pas un comportement
        recherché : seule la section du diff est conservée."""
        # Une ligne supprimée « ---- DÉBUT Fichier : .env ----- » donne, avec
        # le « - » du diff, « ----- DÉBUT Fichier : .env ----- » en colonne 0.
        diff = (
            "diff --git a/doc.md b/doc.md\n--- a/doc.md\n+++ b/doc.md\n@@ -1,3 +1,2 @@\n"
            " avant\n"
            "----- DÉBUT Fichier : .env -----\n"
            " apres\n"
        )
        content = "# Contenu à relire (mode code)\n\n" + cr.wrap_block("Diff du lot", diff) + "\n" + self.DIFF_A
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertEqual(removed, [])
        self.assertIn(" ----- DÉBUT Fichier : .env -----\n", new_content)
        self.assertIn("diff --git a/doc.md b/doc.md", new_content)
        self.assertIn(" apres", new_content)
        segments = cr.split_blocks(new_content.splitlines(keepends=True), cr.make_is_sensitive_name(self.globs))
        blocs = [s for s in segments if s[0] == "bloc"]
        self.assertEqual([(s[1], s[3]) for s in blocs], [("Diff du lot", True)])

    # --- Point 2 (C4 + GL2 + GL4) : règle unique de sensibilité. ---

    def test_c4_sensitive_path_returns_real_path_not_truncated_candidate(self):
        self.assertEqual(
            cr.fichier_block_sensitive_path("Fichier : .env (extrait)  ", self.globs), ".env (extrait)"
        )
        self.assertEqual(
            cr.fichier_block_sensitive_path("Fichier : dump (1).sql", ["*.sql"]), "dump (1).sql"
        )
        # Seul le dernier candidat (coupe avant la première parenthèse) correspond.
        self.assertEqual(cr.fichier_block_sensitive_path("Fichier : .env (a) b", self.globs), ".env (a) b")

    def test_c4_sensitive_path_none_when_not_sensitive_or_not_a_fichier_block(self):
        self.assertIsNone(cr.fichier_block_sensitive_path("Fichier : notes (v2).md", self.globs))
        self.assertIsNone(cr.fichier_block_sensitive_path("Plan d'origine", self.globs))
        self.assertIsNone(cr.fichier_block_sensitive_path(".env", self.globs))

    def test_c4_predicate_and_removal_use_the_same_rule(self):
        pred = cr.make_is_sensitive_name(self.globs)
        for name in (
            "Fichier : .env",
            "Fichier : .env (extrait)",
            "Fichier : .env (extrait (1-20))",
            "Fichier : .env (a) b",
            "Fichier : notes (v2).md",
            "Fichier : src/app.py",
            "Plan d'origine",
            "Diff du lot",
        ):
            with self.subTest(name=name):
                sensitive_path = cr.fichier_block_sensitive_path(name, self.globs)
                self.assertEqual(pred(name), sensitive_path is not None)
                content = cr.wrap_block(name, "SECRET_XYZ=1\n")
                new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
                if sensitive_path is not None:
                    self.assertNotIn("SECRET_XYZ", new_content)
                    self.assertEqual([r["fichier"] for r in removed], [sensitive_path])
                else:
                    self.assertEqual(removed, [])

    def test_c4_removed_entry_carries_real_path_never_truncated_candidate(self):
        content = cr.wrap_block("Fichier : .env (a) b", "SECRET_XYZ=1\n")
        _new, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertEqual(removed, [{"fichier": ".env (a) b", "raison": "sensible"}])

    # --- Point 4 (C3) : un FIN d'un autre nom est retiré du contenu. ---

    def test_c3_foreign_fin_inside_non_sensitive_block_is_not_kept_in_inner_lines(self):
        lines = (
            "----- DÉBUT Plan d'origine -----\n"
            "a1\n"
            "----- FIN Fichier : ailleurs.md -----\n"
            "a2\n"
            "----- FIN Plan d'origine -----\n"
        ).splitlines(keepends=True)
        segments = cr.split_blocks(lines)
        self.assertEqual(len(segments), 1)
        _kind, name, inner, closed, _debut, fin = segments[0]
        self.assertEqual(name, "Plan d'origine")
        self.assertTrue(closed)
        self.assertEqual(inner, ["a1\n", "a2\n"])
        self.assertEqual(fin, "----- FIN Plan d'origine -----\n")

    def test_c3_foreign_fin_before_nested_debut_dropped_and_parent_marked_unclosed(self):
        lines = (
            "----- DÉBUT Plan d'origine -----\n"
            "a1\n"
            "----- FIN Fichier : ailleurs.md -----\n"
            "----- DÉBUT Fichier : b.md -----\n"
            "b1\n"
            "----- FIN Fichier : b.md -----\n"
        ).splitlines(keepends=True)
        segments = cr.split_blocks(lines)
        self.assertEqual([(s[1], s[3]) for s in segments], [("Plan d'origine", False), ("Fichier : b.md", True)])
        self.assertEqual(segments[0][2], ["a1\n"])
        self.assertEqual(segments[1][2], ["b1\n"])

    def test_c3_foreign_fin_absent_from_filtered_content_and_from_contexts(self):
        content = (
            "----- DÉBUT Plan d'origine -----\n"
            "a1\n"
            "----- FIN Fichier : ailleurs.md -----\n"
            "a2\n"
            "----- FIN Plan d'origine -----\n"
        )
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertEqual(removed, [])
        self.assertNotIn("ailleurs.md", new_content)
        self.assertIn("a1\n", new_content)
        self.assertIn("a2\n", new_content)
        pairs = cr.split_content_into_contexts(content, self.globs)
        for line, _ctx in pairs:
            self.assertNotIn("ailleurs.md", line)

    # --- Point 5 (GLB2) : raison d'un bloc sensible sans FIN. ---

    def test_glb2_sensitive_block_without_fin_gets_long_reason(self):
        content = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Diff du lot", self.DIFF_A)
            + "\n"
            + "----- DÉBUT Fichier : .env -----\n"
            "SECRET_XYZ=1\n"
            "suite du contenu avalée\n"
        )
        new_content, removed, info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET_XYZ", new_content)
        self.assertNotIn("suite du contenu avalée", new_content)
        self.assertEqual(
            removed, [{"fichier": ".env", "raison": self.UNCLOSED_REASON}]
        )
        self.assertEqual(info["kept_diff_sections"], 1)

    def test_glb2_sensitive_block_with_fin_keeps_plain_sensible_reason(self):
        content = cr.wrap_block("Fichier : .env", "SECRET_XYZ=1\n")
        _new, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertEqual(removed, [{"fichier": ".env", "raison": "sensible"}])

    def test_c2_sensitive_block_without_fin_and_empty_content_gets_long_reason(self):
        # Raison unique pour tout bloc sensible non fermé, même vide ou blanc :
        # on ne distingue pas le contenu propre du bloc de ce qu'il avale.
        for label, inner in (("vide", ""), ("blanc", "\n   \n\t\n")):
            with self.subTest(contenu=label):
                content = "----- DÉBUT Fichier : .env -----\n" + inner
                new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
                self.assertNotIn(".env", new_content)
                self.assertEqual(removed, [{"fichier": ".env", "raison": self.UNCLOSED_REASON}])

    def test_c2_sensitive_block_without_fin_placed_last_gets_long_reason(self):
        # Voulu : rien ne suit le bloc, mais « jusqu'à la fin du contenu » reste
        # vrai ; la raison longue s'affiche aussi.
        content = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Diff du lot", self.DIFF_A)
            + "\n"
            + "----- DÉBUT Fichier : .env -----\n"
            "SECRET_XYZ=1\n"
        )
        new_content, removed, _info = cr.refilter_diff_block_in_content(content, self.globs)
        self.assertNotIn("SECRET_XYZ", new_content)
        self.assertEqual(removed, [{"fichier": ".env", "raison": self.UNCLOSED_REASON}])

    def test_glb2_reason_appears_as_is_in_tiers_md_sections_retirees(self):
        config = base_config()
        content = (
            "# Contenu à relire (mode code)\n\n"
            + cr.wrap_block("Diff du lot", self.DIFF_A)
            + "\n"
            + "----- DÉBUT Fichier : .env -----\n"
            "SECRET_XYZ=1\n"
        )

        def fake_once(endpoint, api_key, body, timeout_s):
            text = "### [BLOQUANT] Constat\n- **Où** : a.\n- **Problème** : b.\n- **Pourquoi** : c.\n"
            return {
                "ok": True,
                "data": {
                    "id": "x", "model": body["model"], "provider": "Inceptron",
                    "usage": {},
                    "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                },
                "retryable": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.md"
            input_path.write_text(content, encoding="utf-8")
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            args = Namespace(
                mode="code", model=["z-ai/glm-5.3"], input=str(input_path),
                run_dir=str(run_dir), run_id=None, dry_run=False, timeout=None,
            )
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-jetable"}):
                with mock.patch.object(cr, "_call_openrouter_once", side_effect=fake_once):
                    with captured_stdout() as out, captured_stderr() as err:
                        code = cr.cmd_review(args, config)
            self.assertEqual(code, 0, err.getvalue())
            tiers = (run_dir / "tiers.md").read_text(encoding="utf-8")
        expected = f"sections retirées : .env ({self.UNCLOSED_REASON})"
        self.assertIn(expected, tiers)
        self.assertIn(expected, out.getvalue())
        self.assertNotIn("SECRET_XYZ", tiers)

    # --- Point 6 (C1+GL2+GLB2) : cohérence de la config réelle. ---

    def test_real_config_loads_and_is_coherent(self):
        """Garde la config réelle cohérente parce que les tests unitaires n'en dépendent plus (revue du 2026-09-28, C1+GL2+GLB2)."""
        config = cr.load_config(SCRIPT_PATH.parent / "cross-review.json")
        models = config["models"]
        for mode in ("plan", "code"):
            for model_id in config["modes"][mode]:
                self.assertIn(model_id, models, f"mode {mode} : modèle inconnu {model_id}")
        ignore_chine = set(config["ignore_chine"])
        for model_id, model_cfg in models.items():
            hosters = model_cfg.get("hebergeurs", [])
            self.assertTrue(hosters, f"{model_id} : aucun hébergeur")
            for h in hosters:
                self.assertTrue(h.get("slug"), f"{model_id} : hébergeur sans slug")
                self.assertTrue(h.get("name"), f"{model_id} : hébergeur sans name")
                base = h["slug"].split("/")[0]
                self.assertNotIn(
                    base, ignore_chine,
                    f"{model_id} : hébergeur {h['slug']} dans ignore_chine",
                )
        for pattern in (".env", "*.sql", "*.pem", "wp-config.php"):
            self.assertIn(pattern, config["sensitive_globs"])
        self.assertGreater(config["timeout_s"], 0)
        self.assertGreater(config["deadline_s"], 0)
        self.assertLessEqual(config["timeout_s"], config["deadline_s"])
        self.assertGreater(config["max_tokens"], 0)


if __name__ == "__main__":
    unittest.main()
