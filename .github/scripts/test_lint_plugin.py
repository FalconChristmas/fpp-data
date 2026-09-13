"""Unit tests for lint_plugin.py. Run from this directory:
    python3 -m unittest test_lint_plugin
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lint_plugin as L  # noqa: E402


def write_tree(root: str, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


class ConfigDirMigration(unittest.TestCase):
    """A one-time move of a DB OUT of config/ (the fix config-dir-binary-write
    asks for) must not trip the rule on itself; the same call with config/ as
    the destination still does."""

    def hits(self, text: str, rel: str = "functions.inc.php"):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {rel: text})
            return [(h[0], h[4]) for h in L._config_dir_hits(tmp)]

    def test_php_rename_out_of_config_is_skipped(self):
        self.assertEqual(self.hits(
            '<?php @rename($settings[\'configDirectory\'] . "/FPP.X.db", $dbFile);'), [])

    def test_guarded_rename_is_skipped(self):
        self.assertEqual(self.hits(
            '<?php if (!@rename($settings[\'configDirectory\'] . "/FPP.X.db", $dbFile)) { logEntry("x"); }'), [])

    def test_php_rename_into_config_still_fires(self):
        self.assertEqual(self.hits(
            '<?php rename($dbFile, $settings[\'configDirectory\'] . "/FPP.X.db");'),
            [("functions.inc.php", "binary")])

    def test_move_within_config_still_fires(self):
        self.assertEqual(self.hits(
            '<?php rename($settings[\'configDirectory\'] . "/a.db", $settings[\'configDirectory\'] . "/b.db");'),
            [("functions.inc.php", "binary")])

    def test_shell_mv_out_of_config_is_skipped(self):
        self.assertEqual(self.hits(
            'mv "${MEDIADIR}/config/FPP.X.db" "${MEDIADIR}/plugindata/x/"\n', "scripts/fpp_install.sh"), [])

    def test_shell_mv_noclobber_out_of_config_is_skipped(self):
        self.assertEqual(self.hits(
            'mv -n "${MEDIADIR}/config/FPP.X.db" "${DATADIR}/" 2>/dev/null || true\n', "scripts/fpp_install.sh"), [])

    def test_shell_mv_into_config_still_fires(self):
        self.assertEqual(self.hits(
            'mv "/tmp/FPP.X.db" "${MEDIADIR}/config/FPP.X.db"\n', "scripts/fpp_install.sh"),
            [("scripts/fpp_install.sh", "binary")])

    def test_plain_path_expression_still_fires(self):
        self.assertEqual(self.hits(
            '<?php $legacy = $settings[\'configDirectory\'] . "/FPP.X.db";'),
            [("functions.inc.php", "binary")])


class DestructiveNoGuard(unittest.TestCase):
    """destructive-no-csrf targets web pages; a shebang'd .php file is a CLI
    script with no request to guard against."""

    def hits(self, text: str, rel: str = "page.php"):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {rel: text})
            return [h[0] for h in L._destructive_no_guard_hits(tmp)]

    def test_page_with_unguarded_unlink_fires(self):
        self.assertEqual(self.hits('<?php\nunlink($settings["configDirectory"] . "/x.json");\n'), ["page.php"])

    def test_page_with_post_guard_is_skipped(self):
        self.assertEqual(self.hits('<?php\nif (isset($_POST["del"])) { unlink("/tmp/x"); }\n'), [])

    def test_cli_script_with_shebang_is_skipped(self):
        self.assertEqual(self.hits('#!/usr/bin/env php\n<?php\nunlink("/tmp/STOP");\nwhile (true) { sleep(1); }\n', "Poll.php"), [])

    def test_shebang_variant_is_skipped(self):
        self.assertEqual(self.hits('#!/bin/env php\n<?php\nunlink("/tmp/STOP");\n', "Poll.php"), [])

    def test_shebang_not_on_first_line_still_fires(self):
        self.assertEqual(self.hits('<?php\n// #!/usr/bin/env php\nunlink("/tmp/x");\n'), ["page.php"])

    def multi_hits(self, files: dict):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, files)
            return sorted(h[0] for h in L._destructive_no_guard_hits(tmp))

    CLI = '#!/usr/bin/php\n<?php\nrequire ("lock.helper.php");\nlockHelper::unlock();\n'
    LOCK = '<?php\nclass lockHelper {\n  public static function unlock() { unlink(LOCK_DIR . "x.lock"); }\n}\n'

    def test_include_used_only_by_cli_script_is_skipped(self):
        self.assertEqual(self.multi_hits({"runEventDate.php": self.CLI, "lock.helper.php": self.LOCK}), [])

    def test_include_also_used_by_a_page_still_fires(self):
        self.assertEqual(self.multi_hits({
            "runEventDate.php": self.CLI, "lock.helper.php": self.LOCK,
            "plugin_setup.php": '<?php\nrequire_once __DIR__ . "/lock.helper.php";\n',
        }), ["lock.helper.php"])

    def test_include_reached_only_through_another_cli_only_include_is_skipped(self):
        self.assertEqual(self.multi_hits({
            "daemon.php": '#!/usr/bin/env php\n<?php\ninclude "functions.inc.php";\n',
            "functions.inc.php": '<?php\nrequire("lock.helper.php");\n',
            "lock.helper.php": self.LOCK,
        }), [])

    def test_unincluded_file_is_a_page_and_still_fires(self):
        self.assertEqual(self.multi_hits({"runEventDate.php": self.CLI, "orphan.php": self.LOCK}), ["orphan.php"])


if __name__ == "__main__":
    unittest.main()
