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


if __name__ == "__main__":
    unittest.main()
