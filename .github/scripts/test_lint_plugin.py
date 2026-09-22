"""Unit tests for lint_plugin.py. Run from this directory:
    python3 -m unittest test_lint_plugin
"""
from __future__ import annotations

import json
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




class RestartFlagOneRule(unittest.TestCase):
    """Exactly one finding exists about the restart flag - no-restart-flag, when the
    flag is missing where FPP needs it. A plugin with the flag set gets nothing under
    any versions[] shape; a hot-load-safe plugin that only serves FPP 10+ needs no flag
    at all (fpp-data#136, #236, #241)."""

    FLAG = "#!/bin/bash\n. ${FPPDIR}/scripts/common\nsetSetting restartFlag 1\n"
    NOFLAG = "#!/bin/bash\necho installing\n"
    INFO = {
        "repoName": "fpp-synthetic", "name": "Synthetic", "author": "test", "description": "test plugin",
        "homeURL": "https://github.com/example/fpp-synthetic",
        "srcURL": "https://github.com/example/fpp-synthetic.git",
        "bugURL": "https://github.com/example/fpp-synthetic/issues",
        "privacy": {"summary": "Runs on this device only.", "sends": [], "collects": [], "sensors": [],
                    "remoteAccess": "none", "systemChanges": [], "closedCode": False, "other": "none"},
    }
    SPANNING = [
        {"minFPPVersion": "9.0", "maxFPPVersion": "9.99", "branch": "main", "sha": ""},
        {"minFPPVersion": "10.0", "maxFPPVersion": "0", "branch": "main", "sha": ""},
    ]
    TEN_ONLY = [{"minFPPVersion": "10.0", "maxFPPVersion": "0", "branch": "main", "sha": ""}]

    def restart_findings(self, versions, hook):
        files = {
            "callbacks.sh": "#!/bin/bash\necho\n",
            "commands/descriptions.json": "[]",
            "scripts/fpp_install.sh": hook,
            "scripts/fpp_uninstall.sh": hook,
        }
        info = dict(self.INFO, versions=versions)
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, dict(files, **{"pluginInfo.json": json.dumps(info)}))
            return {f.code: f for f in L.lint_plugin_dir(tmp, "fpp-synthetic", info)
                    if "restart" in f.code or "hotload" in f.code}

    def test_flag_set_spanning_majors_is_silent(self):
        self.assertEqual(self.restart_findings(self.SPANNING, self.FLAG), {})

    def test_flag_set_ten_only_is_silent(self):
        self.assertEqual(self.restart_findings(self.TEN_ONLY, self.FLAG), {})

    def test_flag_missing_spanning_majors_fires_with_the_versions_reason(self):
        found = self.restart_findings(self.SPANNING, self.NOFLAG)
        self.assertEqual(list(found), ["no-restart-flag"])
        self.assertEqual(found["no-restart-flag"].severity, L.BEST_PRACTICE)
        self.assertIn("versions[] serves this exact branch/build to FPP majors before 10", found["no-restart-flag"].message)

    def test_flag_missing_ten_only_hotload_safe_is_silent(self):
        self.assertEqual(self.restart_findings(self.TEN_ONLY, self.NOFLAG), {})

    def test_pinned_old_major_does_not_span(self):
        pinned = [dict(self.SPANNING[0], sha="0123456789abcdef0123456789abcdef01234567"), self.SPANNING[1]]
        self.assertEqual(self.restart_findings(pinned, self.NOFLAG), {})


class SudoInComments(unittest.TestCase):
    """`sudo` in a comment explaining a choice is not a sudo call (fpp-data#266:
    `# sudo, not plain rm: ...` was reported, with advice to run the comment)."""

    def sudo(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"scripts/fpp_uninstall.sh": text})
            return [f for f in L.lint_plugin_dir(tmp, "fpp-synthetic", None) if f.code == "sudo"]

    def test_comment_lines_are_skipped(self):
        self.assertEqual(self.sudo("#!/bin/bash\n# sudo, not plain rm: same reasoning as delete_backup.sh\nrm -rf \"$d\"  # no sudo needed\n"), [])

    def test_root_guarded_call_is_skipped(self):
        # fpp-data#266: escalates only when run by hand as non-root
        self.assertEqual(self.sudo('#!/bin/bash\nif [ "$(id -u)" -eq 0 ]; then\n    rm -rf "$d"\nelse\n    sudo rm -rf "$d"\nfi\n'), [])
        self.assertEqual(self.sudo('#!/bin/bash\n[ "$EUID" -ne 0 ] && sudo rm -rf "$d"\n'), [])

    def test_guard_too_far_above_does_not_count(self):
        body = '#!/bin/bash\nme=$(id -u)\n' + 'echo x\n' * 8 + 'sudo rm -rf "$d"\n'
        self.assertEqual(len(self.sudo(body)), 1)

    def test_real_call_still_fires(self):
        found = self.sudo("#!/bin/bash\n# sudo, not plain rm\nsudo rm -rf \"$d\"\n")
        self.assertEqual(len(found), 1)
        self.assertIn("fpp_uninstall.sh:3", found[0].message)




class SetEPosition(unittest.TestCase):
    """no-set-e: `set -e` only guards what runs after it, so the rule checks
    where it sits, not just that the text appears somewhere (fpp-jukebox put it
    on the last line and the old presence-only grep passed it)."""

    def findings(self, hook: str):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"scripts/fpp_install.sh": hook})
            os.chmod(os.path.join(tmp, "scripts/fpp_install.sh"), 0o755)
            return {f.code: f.message for f in L.lint_plugin_dir(tmp, "fpp-synthetic", None)
                    if f.code == "no-set-e"}

    def test_missing_entirely_fires(self):
        found = self.findings("#!/bin/bash\napt-get install -y foo\n")
        self.assertIn("no-set-e", found)
        self.assertIn("has no `set -e`", found["no-set-e"])
        self.assertIn("not `exit`", found["no-set-e"])

    def test_under_shebang_is_silent(self):
        self.assertEqual(self.findings("#!/bin/bash\nset -e\napt-get install -y foo\n"), {})

    def test_euo_pipefail_and_o_errexit_are_silent(self):
        self.assertEqual(self.findings("#!/bin/bash\nset -euo pipefail\nfoo\n"), {})
        self.assertEqual(self.findings("#!/bin/bash\nset -o errexit\nfoo\n"), {})

    def test_shebang_dash_e_is_silent(self):
        self.assertEqual(self.findings("#!/bin/bash -e\nfoo\n"), {})

    def test_after_comments_assignments_and_trap_is_silent(self):
        hook = ('#!/bin/bash\n# header\n\nPLUGIN_DIR="$(dirname "$0")"\nexport FPPDIR=/opt/fpp\n'
                ': "${MEDIADIR:=/home/fpp/media}"\ntrap "echo bye" EXIT\nset -e\nfoo\n')
        self.assertEqual(self.findings(hook), {})

    def test_guarded_line_before_it_is_silent(self):
        self.assertEqual(self.findings('#!/bin/bash\n. common 2>/dev/null || true\nset -e\nfoo\n'), {})

    def test_or_exit_guards_are_an_alternative(self):
        self.assertEqual(self.findings("#!/bin/bash\napt-get install -y foo || exit 1\n"), {})

    def test_on_last_line_fires_with_position_message(self):
        found = self.findings("#!/bin/bash\nmkdir -p /x\ncp a b\nset -e\n")
        self.assertIn("no-set-e", found)
        msg = found["no-set-e"]
        self.assertIn("scripts/fpp_install.sh:4 has `set -e`, but it comes too late", msg)
        self.assertIn("2 commands already run before it", msg)
        self.assertIn("first: line 2 `mkdir -p /x`", msg)
        self.assertIn("last line of the script it protects nothing", msg)

    def test_mid_script_fires_without_last_line_note(self):
        found = self.findings("#!/bin/bash\nmkdir -p /x\nset -e\ncp a b\n")
        self.assertIn("1 command already runs before it", found["no-set-e"])
        self.assertNotIn("last line", found["no-set-e"])

    def test_heredoc_and_function_bodies_are_not_counted(self):
        hook = ('#!/bin/bash\nlog() {\n    echo "$*"\n}\ncat > /tmp/x <<EOF\nnot a command\nEOF\nset -e\n')
        found = self.findings(hook)
        self.assertIn("1 command already runs before it", found["no-set-e"])
        self.assertIn("first: line 5 `cat > /tmp/x <<EOF`", found["no-set-e"])

    def test_indented_terminator_only_ends_a_dash_heredoc(self):
        # plain <<EOF: an indented `EOF` is still body, the flush-left one ends it
        found = self.findings("#!/bin/bash\ncat <<EOF\nx\n  EOF\nEOF\nset -e\n")
        self.assertIn("1 command already runs before it", found["no-set-e"])
        # <<-EOF: a tab-indented terminator does end it
        found = self.findings("#!/bin/bash\ncat <<-EOF\nx\n\tEOF\nset -e\n")
        self.assertIn("1 command already runs before it", found["no-set-e"])

    def test_function_keyword_without_parens_is_a_definition(self):
        self.assertEqual(self.findings("#!/bin/bash\nfunction foo {\n    rm -rf /x\n}\nset -e\n"), {})
        self.assertEqual(self.findings("#!/bin/bash\nfunction foo() {\n    rm -rf /x\n}\nset -e\n"), {})


class BlockingSleepInHook(unittest.TestCase):
    """blocking-sleep-in-hook: a bounded/liveness-polling loop or a backgrounded
    helper suppresses the hit; a plain redirection near a flat sleep must not."""

    def hits(self, hook: str):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"scripts/postStart.sh": hook})
            return list(L._blocking_sleep_in_hook_hits(tmp))

    def test_flat_sleep_fires(self):
        self.assertEqual(len(self.hits("#!/bin/bash\nsleep 5\n")), 1)

    def test_redirect_near_flat_sleep_still_fires(self):
        # `>` in `echo ... > file` is a redirection, not a bounded-loop comparison
        self.assertEqual(len(self.hits("#!/bin/bash\necho starting > /tmp/x.log\nsleep 5\n")), 1)
        self.assertEqual(len(self.hits("#!/bin/bash\nfoo 2> /dev/null\nsleep 5\n")), 1)

    def test_arithmetic_and_double_bracket_bounds_are_silent(self):
        self.assertEqual(self.hits("#!/bin/bash\nwhile (( ticks < max )); do\n    sleep 1\ndone\n"), [])
        self.assertEqual(self.hits("#!/bin/bash\nwhile [[ $i < $n ]]; do\n    sleep 1\ndone\n"), [])
        self.assertEqual(self.hits("#!/bin/bash\nwhile [ $i -lt 3 ]; do\n    sleep 1\ndone\n"), [])

    def test_liveness_poll_is_silent(self):
        self.assertEqual(self.hits(
            '#!/bin/bash\nfor i in 1 2 3; do kill -0 "$PID" || break; sleep 1; done\n'), [])

    def test_backgrounded_helper_is_silent(self):
        self.assertEqual(self.hits(
            "#!/bin/bash\nwait_ready() {\n    sleep 5\n}\n(\n    wait_ready\n    start\n) >> /tmp/l 2>&1 &\n"), [])



def _lint(files: dict[str, str], repo: str = "fpp-synthetic", info: dict | None = None,
          codes: tuple[str, ...] = ()):
    """{code: (severity, message)} for the given codes over a throwaway tree."""
    with tempfile.TemporaryDirectory() as tmp:
        write_tree(tmp, files)
        for rel in files:
            if rel.endswith(".sh"):
                os.chmod(os.path.join(tmp, rel), 0o755)
        return {f.code: (f.severity, f.message) for f in L.lint_plugin_dir(tmp, repo, info)
                if not codes or f.code in codes}


class SoNameMismatch(unittest.TestCase):
    """so-name-mismatch: fppd loads lib<repoName>.so OR whatever the callbacks
    script names with `c++:<file>` (Plugins.cpp loadUserPlugin); only a
    Makefile BUILD TARGET counts, not a dependency or a `rm -f` in clean."""

    CB = "#!/bin/bash\necho \"c++\"\n"

    def findings(self, makefile: str, callbacks: str = CB, repo: str = "fpp-foo"):
        return _lint({"Makefile": makefile, "callbacks.sh": callbacks}, repo,
                     codes=("so-name-mismatch",))

    def test_matching_shlib_ext_target_is_silent(self):
        mk = ("include $(SRCDIR)/makefiles/common/setup.mk\nall: libfpp-foo.$(SHLIB_EXT)\n"
              "libfpp-foo.$(SHLIB_EXT): a.o $(SRCDIR)/libfpp.$(SHLIB_EXT)\n\t$(CXX) -o libfpp-foo.so a.o\n"
              "clean:\n\trm -f libfpp-foo.so\n")
        self.assertEqual(self.findings(mk), {})

    def test_wrong_target_fires_blocker(self):
        mk = "include $(SRCDIR)/makefiles/common/setup.mk\nall: libfpp-bar.$(SHLIB_EXT)\n"
        found = self.findings(mk)
        self.assertEqual(found["so-name-mismatch"][0], L.BLOCKER)
        self.assertIn("`libfpp-bar.so`", found["so-name-mismatch"][1])
        self.assertIn("`libfpp-foo.so`", found["so-name-mismatch"][1])

    def test_callbacks_override_is_honoured(self):
        # fpp-plugin-TMCStepper2: Makefile builds libTMCStepper2.so, callbacks.sh
        # tells fppd to load exactly that - a sanctioned layout, not a mismatch
        mk = "include $(SRCDIR)/makefiles/common/setup.mk\nTARGET = libTMCStepper2.so\n"
        self.assertEqual(self.findings(mk, "#!/bin/bash\necho \"c++:libTMCStepper2.so\"\n",
                                       repo="fpp-plugin-TMCStepper2"), {})
        self.assertIn("so-name-mismatch", self.findings(mk, repo="fpp-plugin-TMCStepper2"))

    def test_dependency_mention_is_not_a_target(self):
        mk = ("include $(SRCDIR)/makefiles/common/setup.mk\nLIBS += -l:libavcodec.so\n"
              "all: libfpp-foo.$(SHLIB_EXT)\n")
        self.assertEqual(self.findings(mk), {})

    def test_case_differs_is_still_a_mismatch(self):
        mk = "include $(SRCDIR)/makefiles/common/setup.mk\nall: libFPP-Foo.so\n"
        found = self.findings(mk)
        self.assertIn("so-name-mismatch", found)
        self.assertIn("only in case", found["so-name-mismatch"][1])

    def test_variable_stem_is_ignored(self):
        mk = "include $(SRCDIR)/makefiles/common/setup.mk\nall: lib$(NAME).so\n"
        self.assertEqual(self.findings(mk), {})


class ApiPhpRegistrar(unittest.TestCase):
    """api-php-not-a-registrar / api-php-namespace-collision: strings, comments
    and heredocs must not skew the brace-depth count; registrar match is
    case-insensitive like core's; FPP-9 support needs the exact name."""

    REG = ("<?php\nfunction getEndpointsFppFoo() {\n"
           "    return [['method'=>'GET','endpoint'=>'status','callback'=>'fppFooStatus']];\n}\n")
    V9 = {"versions": [{"minFPPVersion": "9.0", "maxFPPVersion": "0"}]}
    V10 = {"versions": [{"minFPPVersion": "10.0", "maxFPPVersion": "0"}]}

    def findings(self, api: str, info=None, repo="fpp-foo"):
        return _lint({"api.php": api}, repo, info,
                     codes=("api-php-not-a-registrar", "api-php-namespace-collision"))

    def test_clean_registrar_is_silent(self):
        self.assertEqual(self.findings(self.REG, self.V10), {})

    def test_url_literal_inside_function_is_not_top_level(self):
        api = self.REG + (
            "function fppFooStatus() {\n"
            "    $url = \"http://127.0.0.1/api/system/status\"; // trailing } brace\n"
            "    $c = '#fff';\n"
            "    $h = <<<EOT\n    } not a brace {\nEOT;\n"
            "    if ($r) { $o = \"ok\"; }\n"
            "    foreach ($r as $k => $v) { $out[$k] = $v; }\n"
            "    return json($out);\n}\n")
        self.assertEqual(self.findings(api, self.V10), {})

    def test_top_level_echo_fires(self):
        found = self.findings(self.REG + "echo json_encode(['x' => 1]);\n", self.V10)
        self.assertEqual(found["api-php-not-a-registrar"][0], L.BLOCKER)
        self.assertIn("api.php:5", found["api-php-not-a-registrar"][1])

    def test_no_registrar_fires(self):
        self.assertIn("api-php-not-a-registrar",
                      self.findings("<?php\nfunction fppFooStatus() { return 1; }\n", self.V10))

    def test_registrar_case_insensitive(self):
        self.assertEqual(self.findings(self.REG.replace("getEndpointsFppFoo", "GETENDPOINTSFPPFOO"), self.V10), {})

    def test_superglobal_read_into_var_is_not_a_side_effect(self):
        api = self.REG + "$pluginDir = $_SERVER['DOCUMENT_ROOT'] . '/plugins/fpp-foo';\n"
        self.assertEqual(self.findings(api, self.V10), {})
        self.assertIn("api-php-not-a-registrar",
                      self.findings(self.REG + "$page = $_GET['page'];\n", self.V10))

    def test_exact_name_required_while_fpp9_supported(self):
        api = self.REG.replace("getEndpointsFppFoo", "getEndpointsWhatever")
        self.assertEqual(self.findings(api, self.V10), {})
        found = self.findings(api, self.V9)
        self.assertIn("api-php-not-a-registrar", found)
        self.assertIn("getEndpointsfppfoo", found["api-php-not-a-registrar"][1])
        self.assertEqual(self.findings(self.REG, self.V9), {})

    def test_reserved_limonade_name_is_blocker(self):
        found = self.findings(self.REG + "function configure() { }\n", self.V10)
        self.assertEqual(found["api-php-namespace-collision"][0], L.BLOCKER)

    def test_generic_name_is_best_practice(self):
        found = self.findings(self.REG + "function getStatus() { return 1; }\n", self.V10)
        self.assertEqual(found["api-php-namespace-collision"][0], L.BEST_PRACTICE)

    def test_fpp_core_global_is_blocker(self):
        # `status()` and `GetPluginInfo()` are defined by FPP core on every /api request
        for name in ("status", "GetPluginInfo"):
            found = self.findings(self.REG + f"function {name}() {{ return 1; }}\n", self.V10)
            self.assertEqual(found["api-php-namespace-collision"][0], L.BLOCKER, name)
            self.assertIn("Cannot redeclare", found["api-php-namespace-collision"][1])

    def test_class_method_cannot_collide(self):
        api = self.REG + "class FppFooApi {\n    function status() { return 1; }\n    function configure() { }\n}\n"
        self.assertEqual(self.findings(api, self.V10), {})


class BlockDeviceNoExclusion(unittest.TestCase):
    """block-device-no-exclusion: destructive writes to a real disk device only,
    and the storage-device exclusion must be in the SAME file."""

    def findings(self, files: dict[str, str]):
        return _lint(files, codes=("block-device-no-exclusion",))

    def test_mkfs_on_generic_device_fires(self):
        found = self.findings({"scripts/wipe.sh": "#!/bin/bash\nDEV=$(lsblk -dn -o NAME | head -1)\nmkfs.ext4 /dev/$DEV\n"})
        self.assertEqual(found["block-device-no-exclusion"][0], L.BLOCKER)

    def test_exclusion_in_same_file_is_silent(self):
        self.assertEqual(self.findings({"scripts/wipe.sh":
            "#!/bin/bash\nBOOT=$(findmnt -n -o SOURCE /home/fpp/media)\nmkfs.ext4 /dev/sda1\n"}), {})

    def test_exclusion_in_other_file_does_not_count(self):
        found = self.findings({
            "scripts/wipe.sh": "#!/bin/bash\nmkfs.ext4 /dev/sda1\n",
            "scripts/fpp_install.sh": "#!/bin/bash\nmkdir -p /home/fpp/media/plugindata/x\n"})
        self.assertIn("block-device-no-exclusion", found)

    def test_read_only_and_null_sink_are_silent(self):
        self.assertEqual(self.findings({"scripts/diag.sh":
            "#!/bin/bash\nlsblk -J\nfsck -n /dev/sda1\ndd if=/dev/zero of=/dev/null bs=1M count=10\n"
            "echo 'Tip: run lsblk to see disks'\n"}), {})

    def test_dd_to_disk_fires(self):
        self.assertIn("block-device-no-exclusion", self.findings({"scripts/flash.sh":
            "#!/bin/bash\ndd if=image.img of=/dev/mmcblk1 bs=4M\n"}))


class NoUninstallTiers(unittest.TestCase):
    """no-uninstall: an artifact the plugin created (unit file, media/scripts
    drop, /etc file) is a BLOCKER; enabling a pre-existing service or writing
    an FPP setting is BEST_PRACTICE. No fpp_uninstall.sh in any case."""

    def findings(self, install: str, extra: dict[str, str] | None = None):
        files = {"scripts/fpp_install.sh": "#!/bin/bash\nset -e\n" + install}
        files.update(extra or {})
        return _lint(files, codes=("no-uninstall",))

    def test_media_scripts_directory_destination_is_blocker(self):
        # fpp-PictureFrame: `cp x.sh /home/fpp/media/scripts/` (trailing slash)
        found = self.findings("cp scripts/Check.sh /home/fpp/media/scripts/\n")
        self.assertEqual(found["no-uninstall"][0], L.BLOCKER)
        self.assertIn("file dropped in", found["no-uninstall"][1])

    def test_enable_preexisting_service_is_best_practice(self):
        found = self.findings("systemctl --now enable smbd\nsystemctl --now enable nmbd\n"
                              "echo 'Service_smbd_nmbd = \"1\"' >> /home/fpp/media/settings\n")
        self.assertEqual(found["no-uninstall"][0], L.BEST_PRACTICE)
        self.assertIn("enables system service `smbd`", found["no-uninstall"][1])

    def test_shipped_unit_file_is_blocker(self):
        found = self.findings("cp fpp-foo.service /etc/systemd/system/\nsystemctl enable fpp-foo\n",
                              {"fpp-foo.service": "[Unit]\nDescription=x\n"})
        self.assertEqual(found["no-uninstall"][0], L.BLOCKER)

    def test_kinds_are_deduplicated(self):
        found = self.findings("cp a.sh /home/fpp/media/scripts/\ncp b.sh /home/fpp/media/scripts/\n")
        self.assertEqual(found["no-uninstall"][1].count("file dropped in"), 1)

    def test_with_uninstall_is_silent(self):
        self.assertEqual(self.findings("cp a.sh /home/fpp/media/scripts/\n",
                                       {"scripts/fpp_uninstall.sh": "#!/bin/bash\nrm -f /home/fpp/media/scripts/a.sh\n"}), {})

    def test_group_membership_alone_is_best_practice(self):
        found = self.findings("usermod -aG dialout fpp\n")
        self.assertEqual(found["no-uninstall"][0], L.BEST_PRACTICE)


class MediaWriteAlias(unittest.TestCase):
    """_priv_media_write_hits alias hop: only a write whose DESTINATION is the
    aliased path counts (fpp-jukebox's `cp ... "${PLACEHOLDERIMAGE}"`), not a
    read of it."""

    def hits(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"scripts/fpp_install.sh": text})
            return [(h[1], h[3]) for h in L._priv_media_write_hits(tmp)]

    def test_alias_as_destination_fires(self):
        self.assertEqual(self.hits(
            'PH=/home/fpp/media/images/placeholder.jpg\ncp assets/ph.jpg "${PH}"\n'),
            [(2, "/home/fpp/media/images/placeholder.jpg")])

    def test_alias_as_source_is_silent(self):
        self.assertEqual(self.hits(
            'PH=/home/fpp/media/images/placeholder.jpg\ncp "$PH" /tmp/\nif [ -f "$PH" ]; then echo ok; fi\n'), [])

    def test_alias_redirect_fires(self):
        self.assertEqual(self.hits(
            'OUT=/home/fpp/media/scripts/foo.sh\necho "#!/bin/bash" > "$OUT"\n'),
            [(2, "/home/fpp/media/scripts/foo.sh")])


class SetEHereString(unittest.TestCase):
    """_set_e_position: `<<<` and `<<` in arithmetic are not heredoc openers."""

    def findings(self, hook: str):
        return _lint({"scripts/fpp_install.sh": hook}, codes=("no-set-e",))

    def test_here_string_before_set_e_does_not_swallow_it(self):
        self.assertEqual(self.findings('#!/bin/bash\nset -e\nread -r a <<< "$x"\napt-get install -y foo\n'), {})
        self.assertEqual(self.findings('#!/bin/bash\nset -e\nX=$(( 1 << 3 ))\napt-get install -y foo\n'), {})

    def test_real_heredoc_still_recognised(self):
        # set -e inside a heredoc body is data, not a command
        found = self.findings('#!/bin/bash\ncat > /tmp/x <<EOF\nset -e\nEOF\napt-get install -y foo\n')
        self.assertIn("no-set-e", found)



class AptManualInstall(unittest.TestCase):
    """apt-manual-install: BEST_PRACTICE only, FPP 10+-only plugins, options
    before or after the verb, not help text, not fpp_uninstall.sh."""

    V9 = {"versions": [{"minFPPVersion": "9.0", "maxFPPVersion": "0"}]}
    V10 = {"versions": [{"minFPPVersion": "10.0", "maxFPPVersion": "0"}]}

    def findings(self, install: str, info=V10, rel="scripts/fpp_install.sh"):
        return _lint({rel: "#!/bin/bash\nset -e\n" + install}, info=info, codes=("apt-manual-install",))

    def test_options_before_verb_fires(self):
        found = self.findings("apt-get -y install libfoo\n")
        self.assertEqual(found["apt-manual-install"][0], L.BEST_PRACTICE)

    def test_initramfs_package_is_not_a_blocker(self):
        self.assertEqual(self.findings("apt-get install -y dosfstools e2fsprogs\n")["apt-manual-install"][0],
                         L.BEST_PRACTICE)

    def test_pre_10_plugin_is_silent(self):
        self.assertEqual(self.findings("apt-get install -y libfoo\n", self.V9), {})

    def test_help_text_and_uninstall_are_silent(self):
        self.assertEqual(self.findings('echo "If this fails, run: sudo apt-get install -y libfoo"\n'), {})
        self.assertEqual(self.findings("apt-get remove -y libfoo\n", rel="scripts/fpp_uninstall.sh"), {})


class ServerBindAllInterfaces(unittest.TestCase):
    """server-bind-all-interfaces: BLOCKER only when paired with a ProxyPass;
    a bare 0.0.0.0 bind is OPTIONAL, and a UDP receiver isn't flagged at all."""

    def findings(self, files):
        return _lint(files, codes=("server-bind-all-interfaces",))

    def test_proxypass_pair_is_blocker(self):
        found = self.findings({"daemon.py": "app.run(host='0.0.0.0', port=8080)\n",
                               "scripts/fpp_install.sh": "#!/bin/bash\necho 'ProxyPass /foo http://127.0.0.1:8080/' > /tmp/x\n"})
        self.assertEqual(found["server-bind-all-interfaces"][0], L.BLOCKER)

    def test_bare_bind_is_optional(self):
        found = self.findings({"daemon.py": "app.run(host='0.0.0.0', port=8080)\n"})
        self.assertEqual(found["server-bind-all-interfaces"][0], L.OPTIONAL)

    def test_udp_receiver_is_silent(self):
        self.assertEqual(self.findings({"e131.py":
            "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.bind(('0.0.0.0', 5568))\n"}), {})


class SetEShapes(unittest.TestCase):
    """_set_e_position: syntax, conditions, env-prefixed commands, continuation
    lines and the other spellings of errexit."""

    def pos(self, body):
        return L._set_e_position(body)

    def test_other_errexit_spellings(self):
        for line in ("set -o pipefail -e", "set -o nounset -o errexit", "set -eu", "set -o errexit"):
            self.assertEqual(self.pos(f"#!/bin/bash\n{line}\nfoo\n"), (2, []), line)

    def test_brace_and_split_function_def_are_not_commands(self):
        self.assertEqual(self.pos("#!/bin/bash\nfoo()\n{\n    echo hi\n}\nfunction bar {\n    echo x\n}\nset -e\n"), (9, []))
        self.assertEqual(self.pos("#!/bin/bash\nfoo() { echo hi; }\nset -e\n"), (3, []))

    def test_condition_headers_are_exempt(self):
        body = ('#!/bin/bash\nif [ -z "$FPPDIR" ]; then\n    FPPDIR=/opt/fpp\nfi\n'
                'case "$1" in\n  x) ;;\nesac\nset -e\n')
        self.assertEqual(self.pos(body), (8, []))

    def test_brace_group_exit_guard(self):
        self.assertEqual(self.pos('#!/bin/bash\n[ -d /x ] || { echo "no" >&2; exit 1; }\nset -e\n'), (3, []))

    def test_env_prefixed_command_is_a_command(self):
        self.assertEqual(self.pos("#!/bin/bash\nDEBIAN_FRONTEND=noninteractive apt-get install -y foo\nset -e\n"),
                         (3, [(2, "DEBIAN_FRONTEND=noninteractive apt-get install -y foo")]))

    def test_dirname_assignment_is_preamble(self):
        self.assertEqual(self.pos('#!/bin/bash\nDIR=$(cd "$(dirname "$0")" && pwd)\n. /opt/fpp/scripts/common\nset -e\n'), (4, []))

    def test_continuation_guarded_on_last_line(self):
        self.assertEqual(self.pos("#!/bin/bash\napt-get install -y \\\n    foo bar || true\nset -e\n"), (4, []))
        p = self.pos("#!/bin/bash\napt-get install -y \\\n    foo bar\nset -e\n")
        self.assertEqual(p[0], 4)
        self.assertEqual(p[1][0][0], 2)


class BlockingSleepShapes(unittest.TestCase):
    """blocking-sleep-in-hook: `function foo {` helpers, brace-range and seq
    loops, `until [ -S ]` polls, backgrounded sleeps; a pgrep outside any loop
    doesn't excuse a flat sleep; only scripts/<hook>.sh is a hook."""

    def hits(self, hook: str, rel="scripts/postStart.sh"):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {rel: hook})
            return [h[1] for h in L._blocking_sleep_in_hook_hits(tmp)]

    def test_function_keyword_helper_backgrounded_is_silent(self):
        self.assertEqual(self.hits("#!/bin/bash\nfunction wait_ready {\n    sleep 5\n}\nwait_ready &\n"), [])

    def test_recommended_poll_shapes_are_silent(self):
        self.assertEqual(self.hits("#!/bin/bash\nfor i in {1..10}; do\n    [ -S /tmp/s.sock ] && break\n    sleep 0.5\ndone\n"), [])
        self.assertEqual(self.hits("#!/bin/bash\nfor i in $(seq 1 10); do\n    nc -z localhost 80 && break\n    sleep 1\ndone\n"), [])
        self.assertEqual(self.hits("#!/bin/bash\nuntil [ -S /tmp/s.sock ]; do\n    sleep 0.5\ndone\n"), [])

    def test_pgrep_outside_a_loop_does_not_excuse_flat_sleep(self):
        self.assertEqual(self.hits("#!/bin/bash\npgrep -f foo | xargs -r kill\nsleep 5\n"), [3])

    def test_backgrounded_sleep_is_silent(self):
        self.assertEqual(self.hits("#!/bin/bash\nsleep 5 &\n(sleep 5; systemctl start x) &\n"), [])

    def test_all_flat_sleeps_reported(self):
        self.assertEqual(self.hits("#!/bin/bash\nsleep 2\necho x\nsleep 5\n"), [2, 4])

    def test_only_scripts_hook_path_counts(self):
        self.assertEqual(self.hits("#!/bin/bash\nsleep 5\n", rel="backup/preStart.sh.orig"), [])
        self.assertEqual(self.hits("#!/bin/bash\nsleep 5\n", rel="preStart.sh"), [])
        self.assertEqual(self.hits("#!/bin/bash\nsleep 5\n", rel="scripts/preStart.sh"), [2])


class SubshellExitSwallowed(unittest.TestCase):
    def hits(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"scripts/fpp_install.sh": text})
            return [h[1] for h in L._subshell_exit_swallow_hits(tmp)]

    FN = '#!/bin/bash\nvalidate() {\n    [ -n "$1" ] || exit 1\n    echo "$1"\n}\n'

    def test_validator_shapes_fire(self):
        self.assertEqual(self.hits(self.FN + 'X="$(validate "$1")"\n'), [6])
        self.assertEqual(self.hits(self.FN + 'local X=$(validate "$1")\n'), [6])
        self.assertEqual(self.hits(self.FN.replace("validate() {", "function validate {") + 'X=$(validate "$1")\n'), [6])

    def test_status_checked_is_the_correct_shape(self):
        self.assertEqual(self.hits(self.FN + 'X=$(validate "$1") || exit 1\n'), [])

    def test_direct_call_is_silent(self):
        self.assertEqual(self.hits(self.FN + 'validate "$1"\n'), [])


class ObfuscatedCode(unittest.TestCase):
    def findings(self, files):
        return _lint(files, codes=("obfuscated-code",))

    def test_data_url_upload_is_silent(self):
        self.assertEqual(self.findings({"upload.php":
            "<?php\n$img = base64_decode(preg_replace('#^data:image/\\w+;base64,#i', '', $_POST['data']));\n"}), {})

    def test_eval_of_decoded_fires(self):
        self.assertIn("obfuscated-code", self.findings({"x.php": '<?php\neval("?>" . base64_decode($p));\n'}))
        self.assertIn("obfuscated-code", self.findings({"x.py": "exec(base64.b64decode(p))\n"}))
        self.assertIn("obfuscated-code", self.findings({"scripts/fpp_install.sh": "#!/bin/bash\necho $P | base64 -d | bash\n"}))

    def test_embedded_literal_payload_fires(self):
        found = self.findings({"x.php": "<?php\n$c = base64_decode('" + "QUJD" * 20 + "');\n"})
        self.assertIn("ships an encoded payload", found["obfuscated-code"][1])


class LogNamingAlias(unittest.TestCase):
    def hits(self, text: str, rel="scripts/foo.sh"):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {rel: text})
            return [h[1] for h in L._log_naming_hits(tmp)]

    def test_naming_own_log_via_alias_fires(self):
        self.assertEqual(self.hits('LOG_DIR="${LOGDIR:-/home/fpp/media/logs}"\nLOG_FILE="$LOG_DIR/Foo.log"\n'), [2])

    def test_reading_or_rotating_via_alias_is_silent(self):
        self.assertEqual(self.hits('LOG_DIR="${LOGDIR:-/home/fpp/media/logs}"\ntail -n 50 "$LOG_DIR/fppd.log"\n'), [])
        self.assertEqual(self.hits('LOG_DIR="${LOGDIR:-/home/fpp/media/logs}"\nfind "$LOG_DIR" -name "*.log" -mtime +7 -delete\n'), [])
        self.assertEqual(self.hits("<?php\n$logDir = $settings['logDirectory'];\n$t = file_get_contents($logDir . '/fppd.log');\n", "x.php"), [])


class BusyWaitPoll(unittest.TestCase):
    def hits(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, files)
            return [h[0] for h in L._busy_wait_poll_hits(tmp)]

    LOOP = "<?php\nwhile (true) {\n    doWork();\n    sleep(1);\n}\n"

    def test_unbounded_loop_in_web_php_fires(self):
        self.assertEqual(self.hits({"daemon.php": self.LOOP}), ["daemon.php"])

    def test_suppressors(self):
        self.assertEqual(self.hits({"daemon.php": "#!/usr/bin/php\n" + self.LOOP[6:]}), [])
        self.assertEqual(self.hits({"daemon.php": "<?php\nif (php_sapi_name() !== 'cli') exit;\n" + self.LOOP[6:]}), [])
        self.assertEqual(self.hits({"daemon.php": self.LOOP,
                                    "scripts/postStart.sh": "#!/bin/bash\nnohup php daemon.php &\n"}), [])

    def test_non_shell_launchers(self):
        self.assertEqual(self.hits({"daemon.php": self.LOOP,
                                    "fpp-foo.service": "[Service]\nExecStart=/usr/bin/php /home/fpp/media/plugins/x/daemon.php\n"}), [])
        self.assertEqual(self.hits({"daemon.php": self.LOOP,
                                    "start.php": "<?php\nexec('php ' . __DIR__ . '/daemon.php > /dev/null 2>&1 &');\n"}), [])
        self.assertEqual(self.hits({"daemon.php": self.LOOP,
                                    "ctl.py": "subprocess.Popen(['php', 'daemon.php'])\n"}), [])
        self.assertEqual(self.hits({"daemon.php": self.LOOP,
                                    "start.php": "<?php\nexec('php daemon.php');\n"}), ["daemon.php"])


class ExecDelegation(unittest.TestCase):
    def target(self, files, hook="scripts/fpp_install.sh"):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, files)
            return L._exec_delegation_target(os.path.join(tmp, hook), tmp)

    REAL = {"scripts/sub/fpp_install.sh": "#!/bin/bash\nset -e\n"}

    def test_allow_listed_var(self):
        self.assertEqual(self.target({**self.REAL, "scripts/fpp_install.sh":
            '#!/bin/bash\nPLUGIN_DIR=$(cd "$(dirname "$0")" && pwd)\nexec bash "$PLUGIN_DIR/sub/fpp_install.sh"\n'}),
            "scripts/sub/fpp_install.sh")

    def test_unknown_var_dotdot_and_missing_are_rejected(self):
        self.assertIsNone(self.target({**self.REAL, "scripts/fpp_install.sh":
            '#!/bin/bash\nexec bash "$OTHER/sub/fpp_install.sh"\n'}))
        self.assertIsNone(self.target({**self.REAL, "scripts/fpp_install.sh":
            '#!/bin/bash\nSCRIPT_DIR=$(dirname "$0")\nexec bash "$SCRIPT_DIR/../../etc/x.sh"\n'}))
        self.assertIsNone(self.target({"scripts/fpp_install.sh":
            '#!/bin/bash\nSCRIPT_DIR=$(dirname "$0")\nexec bash "$SCRIPT_DIR/nope.sh"\n'}))

    def test_self_is_rejected(self):
        self.assertIsNone(self.target({"scripts/fpp_install.sh":
            '#!/bin/bash\nSCRIPT_DIR=$(dirname "$0")\nexec bash "$SCRIPT_DIR/fpp_install.sh"\n'}))

    def test_other_spellings(self):
        for line in ('exec bash "$(dirname "$0")/sub/fpp_install.sh"',
                     'exec "$SCRIPT_DIR/sub/fpp_install.sh"',
                     'exec bash "$SCRIPT_DIR/sub/fpp_install.sh" "$@"',
                     'exec /bin/sh $SCRIPT_DIR/sub/fpp_install.sh FPPDIR=$FPPDIR'):
            self.assertEqual(self.target({**self.REAL, "scripts/fpp_install.sh":
                f'#!/bin/bash\nSCRIPT_DIR=$(dirname "$0")\n{line}\n'}), "scripts/sub/fpp_install.sh", line)


class ReleaseNotesStyle(unittest.TestCase):
    def findings(self, info):
        return _lint({"README.md": "x\n"}, info=info, codes=("no-release-notes-style",))

    def test_absent_or_none_fires_optional(self):
        self.assertEqual(self.findings({})["no-release-notes-style"][0], L.OPTIONAL)
        self.assertIn("no-release-notes-style", self.findings({"releaseNotesStyle": "none"}))

    def test_set_or_no_info_is_silent(self):
        self.assertEqual(self.findings({"releaseNotesStyle": "gitHistory"}), {})
        self.assertEqual(self.findings(None), {})



class ReReviewFixes(unittest.TestCase):
    """Defects found by the second (adversarial) review of the rewritten rules."""

    def test_set_e_preamble_regex_is_linear(self):
        import time
        t = time.time()
        L._SET_E_PREAMBLE_RX.match("PYTHONPATH=" + "a" * 400 + " python3 setup.py")
        self.assertLess(time.time() - t, 0.05)
        self.assertEqual(L._set_e_position("#!/bin/bash\nPKGS=(a b c)\ntypeset -i N=3\nx=$((y << 2))\nset -e\n"), (5, []))

    def test_exec_only_wrapper_needs_no_set_e(self):
        found = _lint({"scripts/fpp_install.sh": '#!/bin/bash\nexec bash "$(dirname "$0")/sub/fpp_install.sh" "$@"\n',
                       "scripts/sub/fpp_install.sh": "#!/bin/bash\nset -e\napt-get install -y x\n"},
                      codes=("no-set-e",))
        self.assertEqual(found, {})

    def test_so_name_only_for_cpp_plugins(self):
        found = _lint({"callbacks.sh": "#!/bin/bash\necho 'media,playlist'\n",
                       "Makefile": "include $(SRCDIR)/makefiles/common/setup.mk\nall: libgpiohelper.so\nlibgpiohelper.so: h.o\n"},
                      "fpp-foo", codes=("so-name-mismatch",))
        self.assertEqual(found, {})

    def test_so_name_override_with_relative_path(self):
        found = _lint({"callbacks.sh": "#!/bin/bash\n# not c++:libother.so\necho 'c++:./build/libfoo.so'\n",
                       "Makefile": "include $(SRCDIR)/makefiles/common/setup.mk\nall: libfoo.so\nlibfoo.so: a.o\n"},
                      "fpp-bar", codes=("so-name-mismatch",))
        self.assertEqual(found, {})

    def test_modprobe_alone_is_not_an_artifact(self):
        found = _lint({"scripts/fpp_install.sh": "#!/bin/bash\nset -e\nmodprobe i2c-dev\nudevadm control --reload-rules\n"},
                      codes=("no-uninstall",))
        self.assertEqual(found["no-uninstall"][0], L.BEST_PRACTICE)
        found = _lint({"scripts/fpp_install.sh": "#!/bin/bash\nset -e\ncp 99-foo.rules /etc/udev/rules.d/\n"},
                      codes=("no-uninstall",))
        self.assertEqual(found["no-uninstall"][0], L.BLOCKER)

    def test_block_device_variable_forms(self):
        code = ("block-device-no-exclusion",)
        self.assertEqual(_lint({"scripts/b.sh": "#!/bin/bash\nBACKUP_TARGET=/tmp/b.img\ndd if=/dev/zero of=$BACKUP_TARGET bs=1M\n"}, codes=code), {})
        self.assertIn("block-device-no-exclusion",
                      _lint({"scripts/w.sh": "#!/bin/bash\nfor dev in $(lsblk -dno NAME | grep -v mmcblk0); do\n  mkfs.vfat -F32 /dev/$dev\ndone\n"}, codes=code))
        self.assertIn("block-device-no-exclusion",
                      _lint({"w.php": '<?php\n$device = $_POST["dev"]; exec("mkfs.vfat -F32 $device");\n'}, codes=code))
        self.assertEqual(_lint({"t.py": '"""Tool.\n\nManual: sudo dd if=fpp.img of=/dev/sdb bs=4M\n"""\nprint(1)\n'}, codes=code), {})
        self.assertEqual(_lint({"scripts/u.sh": "#!/bin/bash\ncat <<EOF\nusage: dd if=x of=/dev/sdb\nEOF\n"}, codes=code), {})

    def test_service_hit_in_helper_does_not_shadow_install(self):
        found = _lint({"scripts/control.sh": "#!/bin/bash\nsystemctl start fpp-foo\n",
                       "scripts/fpp_install.sh": "#!/bin/bash\nset -e\ncp fpp-foo.service /etc/systemd/system/fpp-foo.service\nsystemctl enable fpp-foo\n",
                       "fpp-foo.service": "[Unit]\n"}, codes=("no-uninstall",))
        self.assertEqual(found["no-uninstall"][0], L.BLOCKER)

    def test_directory_alias_for_media_drop(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"scripts/fpp_install.sh": 'SCRIPTDIR=/home/fpp/media/scripts\ncp scripts/x.sh "$SCRIPTDIR/x.sh"\n'})
            self.assertEqual([h[1] for h in L._priv_media_write_hits(tmp)], [2])

    def test_php_builtin_in_api_php_is_blocker(self):
        reg = "<?php\nfunction getEndpointsFppFoo() { return []; }\n"
        found = _lint({"api.php": reg + "function log($m) {}\n"}, "fpp-foo",
                      {"versions": [{"minFPPVersion": "10.0"}]}, codes=("api-php-namespace-collision",))
        self.assertEqual(found["api-php-namespace-collision"][0], L.BLOCKER)
        self.assertIn("built-in", found["api-php-namespace-collision"][1])

    def test_apt_call_shapes(self):
        V10 = {"versions": [{"minFPPVersion": "10.0"}]}
        for line in ('echo "Installing"; apt-get install -y foo', 'echo x && apt-get install -y foo',
                     'sudo bash -c "apt-get install -y foo"', 'apt-get -o Dpkg::Options::="--force-confold" -y install foo'):
            self.assertIn("apt-manual-install", _lint({"scripts/fpp_install.sh": f"#!/bin/bash\nset -e\n{line}\n"},
                                                      info=V10, codes=("apt-manual-install",)), line)
        self.assertEqual(_lint({"scripts/fpp_install.sh": '#!/bin/bash\nset -e\necho "If this fails: sudo apt-get install -y foo"\n'},
                               info=V10, codes=("apt-manual-install",)), {})

    def test_blocking_sleep_more_bounded_shapes(self):
        def hits(hook):
            with tempfile.TemporaryDirectory() as tmp:
                write_tree(tmp, {"scripts/postStart.sh": hook})
                return [h[1] for h in L._blocking_sleep_in_hook_hits(tmp)]
        self.assertEqual(hits("#!/bin/bash\nwhile [ ! -e /tmp/sock ]; do\n  sleep 0.5\ndone\n"), [])
        self.assertEqual(hits("#!/bin/bash\nuntil curl -sf http://localhost:8080/ > /dev/null; do sleep 1; done\n"), [])
        self.assertEqual(hits("#!/bin/bash\n(\n  sleep 5\n  ./x\n) &\n"), [])
        self.assertEqual(hits("#!/bin/bash\n(\n  sleep 5\n  ./x\n)\n"), [3])

    def test_obfuscated_image_literal_is_silent(self):
        self.assertEqual(_lint({"x.php": "<?php\n$png = base64_decode('iVBORw0KGgo" + "AAAA" * 20 + "');\n"},
                               codes=("obfuscated-code",)), {})

    def test_bind_udp_far_above_and_aiohttp(self):
        src = "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n" + "x = 1\n" * 30 + "s.bind(('0.0.0.0', 5568))\n"
        self.assertEqual(_lint({"e131.py": src}, codes=("server-bind-all-interfaces",)), {})
        self.assertIn("server-bind-all-interfaces",
                      _lint({"web.py": "# not udp\nweb.run_app(app, host='0.0.0.0', port=8080)\n"}, codes=("server-bind-all-interfaces",)))

    def test_busy_wait_cron_and_systemd_run_launchers(self):
        loop = "<?php\nwhile (true) {\n    doWork();\n    sleep(1);\n}\n"
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"poll.php": loop,
                             "scripts/fpp_install.sh": '(crontab -l; echo "@reboot php /x/poll.php") | crontab -\n'})
            self.assertEqual(list(L._busy_wait_poll_hits(tmp)), [])
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"poll.php": loop, "scripts/postStart.sh": "systemd-run --unit=x php poll.php\n"})
            self.assertEqual(list(L._busy_wait_poll_hits(tmp)), [])


if __name__ == "__main__":
    unittest.main()
