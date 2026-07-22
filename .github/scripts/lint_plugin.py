"""Static plugin linter for a single FPP plugin working tree.

Runs the guideline/hygiene checks (the "areas of concern / optimisation"
surfaced in a release-readiness scan) against a plugin's cloned directory.
No clone/network here - the caller provides a path. Uses the third-party
`jsonschema` package (already a hard dependency of this repo's other scan
scripts) for the pluginInfo.json schema check.

Each check yields a Finding(severity, code, message). Severities:
  blocker        - dangerous or breaks FPP/other users (reboots the box, kills a running
                   show, remote code exec, world-writable, corrupts the system Python,
                   bypasses the stable API contract)
  best-practice  - against the guidelines but not dangerous (sudo in a script, no
                   `set -e`, no uninstall script, CRLF line endings)
  optional       - polish (missing LICENSE/README, no bugURL)

Reference: PLUGIN_GUIDELINES.md and PLUGININFO_FORMAT.md in fpp-plugin-Template.

Standalone:  python lint_plugin.py <plugin_dir> [repoName]
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass

# schema_validation_error needs the third-party jsonschema package (a hard
# dependency of this repo's other scan scripts, but lint_plugin.py itself was
# previously stdlib-only and is used more widely/standalone) - degrade to
# skipping just the schema check rather than making the whole linter unusable
# wherever jsonschema isn't installed.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from lib_plugin_schema import schema_validation_error, parse_github_repo
except ImportError:
    schema_validation_error = None
    parse_github_repo = None

BLOCKER, BEST_PRACTICE, OPTIONAL = "blocker", "best-practice", "optional"

HOOKS = ("fpp_install.sh", "fpp_uninstall.sh", "preStart.sh", "postStart.sh",
         "preStop.sh", "postStop.sh")
SCRIPT_EXT = (".sh", ".py", ".php")

# Files fppd actually executes as root (fppd.service has no User=, so it and
# everything it shells out to - runPreStartScripts/install_plugin/
# upgrade_plugin/uninstall_plugin - runs as root). Everything else (cmd.php and
# other runtime request-handler scripts) runs as the `fpp` user, where sudo can
# be legitimate.
SUDO_SCOPE = HOOKS + ("fpp_upgrade.sh",)


@dataclass
class Finding:
    severity: str
    code: str
    message: str


def _iter_files(root: str, exts=None):
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if exts and not fn.endswith(exts):
                continue
            yield os.path.join(dirpath, fn)


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


_VENDOR_DIRS = ("/vendor/", "/vendored/", "/node_modules/", "/third_party/", "/thirdparty/")


def _grep(root, pattern, exts=SCRIPT_EXT, flags=re.I):
    """Yield (relpath, lineno, line) for a regex over code files, skipping docs and
    vendored third-party code (a plugin's own bugs are what we're checking for; a
    vendored library's internals are out of scope and would just add noise)."""
    rx = re.compile(pattern, flags)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        low = "/" + rel.lower()
        if low.endswith((".md", ".markdown")) or "/help/" in low or "/test" in low \
           or any(v in low for v in _VENDOR_DIRS):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            stripped = line.lstrip()
            # skip full comment lines (PHP/JS/C //*, shell/py #, HTML <!--, ini ;)
            if stripped[:2] in ("//", "/*", "* ") or stripped[:1] in ("#", ";") \
               or stripped.startswith("<!--") or stripped in ("*", "*/"):
                continue
            if rx.search(line):
                yield rel, i, line.strip()


def _skippable(rel: str) -> bool:
    """Same doc/help/test exclusion _grep applies, for checks that need raw file text."""
    low = "/" + rel.lower()
    return (low.endswith((".md", ".markdown")) or "/help/" in low or "/test" in low
            or any(v in low for v in _VENDOR_DIRS))


def _assign_then_sink(root: str, taint_pattern: str, sink_pattern_tpl: str, window: int = 6, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) where a variable assigned from something matching
    `taint_pattern` is passed into a sink matching `sink_pattern_tpl % varname` within
    `window` lines after the assignment. Cheap stand-in for real taint tracking."""
    assign_rx = re.compile(r'\$(\w+)\s*=.*' + taint_pattern, re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        lines = _read(path).splitlines()
        for i, line in enumerate(lines):
            m = assign_rx.search(line)
            if not m:
                continue
            var = re.escape(m.group(1))
            sink_rx = re.compile(sink_pattern_tpl % var, re.I)
            for j in range(i, min(i + window, len(lines))):
                if sink_rx.search(lines[j]):
                    yield rel, j + 1, lines[j].strip()
                    break


def _sql_concat_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for ->query()/->exec() calls on a variable that was
    built via string concatenation, in a file with no prepare/bind/escapeString anywhere -
    i.e. no evidence the query is ever parameterized. Regex heuristic, not real taint
    tracking; flags for manual triage rather than proving exploitability."""
    call_rx = re.compile(r'->(?:query|exec)\s*\(\s*\$(\w+)\s*\)')
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if re.search(r'escapeString\s*\(|->prepare\s*\(|bindValue|bindParam', text, re.I):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            m = call_rx.search(line)
            if not m:
                continue
            var = re.escape(m.group(1))
            if re.search(rf'\${var}\s*=\s*["\'][^"\']*["\']\s*\.\s*\$', text):
                yield rel, i, line.strip()


def _webhook_no_auth_hits(root: str, exts=(".php",)):
    """Yield (relpath, lineno, line) for a file that reads a webhook-shaped request field
    (From/Body/Sender - common inbound-SMS/messaging-provider field names) with no
    signature/HMAC verification string anywhere in the file. Heuristic, not proof the
    field is actually used for auth - flags for manual triage."""
    field_rx = re.compile(r'''\$_(?:POST|REQUEST)\s*\[\s*['"](From|Body|Sender)['"]\s*\]''')
    auth_rx = re.compile(r'signature|hash_hmac|validaterequest', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if auth_rx.search(text):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if field_rx.search(line):
                yield rel, i, line.strip()
                break


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return (stripped[:2] in ("//", "/*", "* ") or stripped[:1] in ("#", ";")
            or stripped.startswith("<!--") or stripped in ("*", "*/"))


def _unescaped_html_attr_hits(root: str, exts=(".php",)):
    """Yield (relpath, lineno, line) where an `echo`/short-echo statement writes a known
    HTML attribute (value/action/href/src/placeholder) built by concatenating a PHP
    variable, with no htmlspecialchars/htmlentities on that line. Scoped to a real
    output statement + a real attribute name (not just any `x = "..." . $var` shape)
    to keep false positives low - log calls and URL/query-string building don't match."""
    # PHP's usual idiom here is `value=\"".$var` - a backslash-escaped quote that
    # closes the *attribute's* opening quote, immediately followed by the real
    # quote that closes the PHP string literal itself, then `.` - i.e. up to two
    # quote characters can appear before the concatenation dot, not just one.
    attr_rx = re.compile(r'''(echo\b|<\?=)[^\n]*\b(value|action|href|src|placeholder)\s*=\s*\\?['"]{1,2}\s*\.\s*\$\w''')
    escape_rx = re.compile(r'htmlspecialchars\s*\(|htmlentities\s*\(', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if attr_rx.search(line) and not escape_rx.search(line):
                yield rel, i, line.strip()
                break


def _destructive_no_guard_hits(root: str, exts=(".php",)):
    """Yield (relpath, lineno, line) for a file that runs a destructive call
    (unlink/rm/exec-rm) with no HTTP-method or $_POST check anywhere in that same
    file - i.e. potentially reachable via a plain GET with no confirmation. Excludes
    cleanup registered via register_shutdown_function (e.g. deleting your own PID
    file on exit) and `@`-suppressed calls (the error-suppression idiom is a strong
    signal for "best-effort internal cleanup", e.g. removing a temp file after an
    atomic rename or a PID file when stopping a process, rather than a page whose
    entire job is the destructive action) - neither is the shape this rule targets."""
    destructive_rx = re.compile(r'(?<!@)\bunlink\s*\(|(?<!@)\brm\s+-[rf]|(?:exec|system|shell_exec)\s*\([^)]*\brm\s+')
    guard_rx = re.compile(r"\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\]|\$_POST\b")
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if guard_rx.search(text):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line) or "register_shutdown_function" in line:
                continue
            if destructive_rx.search(line):
                yield rel, i, line.strip()
                break


def _secret_in_log_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a log/echo/file_put_contents(...log) call whose
    argument concatenates a variable named like a credential (key/token/secret/password/
    apikey). Narrow heuristic per the report this was written from - real secret detection
    is out of scope, this only catches "the variable name gives it away". Requires more
    than a bare `$key` (too generic - a dict/array key has nothing to do with credentials);
    "token"/"secret"/"password"/"apikey" are specific enough to match on their own."""
    log_call_rx = re.compile(
        r'(logEntry|logMessage|error_log|console\.(log|error)|print(?:_r)?|echo)\s*\(')
    var_rx = re.compile(r'\$(?:\w*(?:token|secret|password|apikey)\w*|\w+key\w*)\b', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if log_call_rx.search(line) and var_rx.search(line):
                yield rel, i, line.strip()
                break


def _log_naming_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a log filename built from logDirectory/LOGDIR
    that doesn't include the mandated "plugin-" prefix - e.g. `$pluginName.".log"` instead
    of `"plugin-".$pluginName.".log"`."""
    rx = re.compile(r'(logDirectory|LOGDIR)\b.*\.log\b', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if rx.search(line) and "plugin-" not in line.lower():
                yield rel, i, line.strip()
                break


def _missing_timeout_hits(root: str, exts=(".php", ".py", ".sh")):
    """Yield (relpath, lineno, line) for a file with an outbound HTTP call and NO timeout
    setting anywhere in that file - curl_init/curl_setopt with no CURLOPT_(CONNECT)?TIMEOUT,
    stream_context_create with no 'timeout' key, Python requests.get/post/put without
    timeout=, or a shell `curl` command with no --max-time/-m/--connect-timeout. PHP/Python
    are checked file-level (a file legitimately mixing timed and untimed calls is rare, so
    presence/absence beats matching each call to its own config); shell curl is checked
    per-line since command-line invocations are typically standalone one-liners."""
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if path.endswith(".php"):
            if not re.search(r'curl_init\s*\(|stream_context_create\s*\(', text):
                continue
            if re.search(r'CURLOPT_(CONNECT)?TIMEOUT|(?:[\'"])timeout(?:[\'"])\s*=>', text, re.I):
                continue
            call_rx = re.compile(r'curl_init\s*\(|stream_context_create\s*\(')
        elif path.endswith(".py"):
            if not re.search(r'requests\.(get|post|put|patch|delete)\s*\(', text):
                continue
            if re.search(r'\btimeout\s*=', text):
                continue
            call_rx = re.compile(r'requests\.(get|post|put|patch|delete)\s*\(')
        else:  # .sh - checked per line, not file-level
            # curl to localhost/127.0.0.1 in an install/uninstall script (e.g. hitting
            # FPP's own API to restart fppd) is excluded: it's a one-shot call at
            # install/uninstall time, not a recurring hook, and a local connection
            # fails fast rather than hanging on cross-network TCP retries - the
            # remaining risk (fppd alive but wedged) doesn't clear the bar here.
            is_install_script = os.path.basename(path) in ("fpp_install.sh", "fpp_uninstall.sh")
            # Match curl only where it's actually being invoked as a command (start
            # of line, after ;&| / sudo/then/do, or a $()/backtick substitution) -
            # not anywhere the bare word "curl" appears, which also matches it as an
            # apt-get/pip package name being installed (e.g. `apt-get install curl`).
            curl_cmd_rx = re.compile(r'(^|[;&|]|\$\(|`|\bsudo\s+|\bthen\s+|\bdo\s+)\s*curl\b')
            for i, line in enumerate(text.splitlines(), 1):
                if _is_comment_line(line):
                    continue
                if not curl_cmd_rx.search(line) or re.search(r'--max-time\b|-m\s+\d|--connect-timeout\b', line):
                    continue
                if is_install_script and re.search(r'://(localhost|127\.0\.0\.1)\b', line):
                    continue
                yield rel, i, line.strip()
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line):
                continue
            if call_rx.search(line):
                yield rel, i, line.strip()
                break


def _device_path_no_allowlist_hits(root: str, exts=(".cpp", ".c", ".h", ".hpp", ".php", ".py"), window: int = 20):
    """Yield (relpath, lineno, line) for a device path built by concatenating a variable
    (`"/dev/" + var` in C++ or Python, `"/dev/".$var` in PHP, `f"/dev/{var}"` in Python)
    with no ttyUSB/ttyACM/ttyAMA allow-list check within `window` lines either side.
    Whole-file presence isn't enough to clear a hit - a plugin can have an unrelated
    hardcoded `"ttyUSB0"` default elsewhere (a string, not a validation) hundreds of
    lines from the actual taint point, or a real allow-list that lives in a completely
    different file/handler than the one doing the concatenation."""
    build_rx = re.compile(r'"/dev/"\s*\+\s*\w+|["\']/dev/["\']\s*\.\s*\$\w+|f["\']/dev/\{\w+')
    # Optional literal '(' between 'tty' and the alternation: the finding's own
    # suggested fix ("^tty(USB|ACM|AMA)\d+$") is a regex PATTERN written as
    # source text, where the '(' is a literal character in that text, not a
    # regex metacharacter - without tolerating it here, that exact suggested
    # fix would still trip this same check forever.
    allowlist_rx = re.compile(r'tty\(?(USB|ACM|AMA)', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        lines = _read(path).splitlines()
        for i, line in enumerate(lines):
            if _is_comment_line(line):
                continue
            if not build_rx.search(line):
                continue
            lo, hi = max(0, i - window), min(len(lines), i + window)
            if not allowlist_rx.search("\n".join(lines[lo:hi])):
                yield rel, i + 1, line.strip()
                break


def _socket_port_hits(root: str, port: int, exts=SCRIPT_EXT, window: int = 3):
    """Yield (relpath, lineno, line) for a raw socket/HTTPConnection construction
    naming `port` literally, tolerating the call being wrapped across a few lines
    (e.g. `HTTPConnection(\\n    '127.0.0.1', 32322)`). Reports the line the call
    actually starts on, even when the port itself is on a later line."""
    opener_rx = re.compile(r'(HTTPConnection|socket\.connect|new\s+Socket|createConnection)\s*\(', re.I)
    port_rx = re.compile(r'\b%d\b' % port)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        lines = _read(path).splitlines()
        for i in range(len(lines)):
            if _is_comment_line(lines[i]) or not opener_rx.search(lines[i]):
                continue
            if port_rx.search(" ".join(lines[i:i + window])):
                yield rel, i + 1, lines[i].strip()
                break


def lint_plugin_dir(root: str, repo_name: str | None = None, info: dict | None = None,
                     schema: dict | None = None) -> list[Finding]:
    """Run all static checks against a plugin working tree; return findings.

    `info` is the plugin's already-parsed pluginInfo.json, if the caller has it (both
    new_major_release_scan.py and scan_submission.py load it anyway) - used for checks
    that need to cross-reference the manifest against the working tree, like the icon
    check.

    `schema` is pluginInfo.schema.json, already parsed, if the caller wants the
    schema check run HERE. Optional and off by default: new_major_release_scan.py
    and scan_submission.py already call lib_plugin_schema.schema_validation_error()
    themselves and report it through their own severity model - passing `schema`
    here too would double-report the same finding for them. It exists so the
    standalone CLI (`main()`, below) isn't blind to schema violations when run by
    itself, since it has no other caller doing that check for it.
    """
    out: list[Finding] = []
    repo = repo_name or os.path.basename(os.path.normpath(root))
    names = os.listdir(root) if os.path.isdir(root) else []
    lower = {n.lower() for n in names}

    def first(pattern, exts=SCRIPT_EXT):
        for hit in _grep(root, pattern, exts):
            return hit
        return None

    # --- dangerous host behaviour -------------------------------------------
    hit = first(r'(curl|wget)\b[^|]*\|[^|]*(sudo\s+)?(bash|sh)\b')
    if hit:
        out.append(Finding(BLOCKER, "remote-exec",
                   f"pipes a remote script into a shell ({hit[0]}:{hit[1]}: `{hit[2]}`) - install "
                   f"the dependency through a package manager FPP already has instead: `apt-get "
                   f"install` for system packages, `npm install` for Node packages, or `pip install "
                   f"--break-system-packages` for Python packages. Only if there's genuinely no package for it, "
                   f"download the installer to a file, verify its checksum, then run it, e.g. "
                   f"`curl -fsSLo installer.sh https://example.com/install.sh && "
                   f"echo \"<sha256>  installer.sh\" | sha256sum -c && bash installer.sh`"))

    # Reboots/shutdowns are an error. A bare reboot/shutdown only counts as a
    # command (start of line / after ;&| / sudo / then|do, in a shell script, or
    # wrapped in system()/exec()) - not the word "Reboot" in UI text.
    hit = (next(iter(_grep(root, r'(^|[;&|]|\bsudo\s+|\bthen\s+|\bdo\s+)\s*(reboot|shutdown|halt)\b',
                           exts=(".sh",))), None)
           or first(r'(system|exec|shell_exec|passthru|popen)\s*\([^)]*\b(reboot|shutdown)\b'))
    if hit:
        out.append(Finding(BLOCKER, "reboot",
                   f"reboots/shuts down the box ({hit[0]}:{hit[1]}: `{hit[2]}`) - replace it with "
                   f"`setSetting rebootFlag 1` (shell) or the equivalent in your language, so FPP "
                   f"reboots on its own schedule instead of pulling the box down mid-show"))

    # Restarting fppd DIRECTLY (RestartFPPD(), systemctl/service/kill, `fpp -r`) is
    # the anti-pattern. The sanctioned way is SetRestartFlag()/`setSetting restartFlag`
    # (deferred, sequenced around a running show) - those are NOT flagged.
    hit = first(r'\bRestartFPPD\s*\(|\bfppd_restart\b|systemctl\s+(restart|stop|start)\s+fppd'
                r'|service\s+fppd\s+(restart|stop)|(pkill|killall)\s+[^\n]*fppd|\bfpp\s+-r\b|\bfpp\s+--restart\b'
                r'|/api/system/fppd/(restart|reboot)|api/system/restart')
    if hit:
        out.append(Finding(BLOCKER, "fppd-restart",
                   f"restarts fppd directly ({hit[0]}:{hit[1]}: `{hit[2]}`) - replace it with "
                   f"the restart flag instead, so FPP restarts safely between sequences instead of "
                   f"killing a running show. Shell: source `${{FPPDIR}}/scripts/common` first (it "
                   f"defines the function), then call `setSetting restartFlag 1`. C++: call "
                   f"`setSetting(\"restartFlag\", \"1\")` (declared in `settings.h`, already pulled "
                   f"in via `fpp-pch.h`) - not `SetRestartFlag()`, which is the browser-JS helper "
                   f"used from PHP pages, not a C++ API"))

    # Hitting fppd's raw port 32322 bypasses the documented, Apache-proxied API.
    # Match real URLs (http://host:32322…) AND non-URL socket construction that
    # names the port literally (HTTPConnection('127.0.0.1', 32322), raw
    # socket.connect, etc - often wrapped across 2-3 lines, hence the window
    # instead of a single-line regex) - not comments like "…proxies to
    # localhost:32322/LoRa" that describe the plugin-apis registration mechanism.
    hit = first(r'https?://(localhost|127\.0\.0\.1|0\.0\.0\.0):32322') \
        or next(iter(_socket_port_hits(root, 32322)), None)
    if hit:
        out.append(Finding(BLOCKER, "fppd-port",
                   f"calls fppd's internal port :32322 directly ({hit[0]}:{hit[1]}: `{hit[2]}`) - "
                   f"replace `http://localhost:32322/...` with the proxied, documented equivalent "
                   f"at `http://localhost/api/...` instead"))

    # `pip install` with no `--break-system-packages` isn't just against
    # convention - on any current PEP 668-managed image (Debian/RPi OS
    # Bookworm+) it fails outright ("externally managed environment"),
    # verified directly against a real PEP-668-enforcing system. The flag is
    # safe to add: it installs into /usr/local/lib/python3.x/dist-packages,
    # which is NOT tracked by dpkg (apt-installed python3-* packages live in
    # /usr/lib/python3/dist-packages instead, a different directory) - so it
    # doesn't touch anything apt manages, despite the scary-sounding name.
    # (This used to recommend switching to `uv pip install --system` instead,
    # believing that avoided needing the flag entirely - it doesn't; `uv
    # pip install --system` hits the identical PEP 668 refusal and needs the
    # same flag, confirmed directly against a real system.)
    #
    # Checks each `pip install` hit individually, not just the first one in
    # the tree (`first()` alone would miss a bare `pip install` anywhere after
    # an earlier, compliant `pip install --break-system-packages` line - a
    # real false-negative gap, not hypothetical, worth closing now that this
    # is a BLOCKER rather than a BEST_PRACTICE).
    hit = next((h for h in _grep(root, r'\bpip3?\s+install\b')
                if "--break-system-packages" not in h[2]), None)
    if hit:
        out.append(Finding(BLOCKER, "pip-install",
                   f"installs Python packages with pip but no --break-system-packages "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - this fails outright on any current PEP "
                   f"668-managed image ('externally managed environment'). Add "
                   f"`--break-system-packages`: it's safe here because pip targets "
                   f"`/usr/local/lib/python3.x/dist-packages`, which isn't tracked by dpkg, so it "
                   f"can't conflict with anything apt manages"))

    # Bootstrapping a second language/version-package-manager (uv, pipx, nvm,
    # rustup, conda/miniconda, asdf, volta, sdkman) is its own anti-pattern,
    # distinct from `remote-exec` above. A `curl | sh` install of one of these
    # already trips remote-exec, but installing the SAME tool through an
    # otherwise-compliant path (`pip install uv`, `apt-get install pipx`) does
    # not - and that's exactly what happened in practice (fpp-live-follow /
    # fpp-servo-calibrator both `pip install --break-system-packages uv`,
    # which passes every other check here). The problem isn't how it's
    # installed, it's that FPP's image already ships apt/pip/npm, and a second
    # manager is an unaudited, unpinned dependency surface fpp_uninstall.sh
    # never accounts for and that can silently change behavior on a future
    # `git pull` of the plugin with no version pin at all. Matched on the
    # tool's own install invocation (not just its installer domain) so this
    # also catches `pip install pipx`-style installs that don't pipe a remote
    # script into a shell. Homebrew is deliberately excluded: FPP also runs on
    # macOS (dev/desktop builds), where brew IS the system package manager,
    # not a bolted-on second one - flagging it there would be exactly backwards.
    hit = first(r'astral\.sh/uv\b|\buv\s+(pip|python|venv|tool)\s+\w|pip3?\s+install\b[^\n]*\buv\b'
                r'|\bpipx\s+(install|run)\b|pip3?\s+install\b[^\n]*\bpipx\b'
                r'|nvm-sh/nvm|\.nvm/nvm\.sh|\bnvm\s+install\b'
                r'|sh\.rustup\.rs|\brustup\s+(install|default|toolchain)\b'
                r'|\b(mini|ana)conda3?\b|\bconda\s+(install|create)\b'
                r'|asdf-vm/asdf|\basdf\s+(install|plugin)\b'
                r'|get\.volta\.sh|\bvolta\s+install\b'
                r'|get\.sdkman\.io|\bsdk\s+install\b')
    if hit:
        out.append(Finding(BEST_PRACTICE, "extra-pkg-manager",
                   f"installs a second package/version manager on top of what FPP's image already "
                   f"provides ({hit[0]}:{hit[1]}: `{hit[2]}`) - apt/pip/npm already cover system and "
                   f"language packages; a bolted-on manager (uv, pipx, nvm ...) is undesirable. "
                   f"If there's a genuine need it can't cover (e.g. a Python/Node version the OS image "
                   f"doesn't ship), say so explicitly via `/submit` instead of adding a manager "
                   f"silently"))

    # Reading/parsing FPP's raw core config directly (the settings file, channel
    # outputs) is fragile - use getSetting()/$settings/the API. Writing your OWN
    # config via WriteSettingToFile(key, val, pluginName) is fine and NOT flagged.
    # The co-*.json family covers more than the 3 originally-listed filenames
    # (co-other, co-bbb48, co-pi, ...) - match the whole family, not just those 3.
    hit = first(r'''(open|file_get_contents|fopen|fgets|cat)\s*\(?\s*['"]?[^'"\n]*media/settings\b'''
                r'''|['"][^'"\n]*/(channeloutputs\.json|co-[A-Za-z0-9_-]+\.json)''')
    if hit:
        # Point at the fix for the language the offending file is actually in,
        # not a generic PHP example that's useless if the hit is a .py/.sh file.
        if hit[0].endswith(".php"):
            lang_fix = ("`getSetting('settingName')` - if this file isn't already running inside "
                        "an FPP page (e.g. it's hit directly, not included by one), add "
                        "`include_once(\"/opt/fpp/www/common.php\")` first to get it and `$settings`")
        elif hit[0].endswith(".py"):
            lang_fix = ("the `/api/settings/<name>` endpoint (e.g. `requests.get(\"http://localhost/"
                        "api/settings/settingName\")`) - there's no Python helper, just the HTTP API")
        else:
            lang_fix = ("the `/api/settings/<name>` endpoint (`curl http://localhost/api/settings/"
                        "settingName`), or source `${FPPDIR}/scripts/common` and call "
                        "`getSetting settingName`")
        out.append(Finding(BLOCKER, "core-config",
                   f"reads/writes FPP core config directly ({hit[0]}:{hit[1]}: `{hit[2]}`) - read "
                   f"it through {lang_fix} instead of parsing the settings file yourself; the "
                   f"file's format is not a stable contract across FPP releases"))

    # Destructive call (unlink/rm/exec-rm) with no HTTP-method or POST-field
    # guard in that SAME file - reachable via a plain GET, no confirmation.
    # BEST_PRACTICE not BLOCKER: at corpus scale this regex can't reliably tell
    # a real unauthenticated "delete this file" endpoint (the evidence this
    # rule was written from) apart from ordinary internal cleanup - a temp file
    # removed after an atomic rename, a stale file removed right after writing
    # its replacement, a PID file removed when stopping a process. Flag for a
    # human to check reachability rather than treat as proven dangerous.
    hit = next(iter(_destructive_no_guard_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "destructive-no-csrf",
                   f"destructive action with no method/CSRF guard ({hit[0]}:{hit[1]}: `{hit[2]}`) - "
                   f"if this runs on a plain page load (not just internal cleanup after writing a "
                   f"replacement file, or stopping a process this same request started), it's "
                   f"reachable via a plain GET request with no confirmation. Require "
                   f"`$_SERVER['REQUEST_METHOD'] === 'POST'` (or check a `$_POST` field) before "
                   f"running it if so"))

    # Backend daemon binds every interface (0.0.0.0) while the plugin's own
    # install script also sets up an Apache ProxyPass - a strong signal the
    # service was designed to be internal-only, so the 0.0.0.0 bind exposes
    # its (often unauthenticated) routes directly on the LAN instead.
    hit = first(r'\.(run|listen|bind)\s*\([^)]*0\.0\.0\.0', exts=(".py", ".js"))
    if hit and first(r'ProxyPass', exts=(".sh", ".conf")):
        out.append(Finding(BLOCKER, "server-bind-all-interfaces",
                   f"daemon binds 0.0.0.0 despite an Apache ProxyPass for the same service "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - the ProxyPass means this was designed to be "
                   f"reached through Apache only. Bind to `127.0.0.1` instead so the routes aren't "
                   f"directly reachable on the LAN, bypassing whatever auth Apache would add"))

    # Request-controlled value concatenated into a device path with no
    # allow-list check IN THAT SAME FILE (an allow-list living in some other
    # file - e.g. a page that scans /dev/ itself - doesn't help an API handler
    # that never calls it). Narrow, language-specific heuristic (the report
    # this was written from calls it "needs real taint tracking" - this only
    # catches the literal `"/dev/" + var` C++ idiom). BEST_PRACTICE not
    # BLOCKER: this can't tell an unauthenticated-JSON-API source (the real
    # evidence, fpp-LoRa) apart from a value that's actually an admin-configured
    # setting read from a CLI script (FPP-Plugin-Projector-Control's proj.php,
    # invoked via getopt - not web-reachable at all despite the same shape).
    hit = next(iter(_device_path_no_allowlist_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "device-path-no-allowlist",
                   f"device path built from a variable with no allow-list check ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - if that variable traces back to request data (not just "
                   f"an admin-configured setting), a value like `../../etc/passwd` makes this open "
                   f"an arbitrary path instead of a serial device. Validate it against an allow-list "
                   f"pattern first, e.g. `^tty(USB|ACM|AMA)\\d+$`"))

    # Secret/API-key value written straight into a log line, either directly
    # or via a URL/message variable it was concatenated into a few lines earlier
    # (e.g. `$url = "...key/".$apiKey; ... logEntry("URL: ".$url);`).
    hit = next(iter(_secret_in_log_hits(root)), None) \
        or next(iter(_assign_then_sink(
            root, r'\$(?:\w*(?:token|secret|password|apikey)\w*|\w+key\w*)\b',
            r'(?:logEntry|logMessage|error_log|console\.(?:log|error)|print(?:_r)?|echo)\s*\([^)]*\$%s\b')), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "secret-in-log",
                   f"secret-shaped value written into a log line ({hit[0]}:{hit[1]}: `{hit[2]}`) - "
                   f"logs are often included in Support Zips and shared for debugging; drop the "
                   f"key/token/password from the message before logging it, e.g. log the URL with "
                   f"the credential redacted"))

    # A build step run synchronously in preStart/postStart delays fppd startup
    # by however long the (re)build takes - tens of seconds to minutes on a
    # cold Pi Zero rebuild - directly violating guideline 2.6 (no blocking work
    # in these hooks). It's also almost always dead weight, not a safety net:
    # fpp_install.sh already builds on fresh install and on plugin-only update
    # (upgrade_plugin falls back to fpp_install.sh when there's no
    # fpp_upgrade.sh), and FPP's own core-upgrade path (compileBinaries() in
    # scripts/functions) rebuilds every plugin with a root Makefile before
    # restarting fppd - so a build in the hook just repeats work already done.
    # Scoped to preStart.sh/postStart.sh specifically, not all 6 hooks - a
    # build in fpp_install.sh (a one-time, not every-boot, step) is normal and
    # NOT flagged.
    hit = None
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn in ("preStart.sh", "postStart.sh"):
                p = os.path.join(dirpath, fn)
                for i, line in enumerate(_read(p).splitlines(), 1):
                    if _is_comment_line(line):
                        continue
                    if re.search(r'\b(make|cmake|g\+\+|gcc|clang)\b', line):
                        hit = (os.path.relpath(p, root), i, line.strip())
                        break
                if hit:
                    break
        if hit:
            break
    if hit:
        out.append(Finding(BLOCKER, "blocking-build-in-hook",
                   f"runs a build step synchronously in {os.path.basename(hit[0])} ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - this delays fppd startup by however long the "
                   f"(re)build takes, every single boot. This is almost always redundant, not a "
                   f"safety net: fpp_install.sh already builds on fresh install and on plugin-only "
                   f"update (the Plugin Manager falls back to fpp_install.sh when there's no "
                   f"fpp_upgrade.sh), and FPP's own core-upgrade path rebuilds every plugin with a "
                   f"root Makefile before restarting fppd - so this hook rarely has anything left to "
                   f"do. Move the build into fpp_install.sh (or fpp_upgrade.sh) if it isn't there "
                   f"already, and delete it from the hook; only keep a cheap existence/fingerprint "
                   f"check here if you have a real reason to distrust the binary at boot (e.g. an SD "
                   f"image clone from a different CPU)"))

    # Hardcoded absolute paths that bypass FPP's own directory conventions:
    # /home/pi/ (should be ${MEDIADIR}/${FPPDIR}, and inconsistent with a
    # plugin's own /home/fpp/ references elsewhere), or a lock/PID file placed
    # in shared /tmp instead of the plugin's own directory.
    hit = first(r'/home/pi/') \
        or first(r'''define\s*\(\s*['"]LOCK_DIR['"]\s*,\s*['"]\/tmp\/?['"]\s*\)''')
    if hit:
        out.append(Finding(BEST_PRACTICE, "hardcoded-absolute-path",
                   f"hardcoded absolute path bypasses FPP's directory conventions ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - use `${{MEDIADIR}}`/`${{FPPDIR}}` (shell) or "
                   f"`$settings['mediaDirectory']`/`$settings['fppDir']` (PHP) instead of a "
                   f"hardcoded `/home/pi/...`, and put a lock/PID file inside the plugin's own "
                   f"directory rather than shared `/tmp`, which any other process can also write to"))

    hit = first(r'chmod\s+(-R\s+)?(777|666|a\+w|o\+w)\b')
    if hit:
        if re.search(r'/dev/', hit[2]):
            advice = ("since install/hooks already run as root, and the `fpp` runtime user is "
                      "already in the `dialout`/`tty`/`gpio` groups that own these device nodes, "
                      "there's no need to open the device to everyone - either drop the chmod "
                      "entirely (group access already covers it) or scope it to the group, e.g. "
                      "`chmod 660`")
        else:
            advice = ("since install/hooks already run as root, scope the permission to just the "
                      "owner or group that needs it (e.g. `chmod 750` for a directory another "
                      "service-user reads, or `chown` that user instead of opening it to everyone)")
        out.append(Finding(BLOCKER, "world-writable",
                   f"loosens permissions to world-writable ({hit[0]}:{hit[1]}: `{hit[2]}`) - {advice}"))

    # sudo is a guideline violation only in the files fppd runs as root (the
    # install/upgrade/uninstall/pre-post hooks, or a Makefile reached
    # transitively via one of them) - everywhere else (cmd.php and other
    # runtime request-handler scripts) runs as the `fpp` user, where sudo can
    # be legitimate. Scope by filename, not extension, so those runtime
    # scripts aren't flagged.
    hit = None
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn in SUDO_SCOPE:
                body = _read(os.path.join(dirpath, fn))
                m = re.search(r'\bsudo\b', body)
                if m:
                    lineno = body[:m.start()].count("\n") + 1
                    hit = (os.path.relpath(os.path.join(dirpath, fn), root), lineno,
                           body.splitlines()[lineno - 1].strip())
                    break
        if hit:
            break
    if hit is None:
        for cand in ("Makefile", "makefile"):
            p = os.path.join(root, cand)
            if os.path.isfile(p):
                body = _read(p)
                m = re.search(r'\bsudo\b', body)
                if m:
                    lineno = body[:m.start()].count("\n") + 1
                    hit = (cand, lineno, body.splitlines()[lineno - 1].strip())
                break
    if hit:
        # `sudo -u <user> <cmd>` is a privilege DROP (root -> unprivileged runtime
        # user, almost always `fpp`), not the redundant escalation the generic
        # advice below assumes - naively stripping "sudo " would leave a bare
        # `-u fpp <cmd>` that isn't runnable at all (seen verbatim in an earlier
        # finding message before this special case existed). Root can switch to
        # another user without a password anyway, so the direct, no-sudoers-
        # policy-needed tool for that is `runuser -u <user> -- <cmd>`.
        m = re.match(r'sudo\s+-u\s+(\S+)\s+(.*)', hit[2])
        if m:
            user, rest = m.group(1), m.group(2)
            out.append(Finding(BEST_PRACTICE, "sudo",
                       f"uses sudo to drop privileges in a script ({hit[0]}:{hit[1]}: `{hit[2]}`) - "
                       f"install/hooks already run as root, which can switch to another user "
                       f"without a password, so there's no need to go through sudo (and its "
                       f"sudoers policy) for this. Use `runuser -u {user} -- {rest}` instead"))
        else:
            out.append(Finding(BEST_PRACTICE, "sudo",
                       f"uses sudo in a script ({hit[0]}:{hit[1]}: `{hit[2]}`) - install/hooks already "
                       f"run as root, so remove the sudo call and run the command directly, e.g. "
                       f"`{hit[2].replace('sudo ', '', 1)}`"))

    # --- untrusted request data reaching a dangerous sink --------------------

    # Direct case: $_GET/$_POST/$_REQUEST inside the same exec-family call.
    hit = first(r'(exec|system|passthru|shell_exec|popen)\s*\([^)]*\$_(GET|POST|REQUEST)\b')
    if hit is None:
        # Indirect case: a variable assigned from $_GET/$_POST/$_REQUEST on one
        # line, then that same variable passed into an exec-family call within
        # the next few lines - catches the common "$cmd = ...$_POST...; ...
        # exec($cmd);" two-step shape without needing real taint tracking.
        hit = next(iter(_assign_then_sink(
            root, r'\$_(?:GET|POST|REQUEST)\b',
            r'(exec|system|passthru|shell_exec|popen)\s*\(\s*\$%s\b')), None)
    if hit:
        out.append(Finding(BLOCKER, "exec-injection",
                   f"unsanitized request data reaches a shell command ({hit[0]}:{hit[1]}: `{hit[2]}`) "
                   f"- an attacker can run arbitrary shell commands as the FPP user. Validate the "
                   f"value against an allow-list before using it, and wrap it in `escapeshellarg()` "
                   f"(PHP) / `shlex.quote()` (Python) before it reaches exec/system/shell_exec"))

    # SQL built via string concatenation, passed to ->query()/->exec() with no
    # prepare/bind and no escapeString() anywhere in the file.
    hit = next(iter(_sql_concat_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "sql-injection",
                   f"SQL query built by string concatenation ({hit[0]}:{hit[1]}: `{hit[2]}`) - if any "
                   f"part of that string traces back to user input, this is SQL injection. Use a "
                   f"prepared statement instead: `$stmt = $db->prepare('... WHERE x = :x'); "
                   f"$stmt->bindValue(':x', $value); $stmt->execute();`"))

    # SSRF: request data used to build the URL/host of an outbound request.
    # curl calls are unambiguously network; file_get_contents also reads local
    # files, so it only counts here if the same line has an http(s) scheme too
    # (otherwise it's a path-traversal/LFI shape, not SSRF).
    hit = first(r'CURLOPT_URL\s*,[^;\n]*\$_(GET|POST|REQUEST)\b') \
        or first(r'curl_init\s*\([^;\n]*\$_(GET|POST|REQUEST)\b') \
        or first(r'file_get_contents\s*\([^;\n]*https?://[^;\n]*\$_(GET|POST|REQUEST)\b') \
        or first(r'file_get_contents\s*\([^;\n]*\$_(GET|POST|REQUEST)[^;\n]*https?://')
    if hit:
        out.append(Finding(BLOCKER, "ssrf",
                   f"outbound request URL/host built from request data ({hit[0]}:{hit[1]}: "
                   f"`{hit[2]}`) - an attacker can make your plugin fetch an internal-only address "
                   f"(localhost, another device on the LAN, a cloud metadata endpoint) and read the "
                   f"response back. Validate the host against an allow-list before using it in a URL"))

    # Inbound webhook trusts a request field as an authorization credential,
    # with no signature/HMAC/token verification anywhere in the file.
    hit = next(iter(_webhook_no_auth_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "webhook-no-auth",
                   f"webhook handler trusts a request field with no signature check ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - anyone who can reach this URL can send a forged request "
                   f"and have it treated as if it came from the real provider. Verify the provider's "
                   f"signature header (e.g. `hash_hmac()` compared against `X-<Provider>-Signature`) "
                   f"before trusting any field in the body"))

    # TLS certificate verification explicitly disabled - always a deliberate
    # opt-out, so this is low false-positive (contrast: `break-system-packages`).
    hit = first(r'CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)\b') \
        or first(r'CURLOPT_SSL_VERIFYHOST\s*,\s*(0|false)\b') \
        or first(r'verify\s*=\s*False\b') \
        or first(r'curl\s+[^\n]*(-k\b|--insecure\b)', exts=(".sh",)) \
        or first(r'''NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0''')
    if hit:
        out.append(Finding(BLOCKER, "tls-verify-disabled",
                   f"TLS certificate verification is disabled ({hit[0]}:{hit[1]}: `{hit[2]}`) - this "
                   f"accepts a connection to anyone who can intercept the traffic (a malicious AP, a "
                   f"compromised router), not just the intended server. Remove the override and fix "
                   f"the underlying cert issue instead (e.g. bundle/trust the CA properly)"))

    # Settings value concatenated into an HTML attribute with no escaping -
    # stored/reflected XSS if that setting is ever attacker-influenced.
    hit = next(iter(_unescaped_html_attr_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "unescaped-output",
                   f"value written into an HTML attribute with no escaping ({hit[0]}:{hit[1]}: "
                   f"`{hit[2]}`) - wrap it in `htmlspecialchars($value, ENT_QUOTES)` before echoing "
                   f"it into HTML, so a value containing `\"><script>` can't break out of the "
                   f"attribute and run as script in an admin's browser"))

    # --- shell script hygiene ------------------------------------------------
    for path in _iter_files(root, (".sh",)):
        rel = os.path.relpath(path, root)
        head = _read(path).splitlines()
        if not head or not head[0].startswith("#!"):
            out.append(Finding(BEST_PRACTICE, "no-shebang",
                       f"{rel} has no shebang line - add `#!/bin/bash` (or `#!/bin/sh`) as its "
                       f"first line so it runs with a known shell regardless of how it's invoked"))
        try:
            with open(path, "rb") as f:
                raw_lines = f.read().split(b"\n")
        except OSError:
            raw_lines = []
        lines_with_cr = [i for i, line in enumerate(raw_lines, 1) if line.endswith(b"\r")]
        if lines_with_cr:
            out.append(Finding(BEST_PRACTICE, "crlf",
                       f"{rel}:{lines_with_cr[0]} has CRLF line endings - breaks bash (the `\\r` "
                       f"becomes part of the command). Fix with `sed -i 's/\\r$//' {rel}` or "
                       f"`dos2unix {rel}`, and configure your editor/git to use LF"))

    # hook exec bits. All six hooks are gated behind a plain `test -x` in FPP's
    # own invoker, not `bash script.sh`: preStart/postStart/preStop/postStop via
    # runPreStartScripts etc. (scripts/functions), fpp_install.sh via
    # runPluginInstallScript's `[ -x ... ]` (scripts/install_plugin), and
    # fpp_uninstall.sh the same way (scripts/uninstall_plugin). A non-+x hook of
    # any of the six is silently skipped entirely - for fpp_uninstall.sh that
    # means uninstall "succeeds" while every side effect (systemd units, cron
    # entries, files written outside the plugin dir, running daemons) is left
    # behind on the host with no error. All six get the same severity.
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn in HOOKS:
                p = os.path.join(dirpath, fn)
                if not os.access(p, os.X_OK):
                    out.append(Finding(BLOCKER, "exec-bit",
                               f"{os.path.relpath(p, root)} is not executable - commit it +x "
                               f"(git update-index --chmod=+x)"))

    # install error handling
    for cand in ("scripts/fpp_install.sh", "fpp_install.sh"):
        p = os.path.join(root, cand)
        if os.path.isfile(p):
            body = _read(p)
            if not re.search(r'set\s+-e|set\s+-euo|\|\|\s*exit', body):
                out.append(Finding(BEST_PRACTICE, "no-set-e",
                           f"{cand} has no 'set -e' (or `|| exit`) - without it, bash keeps running "
                           f"the rest of the script even after a command fails, so if an earlier "
                           f"step errors out (e.g. a dependency install fails), later steps still "
                           f"run against that broken state and the plugin ends up half-installed "
                           f"with no visible error. Add `set -e` (or `set -euo pipefail`) as the "
                           f"first line after the shebang so the script stops immediately on the "
                           f"first failure instead"))
            break

    # --- logging conventions -------------------------------------------------
    log_hit = first(r'''(['"][^'"]*\.log['"])|>>?\s*\S*\.log''')
    if log_hit:
        # crude: flag logs written to plugin dir (script_dir) or /tmp
        bad_hit = first(r'script_dir\s*\+\s*[^\n]*\.log') or first(r'/tmp/\S*\.log')
        if bad_hit:
            ext = os.path.splitext(bad_hit[0])[1].lower()
            if ext == ".php":
                howto = (f'`$settings[\'logDirectory\']."/{repo}.log"` (requires '
                          f'`include_once("/opt/fpp/www/common.php")` first - that\'s what '
                          f'populates the global `$settings` array)')
            elif ext == ".sh":
                howto = (f'`$(getSetting logDirectory)/{repo}.log` (requires '
                          f'`. /opt/fpp/scripts/common` first - that\'s where `getSetting` is '
                          f'defined)')
            else:
                howto = "FPP's log directory setting (`logDirectory`)"
            out.append(Finding(BEST_PRACTICE, "log-location",
                       f"writes a log outside FPP's logs directory ({bad_hit[0]}:{bad_hit[1]}: "
                       f"`{bad_hit[2]}`) - log to {howto} instead, which resolves to "
                       f"/home/fpp/media/logs/{repo}.log today, so it's rotated and included in "
                       f"the Support Zip"))

    # Log filename doesn't start with the mandated "plugin-" prefix - it still
    # lands in the right directory, just under a name FPP's log viewer/Support
    # Zip convention doesn't expect, and it isn't namespaced against collisions.
    hit = next(iter(_log_naming_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "log-naming",
                   f"log filename doesn't follow the plugin-<repoName>.log convention ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - name it `plugin-{repo}.log` (not just `{repo}.log`), "
                   f"so it's recognized as this plugin's log by FPP's log viewer and namespaced "
                   f"against collisions with other plugins/tools"))

    # An always-on daemon (installs a systemd unit) with no FPP-conformant log
    # reference anywhere - nothing surfaces in the log viewer or Support Zip.
    elif first(r'/etc/systemd/system/|systemctl\s+enable') \
            and not first(r'LOGDIR|logDirectory|plugin-[\w.-]*\.log'):
        out.append(Finding(BEST_PRACTICE, "log-naming",
                   "installs an always-on service but has no FPP-conformant log anywhere "
                   f"(no LOGDIR/logDirectory/plugin-{repo}.log reference) - log to "
                   f'`$settings[\'logDirectory\']."/plugin-{repo}.log"` (PHP) or the equivalent in '
                   f"your language, so the service's output surfaces in FPP's log viewer and "
                   f"Support Zip instead of only wherever stdout happens to go"))

    # Missing timeout on an outbound HTTP call - the highest-frequency finding
    # in the deep-dive this rule set came from (found in every batch). A curl
    # handle or stream context with NO timeout setting anywhere in the file is
    # a much stronger signal than checking any single call in isolation, since
    # a file legitimately mixing timed and untimed calls is rare in practice.
    hit = next(iter(_missing_timeout_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "no-timeout",
                   f"outbound HTTP call has no timeout set ({hit[0]}:{hit[1]}: `{hit[2]}`) - a "
                   f"hung remote server stalls this indefinitely, blocking whatever hook/show "
                   f"command triggered it. Set `CURLOPT_TIMEOUT`/`CURLOPT_CONNECTTIMEOUT` (PHP "
                   f"curl), the `'timeout'` key (PHP stream contexts), or `timeout=` (Python "
                   f"`requests`)"))

    # repoName must match the actual GitHub repo name (PLUGININFO_FORMAT.md's repoName
    # row, in fpp-plugin-Template, states this). validate_pluginlist.py already checks
    # the pluginList.json half of that (repoName vs. the registered listing name); this
    # is the other half, which nothing previously checked. It's easy
    # to miss because nothing breaks visibly - FPP installs into
    # ${PLUGINDIR}/${repoName} regardless of what the repo is actually called (see
    # InstallPluginFromInfo() in www/api/controllers/plugin.php), so a mismatch only
    # shows up as confusion later (support, docs, anyone cross-referencing the repo).
    if info is not None and parse_github_repo is not None:
        declared = (info.get("repoName") or "").strip()
        src = parse_github_repo(info.get("srcURL", "") or "")
        if declared and src and declared.lower() != src[1].lower():
            out.append(Finding(BEST_PRACTICE, "reponame-mismatch",
                       f"pluginInfo.json's repoName (`{declared}`) doesn't match the actual GitHub "
                       f"repo name (`{src[1]}`, parsed from srcURL) - PLUGININFO_FORMAT.md requires them "
                       f"to match. Rename the GitHub repo to `{declared}` (Settings > repository name) "
                       f"or change repoName to `{src[1]}`, whichever is the real name here - just make "
                       f"sure pluginList.json's listing name is updated to match too."))

    # --- repo hygiene --------------------------------------------------------
    if not any(n.startswith(("license", "copying")) for n in lower):
        out.append(Finding(OPTIONAL, "no-license", "no LICENSE file - add one for redistribution clarity"))
    if not any(n.startswith("readme") for n in lower):
        out.append(Finding(OPTIONAL, "no-readme", "no README file"))

    # Leftover copies of fpp-plugin-Template's own meta-docs. PLUGIN_GUIDELINES.md and
    # PLUGININFO_FORMAT.md document how to build ANY FPP plugin - they aren't specific
    # to this one, and were never meant to ship inside a real plugin repo. Forgetting to
    # delete them after forking the template is an easy miss, and leaves every installer
    # looking at generic template docs instead of anything about this actual plugin.
    leftover_template_docs = sorted(n for n in names if n.lower() in ("plugin_guidelines.md", "plugininfo_format.md"))
    if leftover_template_docs:
        out.append(Finding(BEST_PRACTICE, "leftover-template-docs",
                   f"{', '.join(leftover_template_docs)} - these are fpp-plugin-Template's own docs on "
                   "how to build a plugin in general, not part of your plugin. Delete them from your "
                   "repo; they should only exist in fpp-plugin-Template itself."))

    # Icon: FPP prefers a local icon.png (renders offline once installed) and falls back
    # to iconURL (also the ONLY option for a pre-install Plugin Manager thumbnail, since
    # there's no local checkout yet at that point). Neither present => initials fallback
    # everywhere. See www/api/controllers/plugin.php's PluginServeIcon().
    has_icon_url = bool((info or {}).get("iconURL"))
    has_icon_png = "icon.png" in lower
    if not has_icon_png and not has_icon_url:
        out.append(Finding(BEST_PRACTICE, "no-icon",
                   "no icon.png in the repo root and no iconURL in pluginInfo.json - the Plugin "
                   "Manager will show your initials instead of an icon. A local icon.png (128x128 "
                   "or 256x256, repo root) is preferred since it renders offline once installed; "
                   "iconURL is the fallback and the only option shown before install"))
    elif has_icon_png and not has_icon_url:
        out.append(Finding(BEST_PRACTICE, "no-iconurl",
                   "icon.png exists but pluginInfo.json has no iconURL - the local icon only "
                   "renders after install, so the pre-install Plugin Manager listing (which has "
                   "no local checkout yet) still shows your initials. Add iconURL pointing at the "
                   "repo's own raw file, e.g. "
                   "`https://raw.githubusercontent.com/<owner>/<repo>/<branch>/icon.png`"))
    elif has_icon_url and not has_icon_png:
        out.append(Finding(BEST_PRACTICE, "no-local-icon",
                   "iconURL is set but there's no icon.png in the repo root - post-install, the "
                   "Plugin Manager has to fetch the icon over the network every time instead of "
                   "reading it off disk, so it goes back to showing initials if the box is offline "
                   "or the URL/repo ever moves. Add a local icon.png (128x128 or 256x256, repo "
                   "root) so it renders offline once installed; keep iconURL as the pre-install "
                   "fallback"))

    # installs a systemd unit but ships no uninstall script
    if first(r'/etc/systemd/system/|systemctl\s+enable') and \
       not (os.path.isfile(os.path.join(root, "scripts/fpp_uninstall.sh")) or
            os.path.isfile(os.path.join(root, "fpp_uninstall.sh"))):
        out.append(Finding(BLOCKER, "no-uninstall",
                   "creates a systemd service but ships no fpp_uninstall.sh to remove it - add "
                   "one that mirrors the install, e.g. `systemctl disable --now <unit> && rm -f "
                   "/etc/systemd/system/<unit>`, so removing the plugin doesn't leave an orphaned "
                   "service behind"))

    # Generalizes the systemd check above to cron: registers a cron entry
    # (directly, or via python-crontab/similar) but fpp_uninstall.sh never
    # removes it - same "orphaned persistent resource survives uninstall"
    # class of bug, just a different persistence mechanism than systemd.
    cron_hit = first(r'CronTab\s*\(|crontab\s+-l|/etc/cron\.d/|cron\.new\(')
    if cron_hit:
        uninstall_p = next((p for p in (os.path.join(root, "scripts/fpp_uninstall.sh"),
                                         os.path.join(root, "fpp_uninstall.sh")) if os.path.isfile(p)), None)
        uninstall_body = _read(uninstall_p) if uninstall_p else ""
        # Recognize the idiomatic (and correct) removal pattern too: `crontab -l
        # | grep -v <marker> | crontab -` replaces the crontab with everything
        # EXCEPT the matched entry - this is more common, and safer, than a
        # blanket `crontab -r` (which wipes the user's entire crontab).
        has_cleanup = re.search(r'remove_all|crontab\s+-r|cron\.d/.*rm\b', uninstall_body) \
            or re.search(r'crontab\s+-l.*\|.*grep\s+-v.*\|.*crontab\s+-', uninstall_body)
        if not has_cleanup:
            out.append(Finding(BLOCKER, "cron-no-uninstall",
                       f"registers a cron entry but fpp_uninstall.sh never removes it ({cron_hit[0]}:"
                       f"{cron_hit[1]}: `{cron_hit[2]}`) - add cleanup to fpp_uninstall.sh (e.g. "
                       f"`crontab -l | grep -v <marker> | crontab -`, or the removal call for "
                       f"whatever cron library you used to install it), so uninstalling the plugin "
                       f"doesn't leave a cron entry pointing at a script that no longer exists"))

    # External CDN <script>/<link> instead of the Bootstrap/jQuery FPP's own
    # web shell already loads - duplicates what's already available, and is an
    # offline-availability risk on an isolated show network with no internet.
    hit = first(r'https?://(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|ajax\.googleapis\.com)',
                exts=(".php", ".html", ".inc"))
    if hit:
        out.append(Finding(BEST_PRACTICE, "external-cdn",
                   f"loads a script/stylesheet from an external CDN ({hit[0]}:{hit[1]}: `{hit[2]}`) "
                   f"- FPP's web shell already bundles Bootstrap/jQuery, and a show network is often "
                   f"offline/isolated, so a CDN dependency can silently fail to load. Use FPP's "
                   f"already-loaded copy instead of pulling your own from a CDN"))

    # Killing a process by grepping `ps aux`/`ps -ef` output instead of using a
    # PID file - matches ANY process whose command line happens to contain the
    # search string, with no guard against zero or multiple matches.
    hit = first(r'kill\s*(-9)?\s*`ps\s+(aux|-ef)') or first(r'kill\s*(-9)?\s*\$\(ps\s+(aux|-ef)')
    if hit:
        out.append(Finding(BEST_PRACTICE, "kill-by-ps-grep",
                   f"kills a process by grepping ps output ({hit[0]}:{hit[1]}: `{hit[2]}`) - this "
                   f"matches any process whose command line merely CONTAINS the search string (a "
                   f"totally unrelated process could match), and does nothing if zero or several "
                   f"match. Write a PID file when starting the process and kill that specific PID "
                   f"instead (checking it's still running your process before killing it)"))

    # Blocking sleep in a start/stop lifecycle hook delays fppd startup/shutdown
    # by that long, every time - guideline 2.6 again, same class as
    # blocking-build-in-hook. fpp_install.sh/fpp_uninstall.sh are excluded: they
    # run once at install/uninstall time, not on every fppd start/stop.
    hit = None
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn.startswith(("preStart", "postStart", "preStop", "postStop")):
                p = os.path.join(dirpath, fn)
                for i, line in enumerate(_read(p).splitlines(), 1):
                    if _is_comment_line(line):
                        continue
                    if re.search(r'\bsleep\s+[0-9.]+', line):
                        hit = (os.path.relpath(p, root), i, line.strip())
                        break
                if hit:
                    break
        if hit:
            break
    if hit:
        out.append(Finding(BEST_PRACTICE, "blocking-sleep-in-hook",
                   f"unconditional sleep in a lifecycle hook ({hit[0]}:{hit[1]}: `{hit[2]}`) - this "
                   f"blocks fppd startup/shutdown for that long on every run. If you're waiting on a "
                   f"background process, poll for the actual condition (e.g. the PID file existing, "
                   f"or the port accepting connections) with a short bounded retry loop instead of a "
                   f"flat sleep"))

    # Re-running the plugin's OWN fpp_install.sh/fpp_upgrade.sh from inside a
    # start/stop hook is the same class as blocking-build-in-hook, just worse:
    # instead of one compile step it re-runs the WHOLE install (apt/pip/uv
    # installs, systemd unit + Apache conf writes, network downloads) every
    # boot the guard condition trips - seen in practice in a preStart.sh that
    # self-heals a systemd unit wiped by an OS upgrade. If a genuine self-heal
    # is needed, run it detached (e.g. `systemd-run` or `nohup ... &`) so fppd
    # starts immediately instead of waiting on it, or use FPP's actual
    # post-os-upgrade mechanism instead of reinventing one in a start hook.
    hit = None
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn.startswith(("preStart", "postStart", "preStop", "postStop")):
                p = os.path.join(dirpath, fn)
                for i, line in enumerate(_read(p).splitlines(), 1):
                    if _is_comment_line(line):
                        continue
                    if re.search(r'\b(bash|sh|\.\/)?\s*["\']?[\w/${}.-]*fpp_(install|upgrade)\.sh\b', line):
                        hit = (os.path.relpath(p, root), i, line.strip())
                        break
                if hit:
                    break
        if hit:
            break
    if hit:
        out.append(Finding(BLOCKER, "install-in-hook",
                   f"runs the plugin's own install/upgrade script from a lifecycle hook ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - this re-executes the entire install (package installs, "
                   f"service/proxy setup, network downloads) synchronously every time the hook's "
                   f"guard condition trips, blocking fppd startup for however long that takes. Run "
                   f"any genuine self-heal step detached from the hook (e.g. `systemd-run` or "
                   f"`nohup ... &`) instead of inline, or use FPP's actual post-os-upgrade mechanism "
                   f"rather than reinventing one in preStart/postStart"))

    # A bare `git pull`/`fetch`/`clone` in a start/stop hook is an unbounded
    # network call with no timeout (git has no default one) blocking fppd
    # startup/shutdown if the network stalls - the git-specific counterpart to
    # no-timeout above, which only looks at curl/requests. Seen paired with
    # install-in-hook in practice (self-heal logic pulls latest code before
    # reinstalling), but flagged independently since either half is a problem
    # on its own.
    hit = None
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn.startswith(("preStart", "postStart", "preStop", "postStop")):
                p = os.path.join(dirpath, fn)
                for i, line in enumerate(_read(p).splitlines(), 1):
                    if _is_comment_line(line):
                        continue
                    if re.search(r'\bgit\s+(-C\s+\S+\s+)?(pull|fetch|clone)\b', line) \
                       and not re.search(r'\btimeout\s+[0-9]', line):
                        hit = (os.path.relpath(p, root), i, line.strip())
                        break
                if hit:
                    break
        if hit:
            break
    if hit:
        out.append(Finding(BLOCKER, "git-network-call-in-hook",
                   f"unbounded git network call in a lifecycle hook ({hit[0]}:{hit[1]}: `{hit[2]}`) "
                   f"- git has no built-in timeout, so a stalled connection here blocks fppd "
                   f"startup/shutdown indefinitely. Wrap it with `timeout <seconds> git ...` or move "
                   f"it out of the hook entirely"))

    # error_reporting(0) silences fatal/parse errors instead of letting them
    # surface in FPP's log - a broken plugin fails silently instead of visibly.
    hit = first(r'error_reporting\s*\(\s*0\s*\)')
    if hit:
        out.append(Finding(BEST_PRACTICE, "error-reporting-suppressed",
                   f"error_reporting(0) silences PHP errors ({hit[0]}:{hit[1]}: `{hit[2]}`) - a "
                   f"fatal error in this script now fails silently (blank output, nothing in the "
                   f"log) instead of surfacing where it can be debugged. Remove it, or narrow it to "
                   f"a specific error_reporting level you actually intend to suppress"))

    # Synchronous busy-wait poll loop (a sleep() inside a while/do loop) in a
    # PHP file - if that file is directly reachable as a page (not just a CLI
    # script), it ties up an Apache/PHP-FPM worker for the whole poll duration.
    # OPTIONAL: genuinely needs real parsing to tell a page from a CLI-only
    # script reliably; this is a coarse presence check, not a proven defect.
    hit = None
    for path in _iter_files(root, (".php",)):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        lines = _read(path).splitlines()
        for i, line in enumerate(lines):
            if _is_comment_line(line) or not re.search(r'\b(while|do)\s*[({]', line):
                continue
            window = "\n".join(lines[i:i + 10])
            if re.search(r'\bsleep\s*\(', window):
                hit = (rel, i + 1, line.strip())
                break
        if hit:
            break
    if hit:
        out.append(Finding(OPTIONAL, "busy-wait-poll",
                   f"busy-wait poll loop with sleep() ({hit[0]}:{hit[1]}: `{hit[2]}`) - if this file "
                   f"is reachable directly as a page (not just invoked from a hook/cron), the loop "
                   f"ties up a web server worker for its entire duration. Worth a human look to "
                   f"confirm reachability; if so, move the polling into a background process instead"))

    # Missing minMemoryMB/minCpuCores resource hints on a plugin that looks
    # compute-heavy. OPTIONAL and intentionally coarse: PLUGIN_GUIDELINES.md
    # §7 only ASKS heavy plugins to declare these, it doesn't require it, and
    # "looks compute-heavy" is a two-sided guess (native code + no hints), not
    # a proven defect - a documentation-adherence nudge, not a bug report.
    # minMemoryMB/minCpuCores are top-level pluginInfo.json fields (describe the
    # plugin as a whole, no per-version override) - NOT nested in versions[].
    has_hint = bool((info or {}).get("minMemoryMB") or (info or {}).get("minCpuCores"))
    looks_heavy = (not has_hint) and (
        any(n.lower() in ("makefile", "cmakelists.txt") for n in lower)
        or first(r'\b(ffmpeg|opencv|libcamera|videocapture)\b', exts=(".cpp", ".c", ".h", ".hpp", ".py")))
    if looks_heavy:
        out.append(Finding(OPTIONAL, "no-resource-hints",
                   "looks potentially compute/memory heavy (native build / video-capture-shaped code) but declares no "
                   "minMemoryMB/minCpuCores in pluginInfo.json - if this plugin genuinely needs more "
                   "than a Pi Zero's resources to run acceptably, declare it as a top-level field in "
                   "pluginInfo.json (see PLUGININFO_FORMAT.md's Resource hints section) so FPP can warn/hide it on "
                   "underpowered devices instead of the user finding out the hard way"))

    # Still implementing the deprecated registerApis(httpserver::webserver*)
    # overload instead of the modern no-arg registerApis(). FPP's HTTP layer
    # migrated from libhttpserver to Drogon; the httpserver:: shims keep this
    # compiling and working, so it's not a bug, just a docs/DEPRECATED.md nudge.
    hit = first(r'(register|unregister)Apis\s*\(\s*httpserver::webserver',
               exts=(".cpp", ".c", ".h", ".hpp"))
    if hit:
        out.append(Finding(BEST_PRACTICE, "deprecated-httpserver-api",
                   f"implements the deprecated registerApis(httpserver::webserver*) overload "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) instead of the modern no-arg registerApis() - "
                   f"this still works via FPP's httpserver:: compat shims over Drogon, but those "
                   f"shims are on borrowed time (see docs/DEPRECATED.md in the FPP repo). Port to "
                   f"the no-arg registerApis()/unregisterApis() using drogon::app() or the fpphttp.h "
                   f"helpers (makeStringResponse(), getRequestArg(), etc.) directly"))

    # pluginInfo.json schema validation. Off by default (see the `schema` param
    # docstring above) - only runs when the caller explicitly passes a parsed
    # schema, which today is just main()'s standalone CLI path.
    if schema is not None and schema_validation_error is not None and info is not None:
        schema_err = schema_validation_error(info, schema)
        if schema_err:
            out.append(Finding(BLOCKER, "schema-invalid", schema_err))

    return out


def main(argv):
    if len(argv) < 2:
        print("usage: lint_plugin.py <plugin_dir> [repoName]", file=sys.stderr)
        return 2
    # Load pluginInfo.json ourselves so checks that key off it (no-icon,
    # no-resource-hints) see real data under direct CLI use too, matching
    # new_major_release_scan.py/scan_submission.py, which already load and
    # pass it.
    info = None
    info_path = os.path.join(argv[1], "pluginInfo.json")
    if os.path.isfile(info_path):
        try:
            with open(info_path, encoding="utf-8") as f:
                info = json.load(f)
        except (OSError, json.JSONDecodeError):
            info = None
    # Vendored alongside this script (.github/schema/pluginInfo.schema.json) -
    # standalone CLI use has no other caller doing the schema check for it, so
    # do it here (see lint_plugin_dir()'s `schema` param docstring).
    schema = None
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema", "pluginInfo.schema.json")
    if os.path.isfile(schema_path):
        try:
            with open(schema_path, encoding="utf-8") as f:
                schema = json.load(f)
        except (OSError, json.JSONDecodeError):
            schema = None
    findings = lint_plugin_dir(argv[1], argv[2] if len(argv) > 2 else None, info, schema)
    for f in findings:
        print(f"{f.severity.upper():5} [{f.code}] {f.message}")
    print(f"\n{len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
