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
import textwrap
from dataclasses import dataclass

# schema_validation_error needs the third-party jsonschema package (a hard
# dependency of this repo's other scan scripts, but lint_plugin.py itself was
# previously stdlib-only and is used more widely/standalone) - degrade to
# skipping just the schema check rather than making the whole linter unusable
# wherever jsonschema isn't installed.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from lib_plugin_schema import schema_validation_error, parse_github_repo, _major
except ImportError:
    schema_validation_error = None
    parse_github_repo = None

    def _major(v):
        head = str(v).split(".")[0]
        return int(head) if head.isdigit() else None

BLOCKER, BEST_PRACTICE, OPTIONAL = "blocker", "best-practice", "optional"

HOOKS = ("fpp_install.sh", "fpp_uninstall.sh", "preStart.sh", "postStart.sh",
         "preStop.sh", "postStop.sh")
SCRIPT_EXT = (".sh", ".py", ".php", ".js")

# Files fppd actually executes as root (fppd.service has no User=, so it and
# everything it shells out to - runPreStartScripts/install_plugin/
# upgrade_plugin/uninstall_plugin - runs as root). Everything else (cmd.php and
# other runtime request-handler scripts) runs as the `fpp` user, where sudo can
# be legitimate.
SUDO_SCOPE = HOOKS + ("fpp_upgrade.sh",)

# The one-liner every restart-flag finding recommends. Deliberately NOT the bare
# `source ${FPPDIR}/scripts/common; setSetting restartFlag 1` older advice
# suggested: under `set -u` that form aborts the whole script instead of setting
# the flag - FPPDIR is unset on the uninstall path (uninstall_plugin passes it
# only as a trailing arg and sudo strips the exported one) and scripts/common
# itself expands a bare $LD_LIBRARY_PATH, so even with FPPDIR set the sourced
# file trips nounset. fpp-live-follow followed the old advice verbatim and its
# install AND uninstall silently exited on that line (fpp-data #231).
RESTART_FLAG_SNIPPET = '( set +u; source "${FPPDIR:-/opt/fpp}/scripts/common" && setSetting restartFlag 1 ) || true'


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

# Matches creating or activating a Python virtualenv, under any directory
# name (venv, .venv, env, ...) and via either stdlib venv or uv's venv
# subcommand - used to exempt pip installs that are scoped to a plugin's own
# venv (not the system interpreter) from the PEP 668 --break-system-packages
# check below, which only applies to the externally-managed system pip.
_VENV_MARKER_RX = re.compile(
    r'\bpython3?\s+-m\s+venv\b|\bvirtualenv\b|\buv\s+venv\b|/bin/activate\b|\bVIRTUAL_ENV\b',
    re.I)


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
    `window` lines after the assignment. Cheap stand-in for real taint tracking. Skips
    commented-out lines on BOTH sides (assignment and sink) - confirmed real false
    positive without this: a fully commented-out `// exec($x);//$x = ReadSettingFromFile(...)`
    line matched before this check existed, since disabled/dead code containing a
    setting-read call turns out to be common (FPP-Plugin-BetaBrite)."""
    assign_rx = re.compile(r'\$(\w+)\s*=.*' + taint_pattern, re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        lines = _read(path).splitlines()
        for i, line in enumerate(lines):
            if _is_comment_line(line):
                continue
            m = assign_rx.search(line)
            if not m:
                continue
            var = re.escape(m.group(1))
            sink_rx = re.compile(sink_pattern_tpl % var, re.I)
            for j in range(i, min(i + window, len(lines))):
                if _is_comment_line(lines[j]):
                    continue
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


_JS_REQUEST_SRC_RX = r'req\.(?:query|body|params|headers|cookies)\b'


def _js_exec_injection_hits(root: str, exts=(".js",), window: int = 3):
    """Yield (relpath, lineno, line) for a Node child_process exec-family call
    (exec/execSync - NOT execFile/spawn, which take argv arrays and don't go through a
    shell unless {shell: true} is passed) whose command string is built from Express
    request data (req.query/req.body/req.params/req.headers/req.cookies), either inline
    or via a template literal/concatenation on a nearby line. JS analogue of the PHP
    exec-injection check above, which only matches $_GET/$_POST/$_REQUEST."""
    call_rx = re.compile(r'\b(?:child_process\.)?(exec|execSync)\s*\(')
    src_rx = re.compile(_JS_REQUEST_SRC_RX)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        lines = _read(path).splitlines()
        for i in range(len(lines)):
            if _is_comment_line(lines[i]) or not call_rx.search(lines[i]):
                continue
            hi = min(len(lines), i + window)
            if src_rx.search("\n".join(lines[i:hi])):
                yield rel, i + 1, lines[i].strip()


def _js_ssrf_hits(root: str, exts=(".js",), window: int = 2):
    """Yield (relpath, lineno, line) for a Node outbound HTTP call (fetch/axios/http(s).get)
    whose URL is built from Express request data within a couple of lines - JS analogue of
    the PHP SSRF check above."""
    call_rx = re.compile(r'\b(?:fetch|axios(?:\.\w+)?|https?\.get|https?\.request)\s*\(')
    src_rx = re.compile(_JS_REQUEST_SRC_RX)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        lines = _read(path).splitlines()
        for i in range(len(lines)):
            if _is_comment_line(lines[i]) or not call_rx.search(lines[i]):
                continue
            hi = min(len(lines), i + window)
            if src_rx.search("\n".join(lines[i:hi])):
                yield rel, i + 1, lines[i].strip()


def _js_sql_concat_hits(root: str, exts=(".js",)):
    """Yield (relpath, lineno, line) for a `db.prepare()`/`db.exec()` call (better-sqlite3's
    idiom, but the shape generalizes) whose SQL is a template literal containing `${...}`
    interpolation, or built with `+` string concatenation, instead of a `?`/named
    placeholder. JS/better-sqlite3 analogue of the PHP ->query() check above - a per-line
    heuristic, not real taint tracking, so it flags for triage rather than proving the
    interpolated value traces back to user input."""
    template_rx = re.compile(r'\.(?:prepare|exec)\s*\(\s*`[^`]*\$\{')
    concat_rx = re.compile(r'''\.(?:prepare|exec)\s*\(\s*['"][^'"]*['"]\s*\+''')
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if template_rx.search(line) or concat_rx.search(line):
                yield rel, i, line.strip()


def _js_runtime_sudo_hits(root: str, exts=(".js",)):
    """Yield (relpath, lineno, line) for a call whose first argument is the literal string
    `sudo` - `spawn('sudo', ...)`, a template-literal `execSync` call starting with sudo,
    or a project's own thin wrapper
    around one of those (e.g. `run('sudo', ['dpkg', '-i', file])`). Deliberately NOT scoped
    to exec/execSync/spawn/spawnSync by name: real code almost always wraps the raw
    child_process call in a small helper (`run()`, `shellExec()`, ...), and the wrapper's
    own name varies per project - matching on "first arg is the literal string sudo"
    instead is what actually generalizes. Unlike the sudo check above - scoped to HOOKS,
    the one-time install/uninstall/pre-post scripts fppd runs as root - this targets a
    plugin's always-on Node application, which normally runs as the unprivileged `fpp`
    user under its own systemd unit. A sudo call reachable from that long-running process
    (worse still if it's wired to an HTTP route handler) is a continuously-exploitable
    unprivileged-to-root escalation, not a one-shot install step - concrete motivating
    case: a plugin's admin API shelling out through passwordless sudo, via its own `run()`
    wrapper around spawn(), to install a package and manage a systemd unit at runtime."""
    call_rx = re.compile(r'''\w+\s*\(\s*['"`]\s*sudo\b''')
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if call_rx.search(line):
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


def _mass_assignment_hits(root: str, exts=(".php",)):
    """Yield (relpath, lineno, line, persisted) for `array_merge($config, $_POST)` /
    `array_merge($config, $_REQUEST)` - the whole request body merged wholesale into
    a config array, request values winning on key conflicts - with no
    `array_intersect_key`/`array_filter` allow-list anywhere in the file to constrain
    which keys can come through. `persisted` is True if a settings-write call
    (`setPluginJSON`/`WriteSettingToFile`/`file_put_contents`) appears within a few
    lines after the merge, i.e. the attacker-controlled keys actually reach disk
    rather than just living in a local variable for the rest of the request."""
    merge_rx = re.compile(r'array_merge\s*\(\s*\$\w+\s*,\s*\$_(?:POST|REQUEST)\b')
    allowlist_rx = re.compile(r'array_intersect_key\s*\(|array_filter\s*\(', re.I)
    persist_rx = re.compile(r'setPluginJSON\s*\(|WriteSettingToFile\s*\(|file_put_contents\s*\(', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if allowlist_rx.search(text):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if _is_comment_line(line):
                continue
            if merge_rx.search(line):
                window = lines[i - 1:i + 5]
                persisted = any(persist_rx.search(w) for w in window)
                yield rel, i, line.strip(), persisted
                break


_MONEY_DOMAIN_RX = re.compile(
    r'paypal\.(?:me|com)|\bpaypal\b|buymeacoffee\.com|buy\s*me\s*a\s*coffee'
    r'|ko-?fi\.com|\bko-?fi\b|venmo\.com|\bvenmo\b|cash\.app|\bcash\s*app\b|cashapp\b'
    r'|patreon\.com|\bpatreon\b|gofundme\.com|\bgofundme\b|opencollective\.com'
    r'|liberapay\.com|tipeee\.com|subscribestar\.(?:com|adult)|github\.com/sponsors', re.I)
_MONEY_EXTS = (".php", ".html", ".htm", ".inc", ".md", ".markdown", ".json", ".txt", ".js")


def _donation_reference_hits(root: str):
    """Yield (relpath, lineno, line) for a reference to a specific donation/payment
    platform (PayPal, Buy Me a Coffee, Ko-fi, Venmo, Cash App, Patreon, GoFundMe, GitHub
    Sponsors, ...) anywhere in the plugin. Deliberately does NOT use _grep's doc/help/test
    skip - a donation link in a README or help page is just as much a policy violation as
    one in the plugin's live UI. Matches platform NAMES, not just full URLs, since people
    often write "Venmo: @handle" with no link - but deliberately does NOT match the bare
    word "donate"/"donation" (tried that; it flagged a plugin's physical GPIO "donation
    sensor" on a Santa mailbox prop - donation-shaped English, not a payment reference)."""
    for path in _iter_files(root, _MONEY_EXTS):
        rel = os.path.relpath(path, root)
        low = "/" + rel.lower()
        if any(v in low for v in _VENDOR_DIRS):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _MONEY_DOMAIN_RX.search(line):
                yield rel, i, line.strip()


_TELEMETRY_DOMAIN_RX = re.compile(
    r'google-analytics\.com|googletagmanager\.com|gtag\s*\(|analytics\.google\.com'
    r'|mixpanel\.com|mixpanel\.(?:init|track)\s*\('
    r'|segment\.(?:io|com)|analytics\.track\s*\('
    r'|amplitude\.com|posthog\.com'
    r'|sentry\.io|Sentry\.init\s*\(|Raven\.config\s*\('
    r'|hotjar\.com|fullstory\.com|heap\.io|statsig\.com'
    r'|clarity\.ms|countly\.(?:com|io)|appcenter\.ms'
    r'|plausible\.io|umami\.is', re.I)
_PHONE_HOME_PHRASE_RX = re.compile(
    r'\bphone(?:s|d)?\s*home\b|\bcall(?:s|ing)?\s*home\b|\busage\s*(?:statistics|stats)\b'
    r'|\banonymous\s*usage\b|\busage\s*telemetry\b|\bsend\s*telemetry\b|\breport(?:s|ing)?\s*usage\b', re.I)


def _phone_home_hits(root: str):
    """Yield (relpath, lineno, line) for a bundled third-party analytics/telemetry SDK
    (Google Analytics, Mixpanel, Segment, Amplitude, Sentry, ...) or an explicit
    usage-stats/phone-home phrase, anywhere in the plugin (code or docs - same reasoning
    as _donation_reference_hits: disclosed-in-a-README counts too). Heuristic: can't tell
    "essential to plugin function" (e.g. a weather plugin calling its own weather API)
    apart from usage/analytics collection, which is why this is flagged for human review
    rather than treated as proven - see PLUGIN_GUIDELINES.md §11 for the actual rule."""
    for path in _iter_files(root, _MONEY_EXTS):
        rel = os.path.relpath(path, root)
        low = "/" + rel.lower()
        if any(v in low for v in _VENDOR_DIRS):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _TELEMETRY_DOMAIN_RX.search(line) or _PHONE_HOME_PHRASE_RX.search(line):
                yield rel, i, line.strip()


_AD_NETWORK_DOMAIN_RX = re.compile(
    r'googlesyndication\.com|doubleclick\.net|adservice\.google\.com'
    r'|taboola\.com|outbrain\.com|media\.net|amazon-adsystem\.com'
    r'|criteo\.com|revcontent\.com|adroll\.com'
    r'|amazon\.[a-z.]{2,6}/[^\s"\'<>]*[?&]tag=', re.I)
_AD_PHRASE_RX = re.compile(
    r'\bsponsored\s+(?:by|content|post)\b|\badvertisement\b'
    r'|\bshop\s+now\b|\bbuy\s+now\b|\d{1,2}%\s*off\b'
    r'|\baffiliate\s+(?:link|program)\b'
    r'|check\s+out\s+my\s+other\s+plugins?\b', re.I)
# UI-rendered files only (not README/docs/pluginInfo.json) - unlike donation-link and
# phone-home, this rule is scoped to "inside the FPP UI" specifically (PLUGIN_GUIDELINES.md
# #12), so a README line thanking a hardware sponsor for donating gear isn't in scope here.
_AD_EXTS = (".php", ".html", ".htm", ".inc", ".js")


def _advertising_hits(root: str):
    """Yield (relpath, lineno, line) for a known ad-network domain/Amazon affiliate tag, or
    an explicit ad/promotion phrase ("shop now", "sponsored by", "check out my other
    plugins", ...), in the plugin's actual UI files. Heuristic and partial by design - it
    catches mechanical, low-false-positive cases (ad networks, boilerplate ad phrasing);
    a banner image linking to a vendor with no telltale text needs a human to catch. See
    PLUGIN_GUIDELINES.md §12."""
    for path in _iter_files(root, _AD_EXTS):
        rel = os.path.relpath(path, root)
        low = "/" + rel.lower()
        if any(v in low for v in _VENDOR_DIRS):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _AD_NETWORK_DOMAIN_RX.search(line) or _AD_PHRASE_RX.search(line):
                yield rel, i, line.strip()


_TUNNEL_SERVICE_RX = re.compile(
    r'\bdataplicity\b|\bngrok\b|\bcloudflared\b|cloudflare\s+tunnel|cfargotunnel\.com'
    r'|\btailscale\b|\bzerotier\b|\blocaltunnel\b|\bloca\.lt\b|serveo\.net|\bpagekite\b'
    r'|telebit\.cloud|playit\.gg|tunnelto\.dev|localhost\.run'
    # Raspberry-Pi-oriented remote-access services (FPP's main target hardware) -
    # a real gap without these, since PiTunnel/Remote.It specifically market to
    # this exact userbase.
    r'|\bpitunnel\b|remot3\.it|\bweaved\b'
    # Self-hosted tunnel tools - scoped to their actual binary names/domains/repo
    # paths (not just the bare word) to avoid matching generic English ("chisel",
    # "bore", "expose" are all common words outside this context).
    r'|jpillora/chisel|\bchisel\s+(?:client|server)\b|\bfrpc\b|\bfrps\b|\brathole\b'
    r'|\bautossh\b|\bzrok\b|bore\.pub|beyondco/expose|\bexpose\.dev\b|\bloclx\b'
    r'|localxpose|tunnelmole', re.I)


def _tunnel_service_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a reference to a known third-party
    tunneling/remote-access service (Dataplicity, ngrok, Cloudflare Tunnel,
    Tailscale, ZeroTier, localtunnel, serveo, pagekite, ...) in the plugin's own
    code - PLUGIN_GUIDELINES.md §13 requires this be disclosed in
    pluginInfo.json's description, not just a README/setup page, since a user
    decides whether to install before reading either of those, and using one of
    these means the plugin can expose the FPP box's control surface to the
    internet through a third party."""
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if _TUNNEL_SERVICE_RX.search(line):
                yield rel, i, line.strip()


def _menu_type_counts(root: str) -> dict:
    """type -> [(relpath, lineno), ...] for every 'type' => '<value>' entry inside
    menu.inc's $menuEntries array. Regex-based (not a real PHP parser) - matches the
    array-literal shape the template and every real plugin's menu.inc use, one
    'type' => '...' pair per array entry on its own line."""
    result: dict = {}
    for path in _iter_files(root, (".inc",)):
        if os.path.basename(path).lower() != "menu.inc":
            continue
        rel = os.path.relpath(path, root)
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            m = re.search(r'''['"]type['"]\s*=>\s*['"](\w+)['"]''', line)
            if m:
                result.setdefault(m.group(1), []).append((rel, i))
    return result


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return (stripped[:2] in ("//", "/*", "* ") or stripped[:1] in ("#", ";")
            or stripped.startswith("<!--") or stripped in ("*", "*/"))


def _busy_wait_poll_hits(root: str):
    """Yield (relpath, lineno, line) for an UNBOUNDED loop (`while(true)`/
    `while(1)`/`for(;;)`, not any `while`) with a `sleep()` call in its next
    10 lines, in a .php file that has no evidence of being CLI-only: no
    php_sapi_name()/PHP_SAPI guard, no shebang, and not launched backgrounded
    (nohup/setsid/trailing `&`) from any .sh script in the repo.

    All three are real, common ways an FPP plugin's own author already rules
    out web reachability - checking none of them false-positived on every
    single real-world hit this rule had (remote-falcon, showpilot-plugin,
    fpp-sms-control-too, fpp-SETIQ all guard or launch a `*_listener.php`/
    `*-bg.php` daemon exactly this way; FPP-Plugin-Matrix-Message's loop was
    also bounded (`while ($isLocked && $maxWait-- > 0)`), not unbounded, a
    separate reason it wasn't a poll worth flagging at all - busy-wait-poll
    false-positive audit, 2026-09). A 0% true-positive rate on the full
    tracked-plugin corpus at the time this was tightened."""
    # Anything that can launch the daemon detached: a .sh (nohup/setsid/`&`),
    # a systemd unit's ExecStart=, PHP exec()/shell_exec()/popen() with a
    # trailing `&`, Python subprocess.Popen(). Their text is pooled and the
    # candidate .php file's basename looked for in it.
    launch_line_rx = re.compile(r'\b(?:nohup|setsid|Popen|ExecStart|systemd-run)\b|@reboot\b|&\s*(?:["\']\s*[,)]|$)')
    launcher_text = "\n".join(
        l for p in _iter_files(root, (".sh", ".service", ".php", ".py"))
        if not any(v in ("/" + os.path.relpath(p, root).lower()) for v in _VENDOR_DIRS)
        for l in _read(p).splitlines() if launch_line_rx.search(l))
    unbounded_rx = re.compile(r'\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)', re.I)
    for path in _iter_files(root, (".php",)):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        src = _read(path)
        if src.startswith("#!"):
            continue
        if re.search(r'\b(?:php_sapi_name\s*\(\s*\)|PHP_SAPI)\s*(?:[!=]==?)\s*[\'"]cli[\'"]', src):
            continue
        fname = re.escape(os.path.basename(rel))
        if re.search(r'(?:\b(?:nohup|setsid)\b[^\n]*\b' + fname + r'\b'
                     r'|\b' + fname + r'\b[^\n]*&\s*(?:["\']\s*[,)]|$)'      # `... &` in shell, or `... &"` in exec()
                     r'|^\s*ExecStart\s*=[^\n]*\b' + fname + r'\b'
                     r'|(?:\bsystemd-run\b|@reboot\b)[^\n]*\b' + fname + r'\b'
                     r'|\bPopen\s*\([^\n]*\b' + fname + r'\b)', launcher_text, re.M):
            continue
        lines = src.splitlines()
        for i, line in enumerate(lines):
            if _is_comment_line(line) or not unbounded_rx.search(line):
                continue
            window = "\n".join(lines[i:i + 10])
            if re.search(r'\bsleep\s*\(', window):
                yield rel, i + 1, line.strip()
                break


def _blocking_sleep_in_hook_hits(root: str):
    """Yield (relpath, lineno, line) for a flat, unconditional `sleep N` in
    one of FPP's four start/stop lifecycle hooks (preStart/postStart/
    preStop/postStop - any extension; fpp_install.sh/fpp_uninstall.sh run
    once at install/uninstall time, not on every fppd start/stop, so callers
    already exclude those by name).

    Two shapes are NOT actually blocking despite matching a naive sleep-in-
    hook grep, and both are exactly what this finding's own remediation text
    tells an author to do instead of a flat sleep - flagging them told an
    author their correct fix was itself the defect (a 0% true-positive rate
    on the full tracked-plugin corpus before this was tightened -
    blocking-sleep-in-hook false-positive audit, 2026-09):
      - the sleep is inside a shell function only ever invoked, elsewhere in
        the same file, from within a backgrounded call (`nohup`/`setsid`, or
        a bare trailing `&`) - the hook itself returns immediately
        (fpp-plugin-AdvancedStats: `wait_for_broker` is only ever called
        inside `( ... ) ... &`);
      - the sleep sits in a short poll/retry loop that re-checks a real
        liveness condition (`kill -0`, `pgrep`, `nc -z`) or is visibly
        bounded (a numeric `for` loop, or a counter comparison like
        `ticks < max`/`$i -lt 3`) rather than being a flat delay
        (remote-falcon: `for i in 1 2 3; do kill -0 "$OLDPID" || break;
        sleep 1; done`; showpilot-plugin: `while kill -0 ... && ticks <
        max`)."""
    # A sleep is "bounded" only when it sits in a LOOP (window has a
    # while/until/for) that also re-checks liveness or a counter - a bare
    # `pgrep ... | xargs kill` followed by `sleep 5` is still a flat delay.
    loop_rx = re.compile(r'\b(?:while|until|for)\b')
    bounded_rx = re.compile(
        r'\bkill\s+-0\b|\bpgrep\b|\bpidof\b|\bnc\s+-z\b|\bcurl\s+-s\S*\s+.*-o\s*/dev/null'
        r'|\bfor\s+\w+\s+in\s+(?:[\d\s]+;|\{\d+\.\.\d+\}|\$\(\s*seq\b)'
        r'|\buntil\s+(?:!\s*)?\[\[?\s+(?:!\s+)?-[a-zA-Z]\s|\bwhile\s+(?:!\s*\[\[?\s+|\[\[?\s+!\s+)-[a-zA-Z]\s'   # until [ -S sock ] / while [ ! -e f ]
        r'|\buntil\s+(?:curl|wget|nc|test|\[|systemctl\s+is-active|pgrep|pidof)\b'                   # until <probe>; do sleep
        r'|\b\w+\s*(?:-lt|-le|-gt|-ge)\s*\$?\{?\w+\}?'
        r'|\(\([^)]*[<>][^)]*\)\)|\[\[[^\]]*\s[<>]\s[^\]]*\]\]'   # (( i < n )) / [[ $i < $n ]], not `> file`
        r'|(?:\|\||&&)\s*break\b')

    def _hits_in(p, rel, note):
        src = _read(p)
        lines = src.splitlines()

        # (start_line, end_line) for each shell function whose body only ever
        # runs backgrounded elsewhere in this same file.
        backgrounded_ranges = []
        for name, _b0, _b1, start_line, end_line in _shell_functions(src):
            call_rx = re.compile(r'\b' + re.escape(name) + r'\b')
            for k, line in enumerate(lines):
                if start_line <= k <= end_line:
                    continue  # the definition/body itself, not a call site
                code = line.split('#', 1)[0]
                if not call_rx.search(code):
                    continue
                # Backgrounded either on the call's own line (nohup/setsid,
                # or a bare trailing &), or the call sits inside a `( ...`
                # subshell that closes with `) ... &` a few lines below -
                # `wait_for_broker` called on its own line, the subshell's
                # `) >> "$LOG_FILE" 2>&1 &` several lines later, is the real
                # shape (fpp-plugin-AdvancedStats), not a one-liner.
                same_line = (re.search(r'\b(?:nohup|setsid)\b', code)
                             or code.rstrip().endswith('&'))
                closes_backgrounded = any(
                    re.match(r'^\s*\)', l.split('#', 1)[0]) and l.split('#', 1)[0].rstrip().endswith('&')
                    for l in lines[k + 1:k + 15])
                if same_line or closes_backgrounded:
                    backgrounded_ranges.append((start_line, end_line))
                    break

        # Line ranges of `( ... ) &` subshells - a sleep inside runs detached.
        bg_subshell = []
        for k, line in enumerate(lines):
            if re.match(r'^\s*\(\s*$', line.split('#', 1)[0]):
                for e in range(k + 1, min(len(lines), k + 40)):
                    c = lines[e].split('#', 1)[0]
                    if re.match(r'^\s*\)', c):
                        if c.rstrip().endswith('&'):
                            bg_subshell.append((k, e))
                        break
        for i, line in enumerate(lines):
            code = line.split('#', 1)[0]
            if _is_comment_line(line) or not re.search(r'\bsleep\s+[0-9.]+', code):
                continue
            if code.rstrip().endswith('&') or re.search(r'\b(?:nohup|setsid)\b', code):
                continue  # `sleep 5 &` / `(sleep 5; start) &` - not blocking
            if any(s <= i <= e for s, e in bg_subshell):
                continue
            if any(s <= i <= e for s, e in backgrounded_ranges):
                continue
            window = "\n".join(l.split('#', 1)[0] for l in lines[max(0, i - 6):i + 1])
            if loop_rx.search(window) and bounded_rx.search(window):
                continue
            yield rel, i + 1, line.strip(), note

    # fppd runs exactly plugins/<name>/scripts/{preStart,postStart,preStop,
    # postStop}.sh (scripts/functions runPreStartScripts etc.) - a file with a
    # hook-like name anywhere else (backup/preStart.sh.orig, a monorepo
    # subproject's copy) never executes on its own.
    for hook in ("preStart", "postStart", "preStop", "postStop"):
        rel = f"scripts/{hook}.sh"
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        # A hook that just `exec`s into the real script elsewhere in the repo
        # hands the whole process over, so a blocking sleep in THAT script
        # blocks fppd exactly the same way. Checked in addition to the
        # wrapper, not instead of it.
        scan = [(p, rel, "")]
        t = _exec_delegation_target(p, root)
        if t and t != rel:
            scan.append((os.path.join(root, t), t, f" (the real script {rel} `exec`s into)"))
        for sp, srel, note in scan:
            yield from _hits_in(sp, srel, note)


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


def _cli_only_php_includes(root: str) -> set:
    """Relpaths of .php/.inc files that are only ever include/require'd by
    shebang'd CLI scripts (directly, or via another such CLI-only include) and
    never by a web-facing page - so, like the CLI script itself, there is no GET
    request that can reach them. Include targets are matched by basename (the
    usual `require("lock.helper.php")` / `require __DIR__ . '/x.php'` shapes both
    end in the literal filename). A file nobody includes is NOT CLI-only - it's
    a page (fpp-data#202: lock.helper.php, a lock-file class used only by the
    `#!/usr/bin/php` runEventDate.php, tripping destructive-no-csrf)."""
    include_rx = re.compile(r'\b(?:require|include)(?:_once)?\b[^;]*?([\w.\-]+\.(?:php|inc))\s*[\'"]')
    files = {}
    for path in _iter_files(root, (".php", ".inc")):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        files[rel] = (text.startswith("#!"),
                      {m.group(1) for m in include_rx.finditer(text)})
    by_base = {}
    for rel in files:
        by_base.setdefault(os.path.basename(rel), set()).add(rel)
    includers = {}
    for rel, (_, targets) in files.items():
        for base in targets:
            for target in by_base.get(base, ()):
                if target != rel:
                    includers.setdefault(target, set()).add(rel)

    memo = {}

    def is_cli(rel, stack=()):
        if rel in memo:
            return memo[rel]
        if files[rel][0]:
            memo[rel] = True
            return True
        incs = includers.get(rel)
        if not incs or rel in stack:
            return False
        ok = all(is_cli(i, stack + (rel,)) for i in incs)
        memo[rel] = ok
        return ok

    return {rel for rel in files if rel in includers and is_cli(rel)}


def _destructive_no_guard_hits(root: str, exts=(".php",)):
    """Yield (relpath, lineno, line) for a file that runs a destructive call
    (unlink/rm/exec-rm) with no HTTP-method or $_POST check anywhere in that same
    file - i.e. potentially reachable via a plain GET with no confirmation. Excludes
    cleanup registered via register_shutdown_function (e.g. deleting your own PID
    file on exit) and `@`-suppressed calls (the error-suppression idiom is a strong
    signal for "best-effort internal cleanup", e.g. removing a temp file after an
    atomic rename or a PID file when stopping a process, rather than a page whose
    entire job is the destructive action) - neither is the shape this rule targets.
    Also skips a .php file that starts with a shebang (`#!/usr/bin/env php`): that's a
    CLI script (a poller/daemon started from callbacks.sh, a command script), not a
    page - there is no GET request to reach it with (TwilioPoll.php clearing its own
    stop file, fpp-data#206)."""
    destructive_rx = re.compile(r'(?<!@)\bunlink\s*\(|(?<!@)\brm\s+-[rf]|(?:exec|system|shell_exec)\s*\([^)]*\brm\s+')
    guard_rx = re.compile(r"\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\]|\$_POST\b")
    cli_only = _cli_only_php_includes(root)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if text.startswith("#!") or rel in cli_only or guard_rx.search(text):
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


def _log_dir_non_log_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line, fname) for a hardcoded path under FPP's log
    directory (/home/fpp/media/logs/) whose filename doesn't end in .log - a PID
    file, sqlite DB, command queue, or cache file stored in the log directory
    instead of the plugin's own directory. Concrete motivating case:
    fpp-sled-mailbox stores sled_daemon.pid, sled.db, sled_trigger.cmd, and
    sled_radar_<side>.json all inside media/logs/ alongside its actual
    plugin-fpp-sled-mailbox.log. The log directory is rotated and swept wholesale
    into Support Zips as *logs* - non-log state stored there either gets rotated
    away unexpectedly or bloats every Support Zip with data nobody asked for.
    Yields every occurrence (not just the first) - the caller dedupes by `fname`
    so a file referenced from many places (e.g. a PID file opened in five
    different .php pages) is still reported once, but each DISTINCT offending
    file (pid/db/queue/cache/...) gets its own finding rather than only the
    first one seen in the whole tree."""
    path_rx = re.compile(r'''(['"])/home/fpp/media/logs/([^'"]+)\1''')
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            m = path_rx.search(line)
            if not m:
                continue
            fname = m.group(2).rsplit("/", 1)[-1]
            if "." not in fname:
                continue
            ext = fname.rsplit(".", 1)[-1].lower()
            if ext != "log":
                yield rel, i, line.strip(), fname


def _outside_plugin_territory_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a hardcoded file path under /home/fpp/media/
    that falls outside the directories a plugin is expected to touch on its own -
    its own log file (/media/logs/, the *kind* of file there is checked separately
    by _log_dir_non_log_hits above), FPP's config storage (/media/config/, see the
    core-config check's docstring and _config_dir_hits below), its own runtime-data
    directory (/media/plugindata/<repo>/), the plugins directory (/media/plugins/),
    or the playlists directory (/media/playlists/, an established integration point
    for plugin-managed temp playlists) - e.g. a state file dropped straight into
    /home/fpp/media/ itself. fpp_install.sh/fpp_uninstall.sh are excluded: an
    installer legitimately reaches outside the plugin's own footprint (systemd
    units, Apache config, cron, etc.) as part of installing/removing itself."""
    file_rx = re.compile(r'''(['"])(/home/fpp/media/[^'"]*\.\w{1,8})\1''')
    allowed_rx = re.compile(r'^/home/fpp/media/(?:config|plugins|plugindata|playlists|logs)/', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel) or os.path.basename(path) in ("fpp_install.sh", "fpp_uninstall.sh"):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            m = file_rx.search(line)
            if not m or allowed_rx.match(m.group(2)):
                continue
            yield rel, i, line.strip()


# Every shape a plugin uses to spell "FPP's config directory": the literal path
# (with or without trailing slash), `<mediaDir>/config` in its shell/PHP
# interpolated and concatenated forms, FPP's own accessors (`$settings
# ['configDirectory']`, `$(getSetting configDirectory)`, `FPP_DIR_CONFIG(...)`),
# and the usual `$cfgDir`/`$configDir`/`${CFGDIR}` local variable names. `$`-
# prefixed only - a bare `config_dir` identifier (Python/JS/C++) is too often
# assigned to something that isn't config/ at all (plugindata, /etc, ...).
_CFG_DIR_ANCHOR_RX = re.compile(
    r'/home/fpp/media/config(?=[\'"/])'
    r'|\$\{?(?:FPP_)?MEDIA_?DIR\}?/config(?=[\'"/])'
    r'|\$\{?mediaDir(?:ectory)?\}?/config(?=[\'"/])'
    r'|\$settings\s*\[\s*[\'"]mediaDirectory[\'"]\s*\]\s*\.\s*[\'"]/config(?=[\'"/])'
    r'|\$mediaDir(?:ectory)?\s*\.\s*[\'"]/config(?=[\'"/])'
    r'|\$settings\s*\[\s*[\'"]configDirectory[\'"]\s*\]'
    r'|\$\(\s*getSetting\s+configDirectory\s*\)'
    r'|\bFPP_DIR_CONFIG\s*\(\s*'
    r'|\$\{?(?:CFGDIR|CFG_DIR|CONFIG_DIR|FPP_CONFIG_DIR|configDirectory|configDir|config_dir|cfgDir|cfg_dir)\}?(?!\w)')
# The local-alias names above (not FPP's own `$configDirectory` global) only count
# in a file that actually assigns them to a config-dir spelling - `$config_dir =
# ".../plugindata/x"` is a different directory with a confusable name.
_CFG_ALIAS_RX = re.compile(r'^\$\{?(CFGDIR|CFG_DIR|CONFIG_DIR|FPP_CONFIG_DIR|configDir|config_dir|cfgDir|cfg_dir)\}?$')
_CFG_ALIAS_ASSIGN_RX = re.compile(r'(?m)^\s*(?:local\s+|export\s+)?\$?(\w+)\s*=[^;\n]*?(?:/config\b|configDirectory|FPP_DIR_CONFIG)')
# Filename literal after the anchor, past any concat/quote glue (` . "/`, `+ '/`,
# `}/`, `, "` for os.path.join, `"/"."` - BetaBrite's idiom), and the last `.ext`
# in the path expression (terminated by a quote/space/bracket, so a `.write(` or
# `.stringify(` method call later on the line doesn't count as an extension).
_CFG_NAME_RX = re.compile(r'^(?:[\s.+,]|[\'"]|/|[{}])*([^\'"\s,)]*)')
_CFG_EXT_RX = re.compile(r'\.([A-Za-z0-9-]{1,8})(?=[\'"\s),;\]]|$)')
_CFG_BINARY_EXTS = frozenset((
    "db", "db3", "s3db", "sqlite", "sqlite3", "db-wal", "db-shm", "sqlite-wal", "sqlite-shm", "wal", "shm",
    "bin", "dat", "gz", "tgz", "bz2", "xz", "zip", "tar", "7z",
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "mp3", "wav", "mp4", "pkl", "pickle"))
_CFG_STATE_EXTS = frozenset(("log", "cache", "lock", "pid", "tmp"))
# FPP core's own non-settings files under config/ - a plugin READING one is fine.
_CFG_CORE_NAMES = frozenset(("cape-eeprom.bin", "media_durations.cache", "sequence_fps.cache"))
_CFG_DB_SINK_RX = re.compile(
    r'sqlite3\.connect\s*\(|new\s+SQLite3\s*\(|new\s+\\?PDO\s*\(\s*[\'"]sqlite:|sqlite3_open(?:_v2)?\s*\('
    r'|new\s+(?:sqlite3\.)?Database\s*\(|\bsqlite3\s+[\'"]?[/$]', re.I)
# Opening/writing the path for output, on the same line. Reads (file_get_contents,
# fopen 'r', open() with no mode) don't match.
_CFG_WRITE_SINK_RX = re.compile(
    r'file_put_contents\s*\(|\bf?open\s*\(.*?,\s*(?:mode\s*=\s*)?[\'"][waxc]|\.write_(?:text|bytes)\s*\('
    r'|fs\.(?:write|append)File(?:Sync)?\s*\(|fs\.createWriteStream\s*\(|\bofstream\b', re.I)
# Sinks where the config path must be the DESTINATION, matched against the text
# BEFORE the anchor: 2nd arg of copy/rename/move (anchor after the comma), a
# shell redirect (not `2>&1`/`>&2`) or tee/touch target, or cp/mv/rsync/install
# with the anchor as the last argument (`cp <config file> /tmp/x` is a read).
_CFG_DEST_PREFIX_RX = re.compile(
    r'\b(?:copy|rename|move_uploaded_file|shutil\.(?:copy2?|copyfile|move)|os\.rename)\s*\([^,]*,\s*$'
    r'|(?<![-=<&0-9])>>?\s*[\'"]?$|\btee\s+(?:-a\s+)?[\'"]?$|\btouch\s+(?:-\w+\s+)*[\'"]?$'
    r'|\b(?:cp|mv|rsync|install)\s+(?!.*\s(?:cp|mv|rsync|install)\s)')
_CFG_LAST_ARG_RX = re.compile(r'[^\'"\s]*[\'"]?\s*(?:[;&|#].*)?$')
# A file being moved OUT of config/ - rename()/os.rename()/shutil.move() with the
# config path as the FIRST argument, or `mv <config path> <elsewhere>` - is the
# one-time migration the fix text below suggests, not a write. Matched against
# the text BEFORE the anchor (prefix-anchored, unlike the whole-line rm/unlink
# skip), so the same call with config/ as the destination (the
# `_CFG_DEST_PREFIX_RX` shape) still fires; so does a move whose destination is
# also under config/ (checked by the caller).
_CFG_MOVE_SRC_PREFIX_RX = re.compile(
    r'\b(?:rename|shutil\.move|os\.rename|os\.replace)\s*\(\s*(?:os\.path\.join\s*\(\s*)?[\'"]?$'
    r'|\bmv\s+(?:-\w+\s+)*[\'"]?$')
_CFG_SCAN_EXTS = SCRIPT_EXT + (".inc", ".cpp", ".cc", ".c", ".h", ".hpp")


def _config_dir_hits(root: str, exts=_CFG_SCAN_EXTS):
    """Yield (relpath, lineno, line, fname, kind) for a line that builds a path under
    FPP's config directory (/home/fpp/media/config/) for a file that doesn't belong
    there. Single-line only - no variable tracking. `kind`:
      "binary" - a database/binary extension (.db/.sqlite/.bin/.gz/.png/...), or a
                 SQLite open (sqlite3.connect / new SQLite3 / new PDO('sqlite: /
                 sqlite3_open / `sqlite3` CLI) on any config-dir path. Fires on the
                 path expression alone, read or write - a .db under config/ got there
                 by the plugin creating it, and opening a SQLite file creates it.
      "state"  - a .log/.cache/.lock/.pid/.tmp path, likewise on the expression alone.
      "text"   - any other non-`plugin.*` filename with a write sink on the SAME line
                 (file_put_contents, fopen/open for write, fs.writeFile, shell
                 redirect/cp/tee TO the path, ...). `plugin.<name>` / `plugin.<name>.json`
                 is the settings-file convention (WriteSettingToFile/setPluginJSON)
                 and never fires.
    FPP core's own non-settings files (cape-eeprom.bin, *.cache) only fire with a
    write/db sink on the line; rm/unlink lines are skipped (an uninstall cleaning up
    is not a write). Motivating cases: AdvancedStats' plugin.<repo>.db, TwilioControl/
    MessageQueue's FPP.<name>.db. Every hit is yielded; the caller sorts and dedupes."""
    skip_rx = re.compile(r'\brm\s|\bunlink\s*\(')
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        is_shell = path.endswith(".sh")
        text = _read(path)
        aliases = set(_CFG_ALIAS_ASSIGN_RX.findall(text))
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line) or skip_rx.search(line):
                continue
            m = _CFG_DIR_ANCHOR_RX.search(line)
            if not m or re.match(r'\s*=[^=]', line[m.end():]):
                continue  # no anchor, or `$cfgDir = ...` (the dir itself being assigned)
            if _CFG_MOVE_SRC_PREFIX_RX.search(line[:m.start()]) and not _CFG_DIR_ANCHOR_RX.search(line[m.end():]):
                continue  # migrating a file out of config/ - the fix, not the problem
            am = _CFG_ALIAS_RX.match(m.group(0))
            if am and am.group(1) not in aliases:
                continue
            rest = line[m.end():].split(";", 1)[0]
            name = _CFG_NAME_RX.match(rest).group(1)
            exts_found = _CFG_EXT_RX.findall(rest)
            ext = exts_found[-1].lower() if exts_found else ""
            fname = name if not ext or name.lower().endswith("." + ext) else (name or "<var>") + "..." + ext
            db_sink = _CFG_DB_SINK_RX.search(line)
            write_sink = _CFG_WRITE_SINK_RX.search(line) or (
                _CFG_DEST_PREFIX_RX.search(line[:m.start()]) and (not is_shell or _CFG_LAST_ARG_RX.match(rest)))
            if ext in _CFG_BINARY_EXTS or db_sink:
                kind = "binary"
            elif ext in _CFG_STATE_EXTS:
                kind = "state"
            elif name and not name.lower().startswith("plugin.") and write_sink:
                kind = "text"
            else:
                continue
            if fname.lower() in _CFG_CORE_NAMES and not (db_sink or write_sink):
                continue
            yield rel, i, line.strip(), fname, kind

# limonade lifecycle hooks - www/api/controllers/plugin.php PluginApiReservedFunctions().
_LIMONADE_RESERVED_NAMES = frozenset({
    "configure", "initialize", "before", "autorender", "before_exit",
    "before_sending_header", "after", "route_missing", "autoload_controller",
    "not_found", "server_error",
})
_FPP_API_GLOBALS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fpp_api_globals.txt")
_fpp_api_globals_cache: frozenset[str] | None = None


def _fpp_api_globals() -> frozenset[str]:
    """Lower-cased names of every global PHP function FPP core defines on an
    /api/* request (fpp_api_globals.txt, generated from the FPP tree - the
    header says how). Empty if the file is missing, so the check degrades to
    the curated generic list rather than failing."""
    global _fpp_api_globals_cache
    if _fpp_api_globals_cache is None:
        names = set()
        for l in _read(_FPP_API_GLOBALS_FILE).splitlines():
            l = l.strip()
            if l and not l.startswith("#"):
                names.add(l.lower())
        _fpp_api_globals_cache = frozenset(names)
    return _fpp_api_globals_cache


# PHP built-in functions a plugin author might plausibly try to declare -
# "Cannot redeclare" at compile time, whatever FPP version.
_PHP_BUILTIN_NAMES = frozenset({
    "log", "reset", "exec", "system", "header", "settype", "gettype", "count", "sort",
    "filter", "time", "date", "mail", "link", "unlink", "copy", "rename", "stat", "each",
    "end", "next", "current", "key", "list", "array", "min", "max", "abs", "round",
    "trim", "split", "join", "implode", "explode", "print", "echo", "empty", "isset",
    "unset", "die", "exit", "sleep", "usleep", "file", "dir", "glob", "chdir", "mkdir",
    "rmdir", "touch", "chmod", "chown", "readfile", "fopen", "fclose", "fread", "fwrite",
    "serialize", "unserialize", "compact", "extract", "assert", "checkdate", "levenshtein",
})

# Short generic names that two plugins' api.php files could plausibly both pick.
_GENERIC_API_NAMES = frozenset({
    "status", "getstatus", "save", "update", "delete", "remove", "get", "set",
    "init", "config", "log", "notify", "send", "check", "test", "reset",
    "start", "stop", "run", "execute", "process", "handle", "callback",
    "response", "request", "error", "success", "validate", "verify",
})


# Everything that can hide a brace in PHP source, as ONE alternation so the
# leftmost match wins: a `//` inside a string ("http://...") must be string,
# not comment, and a `"` inside a `//` comment must be comment, not string -
# stripping them in two passes (comments first) turned every URL literal
# inside a function into an unterminated string that swallowed braces up to
# the next quote anywhere in the file. Strings can't span lines here (a PHP
# string can, but a multi-line string in an api.php is a heredoc's job, and
# a bounded miss beats an unbounded one). Heredoc/nowdoc bodies are blanked
# whole. Every replacement keeps its newlines so stripped line numbers still
# index the original.
_PHP_OPAQUE_RX = re.compile(
    r'<<<\s*(["\']?)([A-Za-z_]\w*)\1\s*\n.*?\n\s*\2\b'   # heredoc / nowdoc
    r'|/\*.*?\*/'                                             # block comment
    r'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''             # single-line strings
    r'|(?://|#)[^\n]*',                                        # line comment
    re.S)


def _php_strip_opaque(src: str) -> str:
    """`src` with strings, comments and heredocs replaced by a same-line-count
    blank (strings become `""` so `$a = "x";` still reads as a statement)."""
    def _blank(m):
        t = m.group(0)
        if t[0] in "\"'":
            return '""'
        return "\n" * t.count("\n")
    return _PHP_OPAQUE_RX.sub(_blank, src)


_SHELL_FN_DEF_RX = re.compile(
    r'(?m)^\s*(?:function\s+(\w+)\s*(?:\(\s*\))?|(\w+)\s*\(\s*\))\s*\{')


def _shell_functions(src: str) -> list[tuple[str, int, int, int, int]]:
    """Every `name() {`, `function name {` and `function name() {` in a shell
    script as (name, body_start, body_end, start_line, end_line): character
    offsets of the body (just inside the braces) and 0-based line numbers of
    the definition's first and last line. Brace matching is naive (a `}` in a
    string counts) - good enough for the install/hook scripts this is used on."""
    out = []
    for m in _SHELL_FN_DEF_RX.finditer(src):
        name = m.group(1) or m.group(2)
        depth, j = 1, m.end()
        while j < len(src) and depth > 0:
            if src[j] == '{':
                depth += 1
            elif src[j] == '}':
                depth -= 1
            j += 1
        out.append((name, m.end(), j - 1, src.count('\n', 0, m.start()), src.count('\n', 0, j)))
    return out


def _api_php_top_level_hits(path: str):
    """Yield (lineno, line) for a statement at brace depth 0 in a PHP file that
    does something (echo/header/exec/switch/assigns FROM a superglobal, ...)
    rather than just declaring functions/classes or pulling in FPP's helpers.
    Strings, comments and heredocs are blanked first (see _php_strip_opaque)
    so braces inside them don't skew the depth count."""
    side = re.compile(
        r'^\s*(echo\b|print\b|header\s*\(|http_response_code\s*\(|exec\s*\(|shell_exec\s*\(|'
        r'passthru\s*\(|system\s*\(|proc_open\s*\(|switch\s*\(|foreach\s*\(|while\s*\(|'
        r'die\b|exit\b|readfile\s*\(|file_put_contents\s*\(|'
        r'\$\w+\s*=\s*\$_(GET|POST|REQUEST)\b)')
    original = _read(path).splitlines()
    src = _php_strip_opaque("\n".join(original))
    depth = 0
    for i, line in enumerate(src.splitlines(), 1):
        if depth == 0 and side.match(line):
            yield i, original[i - 1].strip()
        depth += line.count('{') - line.count('}')


def _log_naming_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a log filename built from logDirectory/LOGDIR
    that doesn't include the mandated "plugin-" prefix - e.g. `$pluginName.".log"` instead
    of `"plugin-".$pluginName.".log"`.

    One hop of aliasing is followed within a file: a variable assigned from
    LOGDIR/logDirectory (`LOG_DIR="${LOGDIR:-/home/fpp/media/logs}"`,
    `$logDir = $settings['logDirectory']`, `logdir = os.environ.get('LOGDIR', ...)`)
    is treated as the log directory on later lines, so a `.log` filename built from
    that alias is checked too. Confirmed miss before this (fpp-plugin-SDCardRecover,
    2026-09): `LOG_DIR="${LOGDIR:-...}"` on one line and
    `LOG_FILE="$LOG_DIR/SDCardRecover.log"` on the next was invisible to the
    same-line-only regex, and the mis-named log never gets rotated by FPP."""
    rx = re.compile(r'(logDirectory|LOGDIR)\b.*\.log\b', re.I)
    alias_rx = re.compile(r'^\s*(?:local\s+|export\s+|var\s+|let\s+|const\s+)?\$?(\w+)\s*=\s*[^=].*?\b(logDirectory|LOGDIR)\b', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        aliases = set()
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if re.search(r'\b(?:fppd|fpp|fppinit|apache2(?:-\w+)?)\.log\b', line, re.I):
                continue  # reading/tailing FPP's own log isn't naming one
            if rx.search(line) and "plugin-" not in line.lower():
                yield rel, i, line.strip()
                break
            m = alias_rx.match(line)
            if m and m.group(1).lower() not in ('logdir', 'logdirectory'):
                aliases.add(m.group(1))
                continue
            if aliases and '.log' in line.lower() and 'plugin-' not in line.lower():
                # `$ALIAS`/`${ALIAS}` (shell, PHP) or bare word `ALIAS` (Python, JS)
                # used in an expression that NAMES a log file - an assignment,
                # a redirect/tee target, or an open-for-write - not one that
                # reads, tails or rotates logs. Reading FPP's own fppd.log via
                # the alias isn't naming a log either.
                if re.search(r'\b(?:fppd|fpp|fppinit|apache2(?:-\w+)?)\.log\b', line, re.I):
                    continue
                names_log = re.search(
                    r'^\s*(?:local\s+|export\s+|var\s+|let\s+|const\s+|readonly\s+)?\$?\w+\s*=[^=]'
                    r'|(?<![-=<&0-9\w])>>?\s*["\']?\$?\{?\w|\btee\b|\bfopen\s*\(|file_put_contents\s*\('
                    r'|\bopen\s*\([^)]*["\'][aw]|FileHandler\s*\(|logging\.basicConfig\s*\(|createWriteStream\s*\(',
                    line)
                if names_log and any(
                        re.search(r'\$\{?' + re.escape(a) + r'\b|(?<![\w$])' + re.escape(a) + r'\b', line)
                        for a in aliases) and re.search(r'\.log\b', line, re.I):
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


def _unverified_package_install_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a file that downloads a file over the network
    (curl/wget with an output flag - i.e. saving to disk, not piping to a shell, which
    `remote-exec` above already covers) and separately trusts/runs it with no checksum
    or signature verification (sha256sum/sha1sum/md5sum, gpg --verify) anywhere in the
    same file - either installed as a system package (`dpkg -i` / `rpm -i`, including
    the JS array-argument idiom `['dpkg', '-i', path]`), or made directly executable
    (`chmod +x $VAR`, no package manager involved at all - e.g. a native connector
    binary fetched straight from the vendor's own update endpoint). The chmod
    alternative is deliberately narrow - the ENTIRE chmod target must be a single bare
    variable (`chmod +x $BINARY_PATH`, not `chmod +x "$PLUGIN_DIR/scripts"/*.sh`) -
    since chmod +x'ing the plugin's own bundled, literal-path scripts for permissions
    (completely normal, done everywhere) would otherwise co-occur with an unrelated
    config-file download in the same install script and false-positive constantly; a
    bare bareword variable holding a whole path is a much stronger signal of "the
    thing we just computed/downloaded" than a literal repo-relative path ever is.
    File-level presence/absence, like _missing_timeout_hits - a file legitimately
    mixing verified and unverified installs is rare, and multi-line/JS-array argument
    lists (or, for the chmod case, the download and the chmod living in different
    functions with renamed parameters) make a single-line taint match between the
    download and the install/chmod unreliable. HTTPS transport makes this lower-risk
    than a live MITM, but it's still no defense-in-depth if the download URL/CDN/
    upstream repo is ever compromised, and the install/execution almost always runs
    as root or an always-on service."""
    download_rx = re.compile(
        r'\bcurl\b[^\n]*(-o\b|-O\b|--output\b)|\bwget\b[^\n]*(-O\b|--output-document\b)|\bwget\s+[\'"]?https?://')
    install_rx = re.compile(
        r'''\bdpkg\s*[,'"\s]*-i\b|\brpm\s*[,'"\s]*-i\b'''
        r'''|\bchmod\s+(?:-\w+\s+)?\+?x\s+"?\$\{?[A-Za-z_]\w*\}?"?\s*(?:$|[;&|])''', re.MULTILINE)
    verify_rx = re.compile(r'sha256sum|sha1sum|md5sum|gpg\s*[,\'"\s]*--verify|\bchecksum\b', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if not (download_rx.search(text) and install_rx.search(text)) or verify_rx.search(text):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line):
                continue
            if install_rx.search(line):
                yield rel, i, line.strip()
                break


def _download_then_execute_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a script that downloads a file to disk
    (curl -o/-O/--output or wget -O/--output-document) and then separately
    executes THAT SAME file (bash/sh/source/./) later in the same file - the
    staged, two-command equivalent of `curl | sh` (remote-exec above only
    catches the direct single-line pipe/process-substitution/eval shapes).
    File-level presence/absence, like _unverified_package_install_hits: a file
    legitimately mixing a verified and an unverified download is rare, and the
    download/execute steps are often several lines apart (permissions set,
    directories made, etc. in between), so a single-line taint match between
    them would miss most real instances."""
    download_rx = re.compile(
        r'\bcurl\b[^\n]*(?:-o\s+|-O\s+|--output[= ])["\']?([\w./${}-]+\.(?:sh|py|pl|rb))\b'
        r'|\bwget\b[^\n]*(?:-O\s+|--output-document[= ])["\']?([\w./${}-]+\.(?:sh|py|pl|rb))\b')
    verify_rx = re.compile(r'sha256sum|sha1sum|md5sum|gpg\s*[,\'"\s]*--verify|\bchecksum\b', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if verify_rx.search(text):
            continue
        m = download_rx.search(text)
        if not m:
            continue
        # Only the unambiguous "this IS the command being run" shapes - explicit
        # interpreter, or `./fname` - not a bare mention of the filename (which
        # would also match a harmless `chmod +x fname` or `rm fname` cleanup line).
        fname = re.escape(os.path.basename(m.group(1) or m.group(2)))
        exec_rx = re.compile(rf'\b(?:bash|sh|source)\s+\S*{fname}\b|\./\S*{fname}\b')
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line) or download_rx.search(line):
                continue
            if exec_rx.search(line):
                yield rel, i, line.strip()
                break


def _unpinned_third_party_clone_hits(root: str, own_owner: str | None, own_repo: str | None, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) for a `git clone` of a THIRD-PARTY GitHub repo
    (not the plugin's own srcURL) with no pinned commit anywhere in the file - i.e.
    tracking a floating branch (a plain clone, or a later `git fetch && git reset
    --hard origin/<branch>` on reinstall) rather than a specific reviewed commit.
    Same trust model as `curl | bash` (remote-exec) - the code that actually runs is
    whatever's currently on that branch at pull time, not what was reviewed at
    submission time - just done through git instead of a pipe. BEST_PRACTICE, not
    BLOCKER like remote-exec: harder to prove statically that the cloned code is
    actually imported/executed (vs. e.g. used only as data/assets), so this flags
    for a human to confirm reachability rather than asserting it. Confirmed real
    (catalog-wide audit, 2026-08): fpp-live-follow clones
    pgianotto/animatronic-motion-system fresh on install and does `git fetch &&
    git reset --hard origin/master` on every reinstall, with no commit pin anywhere
    and the cloned code then imported by the daemon."""
    clone_rx = re.compile(r'\bgit\s+(?:-C\s+\S+\s+)?clone\b[^\n]*?(https?://github\.com/\S+)')
    # A real commit SHA (hex only) pins the checkout to a specific reviewed state;
    # a branch name like "origin/master" isn't hex-only and won't match this, so
    # that shape is correctly still treated as floating/unpinned. Flags between
    # the subcommand and the sha (`checkout --quiet <sha>`, `checkout -q <sha>`,
    # `reset --hard -q <sha>`) are tolerated: fpp-live-follow pinned exactly as
    # the finding text asked and still tripped this through four /recheck rounds
    # (fpp-data #231) because `--quiet` sat between `checkout` and the sha.
    pin_rx = re.compile(r'\bgit\s+(?:-C\s+\S+\s+)?(?:checkout|reset\s+--hard)\s+(?:-\S+\s+)*(?:origin/)?([0-9a-f]{7,40})\b', re.I)
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if pin_rx.search(text):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line):
                continue
            m = clone_rx.search(line)
            if not m:
                continue
            repo_info = parse_github_repo(m.group(1)) if parse_github_repo else None
            if repo_info is None:
                continue
            owner, repo_name_hit = repo_info
            if (own_owner and own_repo
                    and owner.lower() == own_owner.lower() and repo_name_hit.lower() == own_repo.lower()):
                continue  # cloning its own repo (e.g. a self-reference) - not third-party
            yield rel, i, line.strip()


def _nounset_fppdir_hits(root: str):
    """Yield (relpath, lineno, line) for a shell script that enables `set -u`
    (nounset) and then, while it is still in effect, either sources
    ${FPPDIR}/scripts/common or expands FPPDIR with no default. Both abort the
    script instead of failing soft, and the guidelines' own restart-flag advice
    used to produce exactly this shape:
      - on the uninstall path FPPDIR is unset (uninstall_plugin passes it only as
        a trailing argument and the Plugin Manager's plain `sudo` strips the
        exported one) -> "FPPDIR: unbound variable", script exits before any
        cleanup runs;
      - on the install path FPPDIR IS set, but scripts/common expands a bare
        $LD_LIBRARY_PATH (always stripped by sudo) so sourcing it under nounset
        dies inside common - usually hidden by a 2>/dev/null on the source line.
    Confirmed real (fpp-data #231, 2026-09): fpp-live-follow's fpp_install.sh
    exited right after its first echo for three weeks; nobody noticed because the
    error was silenced. Statement-level `set +u` (or `set +o nounset`) after the
    enabling line ends the window; `set +u` earlier on the same line (the
    recommended subshell form) exempts that line. A script that assigns FPPDIR
    itself first (`FPPDIR="${FPPDIR:-}"`, `: "${FPPDIR:=/opt/fpp}"`) has made
    later bare expansions safe (fpp-AnnouncementAssistant does this), so those
    are exempt from that point on - sourcing common under nounset is not."""
    assigns = re.compile(r'^\s*(export\s+)?FPPDIR=|\$\{FPPDIR:=')
    nounset_on = re.compile(r'(^|[;&|(]\s*|\bthen\s+|\bdo\s+)set\s+(-[a-zA-Z]*u[a-zA-Z]*\b|-o\s+nounset\b)')
    nounset_off = re.compile(r'^\s*set\s+(\+[a-zA-Z]*u[a-zA-Z]*\b|\+o\s+nounset\b)')
    same_line_off = re.compile(r'set\s+(\+[a-zA-Z]*u[a-zA-Z]*\b|\+o\s+nounset\b)')
    source_common = re.compile(r'(^|[;&|(]\s*|\bthen\s+|\bdo\s+)(source|\.)\s+"?\$\{?FPPDIR\}?[^\s"]*/scripts/common\b')
    bare_fppdir = re.compile(r'\$FPPDIR\b|\$\{FPPDIR\}')
    shebang = re.compile(r'^#!\s*\S*/(ba)?sh\b|^#!\s*\S*/env\s+(ba)?sh\b')
    for path in _iter_files(root):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if not rel.endswith(".sh") and not shebang.match(text):
            continue
        armed = assigned = False
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line):
                continue
            if assigns.search(line):
                assigned = True
            if not armed:
                if nounset_on.search(line):
                    armed = True
                continue
            if nounset_off.match(line):
                armed = False
                continue
            m = source_common.search(line) or (None if assigned else bare_fppdir.search(line))
            if not m:
                continue
            off = same_line_off.search(line)
            if off and off.start() < m.start():
                continue
            yield rel, i, line.strip()


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


def _menu_entries(root: str):
    """Yield (relpath, lineno, type, page) for each entry in menu.inc's $menuEntries
    array. Block-based (not just the single-field regex _menu_type_counts uses) since
    this needs 'type' and 'page' from the SAME entry, which can land on different
    lines. Assumes entries have no nested parens (true of every real plugin's
    menu.inc, which only ever holds scalar 'key' => 'value' pairs) - a plugin with
    something more exotic in there just won't match, same trade-off _menu_type_counts
    already makes."""
    entry_rx = re.compile(r'Array\(([^)]*?)\)', re.S)
    type_rx = re.compile(r'''['"]type['"]\s*=>\s*['"](\w+)['"]''')
    page_rx = re.compile(r'''['"]page['"]\s*=>\s*['"]([^'"]+)['"]''')
    for path in _iter_files(root, (".inc",)):
        if os.path.basename(path).lower() != "menu.inc":
            continue
        rel = os.path.relpath(path, root)
        text = _read(path)
        for m in entry_rx.finditer(text):
            block = m.group(1)
            tm, pm = type_rx.search(block), page_rx.search(block)
            if not tm or not pm:
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            yield rel, lineno, tm.group(1), pm.group(1)


_OFF_BOX_REDIRECT_RX = re.compile(
    r"header\s*\(\s*['\"]Location:|<meta[^>]+http-equiv=[\"']refresh[\"']|location\.(?:replace|href)\s*[=(]",
    re.I)
# A literal (or string-concatenation-built) absolute http(s) scheme feeding one of
# the redirect mechanisms above, as opposed to a plain relative Location (e.g.
# 'Location: index.php' or 'Location: /plugin.php?...') - which stays inside FPP's
# own page flow and isn't what this rule is after. Matches a quoted scheme directly
# ("https?://...") or the start of one being concatenated ('http://' . $host . ...).
_OFF_BOX_SCHEME_RX = re.compile(r"""['"]https?://""", re.I)


def _menu_off_box_redirect_hits(root: str):
    """Yield (menu_rel, menu_lineno, target_rel) for a menu.inc entry whose 'page' is a
    local file that itself performs a same-tab redirect (Location header, meta refresh,
    or JS location.replace/href) to an absolute http(s) URL - i.e. the menu link LOOKS
    like it opens a plugin page inside FPP but actually navigates the current tab away
    from FPP entirely, same-origin or not. The menu mechanism already has a sanctioned
    way to send someone off-site: a literal 'page' => 'http://...' entry, which the
    template renders as target='_blank' - an explicit pop-up that says up front where
    it's going and leaves the FPP tab alone. A local .php/.inc shim that redirects the
    current tab at request time is the pattern to catch here; it's indistinguishable
    from a normal in-FPP menu page until you actually click it."""
    for rel, lineno, mtype, page in _menu_entries(root):
        if re.match(r'https?://', page, re.I):
            continue
        target = None
        for path in _iter_files(root, (".php", ".inc", ".html")):
            if os.path.basename(path) == page:
                target = path
                break
        if not target:
            continue
        text = _read(target)
        if not _OFF_BOX_REDIRECT_RX.search(text):
            continue
        if _OFF_BOX_SCHEME_RX.search(text):
            yield rel, lineno, os.path.relpath(target, root)


_DEFAULT_CRED_RX = re.compile(
    r"(?:bcrypt\.hash(?:Sync)?|password_hash)\s*\(\s*['\"](admin|password|changeme|letmein|12345|123456)['\"]",
    re.I)


def _default_credential_hits(root: str, exts=(".php", ".js")):
    """Yield (relpath, lineno, line) for a hashed-password seed call whose plaintext
    input is a well-known default word (admin/password/changeme/...) rather than a
    per-install random value. Forcing a change on first login (as this plugin does)
    mitigates it, but the well-known default is still exposed for a window between
    install and first login, and only via whatever channel the plugin happens to
    print it to (often just install-script stdout, easy to miss) - a per-install
    random default, printed the same way, closes that window instead of just
    shortening it."""
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            if _DEFAULT_CRED_RX.search(line):
                yield rel, i, line.strip()


# --- privacy disclosure (pluginInfo.json `privacy` block) --------------------
# The `privacy` block (pluginInfo.schema.json `$defs/privacy`, PLUGIN_GUIDELINES.md
# §14, PLUGININFO_FORMAT.md `privacy`) is self-declared, so the listing check greps the
# plugin's code against it and fails on a contradiction: a host in the code that
# no `sends[].to` covers, an install-time fetch or package source with no
# download/package-source change, a camera device with no camera sensor, a
# bind() while remoteAccess is "none", and so on. Each category is its own
# `privacy-undeclared-<category>` finding so an author can fix one line of the
# manifest per finding. Everything here is single-line and literal-only, like
# the other checks: a host built from variables is invisible to it and still
# needs the human review.

# A missing block is a listing BLOCKER outright - the original 2027-01-01 grace
# period was dropped for listing. FPP's own
# www/js/fpp-privacy-lights.js still keys the install dialog's grey-vs-red
# "No privacy disclosure" state to its own date; that's the player's concern,
# not the listing's.

# The v3 vocabulary: eight keys, the keys inside each array item, the enums the
# linter reasons about, and the soft length caps (spec §1; the schema carries
# the enums, the linter the lengths - warn, never block).
_PRIV_V3_KEYS = ("summary", "sends", "collects", "sensors", "remoteAccess", "systemChanges", "closedCode", "other")
_PRIV_V3_ITEM_KEYS = {
    "sends": ("to", "what", "why", "alwaysOn"),
    "collects": ("what", "about", "keptDays", "canDelete", "where"),
    "sensors": ("type", "stored"),
    "systemChanges": ("kind", "what"),
}
_PRIV_V3_KINDS = ("service", "network", "core-settings", "download", "package-source", "tunnel", "reads-core-credentials", "privilege")
_PRIV_LEN_SUMMARY, _PRIV_LEN_TEXT, _PRIV_LEN_CHANGE = 200, 100, 120
# The placeholder fpp-plugin-Template ships in privacy.summary / privacy.other
# (matched case-insensitively, so a half-edited copy still trips it).
_PRIV_TEMPLATE_MARK = "template text"
# What a v2 key became, for the privacy-unknown-key message.
_PRIV_V2_KEY_HINTS = {
    "schemaVersion": "dropped in v3", "recipients": "now `sends`", "install": "now `systemChanges` kinds download / package-source, and `closedCode`",
    "inProcess": "dropped - say it in `other` if it matters", "subjects": "now `collects[].about`", "broadcasts": "now a `sends` entry with to = \"anyone in FM range\"",
    "visitorUI": "dropped - describe it in `other`", "payments": "dropped - describe it in `other`", "credentials": "now `systemChanges` kind reads-core-credentials; the plugin's own credentials are its settings.json type: password",
    "hostChanges": "now `remoteAccess` and `systemChanges`", "leftAfterUninstall": "dropped - say it in `other`", "revertedOnUninstall": "dropped - say it in `other`",
}

_PRIVACY_SETTING_KEYS = ("statsPublish", "statsPublishUrl", "ShareCrashData", "FetchVendorLogos",
                         "SendVendorSerial", "SendVendorLogos", "privacyConsent", "LegalJurisdiction")
_PRIVACY_SETTING_RX = re.compile(r'(?<![\w.$-])(' + "|".join(_PRIVACY_SETTING_KEYS) + r')(?![\w-])')
# Core settings that hold a credential - a read has to be declared under
# a systemChanges entry of kind reads-core-credentials (PLUGIN_GUIDELINES.md §14.9). Case-exact:
# these are FPP's own key spellings, and `password` as a plugin's OWN 2-arg
# setting is filtered out by the arg-count check below.
_CORE_CREDENTIAL_KEYS = ("password", "osPassword", "emailpass", "emailuser", "MQTTPassword", "MQTTUsername", "TetherPSK")

_PRIV_EXTS = _CFG_SCAN_EXTS + (".html", ".htm", ".css")
# A committed virtualenv/site-packages (fpp-performance-capture ships one) and
# bundled UI libraries carry hundreds of doc/CDN URLs that say nothing about the
# plugin's own traffic - skipped here on top of _skippable()'s vendor dirs.
_PRIV_SKIP_DIRS = ("/venv/", "/.venv/", "/site-packages/", "/dist-packages/", "/__pycache__/")
_PRIV_LIB_FILE_RX = re.compile(
    r'(^|[/.-])(jquery|bootstrap|sweetalert|popper|chart|moment|lodash|underscore|select2|datatables?'
    r'|fontawesome|font-awesome|d3|three|socket\.io|axios|vue|react|angular|phpmailer|guzzle)[\w.-]*\.(js|php|css)$', re.I)

_PRIV_URL_RX = re.compile(
    r'''(?<![\w/@-])(https?|wss?|mqtts?|ftp|git|ssh|smtps?|imaps?|pop3s?)://'''
    r'''([A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(/[^\s'"`<>)]*)?''')
# Reference/documentation hosts that turn up in code as spec links, license
# headers, badge images and "see also" strings, never as a data recipient.
_PRIV_DOC_HOST_RX = re.compile(
    r'(^|\.)(ietf\.org|rfc-editor\.org|wikipedia\.org|php\.net|w3\.org|whatwg\.org|example\.(com|org|net)'
    r'|gnu\.org|creativecommons\.org|opensource\.org|mozilla\.org|stackoverflow\.com|iana\.org|iso\.org'
    r'|unicode\.org|apache\.org|oracle\.com|wordpress\.org|promisesaplus\.com|php-fig\.org|jquery\.org'
    r'|jqueryui\.com|jquery\.com|curl\.haxx\.se|curl\.se|sourceforge\.net|schema\.org|json-schema\.org'
    r'|purl\.org|falconchristmas\.com|github\.io|python\.org|npmjs\.com|pypi\.org|debian\.org'
    r'|raspberrypi\.(com|org)|ubuntu\.com|nodejs\.org|readthedocs\.io|shields\.io|brew\.sh'
    r'|placehold\.co|youtube\.com|youtu\.be|docs\.\w+\.\w+)$', re.I)


def _priv_private_host(h: str) -> bool:
    """localhost, link-local, RFC1918/loopback/multicast literals, mDNS `.local` and the other
    LAN-only suffixes the install dialog's HOST_RE treats as private - not off-box."""
    m = re.match(r'^(\d+)\.(\d+)\.', h)
    if not m:
        return h in ("localhost", "0.0.0.0", "::1", "::") or h.endswith((".local", ".localhost", ".lan", ".home", ".internal", ".localdomain"))
    a, b = int(m.group(1)), int(m.group(2))
    return a in (0, 10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254) or a >= 224


def _priv_reg_domain(h: str) -> str:
    """Registrable domain for recipient matching (api.twilio.com -> twilio.com,
    fpp-zettle.s3.dualstack.eu-west-2.amazonaws.com -> amazonaws.com, x.co.uk -> x.co.uk).
    Two hosts under one registrable domain are one recipient organisation, which is
    what the dialog names; a declared `twilio.com` covers every Twilio endpoint."""
    h = h.lower().strip().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', h):
        return h
    parts = h.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu", "or", "ne") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


_PRIV_HOST_TOKEN_RX = re.compile(r'(?<![\w-])((?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?![\w-])', re.I)


def _priv_host_declared(host: str, declared: set[str]) -> bool:
    """`declared` holds every host string from the manifest. Each may be a bare host or
    free text naming several ("oauth.zettle.com / pusher.izettle.com", "pypi.org via
    pip") - every host-shaped token in it counts. Text naming no host ("the broker you
    configure") never matches a literal, as intended: a literal host in the code is
    exactly the kind of fixed recipient the block has to name."""
    rd = _priv_reg_domain(host)
    for d in declared:
        for tok in _PRIV_HOST_TOKEN_RX.findall(d.lower()):
            tok = tok.lstrip("*.")
            if host.lower() == tok or host.lower().endswith("." + tok) or _priv_reg_domain(tok) == rd:
                return True
    return False


def _priv_lines(root: str, exts=_PRIV_EXTS):
    """(relpath, lineno, line) for every code line the privacy checks look at: same
    doc/help/test/vendor exclusions as _grep, plus committed venvs, bundled UI
    libraries and minified lines (a 30 KB one-line library has no bearing on what
    the plugin does)."""
    for path in sorted(_iter_files(root, exts)):
        rel = os.path.relpath(path, root)
        low = "/" + rel.lower()
        if _skippable(rel) or any(d in low for d in _PRIV_SKIP_DIRS) or _PRIV_LIB_FILE_RX.search(os.path.basename(rel)):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if len(line) > 600 or _is_comment_line(line):
                continue
            yield rel, i, line


def _priv_split_args(text: str) -> list[str] | None:
    """Split the argument list that `text` starts with (just after the opening paren)
    at top-level commas; None if the closing paren isn't on this line. Quote- and
    paren-aware so `f(a, g(b, c), 'x,y')` is three args."""
    depth, quote, args, cur = 0, None, [], []
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append("".join(cur).strip())
                return [a for a in args if a != ""] if args != [""] else []
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    return None


_PRIV_INSTALL_HOOK_RX = re.compile(r'(^|/)(fpp_install\.sh|fpp_uninstall\.sh|fpp_upgrade\.sh|install[\w.-]*\.sh|setup[\w.-]*\.sh|Makefile|makefile)$', re.I)
_PRIV_TRAILING_COMMENT_RX = re.compile(r'''(?:^|\s)(?://|#|\*|;)\s*[^'"`]*$''')
_PRIV_URL_CMD_RX = re.compile(
    r'\b(curl|wget|git\s+clone|git\s+remote|pip3?\s+install|npm\s+(?:install|i)|add-apt-repository|ping|ssh|scp|rsync'
    r'|nc|ncat|openssl|mosquitto_(?:pub|sub)|ffmpeg|ffplay|mpv|mpg123|mplayer|cvlc|vlc|yt-dlp)\b[^#\n]*$', re.I)


# Where a URL sits in the text before it (`pre`), for the browser-side rule below.
# Attributes that are never a load (a form target, an XML namespace, a citation)
# and tags whose href is a navigation the user may click, not a fetch.
_PRIV_NONLOAD_ATTR_RX = re.compile(r'\b(action|xmlns(?::[\w-]+)?|xsi:[\w-]+|namespace|formaction|cite|ping|manifest)\s*=\s*["\']?$', re.I)
_PRIV_TAG_RX = re.compile(r'<([A-Za-z][\w-]*)\b[^<>]*$')
_PRIV_LOAD_TAGS = ("script", "link", "img", "iframe", "frame", "video", "audio", "source", "track", "embed", "object", "picture", "use", "image")
_PRIV_NAV_TAGS = ("a", "area", "form", "base")
_PRIV_SRC_ATTR_RX = re.compile(r'\b(src|srcset|poster|data-src|data-srcset|data-href|xlink:href)\s*=\s*["\']?$', re.I)
_PRIV_HREF_ATTR_RX = re.compile(r'\bhref\s*=\s*["\']?$', re.I)
# CSS `url(https://...)` and `@import "https://..."` (`@import url(...)` is the former).
# Case-sensitive so JS `new URL("https://...")` is a plain literal, not a load.
_PRIV_CSS_URL_RX = re.compile(r'(?<![\w-])url\(\s*["\']?$|@import\s+["\']$')
# Browser-side request sinks with a literal URL: fetch(), XMLHttpRequest.open(),
# jQuery's $.ajax/$.get/$.post/$.getJSON/$.getScript (positional or `url:` option),
# axios, EventSource, WebSocket, Worker, navigator.sendBeacon, importScripts.
_PRIV_JS_FETCH_RX = re.compile(
    r'(?:\bfetch|\$\.(?:ajax|get|post|getJSON|getScript)|\baxios(?:\.(?:get|post|put|patch|delete|request))?'
    r'|\bnew\s+(?:EventSource|WebSocket|Worker|SharedWorker)|\bsendBeacon|\bimportScripts)\s*\(\s*["\'`]$'
    r'|\.open\s*\(\s*["\'][A-Za-z]+["\']\s*,\s*["\'`]$'
    r'|\burl\s*:\s*["\'`]$', re.I)
# Content-Security-Policy: every host in a *-src directive is a host the page tells
# the browser it may load from - it is there because the page loads from it.
_PRIV_CSP_RX = re.compile(r'Content-Security-Policy(?:-Report-Only)?', re.I)
_PRIV_CSP_DIRECTIVE_RX = re.compile(r'\b((?:default|script|style|img|font|connect|media|frame|child|worker|manifest|prefetch|object)-src(?:-elem|-attr)?)\s+([^;"\\<]*)', re.I)
_PRIV_CSP_SOURCE_RX = re.compile(r'(?:(?:https?|wss?):)?(?://)?(\*\.)?((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::(?:\d+|\*))?(?:/\S*)?')


def _priv_url_context(pre: str) -> str | None:
    """How the URL that follows `pre` is used: "browser" when the plugin's own page
    makes the operator's browser load it (script/link/img/iframe/media `src=`/`href=`,
    CSS url()/@import, fetch()/XHR/$.ajax literals), "link" when it is a hyperlink,
    form target or namespace the browser never fetches on its own (`<a href>` - a
    link the user may click is not the plugin sending anything) or text the operator
    reads (`<code>`, a placeholder/title - _PRIV_PROSE_RX), None for a plain
    code literal handled by the server-side rules."""
    if _PRIV_NONLOAD_ATTR_RX.search(pre) or _PRIV_PROSE_RX.search(pre):
        return "link"
    m = _PRIV_TAG_RX.search(pre)
    tag = m.group(1).lower() if m else None
    if _PRIV_SRC_ATTR_RX.search(pre):
        return "link" if tag in _PRIV_NAV_TAGS else "browser"
    if _PRIV_HREF_ATTR_RX.search(pre):
        return "browser" if tag in _PRIV_LOAD_TAGS else "link"
    if tag in _PRIV_LOAD_TAGS:
        return "browser"
    if tag in _PRIV_NAV_TAGS:
        return "link"
    if _PRIV_CSS_URL_RX.search(pre) or _PRIV_JS_FETCH_RX.search(pre):
        return "browser"
    return None


# FPP serves every plugin page under etc/apache2.csp, generated at boot by
# scripts/ManageApacheContentPolicy.sh from its DEFAULT_VALUES: default-src 'self';
# script-src 'self' (+inline/eval); style-src 'self' (+inline); img-src 'self'
# blob: data:; font-src 'self' data:; object-src 'none'; connect-src 'self' plus
# FPP's own service hosts and local ws://. A directive the header does not name
# (frame-src, media-src, child-src, worker-src, manifest-src) falls back to
# default-src 'self'. So a plugin page's <script src="https://cdn...">, CDN
# stylesheet, font, badge or fetch() never leaves the browser unless the plugin's
# install hook whitelists the host with `ManageApacheContentPolicy.sh add
# <directive> <host>` - the mechanism fpp-plugin-Template's scripts/fpp_install.sh
# documents. `_priv_load_directive` says which directive governs a load;
# `_priv_csp_adds` collects what the plugin whitelists; `_priv_csp_allows` joins
# them with CSP's fallback chain (a directive the header names explicitly is NOT
# covered by default-src).
# The directives ManageApacheContentPolicy.sh will accept for `add` (its JSON
# template); anything else falls back to default-src on FPP's policy.
_PRIV_CSP_SCRIPT_KEYS = ("default-src", "img-src", "script-src", "style-src", "connect-src", "object-src", "font-src")
_PRIV_FPP_CSP_CHAIN = {
    "frame-src": ("frame-src", "child-src", "default-src"),
    "media-src": ("media-src", "default-src"),
    "worker-src": ("worker-src", "child-src", "script-src"),
    "manifest-src": ("manifest-src", "default-src"),
}
# Hosts FPP's own connect-src already names (the update check, stats, crash
# reports, the cape vendors' EEPROM lists); a browser-side fetch() to one of these
# is not blocked. api.github.com / raw.githubusercontent.com are there too, and
# exempt anyway.
_PRIV_FPP_CSP_CONNECT_HOSTS = frozenset((
    "api.falconplayer.com", "crashes.falconplayer.com", "fppstats.falconchristmas.com",
    "hansonelectronics.com.au", "www.hansonelectronics.com.au", "kulplights.com", "www.kulplights.com",
    "wiredwatts.com", "www.wiredwatts.com",
))
_PRIV_CSP_ADD_RX = re.compile(r'ManageApacheContentPolicy\.sh["\']?\s+["\']?add["\']?\s+["\']?([a-z-]+-src)["\']?\s+(\S+)', re.I)
_PRIV_FONT_EXT_RX = re.compile(r'\.(woff2?|ttf|otf|eot)(\?|#|$)', re.I)
_PRIV_IMAGE_EXT_RX = re.compile(r'\.(png|jpe?g|gif|svg|webp|avif|ico|bmp)(\?|#|$)', re.I)
_PRIV_REL_ICON_RX = re.compile(r'\brel\s*=\s*["\']?[^"\'>]*icon', re.I)
_PRIV_JS_SCRIPT_SINK_RX = re.compile(r'(?:\bimportScripts|\$\.getScript)\s*\(\s*["\'`]$', re.I)
_PRIV_JS_WORKER_SINK_RX = re.compile(r'\bnew\s+(?:Worker|SharedWorker)\s*\(\s*["\'`]$', re.I)


def _priv_load_directive(pre: str, urlpath: str) -> str:
    """The CSP directive that governs a browser-side load `_priv_url_context` called
    "browser": which tag/attribute/sink the URL sits in, and for a CSS url() or a
    <source>, the file's extension."""
    m = _PRIV_TAG_RX.search(pre)
    tag = m.group(1).lower() if m else None
    if tag == "script":
        return "script-src"
    if tag == "link":
        return "img-src" if _PRIV_REL_ICON_RX.search(pre) else "style-src"
    if tag in ("iframe", "frame"):
        return "frame-src"
    if tag in ("embed", "object"):
        return "object-src"
    if tag in ("video", "audio", "track") or (tag == "source" and not _PRIV_IMAGE_EXT_RX.search(urlpath or "")):
        return "img-src" if re.search(r'\bposter\s*=\s*["\']?$', pre, re.I) else "media-src"
    if tag in _PRIV_LOAD_TAGS:
        return "img-src"
    if _PRIV_CSS_URL_RX.search(pre):
        if pre.rstrip().endswith(("@import", '@import "', "@import '")) or re.search(r'@import\s+["\']$', pre):
            return "style-src"
        return "font-src" if _PRIV_FONT_EXT_RX.search(urlpath or "") else "img-src"
    if _PRIV_JS_SCRIPT_SINK_RX.search(pre):
        return "script-src"
    if _PRIV_JS_WORKER_SINK_RX.search(pre):
        return "worker-src"
    return "connect-src"


def _priv_csp_adds(root: str) -> dict[str, set[str]]:
    """directive -> source tokens the plugin adds to FPP's Content-Security-Policy
    with `ManageApacheContentPolicy.sh add <directive> <host>` anywhere in its code
    (install hooks, helper scripts, a PHP page shelling out). Tokens are lowercased
    with the scheme, port and path stripped; a shell variable becomes "*" (the host
    is unknowable, so it is taken to cover anything in that directive)."""
    out: dict[str, set[str]] = {}
    for _, _, line in _priv_lines(root):
        for directive, tok in _PRIV_CSP_ADD_RX.findall(line):
            tok = tok.strip("\"';)")
            if tok.startswith("$") or "${" in tok:
                tok = "*"
            elif tok in ("*", "https:", "http:", "*:"):
                tok = "*"
            else:
                tok = re.sub(r'^(?:https?|wss?):(?://)?', "", tok.lower())
                tok = re.sub(r'(?::(?:\d+|\*))?(?:/.*)?$', "", tok)
                if not tok:
                    continue
            out.setdefault(directive.lower(), set()).add(tok)
    return out


def _priv_csp_allows(adds: dict[str, set[str]], directive: str, host: str) -> bool:
    """Whether FPP's policy, plus what the plugin adds to it, lets a page served by
    FPP's Apache load `host` under `directive`."""
    host = host.lower()
    if directive == "connect-src" and host in _PRIV_FPP_CSP_CONNECT_HOSTS:
        return True
    for d in _PRIV_FPP_CSP_CHAIN.get(directive, (directive,)):
        for tok in adds.get(d, ()):
            if tok == "*":
                return True
            if tok.startswith("*."):
                if host == tok[2:] or host.endswith(tok[1:]):
                    return True
            elif host == tok:
                return True
        if d in adds:
            # In CSP a directive that is present is the whole answer for its kind of
            # load; the fallback chain only applies while it is absent.
            break
    return False


_PRIV_SERVED_EXTS = (".php", ".html", ".htm", ".inc", ".js", ".css")
# A command shown to the operator on a plugin page - inside <code>/<pre>/<kbd> or a
# placeholder/title/alt attribute - is one the operator may run, not one the plugin
# runs (Statistics-Fpp-Plugin's "sudo systemctl start mosquitto" warning, Dynamic_RDS's
# "add dtoverlay=pwm" help, fpp-zettle's "curl ... | sudo python" placeholder).
_PRIV_PROSE_RX = re.compile(r'<(?:code|pre|kbd|samp)\b[^<>]*>[^<]*$|\b(?:placeholder|title|alt|aria-label)\s*=\s*(?:"[^"]*|\'[^\']*)$', re.I)


def _priv_in_prose(rel: str, line: str, pos: int) -> bool:
    """Whether the match at `pos` of `line` in a file the web server serves sits in
    operator-facing prose (see _PRIV_PROSE_RX) rather than in code."""
    return rel.lower().endswith(_PRIV_SERVED_EXTS) and bool(_PRIV_PROSE_RX.search(line[:pos]))
_PRIV_GITHUB_HOSTS = ("github.com", "www.github.com", "raw.githubusercontent.com", "api.github.com",
                      "gist.github.com", "objects.githubusercontent.com", "codeload.github.com")


def _priv_host_exempt(host: str, where: str) -> bool:
    """Hosts that are never a `sends` recipient. GitHub (fetching code, releases,
    update checks or a package from GitHub is the same traffic FPP's own plugin
    manager already makes - spec §1, `sends[].to`; a binary fetched from there still
    has to be a `download` system change, which the install rule checks separately),
    private/loopback/LAN names, placeholder names, and - for a server-side literal
    only - the documentation hosts that turn up as spec links and license headers.
    A browser-side load is a load whoever the host is: a badge from shields.io or
    a script from code.jquery.com is the operator's browser contacting that host."""
    if "." not in host or _priv_private_host(host):
        return True
    if host in _PRIV_GITHUB_HOSTS or host.endswith(".github.io"):
        return True
    if re.search(r'yourdomain|example|your-?(?:host|server|domain)|placeholder', host):
        return True
    return where != "browser" and bool(_PRIV_DOC_HOST_RX.search(host))


def _priv_csp_hosts(line: str) -> list[str]:
    """Hosts named by the *-src directives of a Content-Security-Policy on this line
    (a PHP header() call, a meta http-equiv tag, an nginx/Apache config line)."""
    m = _PRIV_CSP_RX.search(line)
    if not m:
        return []
    out = []
    for _, sources in _PRIV_CSP_DIRECTIVE_RX.findall(line[m.end():]):
        for tok in sources.split():
            tok = tok.rstrip("'\");,")   # the closing quote of a header('...') / content='...'
            if tok.startswith(("'", "data:", "blob:", "mediastream:", "filesystem:")):
                continue
            h = _PRIV_CSP_SOURCE_RX.fullmatch(tok)
            if h:
                out.append(h.group(2).lower())
    return out


def _priv_host_hits(root: str, own_owner: str | None, csp_adds: dict[str, set[str]] | None = None,
                    own_server: bool = False) -> dict[str, tuple[str, int, str, str, str | None]]:
    """host -> (relpath, lineno, line, where, directive) for every off-box host
    literal in the plugin's code. `where` is "install" inside an install hook,
    "browser" for a host the plugin's own pages make the operator's browser load
    (`<script src>`, `<link href>`, `<img src>`, iframe/media sources, CSS
    url()/@import, fetch()/XHR/$.ajax literals, Content-Security-Policy *-src hosts
    - PLUGIN_GUIDELINES.md §14.16: a CDN, font or badge host is a `sends` entry like
    any other hostname), "blocked" for a browser-side load FPP's own
    Content-Security-Policy stops before the browser opens a connection (the plugin
    neither whitelists the host with ManageApacheContentPolicy.sh - `csp_adds`, from
    _priv_csp_adds - nor serves the page itself - `own_server`, remoteAccess != none),
    else "runtime". `directive` is the CSP directive that governs a browser-side tag
    load, None otherwise. Skips private/loopback addresses, GitHub, placeholder and
    (server-side only) documentation hosts, URLs that are hyperlinks rather than
    loads (`<a href>`, form action - a link the user may click is not the plugin
    sending anything), and URLs sitting in a trailing comment. Read files in
    README/docs are out of scope (_priv_lines)."""
    out: dict[str, tuple[str, int, str, str, str | None]] = {}
    csp_adds = csp_adds or {}
    # An install hit outranks the others (it changes the category); a browser hit
    # outranks a runtime one (its message tells the author how to word the entry);
    # a blocked load ranks below everything - a host the server also contacts is a
    # recipient whatever the page does.
    rank = {"install": 3, "browser": 2, "runtime": 1, "blocked": 0}

    def add(host, rel, i, line, where, directive=None):
        if host not in out or rank[where] > rank[out[host][3]]:
            out[host] = (rel, i, line.strip(), where, directive)

    prev: list[str] = []   # the last few lines of the current file, for split tags
    prev_rel = None
    for rel, i, line in _priv_lines(root):
        if rel != prev_rel:
            prev, prev_rel = [], rel
        where_file = "install" if _PRIV_INSTALL_HOOK_RX.search(rel) else "runtime"
        # Only a file the player's web server can serve to a browser makes a
        # browser-side load; `src=https://...` in a shell or Python file is a
        # server-side literal like any other.
        served = rel.lower().endswith(_PRIV_SERVED_EXTS) and where_file != "install"
        csp = _priv_csp_hosts(line) if served else []
        if csp:
            for host in csp:
                if not _priv_host_exempt(host, "browser"):
                    add(host, rel, i, line, "browser")
            prev.append(line)
            del prev[:-6]
            continue
        for m in _PRIV_URL_RX.finditer(line):
            pre = line[:m.start()]
            # A tag written over several lines (`<img\n    src="https://...">`)
            # leaves this line with the attribute but no tag, so the directive
            # would fall through to connect-src. Pull the tag opener in from the
            # preceding lines when the attribute is one, and keep it only when it
            # really is still open.
            if not _PRIV_TAG_RX.search(pre) and (_PRIV_SRC_ATTR_RX.search(pre) or _PRIV_HREF_ATTR_RX.search(pre)):
                joined = pre
                for back in reversed(prev[-6:]):
                    joined = back.strip() + " " + joined
                    if "<" in back:
                        break
                if _PRIV_TAG_RX.search(joined):
                    pre = joined
            ctx = _priv_url_context(pre)
            if ctx == "link":
                continue
            if _PRIV_TRAILING_COMMENT_RX.search(pre) and not re.search(r'''['"`]\s*$''', pre):
                continue
            # A code literal ("https://...", `=https://` in shell) or a command-line
            # argument (curl https://...) - not a URL sitting in UI prose or a help
            # sentence, which the user reads rather than the plugin contacting.
            if not (re.search(r'''['"`=(,:\[]\s*$''', pre) or _PRIV_URL_CMD_RX.search(pre)):
                continue
            host = m.group(2).lower()
            where = "browser" if ctx == "browser" and served else where_file
            if _priv_host_exempt(host, where):
                continue
            directive = None
            if where == "browser":
                directive = _priv_load_directive(pre, m.group(3) or "")
                if not own_server and not _priv_csp_allows(csp_adds, directive, host):
                    where = "blocked"
            add(host, rel, i, line, where, directive)
        prev.append(line)
        del prev[:-6]
    return out


# Server-side outbound network sinks whose destination is a variable, not a literal
# (literal destinations go through _priv_host_hits, which also covers browser-side
# fetch()/$.ajax with a literal URL). Deliberately no variable-destination browser
# fetch()/$.ajax here - those overwhelmingly hit FPP's own /api on the same host.
_PRIV_OUTBOUND_RX = re.compile(
    r'\bCurlManager\b|\burl(?:Get|Post|Put|Delete)\s*\(|mqtt->Publish\s*\(|->Publish\s*\(|\.publish\s*\('
    r'|\bpaho\.mqtt\b|\bcurl_exec\s*\(|\bfsockopen\s*\(|\bsocket_connect\s*\(|\bstream_socket_client\s*\('
    r'|\brequests\.(?:get|post|put|patch|delete|request)\s*\(|\burlopen\s*\(|http\.client\.HTTPS?Connection\s*\('
    r'|\bsmtplib\.|new\s+PHPMailer\b|\bmail\s*\(\s*\$|\bsendto\s*\(|\.connect\s*\(\s*\((?!\s*["\']?(?:127|localhost|0\.0))'
    r'|(?:^|[;&|(\s])(?:curl|wget)\s+(?!.*(?:localhost|127\.0\.0\.1))', re.I)
_PRIV_LOCAL_CONTEXT_RX = re.compile(r'localhost|127\.0\.0\.1|::1\b|0\.0\.0\.0|/api/|\$_SERVER|gethostname|HTTP_HOST|fppd?\b.*:\d{4}', re.I)


_PRIV_CONST_RX = re.compile(r'''^\s*(?:(?:const|final|static|var|let|my|our|define\()\s*)?[$]?([A-Za-z_]\w*)\s*(?:=|,)\s*(?:"([^"\n]*)"|'([^'\n]*)')''')


def _priv_local_consts(lines: list[str]) -> set[str]:
    """Names of the file's simple string constants (`HOST = '127.0.0.1'`, `$api =
    "http://localhost/api"`, `define('X', '...')`) whose value is localhost/FPP's
    own API - a sink or bind that names one of them is not off-box."""
    out = set()
    for l in lines:
        m = _PRIV_CONST_RX.match(l)
        if m and re.search(r'localhost|127\.0\.0\.1|::1\b|/api/', m.group(2) or m.group(3) or ""):
            out.add(m.group(1))
    return out


def _priv_names_local_const(line: str, consts: set[str]) -> bool:
    return bool(consts) and any(re.search(r'(?<![\w.])[$]?' + re.escape(c) + r'(?![\w])', line) for c in consts)


def _priv_outbound_hits(root: str, window: int = 12):
    """(relpath, lineno, line) for an outbound sink with a non-literal destination and
    no sign of localhost/FPP's own API within the previous `window` lines or the next
    three (a `curl \\` continued onto the line that carries the URL), and no use of a
    file-level constant that holds such an address."""
    for path in sorted(_iter_files(root, _CFG_SCAN_EXTS)):
        rel = os.path.relpath(path, root)
        low = "/" + rel.lower()
        if _skippable(rel) or any(d in low for d in _PRIV_SKIP_DIRS) or _PRIV_LIB_FILE_RX.search(os.path.basename(rel)):
            continue
        lines = _read(path).splitlines()
        consts = _priv_local_consts(lines)
        for i, line in enumerate(lines):
            if _is_comment_line(line) or not _PRIV_OUTBOUND_RX.search(line) or _PRIV_URL_RX.search(line):
                continue
            if any(_PRIV_LOCAL_CONTEXT_RX.search(l) for l in lines[max(0, i - window):i + 4]):
                continue
            if any(_priv_names_local_const(l, consts) for l in lines[max(0, i - window):i + 4]):
                continue
            yield rel, i + 1, line.strip()


_PRIV_PKG_SOURCE_RX = {
    # A source is ADDED: add-apt-repository, apt-key add/adv, a write (redirect, tee,
    # cp, curl -o) into sources.list.d/keyrings/trusted.gpg.d, or a Signed-By line.
    # The bare path in an echo/rm/comment is not (PulseMesh's cleanup message).
    "apt": re.compile(r'add-apt-repository\s+(?!.*(?:-r\b|--remove))|\bapt-key\s+(?:add|adv)\b'
                      r'|(?:>>?|\btee\s+(?:-a\s+)?|\bcp\s+(?:-\S+\s+)*\S+\s+|\binstall\s+(?:-\S+\s+)*\S+\s+|-o\s+|\bmv\s+\S+\s+)\s*["\']?/etc/apt/(?:sources\.list|keyrings|trusted\.gpg)'
                      r'|\bsigned-by=|gpg\s+--dearmor', re.I),
    "pip": re.compile(r'--(?:extra-)?index-url\b|\bpip\.conf\b|PIP_(?:EXTRA_)?INDEX_URL|--find-links\b|\bpip3?\s+install\s+[^#\n]*(?:git\+|https?://)', re.I),
    "npm": re.compile(r'npm\s+config\s+set\s+registry|--registry[=\s]|\.npmrc\b|npm\s+(?:install|i|ci)\s+[^#\n]*(?:git\+|https?://|github:)', re.I),
    "docker": re.compile(r'\bdocker\s+(?:pull|run|compose)\b|docker-compose\b', re.I),
    "flatpak": re.compile(r'\bflatpak\s+(?:remote-add|install)\b', re.I),
}
_PRIV_REMOTE_SCRIPT_RX = re.compile(
    r'(curl|wget)\b[^|\n]*\|\s*(sudo\s+(?:-\S+\s+)*)?(bash|sh|python3?|perl|ruby|node)\b'
    r'|\b(bash|sh|python3?|perl|ruby|node)\s*<\(\s*(curl|wget)\b|\beval\s+["\'`]?\$?\(\s*(curl|wget)\b')


def _priv_install_hits(root: str):
    """(sources, remote_script): sources is type -> (relpath, lineno, line) for a
    non-default package source being added, remote_script is a `curl | sh` hit or
    None. Plain apt/pip/npm installs are not collected: software from those is
    what the Open code light's green wording allows."""
    sources: dict[str, tuple] = {}
    remote = None
    # `rm /etc/apt/sources.list.d/old.list` is an uninstall or a cleanup of a source
    # the plugin USED to add (PulseMesh), not adding one.
    cleanup_rx = re.compile(r'\brm\s|\bunlink\b|\bapt-key\s+del\b|add-apt-repository\s+(?:-\S+\s+)*(?:-r|--remove)\b')
    for rel, i, line in _priv_lines(root, (".sh", ".py", ".php", "Makefile", ".mk")):
        for name, rx in _PRIV_PKG_SOURCE_RX.items():
            m = rx.search(line)
            if name not in sources and m and not cleanup_rx.search(line) and not _priv_in_prose(rel, line, m.start()):
                sources[name] = (rel, i, line.strip())
        m = _PRIV_REMOTE_SCRIPT_RX.search(line)
        if remote is None and m and not _priv_in_prose(rel, line, m.start()):
            remote = (rel, i, line.strip())
    return sources, remote


_PRIV_SELF_UPDATE_RX = re.compile(r'\bgit\s+(?:-C\s+\S+\s+)?(?:pull\b|reset\s+(?:-\S+\s+)*--hard\s+(?:origin|upstream)/|checkout\s+(?:-\S+\s+)*(?:origin|upstream)/|fetch\b.*&&.*\breset\s+--hard)')


def _priv_self_update_hits(root: str):
    """A `git pull` / `git reset --hard origin/<branch>` / `git checkout origin/x` in one
    of the hooks fppd runs as root (install/uninstall/upgrade/pre-post start-stop)."""
    for rel, i, line in _priv_lines(root, (".sh", ".py", ".php")):
        if os.path.basename(rel) in SUDO_SCOPE and _PRIV_SELF_UPDATE_RX.search(line):
            yield rel, i, line.strip()


# closedCode: false says everything that runs can be read by anyone. The listing
# cannot check that for a package taken from PyPI/npm/CPAN (both host closed binary
# wheels and vendor SDKs) or for a fetched binary/archive, so those get a one-time
# "confirm the source is public" nudge (review-C-policy item 13). A Debian package
# (apt/dpkg) is not collected: Debian's archive carries the source.
_PRIV_PKG_INSTALL_RX = re.compile(
    r'\b(?:(?P<mgr>pip3?|npm|pnpm|yarn|gem|cargo)\s+(?:install|i|add)|(?P<cpan>cpanm?)(?:\s+install)?)\b(?P<args>[^#\n|;&]*)', re.I)
_PRIV_FETCH_ARTEFACT_RX = re.compile(
    r'\b(?:curl|wget)\b[^#\n|]*?(?P<url>https?://[^\s\'"`)>;&|]+?\.(?:bin|so|deb|rpm|whl|jar|AppImage|run|img'
    r'|tar(?:\.(?:gz|xz|bz2|zst))?|tgz|txz|zip|7z|gz|xz|bz2|zst))(?=[\s\'"`)>;&|]|$)', re.I)
_PRIV_PKG_PAGE = {"pip": "https://pypi.org/project/{}/", "pip3": "https://pypi.org/project/{}/",
                  "npm": "https://www.npmjs.com/package/{}", "pnpm": "https://www.npmjs.com/package/{}",
                  "yarn": "https://www.npmjs.com/package/{}", "cpan": "https://metacpan.org/pod/{}",
                  "cpanm": "https://metacpan.org/pod/{}", "gem": "https://rubygems.org/gems/{}",
                  "cargo": "https://crates.io/crates/{}"}


def _priv_unverifiable_code_hits(root: str):
    """(relpath, lineno, line, what, url) for each install of code the listing
    cannot read as source: a pip/npm/cpan/gem/cargo package (url = its registry
    page) or a curl/wget of a binary/archive (url = the fetched URL). apt-get /
    dpkg installs are never collected."""
    seen: set[str] = set()
    for rel, i, line in _priv_lines(root, (".sh", ".py", ".php", "Makefile", ".mk")):
        if _PRIV_REMOTE_SCRIPT_RX.search(line):
            continue  # already a remote-exec / privacy-undeclared-install matter
        m = _PRIV_FETCH_ARTEFACT_RX.search(line)
        if m and _priv_in_prose(rel, line, m.start()):
            continue
        if m:
            url = m.group("url")
            # A GitHub release asset is not exempt: it is open code only if the
            # project publishes its source, which is exactly the one-time look asked for.
            what = url.rsplit("/", 1)[-1]
            if what not in seen:
                seen.add(what)
                yield rel, i, line.strip(), what, url
            continue
        for m in _PRIV_PKG_INSTALL_RX.finditer(line):
            if _priv_in_prose(rel, line, m.start()):
                continue
            mgr = (m.group("mgr") or m.group("cpan")).lower()
            args = m.group("args")
            if re.search(r'(?:git\+|https?://|github:)', args):
                continue  # a package source hit: privacy-undeclared-install covers it
            # Package names only: no flags, no variables or quoted paths (`--prefix "$DIR"`).
            names = [a for a in args.split() if not a.startswith(("-", "$", '"', "'")) and "=" not in a]
            if re.search(r'(?:^|\s)-r\s', args):
                names = [a for a in args.split() if a.endswith(".txt")] or names
            for name in names[:3]:
                key = f"{mgr}:{name}"
                if key in seen:
                    continue
                seen.add(key)
                base = name[0] + re.split(r'[<>=!~\[@]', name[1:], maxsplit=1)[0]  # keep a leading @scope/
                if name.endswith(".txt"):
                    yield rel, i, line.strip(), f"every {mgr} package in `{name}`", ""
                else:
                    yield rel, i, line.strip(), f"{mgr} package `{name}`", _PRIV_PKG_PAGE.get(mgr, "").format(base)


# kind -> (code pattern, words that count as declaring it). A `rm` of the file is
# an uninstall reverting, not a grant.
_PRIV_PRIVILEGE_RX = {
    "sudoers": (re.compile(r'/etc/sudoers(?:\.d)?\b|\bvisudo\b', re.I), ("sudo",)),
    "group membership": (re.compile(r'\busermod\b[^#\n]*-[aG]|\bgpasswd\s+(?:-\S+\s+)*-a\b|\badduser\s+\S+\s+\S+\s*$|\badduser\s+\S+\s+(?:video|audio|gpio|i2c|spi|dialout|plugdev|input|render|netdev|docker|sudo)\b', re.I), ("group",)),
    "kernel module": (re.compile(r'\bmodprobe\s+(?!-r\b)|/etc/modules(?:-load\.d)?\b|\bdtoverlay\b|\binsmod\b', re.I), ("module", "overlay")),
    "udev rule": (re.compile(r'/etc/udev/rules\.d\b|\budevadm\s+(?:control|trigger)\b', re.I), ("udev",)),
    "ssh key on another host": (re.compile(r'authorized_keys\b|\bssh-copy-id\b', re.I), ("authorized_keys", "ssh key", "ssh-copy-id", "key")),
    "capability / setuid": (re.compile(r'\bsetcap\b|\bchmod\s+(?:-\S+\s+)*[ugo]*\+s\b|\bchmod\s+[42]7[0-7]{2}\b', re.I), ("setcap", "setuid", "capabilit")),
}


def _priv_privilege_hits(root: str) -> dict[str, tuple[str, int, str]]:
    out: dict[str, tuple[str, int, str]] = {}
    skip_rx = re.compile(r'\brm\s|\bunlink\b|\bsed\s+(?:-\S+\s+)*-i[^#\n]*/d\b|\bgpasswd\s+(?:-\S+\s+)*-d\b|\busermod\b[^#\n]*-r\b|\bdeluser\b')
    for rel, i, line in _priv_lines(root, (".sh", ".py", ".php")):
        if skip_rx.search(line):
            continue
        for kind, (rx, _) in _PRIV_PRIVILEGE_RX.items():
            m = rx.search(line)
            if kind not in out and m and not _priv_in_prose(rel, line, m.start()):
                out[kind] = (rel, i, line.strip())
    return out


# Only sensor types with an unmistakable code signature. `presence`/`gpio-input`
# are disclosed by the author but not grepped for: a GPIO read is far too generic.
_PRIV_SENSOR_RX = {
    "camera": re.compile(r'/dev/video\d*|\bv4l2\b|v4l2src|\bpicamera2?\b|\blibcamera\b|\brpicam-(?:still|vid|hello|jpeg)\b'
                         r'|\braspi(?:still|vid)\b|cv2\.VideoCapture|\bVideoCapture\s*\(|\bnvarguscamerasrc\b|ffmpeg\s+[^#\n]*-f\s+v4l2', re.I),
    "microphone": re.compile(r'\barecord\b|\bpyaudio\b|\bsounddevice\b|\balsasrc\b|\bpulsesrc\b|SND_PCM_STREAM_CAPTURE'
                             r'|ffmpeg\s+[^#\n]*-f\s+(?:alsa|pulse)\b|\bsox\s+-d\b|\brec\s+(?:-\S+\s+)*\S+\.(?:wav|flac|mp3)\b|speech_recognition|\bvosk\.|import\s+(?:vosk|whisper|faster_whisper)\b|whisper\.load_model', re.I),
    "face-tracking": re.compile(r'\bface_recognition\b|\bmediapipe\b|\bdlib\b|haarcascade|\bFaceMesh\b|\bFaceDetection\b|\bdeepface\b|\binsightface\b', re.I),
    "body-tracking": re.compile(r'\bopenpose\b|\bposenet\b|\bmovenet\b|mp\.solutions\.pose|\bmediapipe\b|\bBlazePose\b|\bultralytics\b|\byolo\w*\b', re.I),
    "rfid": re.compile(r'\bMFRC522\b|\brfid\b|\bpn532\b|\bnfcpy\b|\blibnfc\b', re.I),
}
_PRIV_SENSOR_ALT = {"face-tracking": ("face-tracking", "body-tracking"), "body-tracking": ("body-tracking", "face-tracking")}


def _priv_sensor_hits(root: str) -> dict[str, tuple[str, int, str]]:
    out: dict[str, tuple[str, int, str]] = {}
    for rel, i, line in _priv_lines(root, _CFG_SCAN_EXTS):
        for name, rx in _PRIV_SENSOR_RX.items():
            if name not in out and rx.search(line):
                out[name] = (rel, i, line.strip())
    return out


_PRIV_LISTEN_RX = re.compile(
    r'\.bind\s*\(\s*\(|\bsocket_bind\s*\(|\bstream_socket_server\s*\(|\bbind\s*\(\s*\w+\s*,\s*\(\s*(?:const\s+)?(?:struct\s+)?sockaddr'
    r'|\.listen\s*\(\s*(?:\d+|port|PORT|\w*[Pp]ort\w*)\b|\blisten\s*\(\s*\w+\s*,\s*\d+\s*\)'
    r'|\b(?:Threading)?HTTPServer\s*\(\s*\(|\bsocketserver\.\w+Server\s*\(\s*\(|\bapp\.run\s*\(|\buvicorn\.run\s*\(|\bgunicorn\b|\bwaitress\b'
    r'|\bListenStream\s*=|\bListenDatagram\s*=|^\s*Listen\s+\d+|<VirtualHost\s+[^>]*:\d+|\bnc\s+-l\b|\bsocat\b[^#\n]*-LISTEN|python3?\s+-m\s+http\.server\b'
    r'|\bwebsockets\.serve\s*\(|\bWebSocketServer\s*\(|\bcreateServer\s*\(|\bhttp\.listen\s*\(', re.I)
_PRIV_PORT_RX = re.compile(r'(?<![\d.])(\d{2,5})(?![\d.])')


def _priv_listener_hits(root: str):
    """(relpath, lineno, line, port|None) for a server socket/listener in the plugin's
    own code, an Apache Listen/VirtualHost or a systemd .socket unit. A bind to
    127.0.0.1/localhost is skipped: not reachable off-box, so not a privacy fact."""
    exts = _CFG_SCAN_EXTS + (".conf", ".socket", ".service", ".inc")
    consts: dict[str, set[str]] = {}
    for rel, i, line in _priv_lines(root, exts):
        if not _PRIV_LISTEN_RX.search(line) or re.search(r'127\.0\.0\.1|localhost|::1\b|std::bind|\.bind\s*\(\s*this', line):
            continue
        if rel not in consts:
            consts[rel] = _priv_local_consts(_read(os.path.join(root, rel)).splitlines())
        if _priv_names_local_const(line, consts[rel]):
            continue  # HOST = '127.0.0.1' ... HTTPServer((HOST, PORT), ...)
        ports = [int(p) for p in _PRIV_PORT_RX.findall(line) if 1 <= int(p) <= 65535]
        yield rel, i, line.strip(), (ports[0] if ports else None)


_PRIV_SERVICE_RX = re.compile(r'\bsystemctl\s+(?:--\S+\s+)*(?:enable|start)\b(?:\s+--\S+)*\s+([\w@.:-]+)', re.I)
# Group 3: the crontab command installing a file/stdin (`crontab -`, `crontab x.cron`,
# not `crontab -l`) or python-crontab's CronTab() - the bare word/import is not evidence.
_PRIV_UNIT_FILE_RX = re.compile(
    r'''/etc/systemd/system/([\w@.-]+\.(?:service|socket|timer))\b|/etc/cron\.d/([\w.-]+)'''
    r'''|(\bcrontab\s+(?:-u\s+\S+\s+)?(?:-(?!l\b)|/|<|\S+\.\w+)|\bCronTab\s*\()''', re.I)


def _priv_service_hits(root: str) -> dict[str, tuple[str, int, str]]:
    """unit name -> FIRST hit for `systemctl enable/start <unit>` and for a
    unit/cron file being installed under /etc/systemd or /etc/cron.d. See
    _priv_service_hits_all for every hit."""
    return {u: hits[0] for u, hits in _priv_service_hits_all(root).items()}


def _priv_service_hits_all(root: str) -> dict[str, list[tuple[str, int, str]]]:
    out: dict[str, list[tuple[str, int, str]]] = {}
    skip_rx = re.compile(r'\brm\s|\bunlink\b|systemctl\s+(?:disable|stop)\b')
    for rel, i, line in _priv_lines(root, (".sh", ".py", ".php")):
        # an uninstall script only ever removes (`crontab -l | grep -v x | crontab -`)
        if skip_rx.search(line) or os.path.basename(rel) == "fpp_uninstall.sh":
            continue
        m = _PRIV_SERVICE_RX.search(line)
        if m and _priv_in_prose(rel, line, m.start()):
            continue
        if m:
            unit = m.group(1).lower().removesuffix(".service")
            if unit not in ("fppd", "fpp", "fppinit", "fpp_postinstall", "apache2", "nginx", "--now"):
                out.setdefault(unit, []).append((rel, i, line.strip()))
            continue
        m = _PRIV_UNIT_FILE_RX.search(line)
        if m and not _priv_in_prose(rel, line, m.start()) and (m.group(3) or re.search(r'\bcp\b|\binstall\b|\bln\s|\btee\b|>\s*["\']?/etc|file_put_contents|\bcat\b.*>', line)):
            unit = (m.group(1) or m.group(2) or "crontab").lower().removesuffix(".service")
            out.setdefault(unit, []).append((rel, i, line.strip()))
    return out


_PRIV_CORE_CFG_FILE_RX = re.compile(
    r'''media/config/(gpio\.json|schedule\.json|channeloutputs\.json|co-[\w-]+\.json|commandPresets\.json|model-overlays\.json'''
    r'''|outputprocessors\.json|channelmemorymaps|proxies|ports\.json|virtualdisplaymap|dns|interface\.\w+|fpp-network\w*|sensors\.json|events/[^'"\s]+)\b''', re.I)
# The /etc path must be the DESTINATION: the 2nd argument of cp/mv/install/ln (the
# `(?!-)` stops `cp -rf /etc/x <backup>` - a read - from matching), a redirect/tee
# target, sed -i, or a PHP/Python write call. /etc/systemd and /etc/cron are
# services; /etc/apt is the package-source check's business; sudoers, udev and
# modules are privileges'. A `>` glued to a word character is an HTML tag close
# (`<code>/etc/fpp</code>` in a settings page's help text), not a redirect.
_PRIV_ETC_WRITE_RX = re.compile(
    r'''(?:\bsed\s+(?:-\S+\s+)*-i|(?<![-=<&0-9\w])>>?\s*|\btee\s+(?:-a\s+)?|\b(?:cp|mv|install|ln)\s+(?:-\S+\s+)*(?!-)\S+\s+|file_put_contents\s*\(\s*|\bopen\s*\(\s*)['"]?(/etc/(?!systemd/|cron|apt/|sudoers|udev/|modules)[^'"\s;&|)<]+)''')
_PRIV_SETTINGS_FILE_WRITE_RX = re.compile(r'''(\bsed\s+(?:-\S+\s+)*-i\b[^#\n]*|>>?\s*['"]?[^'"\s]*|\btee\s+(?:-a\s+)?['"]?[^'"\s]*)media/settings\b''')
# Same write-sink-destination shape as _PRIV_ETC_WRITE_RX, aimed at FPP's other
# shared media subdirectories instead of /etc - a file a plugin drops into
# media/scripts (shows up in FPP's own Scripts UI, still schedulable after the
# plugin is gone) or media/images/videos/etc (an orphaned asset) survives
# uninstall exactly like a stray /etc file does, for the same reason: neither
# lives inside the plugin's own directory, which is all FPP's uninstall
# actually deletes. plugins/, plugindata/<repo>/, config/ and logs/ are a
# plugin's own territory (not in this alternation at all, so never match) -
# this is specifically the OTHER shared subdirectories. Confirmed real via
# fpp-PictureFrame (cp .../CheckForNewPictureFrameImages.sh media/scripts/),
# both shipping no fpp_uninstall.sh at all.
_PRIV_MEDIA_WRITE_RX = re.compile(
    r'''(?:\bsed\s+(?:-\S+\s+)*-i|(?<![-=<&0-9\w])>>?\s*|\btee\s+(?:-a\s+)?|\b(?:cp|mv|install|ln)\s+(?:-\S+\s+)*(?!-)\S+\s+|file_put_contents\s*\(\s*|\bopen\s*\(\s*)'''
    r'''['"]?(/home/fpp/media/(?:scripts|images|videos|sequences|music|effects|upload|playlists)/[^'"\s;&|)<]*)''')
# One hop of variable aliasing, same pattern as _log_naming_hits: a variable
# assigned a literal path under one of these subdirectories on an earlier
# line is treated as that path on a later write-sink line too. Confirmed
# real miss without this: fpp-jukebox assigns
# `PLACEHOLDERIMAGE=/home/fpp/media/images/placeholder.jpg` on one line,
# then `cp ... "${PLACEHOLDERIMAGE}"` on another - invisible to the same-
# line-only regex above.
_PRIV_MEDIA_DEST_ALIAS_RX = re.compile(
    r'''^\s*(?:local\s+|export\s+|readonly\s+)?\$?(\w+)\s*=\s*["']?'''
    r'''(/home/fpp/media/(?:scripts|images|videos|sequences|music|effects|upload|playlists)(?:/[^\s"']*)?)["']?\s*$''')


def _priv_media_alias_sink_rx(name: str) -> "re.Pattern[str]":
    """A write sink whose DESTINATION is `$name` / `${name}` / PHP `$name` -
    the same argument-position rule _PRIV_MEDIA_WRITE_RX applies to a literal
    path, so `cp "$PLACEHOLDER" ./assets/` (a read of the aliased path) doesn't
    count. Quoted or not, braces or not."""
    var = r'''["']?\$\{?''' + re.escape(name) + r'''\b'''
    return re.compile(
        r'\b(?:cp|mv|install|ln)\s+(?:-\S+\s+)*(?!-)\S+\s+' + var
        + r'|(?<![-=<&0-9\w])>>?\s*' + var
        + r'|\btee\s+(?:-a\s+)?' + var
        + r'|\bsed\s+(?:-\S+\s+)*-i\b[^#\n]*\s' + var
        + r'|(?:file_put_contents|open)\s*\(\s*' + var)


def _priv_media_write_hits(root: str, exts=_CFG_SCAN_EXTS):
    """Yield (relpath, lineno, line, path) for a write-sink destination that
    lands in one of FPP's other shared media subdirectories, following one
    hop of variable aliasing within the same file (see _PRIV_MEDIA_DEST_ALIAS_RX)."""
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        aliases: dict[str, tuple[str, "re.Pattern[str]"]] = {}
        for i, line in enumerate(_read(path).splitlines(), 1):
            if _is_comment_line(line):
                continue
            m = _PRIV_MEDIA_WRITE_RX.search(line)
            if m and not _priv_in_prose(rel, line, m.start(1)):
                yield rel, i, line.strip(), m.group(1)
                continue
            am = _PRIV_MEDIA_DEST_ALIAS_RX.match(line)
            if am:
                aliases[am.group(1)] = (am.group(2), _priv_media_alias_sink_rx(am.group(1)))
                continue
            for name, (target, sink_rx) in aliases.items():
                sm = sink_rx.search(line)
                if sm and not _priv_in_prose(rel, line, sm.start()):
                    yield rel, i, line.strip(), target
                    break


def _priv_core_write_hits(root: str):
    """(relpath, lineno, line, target) for a write the plugin makes to configuration it
    does not own: a 2-argument WriteSettingToFile (core settings, not the plugin's own
    file), a PUT/POST to /api/settings/<key>, sed/redirect into the settings file, a
    write sink on one of FPP's own config/ files, or a write under /etc/ (systemd and
    cron are services, handled by _priv_service_hits). restartFlag/rebootFlag are
    transient and have their own rules."""
    skip_rx = re.compile(r'\brm\s|\bunlink\s*\(|\brmdir\b')
    for rel, i, line in _priv_lines(root, _CFG_SCAN_EXTS):
        if skip_rx.search(line):
            continue
        for m in re.finditer(r'\bWriteSettingToFile\s*\(', line):
            args = _priv_split_args(line[m.end():])
            if args is not None and len(args) == 2:
                key = args[0].strip("'\" ")
                if key not in ("restartFlag", "rebootFlag") + _PRIVACY_SETTING_KEYS and re.match(r'^[\w-]+$', key):
                    yield rel, i, line.strip(), "settings:" + key
        m = re.search(r'/api/settings/([\w-]+)', line)
        if m and m.group(1) not in ("restartFlag", "rebootFlag") + _PRIVACY_SETTING_KEYS \
           and re.search(r'\bPUT\b|\bPOST\b|requests\.(?:put|post)|method\s*[:=]\s*["\']P|type\s*:\s*["\']P|-X\s*P|\$\.post\b|\.put\s*\(', line):
            yield rel, i, line.strip(), "settings:" + m.group(1)
        if re.search(r'\bsetSetting\s*\(\s*["\']([\w-]+)', line) and not rel.endswith((".js",)):
            key = re.search(r'\bsetSetting\s*\(\s*["\']([\w-]+)', line).group(1)
            if key not in ("restartFlag", "rebootFlag") + _PRIVACY_SETTING_KEYS:
                yield rel, i, line.strip(), "settings:" + key
        if _PRIV_SETTINGS_FILE_WRITE_RX.search(line) and not _PRIVACY_SETTING_RX.search(line):
            yield rel, i, line.strip(), "settings"
        m = _PRIV_CORE_CFG_FILE_RX.search(line)
        if m and not _priv_in_prose(rel, line, m.start()) and (_CFG_WRITE_SINK_RX.search(line) or _CFG_DEST_PREFIX_RX.search(line[:m.start()]) or re.search(r'\bsed\s+(?:-\S+\s+)*-i', line)):
            yield rel, i, line.strip(), "config/" + m.group(1)
        m = _PRIV_ETC_WRITE_RX.search(line)
        if m and not _priv_in_prose(rel, line, m.start(1)) and not (rel.endswith(".py") and "open(" in line and not re.search(r'''open\s*\(\s*['"]/etc/[^'"]+['"]\s*,\s*['"][wax]''', line)):
            yield rel, i, line.strip(), m.group(1)


_PRIV_SETTING_CALL_RX = re.compile(r'\b(ReadSettingFromFile|WriteSettingToFile|getSetting|GetSetting)\s*\(\s*(["\'])([\w.-]+)\2', re.I)
_PRIV_SETTING_INDEX_RX = re.compile(r'\$settings\s*\[\s*(["\'])([\w.-]+)\1\s*\]')


def _priv_core_credential_hits(root: str) -> dict[str, tuple]:
    """key -> hit for a read of one of FPP's credential settings
    (_CORE_CREDENTIAL_KEYS): a 1-argument ReadSettingFromFile/getSetting (the
    2-argument form reads the plugin's OWN file under that key name, not FPP's),
    `$settings['MQTTPassword']`, or a GET of /api/settings/<key>."""
    core: dict[str, tuple] = {}
    for rel, i, line in _priv_lines(root, _CFG_SCAN_EXTS):
        for m in _PRIV_SETTING_CALL_RX.finditer(line):
            key = m.group(3)
            args = _priv_split_args(line[m.start(2):])
            nargs = len(args) if args is not None else 1
            if nargs == 1 and key in _CORE_CREDENTIAL_KEYS:
                core.setdefault(key, (rel, i, line.strip()))
        for m in _PRIV_SETTING_INDEX_RX.finditer(line):
            if m.group(2) in _CORE_CREDENTIAL_KEYS:
                core.setdefault(m.group(2), (rel, i, line.strip()))
        m = re.search(r'/api/settings/(' + "|".join(_CORE_CREDENTIAL_KEYS) + r')\b', line)
        if m:
            core.setdefault(m.group(1), (rel, i, line.strip()))
    return core


_PRIV_SETTING_WRITE_RX = re.compile(
    r'\b(?:WriteSettingToFile|setSetting|SetSetting|setSettingValue|SetSettingValue|writeSetting|saveSetting|putSetting)\s*\('
    r'|\bsed\s|(?<![-=<&0-9])>>?\s|\btee\s|\bPUT\b|\bPOST\b|requests\.(?:put|post)|\$\.post\b|method\s*[:=]\s*["\']P|type\s*:\s*["\']P|-X\s*P'
    r'|\bsettings\s*\[\s*["\'][\w]+["\']\s*\]\s*=[^=]|setSettingsAndRestart|SaveSettings?\b', re.I)


def _privacy_setting_hits(root: str):
    """(relpath, lineno, line, key, is_write) for every non-comment code line naming one
    of FPP's eight privacy settings. `is_write` when the line has a write-shaped sink
    (WriteSettingToFile/setSetting, PUT/POST to /api/settings, sed/redirect/tee, an
    assignment into $settings[]). A 3-argument WriteSettingToFile writes the plugin's
    OWN file under that key name, not FPP's, and is not counted at all."""
    for rel, i, line in _priv_lines(root, _CFG_SCAN_EXTS):
        m = _PRIVACY_SETTING_RX.search(line)
        if not m:
            continue
        key = m.group(1)
        w = re.search(r'\bWriteSettingToFile\s*\(', line)
        if w:
            args = _priv_split_args(line[w.end():])
            if args is not None and len(args) >= 3:
                continue
        yield rel, i, line.strip(), key, bool(_PRIV_SETTING_WRITE_RX.search(line))


def _privacy_findings(root: str, info: dict | None, own_owner: str | None) -> list[Finding]:
    """The privacy-* rule family (PLUGIN_GUIDELINES.md §14.16). Without a `privacy`
    block: one privacy-missing BLOCKER. With one:
    privacy-unknown-key (BLOCKER) for a key outside the v3 vocabulary,
    privacy-text-length (BEST_PRACTICE) for the §1 length caps,
    privacy-closedcode-unverified (BEST_PRACTICE) when closedCode is false but a
    pip/npm/cpan package or fetched binary/archive is installed, and a
    privacy-undeclared-<category> BLOCKER per category where the code contradicts
    the declaration. Independently of the block: privacy-setting-write/read on
    FPP's own privacy settings."""
    out: list[Finding] = []

    def loc(h):
        return f"{h[0]}:{h[1]}: `{h[2]}`" if h[1] else f"{h[0]}: `{h[2]}`"

    # --- FPP's privacy settings: never written, ideally never read -----------
    # A plugin writing statsPublish makes FPP transmit on the operator's behalf
    # within two minutes; the consent record and jurisdiction are the operator's
    # alone. BLOCKER on a write; a read is BEST PRACTICE since it can be an
    # innocent "is the operator OK with sending?" gate, but the plugin should ask
    # for its own consent rather than borrow FPP's (PLUGIN_GUIDELINES.md §14 rule 9).
    writes = [h for h in _privacy_setting_hits(root) if h[4]]
    reads = [h for h in _privacy_setting_hits(root) if not h[4]]
    if writes:
        h = writes[0]
        out.append(Finding(BLOCKER, "privacy-setting-write",
                   f"writes FPP's privacy setting `{h[3]}` ({loc(h)}) - plugins may never change "
                   f"{', '.join(_PRIVACY_SETTING_KEYS)}: they record the operator's own consent, and a "
                   f"write to statsPublish makes FPP transmit on the operator's behalf within two minutes.\n"
                   f"  - Remove the write; if the plugin needs the operator's consent for its own traffic, "
                   f"ask for it with its own setting"))
    if reads:
        h = reads[0]
        out.append(Finding(BEST_PRACTICE, "privacy-setting-read",
                   f"reads FPP's privacy setting `{h[3]}` ({loc(h)}) - FPP's consent settings are the "
                   f"operator's answer to FPP, not to the plugin; a plugin that sends anything needs its "
                   f"own opt-in (PLUGIN_GUIDELINES.md §14).\n"
                   f"  - Gate the plugin's own traffic on its own enable setting, off by default"))

    if info is None:
        return out
    pv = info.get("privacy")
    if not isinstance(pv, dict):
        out.append(Finding(BLOCKER, "privacy-missing",
                   "pluginInfo.json has no `privacy` block - FPP builds the install dialog's privacy "
                   "lights (Sends data, Collects data, Camera & mic, Remote access, System changes, "
                   "Can it be checked?) from it, and without one the dialog says \"No privacy disclosure\".\n"
                   "  - Add the block (eight keys, all required, empty arrays allowed; see the `privacy` "
                   "section of pluginInfo.schema.json and PLUGIN_GUIDELINES.md §14). Every listed "
                   "plugin must carry one, so this blocks the listing"))
        return out

    # fpp-plugin-Template ships its block with "TEMPLATE TEXT - replace me" in
    # `summary` and `other` so an unedited fork can't pass as a "runs on this device
    # only" plugin (the seven structural keys ARE the do-nothing answer, so nothing
    # else distinguishes the two). Those strings are end-user text in the install
    # dialog, so they must never reach the Plugin Manager: blocker, not best practice.
    template_fields = [k for k in ("summary", "other")
                       if isinstance(pv.get(k), str) and _PRIV_TEMPLATE_MARK in pv[k].lower()]
    if template_fields:
        out.append(Finding(BLOCKER, "privacy-template-text",
                   f"`privacy.{'` and `privacy.'.join(template_fields)}` still carry fpp-plugin-Template's "
                   f"\"TEMPLATE TEXT - replace me\" placeholder - the block was never filled in, and FPP "
                   f"would show that text to everyone in the install dialog.\n"
                   f"  - Describe what this plugin actually does with data (the Privacy disclosure builder at "
                   f"https://falconchristmas.github.io/fpp-data/plugin_privacy_builder/ walks through it); if it "
                   f"truly does nothing off this device, `summary` is \"Runs on this device only.\" and "
                   f"`other` is \"none\""))
        return out

    def undeclared(category, msg, fix):
        out.append(Finding(BLOCKER, f"privacy-undeclared-{category}",
                   f"{msg} but the pluginInfo.json `privacy` block doesn't declare it.\n  - {fix}"))

    # --- vocabulary: the eight keys and the keys inside each object ------------
    # The schema rejects these too, but a schema error names a JSON path; this
    # names the key and what the v3 block calls it.
    unknown = [k for k in pv if k not in _PRIV_V3_KEYS]
    for key, allowed in _PRIV_V3_ITEM_KEYS.items():
        for n, item in enumerate(pv.get(key) or []):
            if isinstance(item, dict):
                unknown.extend(f"{key}[{n}].{k}" for k in item if k not in allowed)
    if unknown:
        hints = [f"`{k}`" + (f" ({_PRIV_V2_KEY_HINTS[k]})" if k in _PRIV_V2_KEY_HINTS else "") for k in unknown[:8]]
        out.append(Finding(BLOCKER, "privacy-unknown-key",
                   f"the pluginInfo.json `privacy` block has {len(unknown)} key(s) outside the v3 vocabulary: "
                   f"{', '.join(hints)}{' ...' if len(unknown) > 8 else ''}. FPP ignores unknown keys and the "
                   "listing rejects them.\n"
                   "  - The block has exactly eight keys - summary, sends[to, what, why, alwaysOn], "
                   "collects[what, about, keptDays, canDelete, where], sensors[type, stored], remoteAccess, "
                   "systemChanges[kind, what], closedCode, other; put anything else in `other` "
                   "(PLUGININFO_FORMAT.md, `privacy` section)"))

    def g(key, default=None):
        v = pv.get(key)
        return v if v is not None else default

    def items(key):
        return [x for x in (g(key, []) or []) if isinstance(x, dict)]

    def changes(*kinds):
        return [str(c.get("what", "")) for c in items("systemChanges") if c.get("kind") in kinds]

    # --- length caps (soft: warn, never block - PLUGININFO_FORMAT.md `privacy` length caps) ----
    over = []
    if len(str(g("summary", ""))) > _PRIV_LEN_SUMMARY:
        over.append(f"summary ({len(str(g('summary')))} > {_PRIV_LEN_SUMMARY})")
    for n, s in enumerate(items("sends")):
        for f in ("what", "why"):
            if len(str(s.get(f, ""))) > _PRIV_LEN_TEXT:
                over.append(f"sends[{n}].{f} ({len(str(s.get(f)))} > {_PRIV_LEN_TEXT})")
    for n, c in enumerate(items("collects")):
        if len(str(c.get("what", ""))) > _PRIV_LEN_TEXT:
            over.append(f"collects[{n}].what ({len(str(c.get('what')))} > {_PRIV_LEN_TEXT})")
    for n, c in enumerate(items("systemChanges")):
        if len(str(c.get("what", ""))) > _PRIV_LEN_CHANGE:
            over.append(f"systemChanges[{n}].what ({len(str(c.get('what')))} > {_PRIV_LEN_CHANGE})")
    if over:
        out.append(Finding(BEST_PRACTICE, "privacy-text-length",
                   f"{len(over)} privacy text(s) exceed the install-dialog caps: {', '.join(over[:6])}"
                   f"{' ...' if len(over) > 6 else ''}. FPP shows every word under its light - nothing is cut "
                   "off - so a paragraph here makes the install dialog long.\n"
                   f"  - Keep summary to {_PRIV_LEN_SUMMARY} characters, sends[].what/why and collects[].what to "
                   f"{_PRIV_LEN_TEXT}, systemChanges[].what to {_PRIV_LEN_CHANGE}; the detail goes in `other`"))

    # --- sends / install fetches ------------------------------------------------
    # Runtime hosts in the code are matched against every host-shaped token in
    # sends[].to (an `http://` prefix is just a flag); install-hook hosts against
    # the `what` of download / package-source changes. A `to` that is a phrase
    # ("your MQTT broker") never matches a literal - the literal is exactly the
    # fixed destination the block has to name - but it does cover the code sending
    # to a destination the operator typed (a variable, not a literal).
    sends = items("sends")
    declared_to = {re.sub(r'^https?://', "", str(s.get("to", ""))) for s in sends if s.get("to")}
    declared_fetch = set(changes("download", "package-source"))
    # A download / package-source entry naming no host at all ("downloads a prebuilt
    # binary") is generic and covers any install-time fetch.
    generic_fetch = any(not _PRIV_HOST_TOKEN_RX.search(w) for w in declared_fetch)
    # A page served by the plugin's own listener (remoteAccess != none) is not
    # under FPP's Content-Security-Policy, so every load in it is real.
    own_server = str(g("remoteAccess", "none")) not in ("none", "None", "")
    hosts = _priv_host_hits(root, own_owner, _priv_csp_adds(root), own_server)
    missing_rt = sorted((h, v) for h, v in hosts.items() if v[3] == "runtime" and not _priv_host_declared(h, declared_to))
    if missing_rt:
        h, v = missing_rt[0]
        more = f" (+{len(missing_rt) - 1} more: {', '.join(x for x, _ in missing_rt[1:6])})" if len(missing_rt) > 1 else ""
        undeclared("recipients", f"the code contacts `{h}` ({loc(v)}){more}",
                   "Add a `sends` entry with `to` = that host (or its registrable domain), what is sent, why, and alwaysOn")
    # A CDN, font, badge or API host the plugin's own page makes the operator's
    # browser load is a recipient like any other (spec §1, decided 14 Sep: no
    # carve-out) - the browser hands that host its address on every page view.
    # But only when the load happens: FPP serves plugin pages under its own
    # Content-Security-Policy (script-src 'self', style-src 'self', font-src 'self'
    # data:, img-src 'self' data: blob:, connect-src 'self' + FPP's hosts, and
    # default-src 'self' for the rest), so a host the plugin neither whitelists
    # with `ManageApacheContentPolicy.sh add` nor serves from its own listener is
    # a dead tag, not a recipient - `_priv_host_hits` files those as "blocked".
    missing_br = sorted((h, v) for h, v in hosts.items() if v[3] == "browser" and not _priv_host_declared(h, declared_to))
    if missing_br:
        h, v = missing_br[0]
        more = f" (+{len(missing_br) - 1} more: {', '.join(x for x, _ in missing_br[1:6])})" if len(missing_br) > 1 else ""
        undeclared("recipients", f"{v[0]}:{v[1]} loads https://{h} (browser-side: `{v[2]}`){more}",
                   "Declare it in privacy.sends with `to` = that host, what: \"your browser's address\", why = what "
                   "it loads (\"page styling\", \"chart library\", \"status badge\"), alwaysOn: true if the page "
                   "loads it unasked - or bundle the file with the plugin so the browser never leaves the player, "
                   "or, for a README-style badge or logo, just remove it")
    blocked = sorted((h, v) for h, v in hosts.items() if v[3] == "blocked")
    if blocked:
        h, v = blocked[0]
        # Name where each extra host is loaded from, not just the host: with the
        # first hit sitting in an unused mockup file (fpp-jukebox locked.html,
        # 2026-09) a bare host list hid that the others were on a live page.
        more = (f" (+{len(blocked) - 1} more: {', '.join(f'{x} at {w[0]}:{w[1]}' for x, w in blocked[1:6])})"
                if len(blocked) > 1 else "")
        declared_note = (" privacy.sends already names it - that entry describes traffic that does not happen."
                         if _priv_host_declared(h, declared_to) else "")
        # ManageApacheContentPolicy.sh knows seven keys; a directive it does not
        # keep (frame-src, media-src, worker-src...) is governed by default-src
        # on FPP's policy, so that is the key to tell the author to add.
        add_key = v[4] if v[4] in _PRIV_CSP_SCRIPT_KEYS else "default-src"
        out.append(Finding(BEST_PRACTICE, "privacy-csp-blocked-load",
                   f"{v[0]}:{v[1]} loads https://{h} (`{v[2]}`){more} but FPP's Content-Security-Policy "
                   f"blocks it, so it never loads - the page is served under `{v[4]} 'self'` and nothing "
                   f"in the plugin whitelists the host.{declared_note}\n"
                   f"  - Bundle the file with the plugin or remove the tag; if you do want it, add it with "
                   f"`${{FPPDIR}}/scripts/ManageApacheContentPolicy.sh add {add_key} https://{h}` in "
                   f"scripts/fpp_install.sh and declare it in privacy.sends (to: \"{h}\", what: \"your "
                   f"browser's address\")"))
    if not generic_fetch:
        missing_in = sorted((h, v) for h, v in hosts.items() if v[3] == "install" and not _priv_host_declared(h, declared_fetch | declared_to))
        if missing_in:
            h, v = missing_in[0]
            more = f" (+{len(missing_in) - 1} more: {', '.join(x for x, _ in missing_in[1:6])})" if len(missing_in) > 1 else ""
            undeclared("install", f"an install hook fetches from `{h}` ({loc(v)}){more}",
                       "Add a `systemChanges` entry of kind \"download\" (a file, model, binary or clone) or "
                       "\"package-source\" (an apt/pip/npm source) whose `what` names the host")
    if not sends and not any(v[3] in ("runtime", "browser") for v in hosts.values()):
        hit = next(iter(_priv_outbound_hits(root)), None)
        if hit:
            undeclared("recipients",
                       f"`sends` is empty (\"sends nothing\") but the code sends over the network ({loc(hit)})",
                       "Declare the destination, even when the operator types it in (to: \"your MQTT broker\"); "
                       "traffic through FPP's helpers (CurlManager, urlGet, core MQTT, MultiSync) is the plugin's traffic")

    # --- install: package sources, curl | sh, extra packages --------------------
    sources, remote = _priv_install_hits(root)
    declared_sources = changes("package-source")
    for name, hit in sorted(sources.items()):
        if not declared_sources:
            undeclared("install", f"adds a {name} package source ({loc(hit)})",
                       "Add a `systemChanges` entry of kind \"package-source\" naming the source and the packages taken "
                       "from it - and pin, sign and remove it as PLUGIN_GUIDELINES.md §14 requires")
            break
    declared_downloads = changes("download")
    if remote and not declared_downloads:
        undeclared("install", f"pipes a downloaded script into an interpreter ({loc(remote)})",
                   "Add a `systemChanges` entry of kind \"download\" naming what is fetched and run - and see the "
                   "remote-exec finding: this is not allowed at all")
    # Packages from a public package source (apt/pip/npm/CPAN) are not a download
    # (the Open code light's green wording) - only a non-default
    # source, a fetched file/binary/clone or a piped installer is.
    # Self-update: a hook that pulls or resets to origin runs the newest code on the
    # author's branch, not the commit FPP pinned (haCommands, sled-mailbox, ExternalFPP).
    if not declared_downloads and not any("update" in t.lower() for t in changes(*_PRIV_V3_KINDS) + [str(g("other", ""))]):
        hit = next(iter(_priv_self_update_hits(root)), None)
        if hit:
            undeclared("selfupdate", f"an install/start hook updates the plugin's own checkout ({loc(hit)})",
                       "Add a `systemChanges` entry of kind \"download\" (\"updates itself from GitHub at every start\") - "
                       "better, remove it: FPP's upgrade path installs the pinned `sha`, and a hook that resets to "
                       "origin makes the listed version meaningless")

    # --- sensors ----------------------------------------------------------
    declared_sensors = {str(s.get("type")) for s in items("sensors")}
    for name, hit in sorted(_priv_sensor_hits(root).items()):
        if not any(t in declared_sensors for t in _PRIV_SENSOR_ALT.get(name, (name,))):
            undeclared("sensors", f"the code reads a {name.replace('-', ' ')} source ({loc(hit)})",
                       f"Add a `sensors` entry with type \"{name}\" and whether what it captures is stored; a stream that "
                       "leaves the device is also a `sends` entry")
            break

    # --- listeners → remoteAccess ------------------------------------------------
    # Routes on FPP's own web server are not listeners (and the hit finder skips a
    # bind to localhost), so any hit means the plugin opens its own port. A
    # `network` or `tunnel` system change also declares it (spec §1: remoteAccess
    # is the listener's reach, systemChanges what was installed to get there).
    if g("remoteAccess") == "none" and not changes("network", "tunnel"):
        hit = next(iter(_priv_listener_hits(root)), None)
        if hit:
            port = f" on port {hit[3]}" if hit[3] else ""
            undeclared("listeners", f"the code opens a listening socket{port} ({loc(hit)}) while `remoteAccess` is \"none\" "
                       "and no `systemChanges` entry of kind \"network\" or \"tunnel\" names it",
                       "Set `remoteAccess` to \"lan\", \"internet-authenticated\", \"internet-open\", \"exposes-fpp\" or "
                       "\"tunnel\" - whichever is the widest reach of the plugin's own listener - and/or add a "
                       "`systemChanges` entry of kind \"network\" (LAN port) or \"tunnel\" saying what was opened")

    # --- services ----------------------------------------------------------
    declared_services = [w.lower() for w in changes("service")]
    for unit, hit in sorted(_priv_service_hits(root).items()):
        if not any(unit in d or d.removesuffix(".service") in unit for d in declared_services):
            undeclared("services", f"the code enables or installs the service `{unit}` ({loc(hit)})",
                       f"Add a `systemChanges` entry of kind \"service\" naming `{unit}` (and revert it in fpp_uninstall.sh)")
            break

    # --- core config writes ----------------------------------------------------
    # An /etc file may be declared under a service or network change instead:
    # "apache2 conf rule added" covers /etc/apache2/conf-enabled/x.conf, "installs
    # and configures mpd" covers /etc/mpd.conf. A settings key must be named in a
    # core-settings `what` ("settings:MQTTHost" or just the key).
    declared_core = [w.lower() for w in changes("core-settings")]
    declared_host = declared_core + declared_services + [w.lower() for w in changes("network")]
    for hit in _priv_core_write_hits(root):
        target = hit[3]
        tl = target.lower()
        if tl.startswith("settings:"):
            tokens, pool = {tl, tl.split(":", 1)[1]}, declared_core
        elif tl.startswith("/etc/"):
            base = os.path.basename(tl)
            tokens, pool = {tl, base, base.rsplit(".", 1)[0], tl.split("/")[2]}, declared_host
        else:
            tokens, pool = {tl, os.path.basename(tl)}, declared_core
        if not any(t in d for t in tokens if len(t) > 2 for d in pool):
            what = f"FPP setting `{target[9:]}`" if target.startswith("settings:") else f"`{target}`"
            undeclared("core-config", f"the code writes {what} ({loc(hit)})",
                       f"Add a `systemChanges` entry of kind \"core-settings\" naming \"{target}\" (and revert it in fpp_uninstall.sh)")
            break

    # --- credentials ----------------------------------------------------------
    # The plugin's OWN credentials are covered by its settings.json `type:
    # password` (the crash bundler reads that); only a read of FPP's credential
    # settings is a declaration matter.
    if not changes("reads-core-credentials"):
        for key, hit in sorted(_priv_core_credential_hits(root).items()):
            undeclared("credentials", f"the code reads FPP's `{key}` setting ({loc(hit)})",
                       "Add a `systemChanges` entry of kind \"reads-core-credentials\" saying which of FPP's credentials it "
                       "reads - and only read it if the stated purpose cannot work without it")
            break

    # --- privileges ----------------------------------------------------------
    privilege_pool = [w.lower() for w in changes("privilege")]
    for kind, hit in sorted(_priv_privilege_hits(root).items()):
        words = _PRIV_PRIVILEGE_RX[kind][1]
        if not any(w in d for w in words for d in privilege_pool):
            undeclared("privileges", f"the code changes host privileges - {kind} ({loc(hit)})",
                       "Add a `systemChanges` entry of kind \"privilege\" saying what is granted (\"adds fpp to the video "
                       "group\", \"sudoers rule for systemctl\") and whether fpp_uninstall.sh reverts it")
            break

    # --- closedCode: false but the listing cannot read what is installed ---------
    # A package from PyPI/npm/CPAN counts as open code only when its source is
    # published (a closed wheel or vendor SDK is closed code); a fetched binary or
    # archive is open only if its source is. Neither is checkable here, so the
    # reviewer is asked to look once. BEST_PRACTICE: the block may well be right.
    if g("closedCode") is False:
        unverified = list(_priv_unverifiable_code_hits(root))
        if unverified:
            rel, i, line, what, url = unverified[0]
            asks = [f"the source of {w} is public" + (f" at {u}" if u else "") for _, _, _, w, u in unverified[:4]]
            more = f" (+{len(unverified) - 4} more)" if len(unverified) > 4 else ""
            out.append(Finding(BEST_PRACTICE, "privacy-closedcode-unverified",
                       f"`closedCode` is false but the plugin installs code the listing check cannot read as source "
                       f"({loc((rel, i, line))}){' (+' + str(len(unverified) - 1) + ' more)' if len(unverified) > 1 else ''} - "
                       f"a package from PyPI/npm/CPAN or a fetched binary is open code only if its source is published.\n"
                       f"  - Confirm {'; '.join(asks)}{more}; if any of it has no public source, set `closedCode` to true"))

    return out


# `set -e` placement (no-set-e). Only comments, blank lines, other `set`/`shopt`
# calls, plain variable assignments (`FOO=bar`, `export FOO=bar`, `: "${FOO:=x}"`)
# and `trap` are allowed to precede it - none of those is a step that can fail
# and leave the install half-done. Everything else counts as an unguarded command.
# `set -e`, `set -euo pipefail`, `set -o errexit`, `set -o pipefail -e`,
# `set -o nounset -o errexit` - any mix of short and -o options with errexit
# somewhere in it.
_SET_E_RX = re.compile(r'^\s*set\s+(?:-o\s+\w+\s+|-[a-zA-Z]+\s+)*(?:-[a-zA-Z]*e[a-zA-Z]*\b|-o\s+errexit\b)')
# A value that can follow FOO= and still be "just an assignment" (no command
# run): a quoted string, a $(...)/`...` substitution, or a bare word - anything
# that leaves the line with nothing else on it. `DEBIAN_FRONTEND=x apt-get ...`
# (an env prefix on a real command) is NOT this: it has a command after it.
_SET_E_ASSIGN_VALUE = (r'(?:"(?:[^"\\]|\\.)*"|\'[^\']*\'|\$\([^\n]*\)|`[^`\n]*`'
                       r'|\([^)\n]*\)|[^\s"\'`()]|\\\s)*')
_SET_E_PREAMBLE_RX = re.compile(
    r'^\s*(?:'
    r'(?:set|shopt|trap|umask|cd)\b'                          # other shell options / traps / cwd
    r'|(?:export\s+|declare\s+[-\w ]*|typeset\s+[-\w ]*|readonly\s+|local\s+)?[A-Za-z_]\w*=' + _SET_E_ASSIGN_VALUE + r'\s*(?:#.*)?$'
    r'|(?:export|readonly)\s+[A-Za-z_]\w*\s*$'                # export FOO (already assigned)
    r'|:\s'                                                   # : "${FOO:=default}"
    r'|(?:if|elif|while|until|for|case|select)\b'             # a condition is exempt from errexit by definition
    r'|[\w|*"\'$\[\]{},.-]+\)\s*(?:;;)?\s*$'                    # a `case` arm label with no command on it
    r'|(?:source|\.)\s+\S*(?:/opt/fpp/scripts/common|/common\b)' # FPP's own helpers - a fixed, known step
    r')')
_SET_E_SYNTAX = frozenset(('then', 'else', 'fi', 'do', 'done', 'esac', '{', '}', ';;', 'in'))


def _set_e_position(body: str) -> tuple[int, list[tuple[int, str]]] | None:
    """None when the script never enables errexit (`set -e`, `set -euo pipefail`,
    `set -o errexit`, or `-e` on the shebang). Otherwise (lineno, unguarded) where
    lineno is the line `set -e` sits on (0 for the shebang) and `unguarded` lists
    the (lineno, text) of every top-level command that runs before it without its
    own `|| true` / `|| exit` guard. Heredoc bodies and function bodies are not
    commands that run at that point, so they are skipped. An empty list means
    `set -e` is positioned correctly."""
    lines = body.splitlines()
    if lines and lines[0].startswith("#!") and re.search(r'\s-[a-zA-Z]*e', lines[0]):
        return (0, [])
    unguarded: list[tuple[int, str]] = []
    heredoc = None      # (terminator, strip_tabs) while inside a heredoc body
    depth = 0           # brace depth: >0 means inside a function body
    cont_from = None    # first physical line of a `\`-continued logical line
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if heredoc is not None:
            # `<<EOF` needs the terminator flush-left; only `<<-EOF` strips
            # leading tabs, so an indented `EOF` inside a plain heredoc is body.
            if (line.lstrip("\t") if heredoc[1] else line).rstrip("\n") == heredoc[0]:
                heredoc = None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        # A `\`-continued command is one command: judge it by its first line,
        # guard it by its last (`apt-get install -y \` / `  foo || true`).
        if cont_from is None and stripped.endswith("\\"):
            cont_from = (i, stripped)
            continue
        if cont_from is not None:
            if stripped.endswith("\\"):
                continue
            i, stripped = cont_from[0], cont_from[1].rstrip("\\").rstrip() + " ... " + stripped
            cont_from = None
        if depth == 0 and _SET_E_RX.match(line):
            return (i, unguarded)
        # `<<<` is a here-string and `1 << 3` is a shift - neither opens a
        # heredoc (treating them as one swallowed the rest of the file and
        # reported "has no set -e" on a script that plainly had one).
        m = re.search(r'(?<!<)<<(?!<)(-?)\s*[\'"]?([A-Za-z_]\w*)[\'"]?',
                      re.sub(r'\$\(\(.*?\)\)', '', line.split('#', 1)[0]))
        if m:
            heredoc = (m.group(2), m.group(1) == "-")
        # A function definition line - `foo() {`, `function foo {`, `foo()` with
        # the `{` on the next line, or a one-liner `foo() { echo hi; }` whose
        # braces balance on the line - defines, it doesn't run.
        is_fn_def = re.match(r'^(?:function\s+[A-Za-z_]\w*\s*(?:\(\s*\))?|[A-Za-z_]\w*\s*\(\s*\))\s*(?:\{.*)?$', stripped)
        is_cmd = depth == 0 and not _SET_E_PREAMBLE_RX.match(stripped) \
            and stripped not in _SET_E_SYNTAX \
            and not is_fn_def \
            and not re.search(r'\|\|\s*(?:true|:|exit\b[^|]*|\{[^}]*\bexit\b[^}]*\}|return\b[^|]*)\s*$', stripped)
        depth += stripped.count("{") - stripped.count("}")
        if is_cmd:
            unguarded.append((i, stripped if len(stripped) <= 60 else stripped[:57] + "..."))
    return None


def _set_e_is_last(body: str, set_line: int) -> bool:
    """True when nothing but blanks/comments follows the `set -e` on `set_line`."""
    rest = body.splitlines()[set_line:]
    return all(not l.strip() or l.strip().startswith("#") for l in rest)


# A hook script that is nothing but a wrapper: it `exec`s into the real script
# somewhere else in the repo (fpp-performance-capture's monorepo layout, where
# the root fpp_install.sh is a 6-line stub that execs
# fpp-plugins/<name>/fpp_install.sh). Because the trigger is specifically
# `exec`, nothing in the wrapper runs afterwards and process control transfers
# entirely - so a hook-scoped check that reads only the wrapper is reading the
# wrong file, and running the SAME per-file check independently on the target is
# exactly right. Deliberately narrow: only `exec bash|sh <dir>/<path>.sh`, where
# <dir> is $PLUGIN_DIR/$SCRIPT_DIR (assigned from `dirname "$0"` earlier in the
# same file) or an inline `$(cd "$(dirname "$0")" && pwd)`. No `source`/`.`, no
# variable tracing, no recursion (depth 1, hard).
# `exec [bash|sh] <dir>/<rel>.sh [args]` where <dir> is $PLUGIN_DIR/$SCRIPT_DIR
# (assigned from dirname "$0" earlier), an inline `$(dirname "$0")`, or the
# `$(cd "$(dirname "$0")" && pwd)` form. Interpreter optional; trailing "$@"
# or other args allowed.
_EXEC_DELEGATE_RX = re.compile(
    r'^\s*exec\s+(?:(?:/bin/|/usr/bin/)?(?:bash|sh)\s+)?'
    r'"?(?:\$\{?(?P<var>PLUGIN_DIR|SCRIPT_DIR)\}?'
    r'|\$\(\s*dirname\s+"?\$0"?\s*\)'
    r'|\$\(\s*(?:cd\s+"?)?\$\(\s*dirname\s+"?\$0"?[^)]*\)[^)]*\))'
    r'/(?P<rel>[\w./-]+\.sh)"?(?:\s+[^;&|#\n]*)?\s*(?:;|&&|\|\||#|$)')
_DIRNAME_ASSIGN_RX = re.compile(
    r'^\s*(?:export\s+|declare\s+[-\w ]*|readonly\s+)?(?P<var>\w+)=\s*'
    r'"?\$\(\s*(?:cd\s+"?)?(?:\$\(\s*)?dirname\s+"?\$0"?')


def _exec_delegation_target(hook_path: str, root: str) -> str | None:
    """Relpath (from `root`) of the script `hook_path` hands off to via
    `exec bash .../x.sh`, or None. Resolved statically only: rejects `..` in the
    path, a target that doesn't exist on disk, a target outside the plugin root,
    and the hook resolving to itself."""
    if not os.path.isfile(hook_path):
        return None
    body = _read(hook_path)
    dirname_vars = set()
    for line in body.splitlines():
        if _is_comment_line(line):
            continue
        a = _DIRNAME_ASSIGN_RX.match(line)
        if a:
            dirname_vars.add(a.group("var"))
        m = _EXEC_DELEGATE_RX.match(line)
        if not m:
            continue
        var = m.group("var")
        if var and var not in dirname_vars:
            continue        # not provably the script's own directory
        rel = m.group("rel")
        if ".." in rel.split("/"):
            return None
        base = os.path.dirname(os.path.abspath(hook_path))
        target = os.path.realpath(os.path.join(base, rel))
        real_root = os.path.realpath(root)
        if not os.path.isfile(target):
            return None
        if os.path.commonpath([target, real_root]) != real_root:
            return None
        if target == os.path.realpath(hook_path):
            return None     # recursion guard
        return os.path.relpath(target, real_root)
    return None


def _subshell_exit_swallow_hits(root: str, exts=SCRIPT_EXT):
    """Yield (relpath, lineno, line) where a shell function that can `exit` is
    invoked inside a command substitution on an assignment (VAR=$(fn ...) or
    VAR=`fn ...`). `exit` inside `$( )`/backticks only ends the subshell, not
    the calling script - a validator written "exit 1 on bad input" silently
    becomes "assign an empty/partial string on bad input" instead when called
    this way, and the caller has no way to tell the difference from a
    legitimately-empty result."""
    for path in _iter_files(root, exts):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        src = _read(path)
        if not re.match(r'#!.*\b(?:ba|z|da|k)?sh\b', src[:200]) and not rel.endswith(".sh"):
            continue  # shell semantics only
        fn_names = []
        for name, b0, b1, _s, _e in _shell_functions(src):
            body = "\n".join(l.split('#', 1)[0] for l in src[b0:b1].splitlines())
            # `exit` as a statement, or as the `|| exit 1` / `then exit 1` tail
            # of a validator - all end the subshell, not the script.
            if re.search(r'(?m)(?:^|;|\|\||&&|\bthen\b|\belse\b|\bdo\b)\s*exit\b', body):
                fn_names.append(name)
        if not fn_names:
            continue
        alt = "|".join(re.escape(n) for n in fn_names)
        # VAR=$(fn ...), quoted or not, with or without local/export/declare/
        # readonly. A line that then checks the status (`|| exit 1`, `|| return`,
        # `&& ...`) is the CORRECT shape - the assignment's status is the
        # substitution's - so it is skipped.
        rx = re.compile(r'^\s*(?:local\s+|export\s+|declare\s+(?:-\w+\s+)*|readonly\s+)?\w+=["\']?'
                        r'(?:\$\(\s*|`\s*)(?:' + alt + r')\b')
        for i, line in enumerate(src.splitlines(), 1):
            code = line.split('#', 1)[0]
            if rx.search(code) and not re.search(r'\)["\']?\s*(?:\|\||&&)', code):
                yield rel, i, line.strip()
                break


_CALLBACKS_SHLIB_OVERRIDE_RX = re.compile(r'c\+\+:((?:\.{0,2}/)?[\w][\w.+/-]*\.so(?:\.[\w.]+)?)')


def _expected_shlib_names(root: str, repo: str) -> set[str]:
    """The .so filename(s) fppd will actually try to dlopen() for this plugin:
    `lib<repo>.so` by default, or the file named by a `c++:<file>` line in the
    root callbacks script (any of the four extensions or extensionless), which
    Plugins.cpp loadUserPlugin() honours in place of the derived name. Both are
    accepted when an override exists (the override wins at runtime, but a
    Makefile that builds the derived name too isn't wrong)."""
    names = {f"lib{repo}.so"}
    for fn in os.listdir(root) if os.path.isdir(root) else []:
        if fn == "callbacks" or (fn.startswith("callbacks.") and fn.count(".") == 1):
            for line in _read(os.path.join(root, fn)).splitlines():
                if _is_comment_line(line):
                    continue
                for m in _CALLBACKS_SHLIB_OVERRIDE_RX.finditer(line.split('#', 1)[0]):
                    names.add(os.path.basename(m.group(1)))
    return names


_MAKEFILE_SO = r'(lib[\w.+-]*?)(?:\.so|\.\$[({]SHLIB_EXT[)}])'
_MAKEFILE_SHLIB_TARGET_RXS = (
    re.compile(r'(?m)^\s*' + _MAKEFILE_SO + r'\s*:'),                        # libx.so: deps
    re.compile(r'(?m)^\s*(?:all|default|plugin)\s*:\s*(?:[^\n]*?\s)?' + _MAKEFILE_SO + r'(?=\s|$)'),
    re.compile(r'(?m)^\s*(?:TARGET|LIB|LIBRARY|SHLIB|PLUGIN|OUTPUT)\s*[:?+]?=\s*' + _MAKEFILE_SO + r'\s*$'),
    re.compile(r'\s-o\s+' + _MAKEFILE_SO + r'(?=\s|$)'),
)


def _makefile_shlib_targets(makefile_text: str) -> set[str]:
    """lib*.so filenames a Makefile BUILDS (rule targets, `all:` prerequisites,
    a TARGET-style variable, or a `-o` output) - not ones it merely depends on
    or deletes. `$(SHLIB_EXT)` is normalised to `.so`. Makefile variables in
    the stem (`lib$(NAME).so`) can't be resolved, so such targets are ignored
    rather than guessed at."""
    code = "\n".join(l.split('#', 1)[0] for l in makefile_text.splitlines())
    found: set[str] = set()
    for rx in _MAKEFILE_SHLIB_TARGET_RXS:
        for m in rx.finditer(code):
            stem = m.group(1)
            if '$' in stem:
                continue
            found.add(stem + ".so")
    return found


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
    # Three equivalent shapes for "run a downloaded remote script": a direct pipe
    # into an interpreter (the classic `curl | sh`, but the interpreter doesn't
    # have to be bash/sh - python3/perl/ruby/node install scripts do this too),
    # process substitution (`bash <(curl ...)` - functionally identical to a pipe,
    # just different shell syntax), and `eval` on a captured command substitution
    # (`eval "$(curl ...)"` / `eval \`curl ...\`` - the output never touches disk
    # or a pipe at all, but still executes unverified remote content).
    hit = first(r'(curl|wget)\b[^|\n]*\|\s*(sudo\s+(?:-\S+\s+)*)?(bash|sh|python3?|perl|ruby|node)\b') \
        or first(r'\b(bash|sh|python3?|perl|ruby|node)\s*<\(\s*(curl|wget)\b') \
        or first(r'''\beval\s+["'`]?\$?\(\s*(curl|wget)\b''') \
        or first(r'\beval\s+`\s*(curl|wget)\b')
    if hit:
        out.append(Finding(BLOCKER, "remote-exec",
                   f"pipes a remote script into a shell ({hit[0]}:{hit[1]}: `{hit[2]}`) - install the "
                   f"dependency through a package manager FPP already has instead: `apt-get install` "
                   f"for system packages, `npm install` for Node packages, or `pip install "
                   f"--break-system-packages` for Python packages.\n"
                   f"  - Only if there's genuinely no package for it, download the installer to a "
                   f"file, verify its checksum, then run it, e.g. `curl -fsSLo installer.sh "
                   f"https://example.com/install.sh && echo \"<sha256>  installer.sh\" | sha256sum -c "
                   f"&& bash installer.sh`"))

    # Same risk as remote-exec above, staged across two commands instead of one
    # line: download a script to disk, then separately execute that same file
    # with no checksum/signature check anywhere in between - functionally
    # identical to `curl | sh`, just split up (and easy to miss on a quick read
    # since the download and the execution aren't on the same line).
    hit = next(iter(_download_then_execute_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "remote-exec",
                   f"downloads a script and executes it with no checksum/signature check "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - this is the same risk as piping a remote script "
                   f"straight into a shell, just staged across two commands instead of one.\n"
                   f"  - Verify the download before running it, e.g. `curl -fsSLo installer.sh "
                   f"https://example.com/install.sh && echo \"<sha256>  installer.sh\" | sha256sum -c "
                   f"&& bash installer.sh`, or install the dependency through a package manager FPP "
                   f"already has instead"))

    # Same trust model as remote-exec, via git instead of a pipe: a `git clone` of
    # a THIRD-PARTY repo (not the plugin's own srcURL) with no commit pin anywhere,
    # so a reinstall/update tracks whatever's currently on that branch rather than
    # a specific reviewed commit.
    own_owner = own_repo = None
    if info is not None and parse_github_repo is not None:
        own_src = parse_github_repo(info.get("srcURL", "") or "")
        if own_src:
            own_owner, own_repo = own_src
    hit = next(iter(_unpinned_third_party_clone_hits(root, own_owner, own_repo)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "unpinned-third-party-clone",
                   f"clones a third-party repo with no commit pin anywhere in the file "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - if that cloned code is imported or executed (verify "
                   f"this by hand; a static check can't prove it either way), a reinstall or update "
                   f"silently picks up whatever is currently on that branch, not what was reviewed at "
                   f"submission time - the same trust problem as `curl | bash`, just via git.\n"
                   f"  - Pin to a specific commit (`git checkout <sha>` or `git reset --hard <sha>`) and "
                   f"update that sha deliberately when you've reviewed the new code, instead of tracking "
                   f"a floating branch"))

    # `set -u` + ${FPPDIR} / sourcing scripts/common: the script aborts (usually
    # silently) instead of running - see _nounset_fppdir_hits for the two paths.
    hit = next(iter(_nounset_fppdir_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "nounset-fppdir",
                   f"enables `set -u` and then expands FPPDIR or sources scripts/common under it "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - this aborts the script instead of running "
                   f"it: FPPDIR is unset on the uninstall path (uninstall_plugin passes it only as "
                   f"an argument and sudo strips the exported one), and even when it is set, "
                   f"scripts/common expands a bare $LD_LIBRARY_PATH which trips nounset inside the "
                   f"sourced file. A `2>/dev/null` or `|| true` on that line does not help - the "
                   f"expansion error exits the shell before either applies.\n"
                   f"  - Use `${{FPPDIR:-/opt/fpp}}` for the path and source common with nounset "
                   f"relaxed in a subshell, e.g. `{RESTART_FLAG_SNIPPET}`"))

    # Reboots/shutdowns are an error. A bare reboot/shutdown only counts as a
    # command (start of line / after ;&| / sudo / then|do, in a shell script, or
    # wrapped in system()/exec()) - not the word "Reboot" in UI text.
    hit = (next(iter(_grep(root, r'(^|[;&|]|\bsudo\s+|\bthen\s+|\bdo\s+)\s*(reboot|shutdown|halt)\b',
                           exts=(".sh",))), None)
           or first(r'(system|exec|shell_exec|passthru|popen)\s*\([^)]*\b(reboot|shutdown)\b'))
    if hit:
        out.append(Finding(BLOCKER, "reboot",
                   f"reboots/shuts down the box ({hit[0]}:{hit[1]}: `{hit[2]}`).\n"
                   f"  - Replace it with `setSetting rebootFlag 1` (shell) or the equivalent in your "
                   f"language, so FPP reboots on its own schedule instead of pulling the box down "
                   f"mid-show"))

    # Restarting fppd DIRECTLY (RestartFPPD(), systemctl/service/kill, `fpp -r`) is
    # the anti-pattern. The sanctioned way is SetRestartFlag()/`setSetting restartFlag`
    # (deferred, sequenced around a running show) - those are NOT flagged.
    hit = first(r'\bRestartFPPD\s*\(|\bfppd_restart\b|systemctl\s+(restart|stop|start)\s+fppd'
                r'|service\s+fppd\s+(restart|stop)|(pkill|killall)\s+[^\n]*fppd|\bfpp\s+-r\b|\bfpp\s+--restart\b'
                r'|/api/system/fppd/(restart|reboot)|api/system/restart')
    if hit:
        out.append(Finding(BLOCKER, "fppd-restart",
                   f"restarts fppd directly ({hit[0]}:{hit[1]}: `{hit[2]}`) - replace it with the "
                   f"restart flag instead, so FPP restarts safely between sequences instead of "
                   f"killing a running show.\n"
                   f"  - Shell: `{RESTART_FLAG_SNIPPET}` (common defines the function; the "
                   f"subshell/default keep it from aborting a `set -u` script).\n"
                   f"  - C++: call `setSetting(\"restartFlag\", \"1\")` (declared in `settings.h`, "
                   f"already pulled in via `fpp-pch.h`) - not `SetRestartFlag()`, which is the "
                   f"browser-JS helper used from PHP pages, not a C++ API"))

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
                   f"calls fppd's internal port :32322 directly ({hit[0]}:{hit[1]}: `{hit[2]}`).\n"
                   f"  - Replace `http://localhost:32322/...` with the proxied, documented equivalent "
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
    # PEP 668 only guards the system-managed interpreter - a pip running
    # inside a venv the plugin created itself isn't "externally managed" and
    # doesn't need (or accept) the flag at all. Confirmed real, not
    # hypothetical: fpp-plugin-tplink (`python3 -m venv env` + `source
    # env/bin/activate` + `env/bin/pip install python-kasa`) and
    # fpp-performance-capture (`python3 -m venv "$PLUGIN_DIR/venv"` /
    # `uv venv` + `uv pip install --python .../venv/bin/python`) both got
    # blocked here despite never touching the system interpreter. Detected
    # file-wide (like the escapeString check above) rather than by a nearby-
    # line window, since venv setup commonly happens far earlier in the
    # script than the actual install call.
    #
    # Checks each `pip install` hit individually, not just the first one in
    # the tree (`first()` alone would miss a bare `pip install` anywhere after
    # an earlier, compliant `pip install --break-system-packages` line - a
    # real false-negative gap, not hypothetical, worth closing now that this
    # is a BLOCKER rather than a BEST_PRACTICE).
    hit = next((h for h in _grep(root, r'\bpip3?\s+install\b')
                if "--break-system-packages" not in h[2]
                and not _VENV_MARKER_RX.search(_read(os.path.join(root, h[0])))), None)
    if hit:
        out.append(Finding(BLOCKER, "pip-install",
                   f"installs Python packages with pip but no --break-system-packages "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - this fails outright on any current PEP "
                   f"668-managed image ('externally managed environment').\n"
                   f"  - Add `--break-system-packages`: it's safe here because pip targets "
                   f"`/usr/local/lib/python3.x/dist-packages`, which isn't tracked by dpkg, so it "
                   f"can't conflict with anything apt manages"))

    # Downloads a file, then separately trusts/runs it with no checksum/signature
    # check anywhere in the file - installed as a system package (dpkg -i / rpm -i),
    # or made directly executable (chmod +x $VAR, no package manager at all - e.g.
    # a native binary self-update). Distinct from `remote-exec` above: that catches
    # `curl | sh` (piped straight into a shell); this catches "download to disk,
    # then install/run it later" - same lack of integrity verification, different
    # shape, and the install/execution almost always runs as root or an always-on
    # service.
    hit = next(iter(_unverified_package_install_hits(root)), None)
    if hit:
        is_chmod = bool(re.search(r'\bchmod\b', hit[2]))
        what = "makes a downloaded file executable (chmod +x)" if is_chmod else "installs a downloaded package"
        fix_tail = "running it" if is_chmod else "installing it, e.g. `curl -fsSL <checksums-url> | grep <file> | sha256sum -c -` (or check the upstream project's published GPG signature) before `dpkg -i`"
        out.append(Finding(BEST_PRACTICE, "unverified-package-install",
                   f"{what} with no checksum/signature check ({hit[0]}:{hit[1]}: `{hit[2]}`) - HTTPS "
                   f"protects the transport, but there's no defense-in-depth if the download URL, "
                   f"CDN, or upstream release is ever compromised, and this "
                   f"{'runs as an always-on service/binary' if is_chmod else 'install almost certainly runs as root'}.\n"
                   f"  - Verify the download before {fix_tail}"))

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
                   f"language packages; a bolted-on manager (uv, pipx, nvm ...) is undesirable.\n"
                   f"  - If there's a genuine need it can't cover (e.g. a Python/Node version the OS "
                   f"image doesn't ship), say so explicitly via `/submit` instead of adding a manager "
                   f"silently"))

    # apt-get/apt install|remove|purge called directly from a plugin's own
    # scripts, instead of through pluginInfo.json's declarative
    # dependencies.packages (PLUGININFO_FORMAT.md "dependencies" - reference-
    # counted per requesting plugin, which is what lets fpp_uninstall safely
    # decide whether a package is still needed by someone else). A manual call
    # is invisible to that refcount: two plugins apt-get installing the same
    # package, then one `apt-get remove`-ing it on uninstall, silently takes it
    # out from under the other. BLOCKER when the package is one with an
    # update-initramfs hook (e2fsprogs, dosfstools, initramfs-tools, busybox) -
    # removing/reinstalling those can regenerate the system's initramfs, a much
    # bigger blast radius on a device that's expected to keep booting than an
    # ordinary package; BEST_PRACTICE otherwise.
    # .sh only: install/uninstall logic lives in shell hooks, not PHP/JS/Python
    # UI code - restricting to it avoids matching e.g. a PHP page's help text
    # that merely SUGGESTS an apt-get command to the user in an echoed string
    # (confirmed false positive on Si4713_FM_RDS's plugin_setup.php otherwise).
    #
    # pluginInfo.schema.json is explicit that dependencies.packages is "FPP
    # 10+" - it isn't read/installed at all on an older FPP major, so a plugin
    # whose versions[] still covers one has no alternative to a manual apt-get
    # call for that install: the declarative mechanism this finding is nudging
    # toward literally doesn't exist there. Confirmed against the first real
    # pass of this check: 17 of 18 hits were plugins that still declare pre-10
    # support - false positives, not sloppiness - leaving exactly one genuine
    # case (fpp-plugin-SDCardRecover, FPP10-only). So this only fires for a
    # plugin whose EVERY versions[] entry is FPP 10+.
    versions = (info or {}).get("versions") or []
    covers_pre_10 = any(
        (_major(v.get("minFPPVersion")) or 99) < 10
        for v in versions if isinstance(v, dict) and v.get("minFPPVersion"))
    # Options can come before the verb (`apt-get -y install`, the dominant idiom
    # in the corpus) or after. An `echo "run: apt-get install ..."` is help text
    # (skipped by the (?<!...) on the leading quote/echo), and fpp_uninstall.sh
    # removing what fpp_install.sh installed is the right thing, not a finding.
    # BEST_PRACTICE only (2026-09 review): the initramfs escalation this had
    # didn't hold up - dosfstools has no initramfs hook, e2fsprogs is already on
    # every image so its install runs no postinst, and `update-initramfs -u` is
    # what every kernel update does anyway.
    apt_rx = re.compile(r'\bapt(?:-get)?\s+(?:-\S+(?:\s+\S+)?\s+)*(?:install|remove|purge)\b')

    def _apt_call(line: str) -> bool:
        """True when the line RUNS apt (possibly after `;`/`&&`, under sudo, or
        inside `bash -c "..."`) rather than merely printing text that mentions it."""
        for seg in re.split(r'(?:;|&&|\|\|)', line):
            seg = seg.strip()
            m = apt_rx.search(seg)
            if not m:
                continue
            before = seg[:m.start()]
            if re.match(r'^\s*(?:echo|printf|print|cat)\b', seg) and 'bash -c' not in before:
                continue
            if re.search(r'["\']', before) and not re.search(r'\b(?:bash|sh)\s+-c\s+["\']', before):
                continue  # `echo "run apt-get ..."` / a quoted string
            return True
        return False

    hit = None if covers_pre_10 else next(
        (h for h in _grep(root, apt_rx.pattern, exts=(".sh",))
         if os.path.basename(h[0]) != "fpp_uninstall.sh" and _apt_call(h[2])),
        None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "apt-manual-install",
                   f"calls apt/apt-get install|remove|purge directly ({hit[0]}:{hit[1]}: `{hit[2]}`) "
                   f"instead of declaring the package in pluginInfo.json's `dependencies.packages` - "
                   f"that mechanism reference-counts installs per requesting plugin, so "
                   f"fpp_uninstall.sh only removes a package once nobody else still needs it; a "
                   f"manual apt-get call has no such tracking. This plugin declares FPP 10+ only, "
                   f"where that mechanism exists.\n"
                   f"  - Move it into pluginInfo.json's `dependencies.packages` array instead of "
                   f"calling apt-get from a script"))

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
                   f"reads/writes FPP core config directly ({hit[0]}:{hit[1]}: `{hit[2]}`).\n"
                   f"  - Read it through {lang_fix} instead of parsing the settings file yourself; "
                   f"the file's format is not a stable contract across FPP releases"))

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
                   f"reachable via a plain GET request with no confirmation.\n"
                   f"  - Require `$_SERVER['REQUEST_METHOD'] === 'POST'` (or check a `$_POST` field) "
                   f"before running it if so"))

    # Backend daemon binds every interface (0.0.0.0) while the plugin's own
    # install script also sets up an Apache ProxyPass - a strong signal the
    # service was designed to be internal-only, so the 0.0.0.0 bind exposes
    # its (often unauthenticated) routes directly on the LAN instead.
    hit = first(r'\.(run|run_app|listen|bind)\s*\([^)]*0\.0\.0\.0', exts=(".py", ".js"))
    if hit and first(r'ProxyPass', exts=(".sh", ".conf")):
        out.append(Finding(BLOCKER, "server-bind-all-interfaces",
                   f"daemon binds 0.0.0.0 despite an Apache ProxyPass for the same service "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - the ProxyPass means this was designed to be "
                   f"reached through Apache only.\n"
                   f"  - Bind to `127.0.0.1` instead so the routes aren't directly reachable on the "
                   f"LAN, bypassing whatever auth Apache would add"))
    elif hit and not re.search(r'SOCK_DGRAM|createSocket\s*\(\s*["\']udp|\bdgram\.', "\n".join(
            _read(os.path.join(root, hit[0])).splitlines()[max(0, hit[1] - 40):hit[1] + 2])):
        # Same 0.0.0.0 bind, but with no paired ProxyPass to infer "designed to be
        # internal-only" from. The only corpus hit for this branch was a service
        # meant to be reached from other devices on the LAN (showpilot-plugin's
        # audio/WebSocket server), and a UDP receiver (E1.31/ArtNet/OSC/
        # multicast - skipped above) MUST bind every interface. FPP's UI
        # password is off by default, so "the auth Apache would add" is usually
        # nothing anyway. OPTIONAL: a prompt to confirm it's intended, not a
        # finding the author has to argue with.
        out.append(Finding(OPTIONAL, "server-bind-all-interfaces",
                   f"daemon binds 0.0.0.0 ({hit[0]}:{hit[1]}: `{hit[2]}`) - reachable from every "
                   f"device on the LAN, not just FPP's own UI.\n"
                   f"  - Fine if other devices are meant to talk to it directly; if only FPP's own "
                   f"pages use it, bind `127.0.0.1` instead"))

    # A destructive block-device write (mkfs/dd/wipefs/parted/sfdisk onto
    # /dev/sdX, /dev/mmcblkN, /dev/nvmeN) in a file that never references FPP's
    # own storage device or media mount - a script that picks "the inserted SD
    # card" generically has nothing stopping it from formatting the disk FPP
    # boots from or stores shows on. BLOCKER: the failure mode is destroying
    # the media the system runs on. Read-only tools (lsblk, fsck -n, blkid) and
    # `dd of=/dev/null` aren't in the class, and the exclusion is checked in
    # the SAME file as the hit - a `/home/fpp/media` in the log path of some
    # other script says nothing about what this one targets.
    _BLK_DEV = r'/dev/(?:sd[a-z]|mmcblk\d|nvme\d|disk/by-)'
    blk_write_rx = re.compile(
        r'\bmkfs(?:\.\w+)?\s[^\n]*' + _BLK_DEV
        + r'|\bdd\s[^\n]*\bof=' + _BLK_DEV
        + r'|\b(?:wipefs|sfdisk|sgdisk|parted|fdisk)\s[^\n]*' + _BLK_DEV
        + r'|\b(?:mkfs(?:\.\w+)?|wipefs)\s[^\n]*(?:/dev/)?\$\{?(?:dev|device|disk|drive|sdcard|card|blockdev|blkdev|target_dev|dev_name)\}?\b'
        + r'|\bdd\s[^\n]*\bof=(?:/dev/)?\$\{?(?:dev|device|disk|drive|sdcard|card|blockdev|blkdev|target_dev|dev_name)\}?\b'
        + r'|\b(?:mkfs(?:\.\w+)?|wipefs)\s[^\n]*/dev/\$\{?\w+\}?'
        + r'|\bdd\s[^\n]*\bof=/dev/\$\{?\w+\}?', re.I)
    blk_excl_rx = re.compile(r'storageDevice|/home/fpp/media\b|findmnt\s|\bmountpoint\s|/proc/mounts|/etc/fstab', re.I)
    blk_hit = None
    for path in _iter_files(root, SCRIPT_EXT):
        rel = os.path.relpath(path, root)
        if _skippable(rel):
            continue
        text = _read(path)
        if blk_excl_rx.search(text):
            continue
        # Python docstrings and shell heredocs are prose (a usage block
        # saying "sudo dd if=fpp.img of=/dev/sdb" isn't a dd).
        if rel.endswith(".py"):
            text = re.sub(r'(?s)"""(?:[^"\\]|\\.|"(?!""))*"""|\'\'\'(?:[^\'\\]|\\.|\'(?!\'\'))*\'\'\'',
                          lambda m: "\n" * m.group(0).count("\n"), text)
        elif rel.endswith(".sh"):
            text = re.sub(r'(?ms)<<-?\s*[\'"]?(\w+)[\'"]?[^\n]*\n.*?^\s*\1\s*$',
                          lambda m: "\n" * m.group(0).count("\n"), text)
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line):
                continue
            m = blk_write_rx.search(line)
            if m and not _priv_in_prose(rel, line, m.start()) \
                    and not re.search(r'^\s*(?:echo|print|printf)\b|["\'][^"\']*\b(?:dd|mkfs)\b', line[:m.start() + 3]):
                blk_hit = (rel, i, line.strip())
                break
        if blk_hit:
            break
    if blk_hit:
        out.append(Finding(BLOCKER, "block-device-no-exclusion",
                   f"writes to a raw block device with no reference to FPP's own storage device/media "
                   f"mount anywhere in the same file ({blk_hit[0]}:{blk_hit[1]}: `{blk_hit[2]}`) - if "
                   f"this picks its target generically (\"the inserted SD card\"), nothing here stops "
                   f"it from formatting or overwriting the disk FPP itself is running from.\n"
                   f"  - Read FPP's own storage device first (`findmnt -n -o SOURCE /home/fpp/media`, "
                   f"or the `storageDevice` setting) and explicitly skip it before touching "
                   f"anything under `/dev/`"))

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
                   f"an arbitrary path instead of a serial device.\n"
                   f"  - Validate it against an allow-list pattern first, e.g. "
                   f"`^tty(USB|ACM|AMA)\\d+$`"))

    # strcpy()/sprintf() (non-`snprintf`/`vsprintf`-safe forms, word-boundaried so
    # `strcpy_s`/`snprintf`/`vsprintf` don't match) into a fixed-size stack/heap
    # buffer - neither function takes a destination size, so any caller-influenced
    # length overruns it. Essentially never legitimate in a modern C++ FPP plugin
    # (use snprintf/std::string/std::format instead), so this is cheap and
    # near-zero-false-positive: BLOCKER regardless of whether the immediate source
    # is provably request-reachable, matching how `remote-exec` is unconditional too.
    hit = first(r'\bstrcpy\s*\(|\bsprintf\s*\(', exts=(".cpp", ".c", ".h", ".hpp"))
    if hit:
        out.append(Finding(BLOCKER, "unsafe-buffer-copy",
                   f"strcpy()/sprintf() into a fixed buffer with no length check ({hit[0]}:{hit[1]}: "
                   f"`{hit[2]}`) - neither function bounds the write against the destination's actual "
                   f"size, so a longer-than-expected source value overflows it.\n"
                   f"  - Use `snprintf()` (with the real buffer size) or `std::string`/`std::format` "
                   f"instead"))

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
                   f"logs are often included in Support Zips and shared for debugging.\n"
                   f"  - Drop the key/token/password from the message before logging it, e.g. log the "
                   f"URL with the credential redacted"))

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
    #
    # A build guarded by a "the binary is missing" test is the documented
    # exception (see the advice text below) and is NOT flagged: it costs one
    # stat() on a normal boot and only builds in the one case fppd cannot
    # recover from by itself, e.g. an SD image cloned to a different CPU
    # architecture. Both shapes are accepted:
    #     if [ ! -f libfpp-x.so ]; then make; fi
    #     [ -f libfpp-x.so ] || make
    #
    # `g++` can't take a trailing \b - `+` and the following space are both
    # non-word characters, so \b never matches there and the old
    # `\b(...|g\+\+|...)\b` silently never detected a g++ build at all.
    _BUILD_RE = re.compile(r'\b(?:make|cmake|gcc|clang)\b|\bg\+\+')
    # An existence test for a *missing* file, with the negation on either side
    # of the test: `[ ! -f x ]`, `test ! -x x`, `! [ -f x ]`, `if ! test -f x`.
    _MISSING_TEST_RE = re.compile(
        r'(?:\[\[?|\btest\b)[^]]*!\s*-[efxs]\s'
        r'|!\s*(?:\[\[?|\btest\b)[^]]*-[efxs]\s')
    # `[ -f x ] ||` / `test -f x ||` - build only runs when the test fails.
    _PRESENT_OR_RE = re.compile(r'(?:\[\[?|\btest\b)[^]]*-[efxs]\s[^]]*\]?\]?\s*\|\|')
    hit = None
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn in ("preStart.sh", "postStart.sh"):
                p = os.path.join(dirpath, fn)
                depth = 0        # nesting level of open if-blocks
                guard_depth = 0  # depth of the innermost missing-file guard, 0 = none
                for i, line in enumerate(_read(p).splitlines(), 1):
                    if _is_comment_line(line):
                        continue
                    s = line.strip()
                    # Track if/fi nesting so we know when a guard stops applying.
                    # Only `if` opens a block - `elif`/`else` continue the one
                    # already counted, so counting them would inflate the depth
                    # and leave guard_depth stuck set after the matching `fi`.
                    if re.match(r'if\b', s):
                        depth += 1
                        if not guard_depth and _MISSING_TEST_RE.search(s):
                            guard_depth = depth
                    elif re.match(r'fi\b', s):
                        if guard_depth == depth:
                            guard_depth = 0
                        depth = max(0, depth - 1)
                    if not _BUILD_RE.search(s):
                        continue
                    # Inside an `if [ ! -f ... ]` guard, or a `[ -f ... ] ||`
                    # short-circuit on this same line - the documented exception.
                    if guard_depth or _PRESENT_OR_RE.search(s):
                        continue
                    hit = (os.path.relpath(p, root), i, s)
                    break
                if hit:
                    break
        if hit:
            break
    if hit:
        out.append(Finding(BLOCKER, "blocking-build-in-hook",
                   f"runs a build step synchronously in {os.path.basename(hit[0])} ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - this delays fppd startup by however long the "
                   f"(re)build takes, every single boot.\n"
                   f"  - This is almost always redundant, not a safety net: fpp_install.sh already "
                   f"builds on fresh install and on plugin-only update (the Plugin Manager falls back "
                   f"to fpp_install.sh when there's no fpp_upgrade.sh), and FPP's own core-upgrade "
                   f"path rebuilds every plugin with a root Makefile before restarting fppd - so this "
                   f"hook rarely has anything left to do.\n"
                   f"  - Move the build into fpp_install.sh (or fpp_upgrade.sh) if it isn't there "
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
                   f"{hit[1]}: `{hit[2]}`).\n"
                   f"  - Use `${{MEDIADIR}}`/`${{FPPDIR}}` (shell) or `$settings['mediaDirectory']`/"
                   f"`$settings['fppDir']` (PHP) instead of a hardcoded `/home/pi/...`, and put a "
                   f"lock/PID file inside the plugin's own directory rather than shared `/tmp`, which "
                   f"any other process can also write to"))

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
    # A root test just above the sudo: the script also runs by hand as a normal
    # user and escalates only then (`if [ "$(id -u)" -eq 0 ]; then rm; else sudo rm`),
    # which is the right way to write a hook that has a manual mode.
    root_guard_rx = re.compile(r'\$\(\s*id\s+-u\s*\)|`id\s+-u`|\$\{?EUID\}?|\$\{?UID\}?\b|\bwhoami\b|\bid\s+-un?\b')

    def _first_sudo_line(path):
        """(lineno, line) of the first `sudo` on a code line - not one in a comment
        explaining a sudo choice, and not one guarded by a root test on the line or within
        the six lines above (fpp-data#266: both were reported, the first with the advice to
        run the comment directly)."""
        lines = _read(path).splitlines()
        for i, line in enumerate(lines):
            if _is_comment_line(line):
                continue
            code = re.split(r'\s#', line, maxsplit=1)[0]   # `cmd  # a trailing note`
            if not re.search(r'\bsudo\b', code):
                continue
            guarded = [l for l in lines[max(0, i - 6):i] if not _is_comment_line(l)] + [code[:code.index("sudo")]]
            if any(root_guard_rx.search(l) for l in guarded):
                continue
            return i + 1, line.strip()
        return None

    hit = None
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            if fn in SUDO_SCOPE:
                m = _first_sudo_line(os.path.join(dirpath, fn))
                if m:
                    hit = (os.path.relpath(os.path.join(dirpath, fn), root), m[0], m[1])
                    break
        if hit:
            break
    if hit is None:
        for cand in ("Makefile", "makefile"):
            p = os.path.join(root, cand)
            if os.path.isfile(p):
                m = _first_sudo_line(p)
                if m:
                    hit = (cand, m[0], m[1])
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
                       f"install/hooks already run as root, which can switch to another user without "
                       f"a password, so there's no need to go through sudo (and its sudoers policy) "
                       f"for this.\n"
                       f"  - Use `runuser -u {user} -- {rest}` instead"))
        else:
            out.append(Finding(BEST_PRACTICE, "sudo",
                       f"uses sudo in a script ({hit[0]}:{hit[1]}: `{hit[2]}`) - install/hooks already "
                       f"run as root.\n"
                       f"  - Remove the sudo call and run the command directly, e.g. "
                       f"`{hit[2].replace('sudo ', '', 1)}`; if the script is also run by hand as a "
                       f"normal user, escalate only then: `if [ \"$(id -u)\" -eq 0 ]; then <cmd>; else "
                       f"sudo <cmd>; fi`"))

    # --- untrusted request data reaching a dangerous sink --------------------

    # Direct case: $_GET/$_POST/$_REQUEST inside the same exec-family call. `.*`
    # rather than `[^)]*` so a nested call before the tainted var (e.g.
    # `exec(dirname(__FILE__)."...$var...")`) doesn't break the match on its own
    # closing paren - confirmed real gap (fpp-tirprog: three separately-tainted
    # vars interpolated into a string built on top of a dirname() call).
    hit = first(r'(exec|system|passthru|shell_exec|popen)\s*\(.*\$_(GET|POST|REQUEST)\b')
    if hit is None:
        # Indirect case: a variable assigned from $_GET/$_POST/$_REQUEST on one
        # line, then that same variable reaches an exec-family call within the
        # next few lines - catches the common "$cmd = ...$_POST...; ... exec($cmd);"
        # two-step shape without needing real taint tracking. `.*` (not anchored
        # to right after the opening paren) so the tainted var can be interpolated
        # ANYWHERE inside a larger string/call, not just be the sink's sole/first
        # argument - confirmed real gap (fpp-tirprog again: exec()'s first token is
        # dirname(__FILE__), with three tainted vars interpolated further into the
        # string). Window widened from the function's own default (6) to 10 for
        # the same case: 3 separate one-var-per-line assignments before a single
        # combined exec() a few lines later needs more slack than a typical
        # single-assignment-then-sink pair.
        hit = next(iter(_assign_then_sink(
            root, r'\$_(?:GET|POST|REQUEST)\b',
            r'(exec|system|passthru|shell_exec|popen)\s*\(.*\$%s\b', window=10)), None)
    if hit is None:
        # Setting-mediated case: a plugin setting (ReadSettingFromFile()/
        # $pluginSettings[...], FPP's own persisted-config-read APIs) assigned to a
        # variable that then reaches the same sink. Functionally just as
        # attacker-controlled as $_POST (nothing validates it server-side beyond
        # whatever the save form offers), but invisible to a check that only
        # recognizes the request superglobals - confirmed real gap (catalog-wide
        # audit, 2026-08: silent on FPP-Plugin-RDS-To-Matrix, FPP-Plugin-Switcher).
        # Same single-hop limit as the two cases above: a setting read into one
        # variable that then flows through a SECOND intermediate variable (e.g.
        # explode() into a loop variable) before reaching the sink still isn't
        # traced - real taint tracking would be needed for that, not a regex.
        hit = next(iter(_assign_then_sink(
            root, r'(?:ReadSettingFromFile\s*\(|\$pluginSettings\s*\[)',
            r'(exec|system|passthru|shell_exec|popen)\s*\(.*\$%s\b', window=10)), None)
    # Node/Express case: exec/execSync fed by req.query/req.body/req.params/... .
    if hit is None:
        hit = next(iter(_js_exec_injection_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "exec-injection",
                   f"unsanitized request data reaches a shell command ({hit[0]}:{hit[1]}: `{hit[2]}`) "
                   f"- an attacker can run arbitrary shell commands as the FPP user.\n"
                   f"  - Validate the value against an allow-list before using it, and wrap it in "
                   f"`escapeshellarg()` (PHP) / `shlex.quote()` (Python) / pass args as an array to "
                   f"`execFile`/`spawn` instead of a shell string (Node) before it reaches "
                   f"exec/system/shell_exec"))

    # SQL built via string concatenation, passed to ->query()/->exec() with no
    # prepare/bind and no escapeString() anywhere in the file (PHP), or via a
    # template-literal/concatenated string passed to db.prepare()/db.exec() (Node,
    # e.g. better-sqlite3) instead of a placeholder.
    hit = next(iter(_sql_concat_hits(root)), None) or next(iter(_js_sql_concat_hits(root)), None)
    if hit:
        if hit[0].endswith(".js"):
            fix = ("Use a placeholder instead: `db.prepare('... WHERE x = ?').run(value)` (or "
                   "`@x`/named params), not a template literal or `+` concatenation")
        else:
            fix = ("Use a prepared statement instead: `$stmt = $db->prepare('... WHERE x = :x'); "
                   "$stmt->bindValue(':x', $value); $stmt->execute();`")
        out.append(Finding(BLOCKER, "sql-injection",
                   f"SQL query built by string concatenation ({hit[0]}:{hit[1]}: `{hit[2]}`) - if any "
                   f"part of that string traces back to user input, this is SQL injection.\n"
                   f"  - {fix}"))

    # SSRF: request data used to build the URL/host of an outbound request.
    # curl calls are unambiguously network; file_get_contents also reads local
    # files, so it only counts here if the same line has an http(s) scheme too
    # (otherwise it's a path-traversal/LFI shape, not SSRF). fetch/axios/http(s).get
    # cover the same shape in Node.
    hit = first(r'CURLOPT_URL\s*,[^;\n]*\$_(GET|POST|REQUEST)\b') \
        or first(r'curl_init\s*\([^;\n]*\$_(GET|POST|REQUEST)\b') \
        or first(r'file_get_contents\s*\([^;\n]*https?://[^;\n]*\$_(GET|POST|REQUEST)\b') \
        or first(r'file_get_contents\s*\([^;\n]*\$_(GET|POST|REQUEST)[^;\n]*https?://') \
        or next(iter(_js_ssrf_hits(root)), None)
    if hit is None:
        # Setting-mediated case, same reasoning as exec-injection's addition above -
        # a plugin setting assigned to a variable that later builds a curl target.
        hit = next(iter(_assign_then_sink(
            root, r'(?:ReadSettingFromFile\s*\(|\$pluginSettings\s*\[)',
            r'(?:CURLOPT_URL\s*,|curl_init\s*\()[^\n]*\$%s\b', window=10)), None)
    if hit:
        out.append(Finding(BLOCKER, "ssrf",
                   f"outbound request URL/host built from request data ({hit[0]}:{hit[1]}: "
                   f"`{hit[2]}`) - an attacker can make your plugin fetch an internal-only address "
                   f"(localhost, another device on the LAN, a cloud metadata endpoint) and read the "
                   f"response back.\n"
                   f"  - Validate the host against an allow-list before using it in a URL"))

    # Runtime sudo in a JS exec-family call: the plugin's always-on Node process
    # (typically running as the unprivileged `fpp` user) shelling out through sudo
    # is a continuously-reachable root escalation, not a one-time install step - see
    # _js_runtime_sudo_hits' docstring. Separate from, and more severe than, the
    # HOOKS-scoped `sudo` BEST_PRACTICE check above.
    hit = next(iter(_js_runtime_sudo_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "runtime-sudo",
                   f"runtime application code shells out through sudo ({hit[0]}:{hit[1]}: `{hit[2]}`) "
                   f"- unlike sudo in an install/uninstall hook (which already runs as root), this "
                   f"runs inside the plugin's always-on process, normally started as the unprivileged "
                   f"`fpp` user.\n"
                   f"  - If `fpp` has passwordless sudo for this command, anything that can reach "
                   f"this code path (e.g. an HTTP route) gets root, continuously - not just once at "
                   f"install time.\n"
                   f"  - Move the privileged action into fpp_install.sh/fpp_upgrade.sh (run once, "
                   f"already as root) instead of invoking sudo from the running service"))

    # Inbound webhook trusts a request field as an authorization credential,
    # with no signature/HMAC/token verification anywhere in the file.
    hit = next(iter(_webhook_no_auth_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "webhook-no-auth",
                   f"webhook handler trusts a request field with no signature check ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - anyone who can reach this URL can send a forged request "
                   f"and have it treated as if it came from the real provider.\n"
                   f"  - Verify the provider's signature header (e.g. `hash_hmac()` compared against "
                   f"`X-<Provider>-Signature`) before trusting any field in the body"))

    # Mass assignment: the whole POST/REQUEST body merged into a config array with
    # no allow-list, request values winning on key conflicts. Lets a caller (often
    # an unauthenticated forged webhook) set config keys the plugin never intended
    # to expose - including ones it later treats as trusted, like a command to run
    # on the next event. BLOCKER when the merged result is then written to disk
    # (setPluginJSON/WriteSettingToFile/file_put_contents nearby - the attacker's
    # keys survive past this request); BEST_PRACTICE otherwise, since a merge that's
    # never persisted is a narrower, request-scoped risk.
    hit = next(iter(_mass_assignment_hits(root)), None)
    if hit:
        rel, lineno, line, persisted = hit
        sev = BLOCKER if persisted else BEST_PRACTICE
        out.append(Finding(sev, "mass-assignment",
                   f"entire request body merged into config with no allow-list ({rel}:{lineno}: "
                   f"`{line}`) - a caller can set any config key this way, not just the ones your "
                   f"settings form offers, potentially including ones the plugin later trusts (a "
                   f"command to run, a target host, a credential).\n"
                   f"  - Filter to known keys first, e.g. `array_merge($config, "
                   f"array_intersect_key($_POST, $config))`"))

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
                   f"compromised router), not just the intended server.\n"
                   f"  - Remove the override and fix the underlying cert issue instead (e.g. "
                   f"bundle/trust the CA properly)"))

    # Settings value concatenated into an HTML attribute with no escaping -
    # stored/reflected XSS if that setting is ever attacker-influenced.
    hit = next(iter(_unescaped_html_attr_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "unescaped-output",
                   f"value written into an HTML attribute with no escaping ({hit[0]}:{hit[1]}: "
                   f"`{hit[2]}`).\n"
                   f"  - Wrap it in `htmlspecialchars($value, ENT_QUOTES)` before echoing it into "
                   f"HTML, so a value containing `\"><script>` can't break out of the attribute and "
                   f"run as script in an admin's browser"))

    # --- shell script hygiene ------------------------------------------------
    for path in _iter_files(root, (".sh",)):
        rel = os.path.relpath(path, root)
        head = _read(path).splitlines()
        if not head or not head[0].startswith("#!"):
            out.append(Finding(BEST_PRACTICE, "no-shebang",
                       f"{rel} has no shebang line.\n"
                       f"  - Add `#!/bin/bash` (or `#!/bin/sh`) as its first line so it runs with a "
                       f"known shell regardless of how it's invoked"))
        try:
            with open(path, "rb") as f:
                raw_lines = f.read().split(b"\n")
        except OSError:
            raw_lines = []
        lines_with_cr = [i for i, line in enumerate(raw_lines, 1) if line.endswith(b"\r")]
        if lines_with_cr:
            out.append(Finding(BEST_PRACTICE, "crlf",
                       f"{rel}:{lines_with_cr[0]} has CRLF line endings - breaks bash (the `\\r` "
                       f"becomes part of the command).\n"
                       f"  - Fix with `sed -i 's/\\r$//' {rel}` or `dos2unix {rel}`, and configure "
                       f"your editor/git to use LF"))

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

    # install error handling. `set -e` only protects the commands that run AFTER
    # it, so its position matters as much as its presence: a `set -e` on the last
    # line (fpp-jukebox, 2026-09, added to satisfy the old presence-only grep)
    # guards nothing. _set_e_position() reports where it sits and how many real
    # commands precede it; the message names the first unguarded one so the
    # author can see what the rule is actually about.
    # A wrapper fpp_install.sh that just `exec`s into the real installer elsewhere
    # in the repo hands over the whole process, so `set -e` on the wrapper guards
    # nothing that happens after it: the target is checked as its own file, in
    # addition to (not instead of) the wrapper.
    for cand in ("scripts/fpp_install.sh", "fpp_install.sh"):
        p = os.path.join(root, cand)
        if not os.path.isfile(p):
            continue
        checked = [(cand, "")]
        delegated = _exec_delegation_target(p, root)
        if delegated:
            checked.append((delegated, f" (the real installer {cand} `exec`s into)"))
        for script, note in checked:
            body = _read(os.path.join(root, script))
            # A wrapper that only `exec`s into the real installer: a failed
            # exec already ends a non-interactive bash, so `set -e` here
            # guards nothing - the target is what's checked.
            if delegated and script != delegated and all(
                    not l.strip() or l.startswith("#") or _EXEC_DELEGATE_RX.match(l)
                    or _DIRNAME_ASSIGN_RX.match(l) for l in body.splitlines()):
                continue
            pos = _set_e_position(body)
            if pos is None and not re.search(r'\|\|\s*exit\b', body):
                out.append(Finding(BEST_PRACTICE, "no-set-e",
                           f"{script}{note} has no `set -e` - without it, bash keeps running the rest of the "
                           f"script even after a command fails, so if an earlier step errors out "
                           f"(e.g. a dependency install fails), later steps still run against that "
                           f"broken state and the plugin ends up half-installed with no visible error. "
                           f"(This is not `exit`: `exit` ends the script where you put it; `set -e` "
                           f"makes every command after it end the script if that command fails.)\n"
                           f"  - Add the line `set -e` directly under the `#!/bin/bash` shebang - "
                           f"before any other command - so the script stops on the first failure. "
                           f"(Plain `set -e`: `-u` breaks scripts that reference `$SUDO` and the like "
                           f"before sourcing /opt/fpp/scripts/common, and `pipefail` breaks common "
                           f"`grep | ...` idioms.) Per-command `... || exit 1` guards are an "
                           f"acceptable alternative"))
            elif pos is not None and pos[1]:
                set_line, unguarded = pos
                first_line, first_cmd = unguarded[0]
                n = len(unguarded)
                out.append(Finding(BEST_PRACTICE, "no-set-e",
                           f"{script}:{set_line}{note} has `set -e`, but it comes too late to do anything - "
                           f"`set -e` only affects the commands that run AFTER it, and {n} command"
                           f"{'s' if n != 1 else ''} already run{'s' if n == 1 else ''} before it "
                           f"unguarded (first: line {first_line} `{first_cmd}`)"
                           f"{' - as the last line of the script it protects nothing at all' if _set_e_is_last(body, set_line) else ''}.\n"
                           f"  - Move `set -e` up to directly under the `#!/bin/bash` shebang, before "
                           f"any other command. If a particular command is allowed to fail, append "
                           f"`|| true` to that one line rather than delaying `set -e`"))
        break

    # A shell function that can `exit` gets called inside a command
    # substitution on an assignment - `exit` there only ends the subshell, not
    # the script, so a validator meant to stop the script on bad input instead
    # silently becomes "the assigned variable is empty/partial".
    hit = next(iter(_subshell_exit_swallow_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "subshell-exit-swallowed",
                   f"a shell function that can `exit` is called inside a command substitution on an "
                   f"assignment ({hit[0]}:{hit[1]}: `{hit[2]}`) - `exit` inside `$( )`/backticks only "
                   f"ends the subshell, not the calling script, so a validator written to stop on bad "
                   f"input silently becomes \"assign an empty/partial value\" instead when called "
                   f"this way.\n"
                   f"  - Call the function directly (not inside `$()`), and check its exit status "
                   f"with `$?`/`||` instead of relying on its output; or have it `return` non-zero "
                   f"without ever calling `exit`"))

    # A plugin that ships commands/descriptions.json (command types) or a native
    # lib<repoName>.so (a Makefile at the plugin root - FPP's own core-upgrade
    # path rebuilds every plugin directory that has one, per PLUGIN_GUIDELINES.md's
    # "native (C++) plugins" section) is registering something fppd only ever
    # reads once, at its own startup: PluginManager::loadUserPlugins() (src/
    # Plugins.cpp, called exactly once from fppd.cpp) is what calls
    # LoadPluginCommands() (reads commands/descriptions.json) and dlopen()s a
    # plugin's .so - neither happens again while fppd keeps running. Until fppd
    # is restarted, a freshly-installed command type is invisible everywhere
    # (playlists, schedules, events all read from fppd's in-memory command
    # list) even though every other part of the plugin (api.php, content.php)
    # is already live, since those are loaded fresh per web request instead.
    # Contrast with a plugin that ships neither: it may still need a restart
    # for its own reasons, but this specific, checkable trigger doesn't apply,
    # so nothing is flagged - not every plugin needs one, only this shape does.
    ships_commands = os.path.isfile(os.path.join(root, "commands", "descriptions.json"))
    # A Makefile/CMakeLists.txt catches a plugin that builds its .so from source
    # in this repo, but that's not the only way one ships: FPP itself discovers
    # a native plugin by running the callbacks script with --list and checking
    # whether the output starts with "c++" (PluginManager::loadUserPlugin() ->
    # getOtherTypes(), Plugins.cpp) - that's true whether the .so is built here
    # or fetched prebuilt from a GitHub release (e.g. fpp-FPPMon: no Makefile at
    # all, callbacks.sh echoes "c++" and scripts/fetch-binary.sh downloads the
    # matching release asset). Match that mechanism directly instead of assuming
    # "no Makefile" means "not native". The callbacks script itself can be any of
    # the 4 extensions loadUserPlugin() accepts (.sh/.pl/.php/.py), each with its
    # own print statement - e.g. fpp-plugin-tplink's callbacks.py uses
    # `print("c++")`, not `echo` - so the check has to cover all four, not just
    # shell's echo.
    ships_native = (
        os.path.isfile(os.path.join(root, "Makefile")) or os.path.isfile(os.path.join(root, "makefile"))
        or bool(first(r'''(echo|print|printf)\s*\(?\s*["']c\+\+''', exts=(".sh", ".pl", ".php", ".py"))))

    # FPP's plugin API 6 added runtime load/unload (PluginManager::loadPlugin()/
    # unloadPlugin(), driven by www/api/controllers/plugin.php calling fppd's
    # /api/fppd/plugin/<name>/load|unload after install/uninstall) - on FPP
    # builds that include it, install/uninstall CAN take effect without an fppd
    # restart after all, narrowing the blanket claim below.
    #
    # loadPlugin() itself only calls loadUserPlugin() (which is what reads
    # commands/descriptions.json AND dlopen()s a .so) when a root "callbacks"
    # script exists (any of .sh/.pl/.php/.py, or extensionless) - otherwise it's
    # a no-op. A ships_native plugin is guaranteed one (that's how FPP discovers
    # the "c++" type in the first place), but a ships_commands-only (script)
    # plugin isn't - it needs its OWN root callbacks script for the daemon_start/
    # daemon_stop etc. lifecycle, separate from commands/descriptions.json, so
    # this is checked explicitly below (has_callbacks_script) rather than assumed.
    #
    # plugin_api_ready means "actively uses registerPluginApi()/unregisterPluginApi()
    # for its own HTTP routes" - real signal for the separate no-api-docs check
    # below (there's something to document), but NOT the right gate for hotload
    # safety: a plugin with no HTTP API at all has nothing to disarm either, so
    # requiring it to have adopted an API it doesn't need wrongly denies it credit.
    # The actual unsafe pattern is registering routes directly on drogon::app()
    # instead of through registerPluginApi() - Drogon has no route-removal API, so
    # a handler wired in directly stays in the router forever and can't be
    # unloaded/replaced (see the direct-drogon-registerhandler finding below,
    # which shares these same has_own_register_apis/direct_drogon_hit reads).
    plugin_api_ready = ships_native and bool(
        first(r'\bregisterPluginApi\s*\(', exts=(".cpp", ".cc", ".cxx")) and
        first(r'\bunregisterPluginApi\s*\(', exts=(".cpp", ".cc", ".cxx")))
    has_own_register_apis = first(r'\bregisterApis\s*\(\s*\)', exts=(".cpp", ".cc", ".cxx"))
    direct_drogon_hit = first(r'drogon::app\(\)\s*\.\s*registerHandler\s*\(', exts=(".cpp", ".cc", ".cxx"))
    unsafe_direct_routes = ships_native and bool(has_own_register_apis and direct_drogon_hit)
    # A plugin defining createChannelOutput() (the ChannelOutputPlugin factory -
    # NOT merely inheriting the interface, which FPP's convenience base class
    # does unconditionally) is always refused a runtime unload while that
    # output is in use (PluginManager::unloadPlugin's mPluginsWithOutputs
    # check), independent of how it registers its API.
    channel_output_hit = ships_native and first(r'\bcreateChannelOutput\s*\(', exts=(".cpp", ".cc", ".cxx"))
    # Same file loadPlugin() itself checks (FPP_DIR_PLUGIN("/" + name + "/callbacks")
    # plus each extension) - the precondition for it to call loadUserPlugin() at all
    # for a script-only plugin.
    has_callbacks_script = any(
        os.path.isfile(os.path.join(root, "callbacks" + ext)) for ext in ("", ".sh", ".pl", ".php", ".py"))
    hotload_safe = (
        (ships_native and not unsafe_direct_routes and not channel_output_hit)
        or (ships_commands and not ships_native and has_callbacks_script))

    # hotload_safe above only asks "is this CODE structurally safe to hot-load".
    # It says nothing about which FPP majors actually run it. A versions[] entry's
    # `sha` decides that: "" means "always install the latest commit on branch" -
    # i.e. this entry tracks whatever is CURRENTLY on that branch, which is exactly
    # the code being linted here. A real pinned sha freezes an entry to history
    # instead (PLUGININFO_FORMAT.md: "typical for old FPP majors you no longer
    # update") - that entry's major is served by a commit that no longer changes,
    # decoupled from whatever this scan is looking at.
    #
    # So the risk isn't one entry's own min..max range (an OPEN-ended entry can't
    # even span multiple majors by itself - compatible_with_major()'s semantics,
    # lib_plugin_schema.py, mean it only ever certifies its own major) - it's TWO
    # OR MORE sha=="" entries on the SAME branch whose majors straddle the FPP
    # major that introduced plugin API 6 (10 - HOTLOAD_INTRODUCED_MAJOR). That
    # shape means an old, pre-hotload major and FPP 10+ are BOTH being served the
    # branch's current HEAD - the exact thing being linted right now - so hotload
    # safety on FPP 10 doesn't mean restartFlag/rebootFlag can be dropped; those
    # older installs get this same code with no hot-load feature to rely on at
    # all. Fixing this for real means pinning a real sha for the older entry (or
    # splitting it to its own branch) instead of leaving it tracking HEAD.
    HOTLOAD_INTRODUCED_MAJOR = 10

    def _majors_covered(v):
        mn = _major(v.get("minFPPVersion")) if v.get("minFPPVersion") else None
        if mn is None:
            return set()
        mx_raw = v.get("maxFPPVersion")
        mx = mn if mx_raw in (None, "", "0", "0.0") else (_major(mx_raw) or mn)
        return set(range(mn, mx + 1))

    _head_tracking_by_branch: dict = {}
    for v in (info or {}).get("versions") or []:
        if not isinstance(v, dict) or (v.get("sha") or "").strip():
            continue  # no sha, or a real pin - only "" tracks current HEAD
        _head_tracking_by_branch.setdefault(v.get("branch") or "", set()).update(_majors_covered(v))
    spans_pre_hotload_major = any(
        any(m < HOTLOAD_INTRODUCED_MAJOR for m in majors) and any(m >= HOTLOAD_INTRODUCED_MAJOR for m in majors)
        for majors in _head_tracking_by_branch.values())
    effective_hotload_safe = hotload_safe and not spans_pre_hotload_major
    # ONE rule about the flag: no-restart-flag, below, and only when the flag is
    # missing where FPP needs it. Keeping a restart flag is never a defect, so
    # nothing here ever asks for its removal ("restart-likely-not-required") or
    # explains why it must stay when it is already set
    # ("hotload-safe-but-spans-pre-hotload-fpp") - both fired on plugins that were
    # already correct, could not be cleared without either dropping a harmless
    # flag or restructuring versions[], and kept tracking issues from ever going
    # clean (fpp-data#136, #236, #241). A plugin with the flag set everywhere it
    # is needed gets no restart-flag finding under any versions[] shape.

    if ships_commands or ships_native:
        # A reboot flag also satisfies this: a reboot restarts fppd along with
        # everything else, so a plugin that already asks for one (e.g. it also
        # changed something that genuinely needs the OS to come back up) has no
        # separate gap here - don't make it set both flags just to silence this.
        restart_flag_rx = re.compile(
            r'setSetting\s+(restartFlag|rebootFlag)\s+1'
            r'|setSetting\s*\(\s*["\'](restartFlag|rebootFlag)["\']'
            r'|SetRestartFlag\s*\(|SetRebootFlag\s*\(')

        def _restart_flag_gap(cands, required_if_absent):
            """Check one lifecycle slot (a tuple of candidate relative paths, most
            specific first - same scripts/X.sh-then-X.sh fallback FPP itself uses).
            Returns None if satisfied (a candidate exists and sets the flag, OR
            none exist and none are required to), else a short status string for
            the consolidated message below. `required_if_absent` distinguishes
            fpp_install.sh/fpp_uninstall.sh (FPP always runs these if present, so
            "doesn't exist" IS the gap - create one) from fpp_upgrade.sh (only a
            gap if it exists and is missing the flag; if absent, the Plugin
            Manager's Update button falls back to re-running fpp_install.sh, which
            is already covered by its own slot - PLUGIN_GUIDELINES.md's "native
            (C++) plugins" section)."""
            existing = [c for c in cands if os.path.isfile(os.path.join(root, c))]
            # A wrapper that `exec`s into the real script elsewhere in the repo:
            # the flag can legitimately live in the target, so check it too (in
            # addition to the wrapper, not instead of it).
            for c in list(existing):
                t = _exec_delegation_target(os.path.join(root, c), root)
                if t and t not in existing:
                    existing.append(t)
            if any(restart_flag_rx.search(_read(os.path.join(root, c))) for c in existing):
                return None
            if existing:
                return f"{'/'.join(existing)} present, no restart/reboot flag"
            if required_if_absent:
                return f"no {cands[-1]} (create one)"
            return None

        # One slot per point in the lifecycle FPP actually invokes a plugin
        # script and won't run anything else afterward: fresh install always
        # runs fpp_install.sh; a plugin-only update runs fpp_upgrade.sh INSTEAD
        # of fpp_install.sh when one exists (so having the flag in fpp_install.sh
        # alone doesn't cover it); uninstall runs fpp_uninstall.sh and then
        # unconditionally deletes the plugin directory (scripts/uninstall_plugin,
        # FPP core), so that's the only code that ever runs before removal.
        # FPP core's InstallPluginFromInfo()/UninstallPlugin()
        # (www/api/controllers/plugin.php) never set the flag on the plugin's
        # behalf at any of these points - it's entirely the plugin's own
        # responsibility, in whichever of these scripts it actually has.
        gaps = {}
        # install/uninstall are exactly the two lifecycle points fppd's runtime
        # load/unload now covers (see plugin_api_ready/hotload_safe above) - only
        # skip requiring the flag there when this plugin looks safe to rely on
        # that AND that reliance actually applies on every FPP major this exact
        # branch/build declares support for (effective_hotload_safe - see
        # spans_pre_hotload_major above). fpp_upgrade.sh is untouched: nothing
        # confirms InstallPluginFromInfo()'s hot-load call is reached on that path
        # too, so it keeps the old requirement.
        if not effective_hotload_safe:
            install_gap = _restart_flag_gap(("scripts/fpp_install.sh", "fpp_install.sh"), required_if_absent=True)
            if install_gap:
                gaps["install"] = install_gap
        upgrade_exists = any(os.path.isfile(os.path.join(root, c))
                              for c in ("scripts/fpp_upgrade.sh", "fpp_upgrade.sh"))
        if upgrade_exists:
            upgrade_gap = _restart_flag_gap(("scripts/fpp_upgrade.sh", "fpp_upgrade.sh"), required_if_absent=False)
            if upgrade_gap:
                gaps["upgrade"] = upgrade_gap
        if not effective_hotload_safe:
            uninstall_gap = _restart_flag_gap(("scripts/fpp_uninstall.sh", "fpp_uninstall.sh"), required_if_absent=True)
            if uninstall_gap:
                gaps["uninstall"] = uninstall_gap

        if gaps:
            if ships_commands:
                reason = "registers command type(s) via commands/descriptions.json"
            elif channel_output_hit:
                reason = ("ships a native plugin (.so) that produces a channel output "
                           "(defines createChannelOutput()) - FPP always refuses to hot-unload a plugin "
                           "whose output is in use, regardless of registerPluginApi()/unregisterPluginApi() use,")
            else:
                reason = "ships a native plugin (.so)"
            detail = "; ".join(f"{stage}: {msg}" for stage, msg in gaps.items())
            if hotload_safe and spans_pre_hotload_major:
                # This plugin's own CODE is fine for FPP HOTLOAD_INTRODUCED_MAJOR+ - the
                # generic "fppd only reads commands/.so once, at startup" explanation below
                # is actually FALSE for it there. The real reason it still needs the flag is
                # entirely about pluginInfo.json's versions[]: this same branch/build is also
                # served to FPP majors before HOTLOAD_INTRODUCED_MAJOR, which have no
                # load/unload feature at all - so give that reason instead of the generic one.
                out.append(Finding(BEST_PRACTICE, "no-restart-flag",
                           f"{reason} but doesn't request an fppd restart at every lifecycle point "
                           f"that needs one - {detail}.\n"
                           f"  - This plugin's code itself looks fine for FPP {HOTLOAD_INTRODUCED_MAJOR} "
                           f"- structurally safe to hot-load/unload without a restart there. The flag "
                           f"is still needed because pluginInfo.json's versions[] serves this exact "
                           f"branch/build to FPP majors before {HOTLOAD_INTRODUCED_MAJOR} too, which "
                           f"have no plugin load/unload feature at all - those installs still need a "
                           f"full fppd restart to pick up install/uninstall.\n"
                           f"  - Add `{RESTART_FLAG_SNIPPET}` to "
                           f"each script listed above (creating fpp_install.sh/fpp_uninstall.sh if "
                           f"missing - only fpp_upgrade.sh is optional, and only needs it if you "
                           f"already have one); only drop it once you split off a separate FPP "
                           f"{HOTLOAD_INTRODUCED_MAJOR}+-only branch/sha in versions[]"))
            else:
                out.append(Finding(BEST_PRACTICE, "no-restart-flag",
                           f"{reason} but doesn't request an fppd restart at every lifecycle point that "
                           f"needs one - {detail}.\n"
                           f"  - fppd only reads commands/descriptions.json and loads a native plugin's "
                           f".so once, at its own startup (PluginManager::loadUserPlugins(), called once "
                           f"from fppd.cpp) - never again while running, and never in response to a "
                           f"plugin install/upgrade/uninstall.\n"
                           f"  - Each lifecycle point runs independently (a plugin-only update runs "
                           f"fpp_upgrade.sh INSTEAD of fpp_install.sh when one exists; uninstall runs "
                           f"fpp_uninstall.sh then unconditionally deletes the plugin directory, so that "
                           f"script is the only code that ever runs before removal), so the flag has to "
                           f"be set independently in each one this plugin actually has/needs - fixing it "
                           f"in one script does not cover the others.\n"
                           f"  - Add `{RESTART_FLAG_SNIPPET}` to each "
                           f"script listed above (creating fpp_install.sh/fpp_uninstall.sh if missing - "
                           f"only fpp_upgrade.sh is optional, and only needs it if you already have one) "
                           f"so the Plugin Manager's restart banner appears right after that step instead "
                           f"of leaving the command silently unavailable/lingering as a ghost until fppd "
                           f"happens to restart for an unrelated reason"))

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
                       f"`{bad_hit[2]}`).\n"
                       f"  - Log to {howto} instead, which resolves to /home/fpp/media/logs/{repo}.log "
                       f"today, so it's rotated and included in the Support Zip"))

    # The reverse problem: a non-.log file (PID file, sqlite DB, command queue,
    # cache file) stored in FPP's log directory instead of the plugin's own
    # directory. The log directory is rotated and swept wholesale into Support
    # Zips as *logs* - non-log state living there either gets rotated away
    # unexpectedly or bloats every Support Zip with data that isn't a log.
    # Reports EVERY distinct offending file, not just the first line in the
    # tree: a plugin with a rogue PID file AND a rogue sqlite DB has two
    # separate problems, and only surfacing the first one found means the
    # second is still silently present after the first is fixed and the
    # linter is re-run. Dedupes by filename (not by line) so a file that's
    # opened from several different .php pages is still one finding.
    seen_log_dir_fnames = set()
    for rel, lineno, line, fname in _log_dir_non_log_hits(root):
        key = fname.lower()
        if key in seen_log_dir_fnames:
            continue
        seen_log_dir_fnames.add(key)
        out.append(Finding(BEST_PRACTICE, "log-dir-pollution",
                   f"non-log file stored in FPP's log directory ({rel}:{lineno}: `{line}`) - "
                   f"the log directory is rotated and bundled wholesale into Support Zips as *logs*; "
                   f"a PID file/database/cache/queue file living there either gets rotated away "
                   f"unexpectedly or bloats every Support Zip with non-log data.\n"
                   f"  - Store it in the plugin's own directory instead (`${{PLUGINDIR}}/{repo}/...` "
                   f"(shell), `$settings['pluginDirectory']` (PHP), or "
                   f"`os.path.dirname(os.path.abspath(__file__))` (Python)), and reserve the log "
                   f"directory for the actual `plugin-{repo}.log`"))

    # Broader than the above: ANY hardcoded file path under /home/fpp/media/
    # that isn't inside a directory a plugin is expected to touch on its own
    # (its log file, FPP's config storage, the plugins directory, or the
    # playlists directory) - e.g. a state file dropped straight into
    # /home/fpp/media/ itself. Scoped to /media/ specifically (/home/pi/ and
    # /tmp are already covered by the hardcoded-absolute-path check above) and
    # skips fpp_install.sh/fpp_uninstall.sh, which legitimately reach outside
    # the plugin's own footprint (systemd units, Apache config, cron, ...) as
    # part of installing/removing themselves.
    hit = next(iter(_outside_plugin_territory_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "outside-plugin-territory",
                   f"file path outside the plugin's own directory/log/config/playlists territory "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`).\n"
                   f"  - Store plugin-owned files inside the plugin's own directory "
                   f"(`${{PLUGINDIR}}/{repo}/...`), its runtime-data directory "
                   f"(`/home/fpp/media/plugindata/{repo}/`), FPP's config storage (`/media/config/`, "
                   f"for the `plugin.{repo}` settings file only), or the log directory (a real "
                   f"`.log` file only), rather than loose under `/home/fpp/media/` itself"))

    # Files a plugin creates under FPP's config directory that don't belong
    # there: crash reports bundle every file under config/ and can't redact a
    # binary, so a SQLite DB (AdvancedStats' stats DB, TwilioControl/
    # MessageQueue's visitor-message DBs) ships whole - BLOCKER. A log/lock/
    # cache or a non-`plugin.*` text file written there is the wrong place but
    # redactable - BEST_PRACTICE. See _config_dir_hits for what each tier
    # triggers on. Sorted by (path, line) and deduped by (kind, filename), so
    # the first occurrence of each distinct offending file is what's reported.
    seen_cfg_fnames = set()
    for rel, lineno, line, fname, kind in sorted(_config_dir_hits(root), key=lambda h: (h[0], h[1])):
        key = (kind, fname.lower())
        if key in seen_cfg_fnames:
            continue
        seen_cfg_fnames.add(key)
        if kind == "binary":
            out.append(Finding(BLOCKER, "config-dir-binary-write",
                       f"database/binary file `{fname}` under FPP's config directory ({rel}:{lineno}: "
                       f"`{line}`) - crash reports bundle config/ and cannot redact binaries.\n"
                       f"  - Write it to `/home/fpp/media/plugindata/{repo}/` instead (`mkdir -p` it in "
                       f"scripts/fpp_install.sh, then `chown ${{FPPUSER}}:${{FPPGROUP}}` - install scripts "
                       f"run as root but the web server writes as `fpp`; an existing file can be moved "
                       f"across there with `mv`/`rename()`, which this check doesn't flag); config/ is "
                       f"only for the `plugin.{repo}` settings file"))
        elif kind == "state":
            out.append(Finding(BEST_PRACTICE, "config-dir-misuse",
                       f"log/cache/lock/pid file `{fname}` under FPP's config directory ({rel}:{lineno}: "
                       f"`{line}`) - crash reports bundle config/, and runtime state isn't settings.\n"
                       f"  - Write logs to `/home/fpp/media/logs/plugin-{repo}.log` and other state to "
                       f"`/home/fpp/media/plugindata/{repo}/` (`mkdir -p` it in scripts/fpp_install.sh)"))
        else:
            out.append(Finding(BEST_PRACTICE, "config-dir-misuse",
                       f"file `{fname}` written under FPP's config directory with a non-settings name "
                       f"({rel}:{lineno}: `{line}`) - crash reports bundle config/, where only "
                       f"`plugin.<repoName>` settings files are expected.\n"
                       f"  - Settings: name it `plugin.{repo}` / `plugin.{repo}.json` "
                       f"(WriteSettingToFile/setPluginJSON); anything else: write it to "
                       f"`/home/fpp/media/plugindata/{repo}/` (`mkdir -p` it in scripts/fpp_install.sh)"))

    # A file named api.php in the plugin root is not just another page: FPP core's
    # collectPluginEndpoints() (www/api/controllers/plugin.php:3754) require_once's
    # it on EVERY /api/* request, expecting it to only declare a
    # getEndpoints<repoName>() registrar whose routes mount under
    # /api/plugin/<repoName>/... A plugin that uses that filename for something
    # else - a page-style AJAX dispatcher reached via plugin.php?page=api.php -
    # gets loaded on every API call anyway. Confirmed on a live FPP 10 box
    # (fpp-plugin-SDCardRecover, 2026-09): its api.php did a top-level
    # require_once "config.php" that can't resolve from www/api/'s cwd, which PHP
    # 8 surfaces as a catchable Error, so core skipped the plugin - but logged two
    # lines to media/logs/apache2-error.log per API request (that log ships in
    # support zips; FPP's status page polls ~1/s). Had the require resolved, the
    # top-level http_response_code(400) + JSON echo would have prefixed every API
    # response instead. Even a harmless api.php with no registrar costs one
    # "no callable getEndpoints* function found" error_log line per request
    # (plugin.php:3817). The author had documented at length why the getEndpoints
    # convention "doesn't apply" - confused with the C++ /plugin-apis/ route.
    #
    # Two signals: no `function getEndpoints...(` declared at all, and/or a
    # depth-0 side-effect statement (echo/header/exec/switch/superglobal read).
    # Validated 2026-09 against the local catalog mirror: all 8 api.php files
    # there declare a registrar and have 0 top-level side effects.
    api_php = os.path.join(root, "api.php")
    if os.path.isfile(api_php):
        api_src = _read(api_php)
        api_code = _php_strip_opaque(api_src)
        # PHP function names are case-insensitive and core resolves the
        # registrar with is_callable()/stripos(), so match the same way.
        registrars = re.findall(r'(?im)^\s*function\s+(getEndpoints\w*)\s*\(', api_code)
        has_registrar = bool(registrars)
        # FPP 9.x (www/api/index.php) calls exactly `getEndpoints<repoName minus
        # dashes>` with no fallback - a registrar under any other name is a
        # fatal on every /api/* request there. Master falls back to any
        # getEndpoints* the file defined, so the exact name only matters while
        # versions[] still covers a pre-10 major (same test apt-manual-install
        # uses).
        exact_registrar = "getendpoints" + repo.replace("-", "").lower()
        _vers = (info or {}).get("versions") or []
        _covers_pre_10 = any(
            (_major(v.get("minFPPVersion")) or 99) < 10
            for v in _vers if isinstance(v, dict) and v.get("minFPPVersion"))
        wrong_name = (has_registrar and _covers_pre_10
                      and exact_registrar not in {n.lower() for n in registrars})
        top_hit = next(iter(_api_php_top_level_hits(api_php)), None)
        if not has_registrar or top_hit or wrong_name:
            why = []
            if not has_registrar:
                why.append("declares no `getEndpoints…()` function")
            if wrong_name:
                why.append(f"names its registrar `{registrars[0]}()` but pluginInfo.json still "
                           f"declares FPP 9 support, where core calls exactly "
                           f"`getEndpoints{repo.replace('-', '')}()` with no fallback")
            if top_hit:
                why.append(f"runs code at top level (api.php:{top_hit[0]}: `{top_hit[1][:80]}`)")
            out.append(Finding(BLOCKER, "api-php-not-a-registrar",
                       f"`api.php` {' and '.join(why)} - FPP core require_once's every installed "
                       f"plugin's api.php on EVERY /api/* request (www/api/controllers/plugin.php, "
                       f"collectPluginEndpoints()) and expects it to only declare a "
                       f"`getEndpoints{repo.replace('-', '')}()` registrar for routes under "
                       f"/api/plugin/{repo}/...\n"
                       f"  - Anything else in that file executes (or fails to load, with an error_log "
                       f"line) on every API call from every page, for every user of this plugin - "
                       f"not just when the plugin's own page is open\n"
                       f"  - Either rename the file (e.g. `ajax.php`, reached the same way via "
                       f"plugin.php?page=ajax.php&nopage=1) or turn it into a real registrar: "
                       f"declare only functions, with getEndpoints…() returning "
                       f"[['method'=>'GET','endpoint'=>'status','callback'=>'myPluginStatus'], ...]"))

        # Every other installed plugin's api.php is require_once'd into the same
        # request too (the same fact api-php-not-a-registrar above is built on),
        # so a plain, GENERIC-named top-level `function`/`class` declared here -
        # anything besides the getEndpoints…() registrar itself - collides the
        # moment another plugin's api.php declares the same name. Core (master,
        # PluginApiFunctionConflicts()) now catches a name that already exists
        # and skips the whole plugin's API with an error_log line rather than
        # fataling; FPP 9 fatals with "Cannot redeclare". Two tiers:
        #   BLOCKER - one of limonade's lifecycle hooks (PluginApiReservedFunctions()
        #     in plugin.php: configure/initialize/before/after/...). Core refuses
        #     to load an api.php declaring one at all, because the framework
        #     call_if_exists()es them on EVERY request and a plugin defining
        #     autoload_controller() decides whether FPP's own controllers load.
        #   BEST_PRACTICE - a curated list of short generic names (not "doesn't
        #     contain the repo slug", which false-positived on every plugin
        #     using its own abbreviation - fah_deleteStream, hacLog). This can't
        #     prove another plugin uses the name, only that nothing prevents it.
        # Only depth-0 declarations count: a class METHOD can't collide with a
        # global, whatever it's called.
        top_decls = []
        depth = 0
        for line in api_code.splitlines():
            m = re.match(r'^\s*(?:abstract\s+|final\s+)?(?:function|class)\s+(\w+)', line)
            if depth == 0 and m and not re.match(r'getEndpoints\w*$', m.group(1), re.I):
                top_decls.append(m.group(1))
            depth += line.count('{') - line.count('}')
        reserved = [n for n in top_decls if n.lower() in _LIMONADE_RESERVED_NAMES]
        core_clash = [n for n in top_decls if n.lower() in _fpp_api_globals() or n.lower() in _PHP_BUILTIN_NAMES]
        generic = [n for n in top_decls if n.lower() in _GENERIC_API_NAMES]
        if reserved:
            out.append(Finding(BLOCKER, "api-php-namespace-collision",
                       f"`api.php` declares `{reserved[0]}()`, a lifecycle hook of the limonade "
                       f"framework FPP's API runs on (configure/initialize/before/after/"
                       f"autoload_controller/...) - the framework calls these on EVERY /api/* "
                       f"request, so a plugin defining one silently takes over part of request "
                       f"handling for every API call; FPP core refuses to register an api.php that "
                       f"declares any of them (PluginApiReservedFunctions() in "
                       f"www/api/controllers/plugin.php).\n"
                       f"  - Rename it (e.g. `{repo.replace('-', '')}_{reserved[0]}`)"))
        elif core_clash:
            # Not a "might collide" - it DOES: this name is defined by FPP's own
            # common.php/config.php/api controllers on every /api/* request,
            # before any plugin api.php is loaded. FPP 9: fatal "Cannot
            # redeclare" for every API call; 10+: PluginApiFunctionConflicts()
            # skips this plugin's whole API with an error_log line.
            is_builtin = core_clash[0].lower() in _PHP_BUILTIN_NAMES and core_clash[0].lower() not in _fpp_api_globals()
            out.append(Finding(BLOCKER, "api-php-namespace-collision",
                       f"`api.php` declares `{core_clash[0]}()`, which "
                       + ("is a PHP built-in function" if is_builtin else
                          "FPP core already defines on every /api/* request (www/common.php, "
                          "config.php or an api controller)") + " - "
                       f"FPP 9 fatals with \"Cannot redeclare {core_clash[0]}()\" on every API call "
                       f"for every user of this plugin; FPP 10+ refuses to register this plugin's "
                       f"API at all (PluginApiFunctionConflicts()).\n"
                       f"  - Rename it (e.g. `{repo.replace('-', '')}_{core_clash[0]}`)"))
        elif generic:
            out.append(Finding(BEST_PRACTICE, "api-php-namespace-collision",
                       f"`api.php` declares a generic, unprefixed `{generic[0]}` at top level - "
                       f"api.php is require_once'd for EVERY installed plugin on every /api/* "
                       f"request, so a same-named function/class in another plugin's api.php is a "
                       f"collision the moment both are installed together: FPP 9 fatals with "
                       f"\"Cannot redeclare\", FPP 10+ skips one plugin's whole API with only an "
                       f"error_log line.\n"
                       f"  - Prefix it (e.g. `{repo.replace('-', '')}_{generic[0]}`) or move it into "
                       f"a required file that isn't loaded globally"))

    # Log filename doesn't start with the mandated "plugin-" prefix - it still
    # lands in the right directory, just under a name FPP's log viewer/Support
    # Zip convention doesn't expect, and it isn't namespaced against collisions.
    hit = next(iter(_log_naming_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "log-naming",
                   f"log filename doesn't follow the plugin-<repoName>.log convention ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`).\n"
                   f"  - Name it `plugin-{repo}.log` (not just `{repo}.log`), so it's recognized as "
                   f"this plugin's log by FPP's log viewer and namespaced against collisions with "
                   f"other plugins/tools"))

    # An always-on daemon (installs a systemd unit) with no FPP-conformant log
    # reference anywhere - nothing surfaces in the log viewer or Support Zip.
    elif first(r'/etc/systemd/system/|systemctl\s+enable') \
            and not first(r'LOGDIR|logDirectory|plugin-[\w.-]*\.log'):
        out.append(Finding(BEST_PRACTICE, "log-naming",
                   "installs an always-on service but has no FPP-conformant log anywhere "
                   f"(no LOGDIR/logDirectory/plugin-{repo}.log reference).\n"
                   f'  - Log to `$settings[\'logDirectory\']."/plugin-{repo}.log"` (PHP) or the '
                   f"equivalent in your language, so the service's output surfaces in FPP's log "
                   f"viewer and Support Zip instead of only wherever stdout happens to go"))

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
                   f"command triggered it.\n"
                   f"  - Set `CURLOPT_TIMEOUT`/`CURLOPT_CONNECTTIMEOUT` (PHP curl), the `'timeout'` "
                   f"key (PHP stream contexts), or `timeout=` (Python `requests`)"))

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
                       f"repo name (`{src[1]}`, parsed from srcURL) - PLUGININFO_FORMAT.md requires "
                       f"them to match.\n"
                       f"  - Rename the GitHub repo to `{declared}` (Settings > repository name) or "
                       f"change repoName to `{src[1]}`, whichever is the real name here - just make "
                       f"sure pluginList.json's listing name is updated to match too."))

    # Plugins may not solicit donations, payments, or subscriptions anywhere -
    # not just runtime UI, but README/help/docs too (hence the dedicated
    # _donation_reference_hits, not _grep, which skips those). BLOCKER: this is
    # a flat prohibition (PLUGIN_GUIDELINES.md §10), not a style nudge.
    hit = next(iter(_donation_reference_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "ask-for-money",
                   f"references or links to a donation/payment/subscription service ({hit[0]}:"
                   f"{hit[1]}: `{hit[2]}`) - FPP plugins may not solicit donations, payments, or "
                   f"subscriptions (PayPal, Buy Me a Coffee, Ko-fi, Venmo, Cash App, Patreon, GitHub "
                   f"Sponsors, or similar) anywhere in the plugin - UI, README, help pages, or "
                   f"pluginInfo.json.\n"
                   f"  - Remove it before this can be listed"))

    # Plugins may not log usage/statistics and send them off-box - no bundled
    # analytics/telemetry SDK, no home-rolled phone-home endpoint - except where
    # transmitting data is essential to the plugin's actual function (a weather
    # plugin fetching weather, a plugin calling its own cloud backend to do the
    # thing it exists to do). BLOCKER per policy - a submitter who believes a
    # hit is actually essential-to-function can still `/submit` over it and ask
    # a maintainer to judge intent rather than this being an automatic block
    # with no override. See PLUGIN_GUIDELINES.md §11.
    hit = next(iter(_phone_home_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "phone-home",
                   f"possible usage telemetry / phone-home ({hit[0]}:{hit[1]}: `{hit[2]}`) - plugins "
                   f"may not log plugin usage/statistics and send them off-box, except where that "
                   f"data transmission is essential to the plugin's actual function.\n"
                   f"  - If this is analytics/telemetry rather than core functionality, remove it; if "
                   f"you have a genuine need for usage stats, talk to the FPP developers about "
                   f"extending the existing opt-in `fpp-stats` system instead of rolling your own"))

    # Plugins may not advertise anything inside the FPP UI - products, vendors,
    # things for sale, or even other plugins. BLOCKER per policy - this only
    # catches mechanical cases (known ad networks, boilerplate ad phrasing), so
    # what it does flag is high-confidence; a banner image with no telltale
    # text still needs a human to catch, same as before. See PLUGIN_GUIDELINES.md §12.
    hit = next(iter(_advertising_hits(root)), None)
    if hit:
        out.append(Finding(BLOCKER, "advertising",
                   f"possible advertising in the plugin's UI ({hit[0]}:{hit[1]}: `{hit[2]}`) - "
                   f"plugins may not advertise anything inside the FPP UI, including products, "
                   f"vendors, things for sale, or other plugins (yours or anyone else's).\n"
                   f"  - If this is genuinely ad/promotional content, remove it"))

    # Decoding and executing an encoded/compressed payload at runtime is worth
    # flagging on its own - it's also the most direct way the donation/phone-
    # home/advertising checks just above get evaded (a base64'd PayPal link, a
    # gzinflate'd tracking call this tool can't grep for as plain text).
    # BEST_PRACTICE: this doesn't know whether the payload is malicious or just
    # unusually packaged, only that a human should read it by hand instead of
    # trusting the greps above to have seen everything.
    # Two shapes: decode-and-EXECUTE (eval/assert/exec/`| bash` over a decoder),
    # and a long base64 LITERAL in the source being decoded - the payload is
    # shipped inside the code, whatever is then done with it. A base64_decode
    # of a runtime value (an uploaded data-URL image, a setting) is neither.
    exec_hit = (first(r'\b(?:eval|assert)\s*\(\s*(?:["\']\?>["\']\s*\.\s*)?'
                      r'(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(', exts=(".php",))
                or first(r'\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|zlib\.decompress|codecs\.decode)\s*\(',
                         exts=(".py",))
                or first(r'\bbase64\s+(?:-d|--decode)\b[^|\n]*\|\s*(?:sudo\s+)?(?:bash|sh|python3?|perl)\b',
                         exts=(".sh",))
                or first(r'\beval\s*\(\s*atob\s*\(|new\s+Function\s*\(\s*atob\s*\(', exts=(".js",)))
    literal_hit = None if exec_hit else first(
        r'\b(?:base64_decode|base64\.b64decode|atob)\s*\(\s*["\']'
        r'(?!iVBORw0K|/9j/|R0lGOD|PHN2Zy|UklGR|Qk[0-9A-Za-z]|AAABAA)[A-Za-z0-9+/=\s]{60,}["\']',   # not PNG/JPEG/GIF/SVG/WEBP/BMP/ICO
        exts=(".php", ".py", ".js"))
    hit = exec_hit or literal_hit
    if hit:
        what = ("decodes and executes an encoded/compressed payload at runtime" if exec_hit
                else "ships an encoded payload inside the source and decodes it at runtime")
        out.append(Finding(BEST_PRACTICE, "obfuscated-code",
                   f"{what} ({hit[0]}:"
                   f"{hit[1]}: `{hit[2][:100]}`) - this is also how a donation link, phone-home call, or ad "
                   f"could evade the checks above (base64/gzinflate'd instead of plain text).\n"
                   f"  - Ship the code plainly instead of encoding/compiling it at runtime, so it's "
                   f"actually reviewable; if there's a genuine reason for it, explain via `/submit`"))

    # A plugin that sets up/depends on a third-party tunneling or remote-access
    # service (Dataplicity, ngrok, Cloudflare Tunnel, Tailscale, ZeroTier, ...) has
    # to say so in pluginInfo.json's description, not just a README/setup page -
    # PLUGIN_GUIDELINES.md §13. BLOCKER: not a prohibition on USING one of these
    # services (they're often the only practical way to receive an inbound
    # webhook on a home network) - but failing to disclose it is treated the same
    # as the other flat-prohibition policy checks (ask-for-money, phone-home,
    # advertising), since a user decides whether to install BEFORE reading a
    # README or setup page, and this is a real security-relevant side effect
    # (exposing the FPP box to the internet through a third party) they'd have no
    # way to know about otherwise. Description check is deliberately broad (any of
    # "tunnel"/"remote access"/the specific service names) rather than requiring
    # an exact match to the code hit, since an author describing this in their
    # own words ("exposes your Pi to the internet via a tunnel") still counts as
    # disclosed - fixing it is a one-line pluginInfo.json edit, not a code change.
    hit = next(iter(_tunnel_service_hits(root)), None)
    if hit:
        description = (info or {}).get("description") or ""
        # Reuse _TUNNEL_SERVICE_RX itself (same service names/domains) rather than
        # keeping a second list in sync - OR'd with the generic phrasing an author
        # might use in their own words instead of naming the service.
        disclosure_rx = re.compile(_TUNNEL_SERVICE_RX.pattern + r'|tunnel|remote\s+access', re.I)
        if not disclosure_rx.search(description):
            out.append(Finding(BLOCKER, "tunnel-service-undisclosed",
                       f"sets up or depends on a third-party tunneling/remote-access service "
                       f"({hit[0]}:{hit[1]}: `{hit[2]}`) but pluginInfo.json's description doesn't "
                       f"mention it (PLUGIN_GUIDELINES.md §13).\n"
                       f"  - A user deciding whether to install has to know upfront that this may "
                       f"expose their FPP box's control surface to the internet through a third "
                       f"party - say what the service is and why it's needed directly in the "
                       f"description field, not just a README or setup page"))

    # Privacy disclosure vs the code (PLUGIN_GUIDELINES.md §14): a missing
    # `privacy` block, a block the code contradicts (privacy-undeclared-*), and
    # any touch of FPP's own privacy settings. Same family as phone-home /
    # tunnel-service-undisclosed above - disclosure rules, not code-quality ones.
    out.extend(_privacy_findings(root, info, own_owner))

    # --- repo hygiene --------------------------------------------------------

    # menu.inc: at most one entry per `type` (status/content/output/help) -
    # PLUGIN_GUIDELINES.md §9.1. A plugin can appear under multiple menu areas,
    # just never twice within the SAME area - the guideline's own anti-pattern
    # example is exactly this (three separate 'help' entries instead of one page).
    for mtype, hits in sorted(_menu_type_counts(root).items()):
        if len(hits) > 1:
            rel, lineno = hits[1]
            out.append(Finding(BEST_PRACTICE, "menu-duplicate-type",
                       f"menu.inc has {len(hits)} '{mtype}' entries ({rel}:{lineno}) - each of the "
                       f"four menu areas (status/content/output/help) may contain at most one entry "
                       f"from your plugin.\n"
                       f"  - Combine the extra pages into a single page (e.g. tabs or sections within "
                       f"one page) instead of adding a separate menu entry per page"))

    # A menu.inc entry whose local 'page' file quietly redirects the current tab off
    # FPP (same-origin or not), rather than either rendering as a normal in-FPP plugin
    # page or declaring itself as an external link up front (the guideline-sanctioned
    # 'page' => 'http://...' shape, which opens as an explicit new-tab pop-up). Human
    # review, not a blocker - some plugins legitimately front a real separate service
    # and a pop-up is the right way to do that; a same-tab redirect isn't.
    hit = next(iter(_menu_off_box_redirect_hits(root)), None)
    if hit:
        rel, lineno, target_rel = hit
        out.append(Finding(BEST_PRACTICE, "menu-off-box-redirect",
                   f"menu.inc entry ({rel}:{lineno}) points at {target_rel}, which redirects the "
                   f"current tab away from FPP - the menu link looks like it opens a plugin page "
                   f"inside FPP but doesn't.\n"
                   f"  - Menu entries should land on a page that renders inside FPP; if the plugin "
                   f"genuinely needs to send users to a separate application, use menu.inc's own "
                   f"supported external-link shape ('page' => 'http://...', which opens as an "
                   f"explicit new-tab pop-up) instead of a local page that silently navigates the "
                   f"current tab elsewhere"))

    # A first-run admin account seeded with a well-known default password
    # (admin/password/changeme/...) rather than a per-install random one. Forcing a
    # change on first login helps, but the well-known default is still live for
    # whatever window exists between install and first login.
    hit = next(iter(_default_credential_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "default-admin-credentials",
                   f"first-run account seeded with a well-known default password ({hit[0]}:{hit[1]}: "
                   f"`{hit[2]}`) - even with a forced change on first login, anything scanning for "
                   f"this specific plugin can log in during the window between install and first "
                   f"login.\n"
                   f"  - Generate a random per-install default instead (and surface it the same way - "
                   f"install output, first-run banner, etc.)"))

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
                   "how to build a plugin in general, not part of your plugin.\n"
                   "  - Delete them from your repo; they should only exist in fpp-plugin-Template "
                   "itself."))

    # Icon: FPP prefers a local icon.png (renders offline once installed) and falls back
    # to iconURL (also the ONLY option for a pre-install Plugin Manager thumbnail, since
    # there's no local checkout yet at that point). Neither present => initials fallback
    # everywhere. See www/api/controllers/plugin.php's PluginServeIcon().
    has_icon_url = bool((info or {}).get("iconURL"))
    has_icon_png = "icon.png" in lower
    if not has_icon_png and not has_icon_url:
        out.append(Finding(BEST_PRACTICE, "no-icon",
                   "no icon.png in the repo root and no iconURL in pluginInfo.json - the Plugin "
                   "Manager will show your initials instead of an icon.\n"
                   "  - A local icon.png (128x128 or 256x256, repo root) is preferred since it "
                   "renders offline once installed; iconURL is the fallback and the only option "
                   "shown before install"))
    elif has_icon_png and not has_icon_url:
        out.append(Finding(BEST_PRACTICE, "no-iconurl",
                   "icon.png exists but pluginInfo.json has no iconURL - the local icon only "
                   "renders after install, so the pre-install Plugin Manager listing (which has "
                   "no local checkout yet) still shows your initials.\n"
                   "  - Add iconURL pointing at the repo's own raw file, e.g. "
                   "`https://raw.githubusercontent.com/<owner>/<repo>/<branch>/icon.png`"))
    elif has_icon_url and not has_icon_png:
        out.append(Finding(BEST_PRACTICE, "no-local-icon",
                   "iconURL is set but there's no icon.png in the repo root - post-install, the "
                   "Plugin Manager has to fetch the icon over the network every time instead of "
                   "reading it off disk, so it goes back to showing initials if the box is offline "
                   "or the URL/repo ever moves.\n"
                   "  - Add a local icon.png (128x128 or 256x256, repo root) so it renders offline "
                   "once installed; keep iconURL as the pre-install fallback"))

    # Release notes (FPP 10+): the Plugin Manager only offers a Release Notes
    # icon/link when pluginInfo.json says how to get them (releaseNotesStyle).
    # Omitted or "none" means users see nothing before/after an update - not a
    # defect, so OPTIONAL, but worth a nudge since most plugins can just say
    # "gitHistory" (the commits an update would bring in) with no other work.
    # Only checked when info is present at all - the schema/plugininfo blockers
    # already cover a missing or unreadable pluginInfo.json.
    if info is not None:
        rns = info.get("releaseNotesStyle")
        if not rns or rns == "none":
            has_script = os.path.isfile(os.path.join(root, "scripts", "fpp_releasenotes.sh"))
            out.append(Finding(OPTIONAL, "no-release-notes-style",
                       f"pluginInfo.json has no `releaseNotesStyle`"
                       f"{' (it is \"none\")' if rns == 'none' else ''} - FPP 10+'s Plugin Manager "
                       f"shows a Release Notes link only when this says where to get them, so users "
                       f"currently see nothing about what an update changes.\n"
                       f"  - Add `\"releaseNotesStyle\": \"gitHistory\"` (the commits between the "
                       f"installed clone and the branch tip - no extra work), or `\"gitRelease\"` if "
                       f"you publish GitHub Releases with notes"
                       + (f", or `\"script\"` since scripts/fpp_releasenotes.sh already exists"
                          if has_script else "")
                       + "; see the `releaseNotesStyle` entry in pluginInfo.schema.json"))

    # fpp_install.sh creates state OUTSIDE the plugin's own directory - a
    # systemd unit, a cron entry, a sudoers/udev/kernel-module rule, or a
    # write to /etc or one of FPP's own config files/settings - but the
    # plugin ships no fpp_uninstall.sh at all to revert any of it. FPP's
    # uninstall (scripts/uninstall_plugin, core) deletes only the plugin's
    # own directory - anything reaching outside it needs fpp_uninstall.sh to
    # actually go away, and a plugin with none has no chance of reverting
    # anything, whatever shape that state takes.
    #
    # Generalizes what used to be a systemd-only version of this check to
    # every "reaches outside the plugin directory" signal the privacy checks
    # already detect (_priv_service_hits/_priv_privilege_hits/
    # _priv_core_write_hits, reused rather than reimplemented - each already
    # skips rm/disable/uninstall-shaped lines and is tuned for a low false-
    # positive rate there), plus a fourth, install-hook-specific source:
    # _PRIV_MEDIA_WRITE_RX catches a file dropped into one of FPP's OTHER
    # shared media subdirectories (media/scripts, media/images, ...) - an
    # orphaned script that stays schedulable in FPP's own Scripts UI, or a
    # stray asset, after the plugin is gone (real, not hypothetical:
    # fpp-PictureFrame, fpp-jukebox). Deliberately existence-only (no
    # fpp_uninstall.sh at all, not "exists but its cleanup isn't literally
    # matchable") - cron-no-uninstall below already owns that narrower,
    # regex-blind-spot-prone case for cron specifically; a plugin missing
    # uninstall entirely can trip both, which is fine.
    if not (os.path.isfile(os.path.join(root, "scripts/fpp_uninstall.sh")) or
            os.path.isfile(os.path.join(root, "fpp_uninstall.sh"))):
        # The _priv_* helpers walk the WHOLE tree, so a nested file that happens
        # to be named fpp_install.sh is already seen by the basename filter. A
        # root fpp_install.sh that just `exec`s into the real installer
        # elsewhere in the repo is the same thing logically but need not share
        # the filename, so the target is accepted by path as well (in addition
        # to the wrapper, not instead of it).
        deleg_rels = set()
        for _c in ("scripts/fpp_install.sh", "fpp_install.sh"):
            _t = _exec_delegation_target(os.path.join(root, _c), root)
            if _t:
                deleg_rels.add(_t)

        def _from_install_hook(rel: str) -> bool:
            return os.path.basename(rel) == "fpp_install.sh" or rel in deleg_rels

        # Two tiers. An ARTIFACT the plugin itself created outside its dir - a
        # unit/cron file, an /etc file, a sudoers/udev/modules entry, a file
        # dropped into media/scripts etc. - is orphaned for good when the dir is
        # deleted: BLOCKER. A STATE CHANGE to something that already existed -
        # `systemctl enable smbd` (Debian's own unit; fpp-PictureFrame does this
        # and it's FPP's own Service_smbd_nmbd toggle), an FPP setting, a group
        # membership, setcap - is a real "reaches outside" fact worth an
        # uninstall step, but reverting it can be wrong (switching off a file
        # share the user relies on), so BEST_PRACTICE.
        created, changed = [], []
        repo_units = {os.path.basename(f).lower()
                      for f in _iter_files(root, (".service", ".timer", ".socket"))}
        for unit, hits in _priv_service_hits_all(root).items():
            hook_hits = [h for h in hits if _from_install_hook(h[0])]
            if not hook_hits:
                continue
            ships_unit = (any(_PRIV_UNIT_FILE_RX.search(h[2]) for h in hook_hits)
                          or any(f"{unit}{ext}" in repo_units for ext in (".service", ".timer", ".socket")))
            hit = next((h for h in hook_hits if _PRIV_UNIT_FILE_RX.search(h[2])), hook_hits[0])
            (created if ships_unit else changed).append(
                (f"{'service/cron entry' if ships_unit else 'enables system service'} `{unit}`", hit))
        for kind, hit in _priv_privilege_hits(root).items():
            if _from_install_hook(hit[0]):
                # A FILE under /etc (sudoers.d, udev rules.d, modules-load.d)
                # is an artifact; a bare `modprobe x` / `udevadm control
                # --reload` / `dtoverlay` is gone at reboot - nothing to revert.
                artifact = (kind in ("sudoers", "udev rule", "kernel module")
                            and re.search(r'/etc/(?:sudoers|udev|modules)', hit[2]) is not None)
                (created if artifact else changed).append((f"privilege change ({kind})", hit))
        seen_targets = set()
        for hit in _priv_core_write_hits(root):
            if _from_install_hook(hit[0]) and hit[3] not in seen_targets:
                seen_targets.add(hit[3])
                (created if hit[3].startswith("/etc/") else changed).append(
                    (f"write to `{hit[3]}`", hit[:3]))
        for rel, i, line, target in _priv_media_write_hits(root):
            if _from_install_hook(rel):
                created.append((f"file dropped in `{target}`", (rel, i, line)))
        # One line per kind - PictureFrame copies two scripts into media/scripts
        # and writes the same setting twice; listing each is noise.
        _seen_kinds: set[str] = set()
        external = [(k, h) for k, h in created + changed
                    if not (k in _seen_kinds or _seen_kinds.add(k))]
        if external:
            kinds = ", ".join(k for k, _ in external[:4])
            more = f" (+{len(external) - 4} more)" if len(external) > 4 else ""
            first_hit = external[0][1]
            where = (f" (in {first_hit[0]}, the real installer it `exec`s into)"
                     if first_hit[0] in deleg_rels else "")
            out.append(Finding(BLOCKER if created else BEST_PRACTICE, "no-uninstall",
                       f"fpp_install.sh{where} {'creates state' if created else 'changes system state'} "
                       f"outside the plugin's own directory - {kinds}{more} "
                       f"({first_hit[0]}:{first_hit[1]}: `{first_hit[2]}`) - but ships no "
                       f"fpp_uninstall.sh to revert any of it.\n"
                       f"  - Add fpp_uninstall.sh that reverts each install step above (e.g. "
                       f"`systemctl disable --now <unit> && rm -f /etc/systemd/system/<unit>` for a "
                       f"service the plugin installed, `crontab -l | grep -v <marker> | crontab -` "
                       f"for cron, `rm -f` for a file dropped elsewhere), so removing the plugin "
                       f"doesn't leave it behind - FPP's uninstall only deletes the plugin's own "
                       f"directory"
                       + ("" if created else
                          "\n  - For a pre-existing service or an FPP setting the user may rely on, "
                          "reverting only what the plugin itself turned on is enough")))

    # Generalizes the systemd check above to cron: registers a cron entry
    # (directly, or via python-crontab/similar) but fpp_uninstall.sh never
    # removes it - same "orphaned persistent resource survives uninstall"
    # class of bug, just a different persistence mechanism than systemd.
    cron_hit = first(r'CronTab\s*\(|crontab\s+-l|/etc/cron\.d/|cron\.new\(')
    if cron_hit:
        uninstall_p = next((p for p in (os.path.join(root, "scripts/fpp_uninstall.sh"),
                                         os.path.join(root, "fpp_uninstall.sh")) if os.path.isfile(p)), None)
        # A wrapper fpp_uninstall.sh that just `exec`s into the real uninstaller
        # elsewhere in the repo hands the whole process over, so the cron
        # cleanup can legitimately live in the target: check that body too (in
        # addition to the wrapper's, not instead of it - either one having the
        # cleanup satisfies this).
        uninstall_deleg = _exec_delegation_target(uninstall_p, root) if uninstall_p else None
        uninstall_body = _read(uninstall_p) if uninstall_p else ""
        if uninstall_deleg:
            uninstall_body += "\n" + _read(os.path.join(root, uninstall_deleg))
        # Recognize the idiomatic (and correct) removal pattern too: `crontab -l
        # | grep -v <marker> | crontab -` replaces the crontab with everything
        # EXCEPT the matched entry - this is more common, and safer, than a
        # blanket `crontab -r` (which wipes the user's entire crontab).
        # For /etc/cron.d entries the normal spelling is `rm -f /etc/cron.d/<name>`
        # (rm BEFORE the path); the earlier `cron\.d/.*rm\b` only matched rm AFTER
        # the path, which false-positived every plugin using the normal form.
        has_cleanup = re.search(r'remove_all|crontab\s+-r|\brm\b.*cron\.d/|cron\.d/.*\brm\b', uninstall_body) \
            or re.search(r'crontab\s+-l.*\|.*grep\s+-v.*\|.*crontab\s+-', uninstall_body)
        if not has_cleanup:
            never = (f"neither fpp_uninstall.sh nor {uninstall_deleg} (the real uninstaller it "
                     f"`exec`s into) removes it" if uninstall_deleg
                     else "fpp_uninstall.sh never removes it")
            out.append(Finding(BLOCKER, "cron-no-uninstall",
                       f"registers a cron entry but {never} ({cron_hit[0]}:"
                       f"{cron_hit[1]}: `{cron_hit[2]}`).\n"
                       f"  - Add cleanup to fpp_uninstall.sh (e.g. `crontab -l | grep -v <marker> | "
                       f"crontab -`, or the removal call for whatever cron library you used to "
                       f"install it), so uninstalling the plugin doesn't leave a cron entry pointing "
                       f"at a script that no longer exists"))

    # External CDN <script>/<link> instead of the Bootstrap/jQuery FPP's own
    # web shell already loads - duplicates what's already available, and is an
    # offline-availability risk on an isolated show network with no internet.
    hit = first(r'https?://(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|ajax\.googleapis\.com)',
                exts=(".php", ".html", ".inc"))
    if hit:
        out.append(Finding(BEST_PRACTICE, "external-cdn",
                   f"loads a script/stylesheet from an external CDN ({hit[0]}:{hit[1]}: `{hit[2]}`) "
                   f"- FPP's web shell already bundles Bootstrap/jQuery, and a show network is often "
                   f"offline/isolated, so a CDN dependency can silently fail to load.\n"
                   f"  - Use FPP's already-loaded copy instead of pulling your own from a CDN"))

    # Killing a process by grepping `ps aux`/`ps -ef` output instead of using a
    # PID file - matches ANY process whose command line happens to contain the
    # search string, with no guard against zero or multiple matches.
    hit = first(r'kill\s*(-9)?\s*`ps\s+(aux|-ef)') or first(r'kill\s*(-9)?\s*\$\(ps\s+(aux|-ef)')
    if hit:
        out.append(Finding(BEST_PRACTICE, "kill-by-ps-grep",
                   f"kills a process by grepping ps output ({hit[0]}:{hit[1]}: `{hit[2]}`) - this "
                   f"matches any process whose command line merely CONTAINS the search string (a "
                   f"totally unrelated process could match), and does nothing if zero or several "
                   f"match.\n"
                   f"  - Write a PID file when starting the process and kill that specific PID "
                   f"instead (checking it's still running your process before killing it)"))

    # Blocking sleep in a start/stop lifecycle hook delays fppd startup/shutdown
    # by that long, every time - guideline 2.6 again, same class as
    # blocking-build-in-hook. fpp_install.sh/fpp_uninstall.sh are excluded: they
    # run once at install/uninstall time, not on every fppd start/stop.
    #
    # Originally any sleep anywhere in the file, no check for whether it was
    # actually reachable synchronously - a false-positive audit found it
    # firing exclusively on the two patterns its own remediation text
    # recommends (a backgrounded wait-for-ready helper, a bounded liveness-
    # polling retry loop), never on a genuinely flat blocking delay. See
    # _blocking_sleep_in_hook_hits() for what now suppresses a hit.
    sleep_hits = list(_blocking_sleep_in_hook_hits(root))
    if sleep_hits:
        hit = sleep_hits[0]
        # Name every flat sleep, not just the first - an author who fixes one
        # and gets the same finding back on the next line has been told nothing.
        also = ("; also " + ", ".join(f"{h[0]}:{h[1]}" for h in sleep_hits[1:4])
                + (f" (+{len(sleep_hits) - 4} more)" if len(sleep_hits) > 4 else "")
                if len(sleep_hits) > 1 else "")
        out.append(Finding(BEST_PRACTICE, "blocking-sleep-in-hook",
                   f"unconditional sleep in a lifecycle hook ({hit[0]}:{hit[1]}{hit[3]}: `{hit[2]}`{also}) - this "
                   f"blocks fppd startup/shutdown for that long on every run.\n"
                   f"  - If you're waiting on a background process, poll for the actual condition "
                   f"(e.g. the PID file existing, or the port accepting connections) with a short "
                   f"bounded retry loop instead of a flat sleep"))

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
                   f"guard condition trips, blocking fppd startup for however long that takes.\n"
                   f"  - Run any genuine self-heal step detached from the hook (e.g. `systemd-run` "
                   f"or `nohup ... &`) instead of inline, or use FPP's actual post-os-upgrade "
                   f"mechanism rather than reinventing one in preStart/postStart"))

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
                   f"startup/shutdown indefinitely.\n"
                   f"  - Wrap it with `timeout <seconds> git ...` or move it out of the hook entirely"))

    # error_reporting(0) silences fatal/parse errors instead of letting them
    # surface in FPP's log - a broken plugin fails silently instead of visibly.
    hit = first(r'error_reporting\s*\(\s*0\s*\)')
    if hit:
        out.append(Finding(BEST_PRACTICE, "error-reporting-suppressed",
                   f"error_reporting(0) silences PHP errors ({hit[0]}:{hit[1]}: `{hit[2]}`) - a "
                   f"fatal error in this script now fails silently (blank output, nothing in the "
                   f"log) instead of surfacing where it can be debugged.\n"
                   f"  - Remove it, or narrow it to a specific error_reporting level you actually "
                   f"intend to suppress"))

    # Synchronous busy-wait poll loop (an unbounded while(true)/for(;;) with a
    # sleep() call) in a PHP file that shows no sign of being CLI-only - if
    # this file is directly reachable as a page (not just a background
    # daemon), it ties up an Apache/PHP-FPM worker for the whole poll
    # duration. BEST_PRACTICE, not OPTIONAL: the underlying concern is a real
    # reliability issue (worker exhaustion), same class as
    # blocking-sleep-in-hook, if the precondition holds.
    #
    # Originally any `while`/`do` loop with a sleep() nearby, no CLI-guard
    # check at all - a false-positive audit found it landing on every one of
    # its real-world hits, ALL of them background *_listener.php/*-bg.php
    # daemons (remote-falcon, showpilot-plugin, fpp-sms-control-too,
    # fpp-SETIQ), several with their own explicit `php_sapi_name() !== 'cli'`
    # guard the old check never looked for, plus one bounded retry-wait loop
    # (FPP-Plugin-Matrix-Message) that was never an unbounded poll in the
    # first place. See _busy_wait_poll_hits() for what now suppresses a hit.
    hit = next(iter(_busy_wait_poll_hits(root)), None)
    if hit:
        out.append(Finding(BEST_PRACTICE, "busy-wait-poll",
                   f"busy-wait poll loop with sleep() ({hit[0]}:{hit[1]}: `{hit[2]}`) - if this file "
                   f"is reachable directly as a page (not just invoked from a hook/cron), the loop "
                   f"ties up a web server worker for its entire duration.\n"
                   f"  - Worth a human look to confirm reachability; if so, move the polling into a "
                   f"background process instead"))

    # Missing minMemoryMB/minCpuCores resource hints on a plugin that looks
    # compute-heavy. OPTIONAL and intentionally coarse: PLUGIN_GUIDELINES.md
    # §7 only ASKS heavy plugins to declare these, it doesn't require it, and
    # "looks compute-heavy" is a two-sided guess (native code + no hints), not
    # a proven defect - a documentation-adherence nudge, not a bug report.
    # minMemoryMB/minCpuCores are top-level pluginInfo.json fields (describe the
    # plugin as a whole, no per-version override) - NOT nested in versions[].
    #
    # A Makefile/CMakeLists.txt's mere existence used to be enough on its own to
    # trigger this - dropped (2026-09-19) because every native FPP plugin ships
    # one just to build its .so, so that half of the check was really detecting
    # "written in C++", not "compute/memory heavy" (~22% false-positive rate
    # across the plugin corpus, firing on trivially light native plugins like
    # fpp-midi/fpp-osc/fpp-brightness that just happen to be C++). A build file
    # is still a signal, but only when it links a genuinely heavy library -
    # ffmpeg/opencv/libcamera - not merely for existing. The source/script scan
    # for the same libraries is widened past .cpp/.c/.h/.hpp/.py to .sh/.php/.js
    # too, since the common real case here is a plugin shelling out to the
    # ffmpeg binary rather than linking against it, which the old exts list
    # couldn't see at all.
    has_hint = bool((info or {}).get("minMemoryMB") or (info or {}).get("minCpuCores"))
    heavy_lib_rx = r'\b(ffmpeg|opencv|libcamera|videocapture|tensorflow|tflite|torch|mediapipe|gstreamer)\b'
    build_files = [p for p in _iter_files(root)
                   if os.path.basename(p).lower() in ("makefile", "cmakelists.txt")]
    links_heavy_lib = any(
        re.search(r'-lav(?:codec|format|util)\b|-lswscale\b|-lopencv|pkg-config[^\n]*'
                  r'(?:opencv|libav|libcamera)', _read(p), re.I)
        for p in build_files)
    looks_heavy = (not has_hint) and (
        links_heavy_lib
        or first(heavy_lib_rx, exts=(".cpp", ".c", ".h", ".hpp", ".py", ".sh", ".php", ".js")))
    if looks_heavy:
        out.append(Finding(OPTIONAL, "no-resource-hints",
                   "looks potentially compute/memory heavy (native build / video-capture-shaped code) "
                   "but declares no minMemoryMB/minCpuCores in pluginInfo.json.\n"
                   "  - If this plugin genuinely needs more than a Pi Zero's resources to run "
                   "acceptably, declare it as a top-level field in pluginInfo.json (see "
                   "PLUGININFO_FORMAT.md's Resource hints section) so FPP can warn/hide it on "
                   "underpowered devices instead of the user finding out the hard way"))

    # Still implementing the deprecated registerApis(httpserver::webserver*)
    # overload instead of the modern no-arg registerApis(). FPP_PLUGIN_API_VERSION
    # was bumped to 6 and the libhttpserver compat shims were REMOVED outright
    # (not just deprecated) - a plugin still on this overload no longer compiles
    # against current FPP headers at all, it's not a soft "borrowed time" nudge
    # anymore.
    # Skipped when the repo ALSO defines the no-arg registerApis(): that's the
    # shape of a plugin serving one branch to FPP 8/9 and 10+ (versions[] with
    # both ranges) and keeping the legacy overload under an
    # `#if FPP_PLUGIN_API_VERSION >= 6 ... #else` guard - _grep is line-by-line
    # and can't see the guard, so without this gate the ported plugin stays
    # flagged forever (fpp-gameday, fpp-data#281). has_own_register_apis is
    # computed above (hotload_safe/unsafe_direct_routes).
    hit = first(r'(register|unregister)Apis\s*\(\s*httpserver::webserver',
               exts=(".cpp", ".c", ".h", ".hpp"))
    if hit and not has_own_register_apis:
        out.append(Finding(BLOCKER, "deprecated-httpserver-api",
                   f"implements the removed registerApis(httpserver::webserver*) overload "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) instead of the modern no-arg registerApis() - "
                   f"FPP's libhttpserver compat shims over Drogon have been removed (plugin API 6), "
                   f"so this no longer compiles against current FPP headers.\n"
                   f"  - Port to the no-arg registerApis()/unregisterApis() using drogon::app() or "
                   f"the fpphttp.h helpers (makeStringResponse(), getRequestArg(), etc.) directly"))

    # A plugin registering its HTTP routes straight on drogon::app() instead of
    # through FPPPlugins::registerPluginApi()/unregisterPluginApi() (plugin API 6).
    # It still compiles and serves requests fine - the problem only shows up at
    # runtime: Drogon has no route-removal API, so a handler registered directly
    # stays wired into the router for the life of the process. That makes the
    # plugin impossible to unload or hot-swap for a rebuilt version - every other
    # generation of the plugin is stuck fighting over the same path. Detection is
    # a definition of ClassName::registerApis(), not just the interface being
    # implemented, so an APIProviderPlugin that legitimately does nothing (no
    # routes at all) isn't flagged.
    # Just the call signature, not a full definition match: _grep is line-by-line
    # (no cross-line regex), and real plugins split the signature and opening
    # brace across two lines often enough (fpp-brightness: `void registerApis()
    # override` then `{` on its own line, Allman style) that requiring the brace
    # on the same line silently missed it, along with the out-of-line
    # ClassName::registerApis() form. `registerApis()` appearing at all in a
    # .cpp/.cc/.cxx (never a header, so never a bare interface declaration) is
    # evidence enough that this plugin implements it - a plain call site would
    # be an unusual thing to find in a plugin's own repo, and even then this
    # only feeds a finding gated on also having a direct drogon::app().registerHandler()
    # call in the same repo. has_own_register_apis/direct_drogon_hit are computed
    # earlier (hotload_safe/unsafe_direct_routes above), reused here rather than
    # re-scanning the same files.
    #
    # BLOCKER, not best-practice: FPP_PLUGIN_SUPPORTS_UNLOAD only gates whether the
    # .so is dlclose()'d (unmapped) on unload - it does NOT gate whether the C++
    # plugin OBJECT is destroyed. PluginManager::unloadPlugin() deletes the plugin
    # instance unconditionally on every unload, opted in or not. A handler
    # registered via raw drogon::app().registerHandler() almost always captures
    # `this` (the plugin object) in its closure; once that object is deleted, the
    # route calls into freed memory on its next request - the .so's code can stay
    # mapped forever and this still crashes/corrupts. And this isn't hypothetical:
    # FPP core's InstallPluginFromInfo()/UninstallPlugin() now call the load/unload
    # lifecycle UNCONDITIONALLY for every plugin (not opt-in), so any currently
    # listed plugin using this pattern is exposed to it on an ordinary
    # uninstall/upgrade via the Plugin Manager on FPP 10.0 beta3+.
    if has_own_register_apis and direct_drogon_hit and not plugin_api_ready:
        out.append(Finding(BLOCKER, "direct-drogon-registerhandler",
                   f"registers a route straight on drogon::app() instead of through "
                   f"FPPPlugins::registerPluginApi()/unregisterPluginApi() "
                   f"({direct_drogon_hit[0]}:{direct_drogon_hit[1]}: `{direct_drogon_hit[2]}`) - the "
                   f"handler almost certainly captures `this` (the plugin object), and FPP now calls "
                   f"the plugin load/unload lifecycle unconditionally on every install/uninstall/"
                   f"upgrade (plugin API 6, FPP 10.0 beta3+) - not just for plugins that opt into it.\n"
                   f"  - Unloading deletes the plugin object regardless of FPP_PLUGIN_SUPPORTS_UNLOAD "
                   f"(that flag only controls whether the .so itself is unmapped) - Drogon has no way "
                   f"to remove the route registered directly on it, so it stays wired into the router "
                   f"pointing at a now-freed object. The next request to that route is a use-after-free, "
                   f"not just a stuck/unremovable route.\n"
                   f"  - Route the registration/teardown through registerPluginApi()/"
                   f"unregisterPluginApi() instead so FPP owns the route slot and disarms it (waiting "
                   f"for any in-flight request to finish) before the plugin object is destroyed"))

    # A plugin registering C++ Command objects (CommandManager::addCommand(),
    # not the commands/descriptions.json script mechanism) is expected to take
    # them back in shutdown() - FPP commit 48d30e226 made this the documented
    # contract in Plugin.h: removeCommand() only UNREGISTERS, so a plugin that
    # took a command back owns it again and must delete it too. Before that
    # commit, an unloaded plugin's un-withdrawn commands stayed runnable and
    # invoking one read freed memory through a dangling plugin pointer (silent
    # corruption, not a crash - the specific hazard the contract closes).
    # FPP now keeps a backstop (diffs the command registry around a plugin's
    # load window and deletes anything still there at unload, logging a
    # warning naming the plugin), so this is a best-practice nudge, not a
    # blocker - a plugin skipping this doesn't crash fppd, it just leans on
    # the net and gets a warning in fppd's log every unload/reload cycle.
    has_add_command = first(r'\baddCommand\s*\(', exts=(".cpp", ".cc", ".cxx"))
    has_remove_command = first(r'\bremoveCommand\s*\(', exts=(".cpp", ".cc", ".cxx", ".h", ".hpp"))
    if has_add_command and not has_remove_command:
        out.append(Finding(BEST_PRACTICE, "no-command-withdrawal",
                   f"registers command(s) via CommandManager::addCommand() "
                   f"({has_add_command[0]}:{has_add_command[1]}: `{has_add_command[2]}`) but never "
                   f"calls removeCommand() - Plugin.h's unload contract (FPP plugin API 6+) expects a "
                   f"plugin to withdraw AND delete its own commands in shutdown(), since "
                   f"removeCommand() only unregisters and the plugin owns whatever it takes back.\n"
                   f"  - FPP keeps a backstop that deletes leftover commands at unload and logs a "
                   f"warning naming this plugin, but that's a net, not a substitute - add "
                   f"removeCommand()+delete for each addCommand() in shutdown() so a reload doesn't "
                   f"depend on it"))

    # A native plugin whose Makefile doesn't route through FPP's shared
    # makefiles/common/setup.mk misses whatever that block applies on the
    # plugin's behalf without the author having to know - most concretely,
    # -fno-gnu-unique (FPP commit 24abe9828): without it, a single
    # "static const std::string" inside an inline method (i.e. any method
    # defined in the class body) can make glibc mark the whole .so NODELETE,
    # so dlclose() silently unmaps nothing even though the unload otherwise
    # reports success - FPP_PLUGIN_SUPPORTS_UNLOAD then means less than it
    # says, with no diagnostic anywhere. Every native plugin in the public
    # catalog already does `include $(SRCDIR)/makefiles/common/setup.mk` (or
    # an absolute-path equivalent), so this only fires for a plugin with a
    # genuinely custom build (hand-rolled compiler invocation, vendored
    # build system) that never pulls in the shared flags at all.
    if ships_native and os.path.isfile(os.path.join(root, "Makefile")):
        makefile_text = _read(os.path.join(root, "Makefile"))
        if "setup.mk" not in makefile_text:
            out.append(Finding(BEST_PRACTICE, "no-shared-setup-mk",
                       "ships a Makefile that doesn't include FPP's shared makefiles/common/setup.mk - "
                       "every other native plugin in the catalog does `include "
                       "$(SRCDIR)/makefiles/common/setup.mk`, and that block is what applies "
                       "-fno-gnu-unique on the plugin's behalf (FPP commit 24abe9828).\n"
                       "  - Without it, a single \"static const std::string\" inside an inline method "
                       "(i.e. any method body in a class definition) can silently defeat dlclose() "
                       "even on a plugin that declares FPP_PLUGIN_SUPPORTS_UNLOAD - the unload still "
                       "reports success, only the memory is never returned.\n"
                       "  - Verify with `nm -D lib<repoName>.so | awk '$2==\"u\"'` after a build; a "
                       "non-empty result means this plugin needs the flag"))

        # FPP's plugin loader (src/Plugins.cpp loadUserPlugin) dlopen()s a
        # native plugin's .so from the plugin dir by one of exactly two names:
        # `lib<dirName>.so` by default, or whatever file the callbacks script
        # names with `c++:<file>` (an override honoured since 2019). A Makefile
        # whose BUILD TARGET is some other lib*.so means the artifact never
        # matches either, so the plugin never loads - fppd does log "Failed to
        # find shlib" and raises a "Could not load plugin" warning banner, but
        # the plugin itself is inert. BLOCKER: not degraded, non-functional.
        # Only build targets count (`all: libx.so`, `libx.so:` rule, `TARGET =`,
        # `-o libx.so`) - a `$(SRCDIR)/libfpp.so` dependency or a `rm -f` in
        # clean isn't what the plugin builds. `$(SHLIB_EXT)` is how every
        # first-party Makefile spells the extension, so it's normalised to .so.
        # The comparison is case-sensitive: dlopen() on ext4 is.
        expected = _expected_shlib_names(root, repo)
        built = _makefile_shlib_targets(makefile_text)
        # Only when the callbacks script actually tells fppd to dlopen()
        # something - a script plugin whose Makefile builds a ctypes helper
        # .so is never loaded by fppd at all.
        prints_cpp = bool(first(r'''(echo|print|printf)\s*\(?\s*["']c\+\+''', exts=(".sh", ".pl", ".php", ".py")))
        if prints_cpp and built and not (built & expected):
            wrong = sorted(built)[0]
            exp = sorted(expected)[0]
            case_only = wrong.lower() == exp.lower()
            out.append(Finding(BLOCKER, "so-name-mismatch",
                       f"Makefile builds `{wrong}`, which doesn't match `{exp}` - FPP's plugin "
                       f"loader (Plugins.cpp loadUserPlugin) dlopen()s a native plugin from its "
                       f"directory as `lib<repoName>.so` (repoName `{repo}`) unless the callbacks "
                       f"script prints `c++:<file>` to name a different one, so a build that "
                       f"produces any other filename never loads - fppd logs \"Failed to find "
                       f"shlib\" and shows a \"Could not load plugin\" warning, and the plugin is "
                       f"inert.\n"
                       + (f"  - The names differ only in case - dlopen() is case-sensitive on the "
                          f"Pi's filesystem, so this still fails\n" if case_only else "")
                       + f"  - Rename the Makefile's build target to `{exp}`, or have the callbacks "
                       f"script print `c++:{wrong}` so fppd loads the file the build actually "
                       f"produces"))

    # A plugin registering HTTP routes but shipping no apiDocs.json (FPP commit
    # 006f389dc) - not wrong, but every route it serves shows up under "Undocumented
    # - see plugin documentation" on the API page instead of describing what it does.
    # OpenAPI "paths" fragment, keyed by the path registered with registerPluginApi() -
    # mirrors the existing no-icon polish check (optional, not a hygiene problem).
    if plugin_api_ready and not os.path.isfile(os.path.join(root, "apiDocs.json")):
        out.append(Finding(OPTIONAL, "no-api-docs",
                   "registers HTTP routes via registerPluginApi() but ships no apiDocs.json - its "
                   "routes show up as \"Undocumented - see plugin documentation\" on the API page "
                   "instead of describing what they do.\n"
                   "  - Add an apiDocs.json at the plugin root (an OpenAPI \"paths\" fragment keyed by "
                   "the registered path) so MergePluginApiDocs() picks it up"))

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
    print_report(findings)
    return 0


# Section order/labels for print_report(), most-severe first - a reader should
# hit blockers before scrolling past a wall of polish suggestions. Not reused
# by scan_submission.py/new_major_release_scan.py, which consume Finding
# objects directly and build their own issue-body/dashboard formatting - this
# is purely the standalone `python lint_plugin.py <dir>` CLI report.
_SEVERITY_SECTIONS = ((BLOCKER, "BLOCKERS"), (BEST_PRACTICE, "BEST PRACTICES"), (OPTIONAL, "OPTIONAL / POLISH"))


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("No findings.")
        return
    counts = {sev: 0 for sev, _ in _SEVERITY_SECTIONS}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts[sev]} {label.lower()}" for sev, label in _SEVERITY_SECTIONS if counts.get(sev))
    print(f"{len(findings)} finding(s) - {summary}\n")

    for sev, label in _SEVERITY_SECTIONS:
        section = [f for f in findings if f.severity == sev]
        if not section:
            continue
        heading = f"-- {label} ({len(section)}) "
        print(heading + "-" * max(0, 72 - len(heading)))
        for f in section:
            tag = f"  [{f.code}] "
            print(textwrap.fill(f.message, width=96, initial_indent=tag,
                                 subsequent_indent=" " * len(tag)))
        print()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
