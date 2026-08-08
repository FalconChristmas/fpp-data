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
    core-config check's docstring), the plugins directory (/media/plugins/), or the
    playlists directory (/media/playlists/, an established integration point for
    plugin-managed temp playlists) - e.g. a state file dropped straight into
    /home/fpp/media/ itself. fpp_install.sh/fpp_uninstall.sh are excluded: an
    installer legitimately reaches outside the plugin's own footprint (systemd
    units, Apache config, cron, etc.) as part of installing/removing itself."""
    file_rx = re.compile(r'''(['"])(/home/fpp/media/[^'"]*\.\w{1,8})\1''')
    allowed_rx = re.compile(r'^/home/fpp/media/(?:config|plugins|playlists|logs)/', re.I)
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
    # that shape is correctly still treated as floating/unpinned.
    pin_rx = re.compile(r'\bgit\s+(?:-C\s+\S+\s+)?(?:checkout|reset\s+--hard)\s+(?:origin/)?([0-9a-f]{7,40})\b', re.I)
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
                   f"  - Shell: source `${{FPPDIR}}/scripts/common` first (it defines the function), "
                   f"then call `setSetting restartFlag 1`.\n"
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
    hit = first(r'\.(run|listen|bind)\s*\([^)]*0\.0\.0\.0', exts=(".py", ".js"))
    if hit and first(r'ProxyPass', exts=(".sh", ".conf")):
        out.append(Finding(BLOCKER, "server-bind-all-interfaces",
                   f"daemon binds 0.0.0.0 despite an Apache ProxyPass for the same service "
                   f"({hit[0]}:{hit[1]}: `{hit[2]}`) - the ProxyPass means this was designed to be "
                   f"reached through Apache only.\n"
                   f"  - Bind to `127.0.0.1` instead so the routes aren't directly reachable on the "
                   f"LAN, bypassing whatever auth Apache would add"))

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
                       f"install/hooks already run as root, which can switch to another user without "
                       f"a password, so there's no need to go through sudo (and its sudoers policy) "
                       f"for this.\n"
                       f"  - Use `runuser -u {user} -- {rest}` instead"))
        else:
            out.append(Finding(BEST_PRACTICE, "sudo",
                       f"uses sudo in a script ({hit[0]}:{hit[1]}: `{hit[2]}`) - install/hooks already "
                       f"run as root.\n"
                       f"  - Remove the sudo call and run the command directly, e.g. "
                       f"`{hit[2].replace('sudo ', '', 1)}`"))

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
                           f"with no visible error.\n"
                           f"  - Add `set -e` (or `set -euo pipefail`) as the first line after the "
                           f"shebang so the script stops immediately on the first failure instead"))
            break

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

    if effective_hotload_safe and ships_native:
        out.append(Finding(OPTIONAL, "restart-likely-not-required",
                   "doesn't register HTTP routes directly on drogon::app() (outside registerPluginApi()) "
                   "and defines no createChannelOutput(), so on an FPP build with the plugin load/unload "
                   "feature (plugin API 6+), install/uninstall should be picked up by fppd without a "
                   "restart - this plugin likely doesn't need to force one via restartFlag/rebootFlag at "
                   "those two lifecycle points.\n"
                   "  - Verify with an actual install/uninstall before relying on it"))
    elif effective_hotload_safe:
        out.append(Finding(OPTIONAL, "restart-likely-not-required",
                   "ships a root callbacks script, so on an FPP build with the plugin load/unload feature "
                   "(plugin API 6+), PluginManager::loadPlugin() actually calls loadUserPlugin() (which "
                   "reads commands/descriptions.json) - install/uninstall should register/withdraw this "
                   "plugin's commands without a restart.\n"
                   "  - Verify with an actual install/uninstall before relying on it"))
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
                           f"  - Add `source ${{FPPDIR}}/scripts/common; setSetting restartFlag 1` to "
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
                           f"  - Add `source ${{FPPDIR}}/scripts/common; setSetting restartFlag 1` to each "
                           f"script listed above (creating fpp_install.sh/fpp_uninstall.sh if missing - "
                           f"only fpp_upgrade.sh is optional, and only needs it if you already have one) "
                           f"so the Plugin Manager's restart banner appears right after that step instead "
                           f"of leaving the command silently unavailable/lingering as a ghost until fppd "
                           f"happens to restart for an unrelated reason"))
        elif hotload_safe and spans_pre_hotload_major:
            # Only surface this standalone when the flag genuinely IS set everywhere it's
            # needed (no gaps above) - otherwise it just restates "you need the flag" a
            # second time alongside no-restart-flag's own concrete gap, reading as two
            # different problems instead of one (fpp-data#136: this used to fire even
            # when no-restart-flag ALSO fired for the same plugin, which read as
            # contradictory - "looks safe" immediately followed by an unrelated-sounding
            # restart-flag complaint).
            out.append(Finding(BEST_PRACTICE, "hotload-safe-but-spans-pre-hotload-fpp",
                       "looks structurally safe to hot-load/unload on its own, but pluginInfo.json's "
                       f"versions[] declares a single branch/build whose range starts before FPP "
                       f"{HOTLOAD_INTRODUCED_MAJOR} (where the plugin load/unload feature doesn't "
                       f"exist at all) and extends into or past it - so this same code also has to "
                       f"support install/uninstall via a full fppd restart for those older FPP "
                       f"installs.\n"
                       f"  - Keep restartFlag/rebootFlag set here regardless; only drop it if you "
                       f"split off a separate FPP {HOTLOAD_INTRODUCED_MAJOR}+-only branch/sha in "
                       f"versions[]"))

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
                   f"(`${{PLUGINDIR}}/{repo}/...`), FPP's config storage (`/media/config/`), or the "
                   f"log directory (a real `.log` file only), rather than loose under "
                   f"`/home/fpp/media/` itself"))

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

    # installs a systemd unit but ships no uninstall script
    if first(r'/etc/systemd/system/|systemctl\s+enable') and \
       not (os.path.isfile(os.path.join(root, "scripts/fpp_uninstall.sh")) or
            os.path.isfile(os.path.join(root, "fpp_uninstall.sh"))):
        out.append(Finding(BLOCKER, "no-uninstall",
                   "creates a systemd service but ships no fpp_uninstall.sh to remove it.\n"
                   "  - Add one that mirrors the install, e.g. `systemctl disable --now <unit> && "
                   "rm -f /etc/systemd/system/<unit>`, so removing the plugin doesn't leave an "
                   "orphaned service behind"))

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

    # Synchronous busy-wait poll loop (a sleep() inside a while/do loop) in a
    # PHP file - if that file is directly reachable as a page (not just a CLI
    # script), it ties up an Apache/PHP-FPM worker for the whole poll duration.
    # BEST_PRACTICE, not OPTIONAL: genuinely needs real parsing to tell a page
    # from a CLI-only script reliably, so this can't prove reachability - same
    # "flag for a human to check reachability rather than treat as proven"
    # reasoning as destructive-no-csrf/device-path-no-allowlist above (both
    # BEST_PRACTICE), not a cosmetic/polish item like the true OPTIONAL findings
    # (no-icon, no-readme, no-resource-hints) - the underlying concern here is a
    # real reliability issue (worker exhaustion), same class as
    # blocking-sleep-in-hook, if the precondition holds.
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
    has_hint = bool((info or {}).get("minMemoryMB") or (info or {}).get("minCpuCores"))
    looks_heavy = (not has_hint) and (
        any(n.lower() in ("makefile", "cmakelists.txt") for n in lower)
        or first(r'\b(ffmpeg|opencv|libcamera|videocapture)\b', exts=(".cpp", ".c", ".h", ".hpp", ".py")))
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
    hit = first(r'(register|unregister)Apis\s*\(\s*httpserver::webserver',
               exts=(".cpp", ".c", ".h", ".hpp"))
    if hit:
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
