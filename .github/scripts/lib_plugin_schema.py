"""Helpers shared by the plugin CI scripts.

Kept dependency-light on purpose: only the standard library + `jsonschema`
(installed by the workflow). Network calls use urllib with short timeouts so a
slow/dead host can't hang the CI job.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Optional

import jsonschema

USER_AGENT = "fpp-data-plugin-ci"
HTTP_TIMEOUT = 15  # seconds - generous for CI, still bounded

# This CI NEVER @-mentions an author (see new_major_release_sync_issues.py,
# new_major_release_scan.py) -- bulk scans pinging authors would be spam. verify_remove_plugin.py's
# unconfirmed-ownership escalation PR is a deliberate, narrow exception: naming the
# registered owner there is closer to "you should know about this" than a bulk scan
# is. Held off for now (plain text, no real notification) until release; flip this
# one flag then -- every caller goes through owner_ref() below.
MENTION_OWNER = False


def owner_ref(login: str) -> str:
    """A plugin owner's GitHub login, formatted per MENTION_OWNER.

    True: a real "@login" -- GitHub sends them a notification.
    False (default): backtick-wrapped plain text -- same convention the rest of
    this repo's CI uses ("no leading @, so nobody's pinged").
    """
    return f"@{login}" if MENTION_OWNER else f"`{login}`"


def fetch_json(url: str) -> tuple[Optional[Any], Optional[str]]:
    """GET a URL and parse JSON. Returns (data, error). One is always None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code} fetching {url}"
    except Exception as e:  # noqa: BLE001 - surface any network/parse issue to the report
        return None, f"could not fetch {url}: {e}"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as e:
        return None, f"invalid JSON at {url}: {e}"


def resolve_repo_name(value: str) -> str:
    """Accept a bare repoName, a bare "owner/repo" shorthand, or a GitHub URL, and
    return just the repo name.

    Submitters of the Request Plugin Removal Issue Form often paste something other
    than the bare name FPP actually stores in pluginList.json - a repo page
    (`github.com/<owner>/<repo>`, with or without `.git`, `/issues`,
    `/blob/<branch>/pluginInfo.json`, ...), a raw file URL
    (`raw.githubusercontent.com/<owner>/<repo>/<branch>/pluginInfo.json`), or just
    `<owner>/<repo>` shorthand with no host at all (what the guided page's repo-input
    parser also accepts). Be forgiving rather than failing the request outright:
    `repoName` is required (see PLUGININFO_FORMAT.md, in fpp-plugin-Template) to
    match the GitHub repo name, so the repo segment of any of these shapes IS the
    repoName.
    """
    v = (value or "").strip()
    if not v:
        return v
    if "github.com" not in v and "githubusercontent.com" not in v:
        # No recognizable host: could still be bare "owner/repo" shorthand (exactly
        # one slash, no scheme) -- anything else (a plain repoName, or something that
        # doesn't look like either shape) is returned as-is, unchanged.
        m = re.match(r"^[A-Za-z0-9._-]+/([A-Za-z0-9._-]+?)(?:\.git)?$", v)
        return m.group(1) if m else v
    try:
        from urllib.parse import urlparse

        u = urlparse(v if "://" in v else "https://" + v)
    except Exception:  # noqa: BLE001
        return v
    if not u.hostname or ("github.com" not in u.hostname and "githubusercontent.com" not in u.hostname):
        return v
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 2:
        return v
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return repo


def parse_github_repo(url: str) -> Optional[tuple[str, str]]:
    """Return (owner, repo) for a github.com URL, else None.

    Handles https://github.com/owner/repo(.git)(/issues)(/...) forms.
    """
    try:
        from urllib.parse import urlparse

        u = urlparse(url)
    except Exception:  # noqa: BLE001
        return None
    if u.hostname not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def parse_raw_github_repo(url: str) -> Optional[tuple[str, str]]:
    """(owner, repo) from a raw.githubusercontent.com file URL, else None.

    Complements parse_github_repo() above, which only handles github.com repo pages -
    a pluginInfo.json URL is a raw.githubusercontent.com file URL instead, and is
    sometimes the only URL a caller has (e.g. a submission with no srcURL yet).
    """
    m = re.match(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/", url or "")
    return (m.group(1), m.group(2)) if m else None


def schema_validation_error(info: dict, schema: dict) -> Optional[str]:
    """Validate pluginInfo.json against the schema. Returns a message, or None if valid.

    Severity-free on purpose: validate_pluginlist.py (ERROR/WARNING, downgraded for
    pre-existing entries not touched by a PR) and the new-major-release/submission
    scanners (BLOCKER/BEST_PRACTICE/OPTIONAL) each wrap this in their own severity
    model rather than sharing one - the two vocabularies don't map onto each other
    cleanly.
    """
    try:
        jsonschema.validate(info, schema)
        return None
    except jsonschema.ValidationError as e:
        loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
        return f"pluginInfo.json fails schema at `{loc}`: {e.message}"


def repo_metadata_findings(meta: dict, bug_url: str) -> list[tuple[str, str, str]]:
    """archived / issues-disabled / bugURL findings from a GitHub API repo response.

    Pure (no network) - the caller already has `meta` from gh_get_repo(). Returns
    (severity, code, message) tuples using the same string severities as lint_plugin.py's
    BLOCKER/BEST_PRACTICE/OPTIONAL ("blocker"/"best-practice"/"optional"), so callers can
    append these directly alongside lint_plugin_dir()'s findings without translation.
    """
    out: list[tuple[str, str, str]] = []
    if not meta:
        return out
    if meta.get("archived"):
        out.append(("best-practice", "archived", "source repo is archived"))
    has_bug = bool(parse_github_repo(bug_url or ""))
    # An archived repo is read-only regardless of what has_issues says, so archiving
    # always implies issues-disabled even if the flag wasn't flipped.
    if meta.get("has_issues") is False or meta.get("archived"):
        out.append(("blocker", "issues-disabled",
                     "GitHub Issues are disabled - users can't report bugs and we can't reach you there"))
    elif not has_bug:
        out.append(("optional", "bugurl", "no bugURL set (Report-a-Bug link)"))
    return out


def gh_get_repo(owner: str, repo: str, token: Optional[str]) -> tuple[Optional[dict], Optional[str]]:
    """GET /repos/{owner}/{repo} from the GitHub API. Token lifts the rate limit to 5000/hr."""
    api = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def gh_get_contributors(owner: str, repo: str, token: Optional[str], limit: int = 5) -> list[str]:
    """Top `limit` contributor logins (by commit count, the API's default order)
    for owner/repo. Public endpoint, no special access needed.

    Used when a plugin's repo is org-owned (see new_major_release_scan.py): the org login
    itself isn't a person who can be @-mentioned or notified, so the individual
    contributors most likely to actually see a tracking issue are surfaced
    instead. Best-effort - returns [] on any failure (private/empty repo, rate
    limit, anonymous-only history, etc.), never raises.
    """
    api = f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page={limit}"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return [c["login"] for c in data if isinstance(c, dict) and c.get("login") and not c.get("type") == "Bot"][:limit]
    except Exception:  # noqa: BLE001
        return []


def gh_get_pr_mergers(owner: str, repo: str, token: Optional[str],
                       scan_limit: int = 100, limit: int = 5) -> list[str]:
    """Distinct logins with demonstrated write access to owner/repo, found by
    walking first-parent history from HEAD (the same mainline `git log
    --first-parent` shows) - a stronger maintainer signal than
    gh_get_contributors for an org repo that takes outside PRs: a one-off
    external contributor's commit inflates the contributor count exactly as
    much as a real maintainer's.

    Every commit on the first-parent chain required write access to get
    there, however it got there: a merge commit only exists because someone
    with merge rights created it (and its `author` field IS that person, not
    the PR's submitter), while a plain commit reachable via first-parent was
    pushed directly to the branch - only possible with write access. A merged
    PR's OWN commits are correctly excluded either way: they're only reachable
    via the merge commit's second parent, never its first, so the walk never
    touches them.

    This starts from (and subsumes) an earlier version of this function that
    only credited merge-commit authors - that missed FalconChristmas' most
    tenured contributors entirely (cpinkham on fpp-BigButtons,
    computergeek1507 on fpp-brightness: both write directly to the branch,
    never merging anyone else's PR in these repos, so a mergers-only view saw
    them as strangers). The first-parent walk catches both cases in one pass,
    with no separate self-merge check needed - direct-push or merge, everyone
    it finds already proved write access by definition.

    One API call fetches up to `scan_limit` recent commits (each with its full
    parent SHA list); the first-parent chain is then walked locally with no
    further requests, starting at the batch's first entry (HEAD, since the
    list endpoint returns newest-first) and repeatedly following
    commit.parents[0].sha within the fetched batch. The walk stops early if a
    parent isn't in the fetched batch (older than `scan_limit` commits back) -
    fine for finding currently-active maintainers, not meant to cover a repo's
    entire history. `limit` bounds the returned list. Public endpoint, no
    special access needed. Best-effort - returns [] on any failure, never
    raises.
    """
    api = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page={scan_limit}"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            commits = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(commits, list) or not commits:
        return []
    by_sha = {c["sha"]: c for c in commits if isinstance(c, dict) and c.get("sha")}
    authors: list[str] = []
    seen_shas: set[str] = set()
    cur = commits[0]
    while isinstance(cur, dict) and cur.get("sha") not in seen_shas:
        seen_shas.add(cur["sha"])
        author = cur.get("author") or {}
        login = author.get("login")
        if login and author.get("type") != "Bot" and login not in authors:
            authors.append(login)
            if len(authors) >= limit:
                break
        parents = cur.get("parents") or []
        if not parents:
            break
        cur = by_sha.get(parents[0].get("sha"))
    return authors


def list_open_issues(gh_repo: str, label: str, token: Optional[str]) -> list[dict]:
    """Open issues on `gh_repo` (\"owner/repo\") carrying `label`. One page (100) is
    plenty for this repo's issue volume - not worth paginating.

    Used for same-plugin duplicate-open-request detection (removal and submission
    flows both label their issue kind, so filtering server-side keeps this cheap).
    """
    api = f"https://api.github.com/repos/{gh_repo}/issues?state=open&labels={label}&per_page=100"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - best-effort; a failure here just skips dupe detection
        return []


def field(body: str, label: str) -> str:
    """Value under a GitHub issue-form '### <label>' heading (first non-empty line).
    Shared by every script that parses an issue-form body - the field/heading shape
    is a GitHub Issue Forms convention, not specific to any one flow."""
    lines = (body or "").splitlines()
    for i, line in enumerate(lines):
        if line.strip().lstrip("#").strip().lower() == label.lower():
            for nxt in lines[i + 1:]:
                s = nxt.strip()
                if s and not s.startswith("#"):
                    return s
    return ""


def load_categories(path: str) -> set[str]:
    """Load the allowed category names from pluginCategories.json.

    `name` is the short name pluginList.json stores and matches on; `longName`
    is the descriptive form used only for display.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {c["name"] for c in data.get("categories", [])}


def load_category_map(path: str) -> dict[str, str]:
    """{longName: shortName, ...} - pluginList.json stores shortName, but Issue Form
    dropdowns (a static YAML copy, see check_category_drift.py) show longName, so
    anything mapping a submitted form value back onto a pluginList.json entry needs
    this both ways."""
    data = json.load(open(path, encoding="utf-8"))
    return {c["longName"]: c["name"] for c in data.get("categories", []) if c.get("longName")}


def load_pluginlist(path: str) -> list[list]:
    """Load pluginList.json and return its `pluginList` array (raises on parse error)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["pluginList"]
