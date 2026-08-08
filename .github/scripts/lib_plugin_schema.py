"""Helpers shared by the plugin CI scripts.

Kept dependency-light on purpose: only the standard library + `jsonschema`
(installed by the workflow). Network calls use urllib with short timeouts so a
slow/dead host can't hang the CI job.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jsonschema

USER_AGENT = "fpp-data-plugin-ci"
HTTP_TIMEOUT = 15  # seconds - generous for CI, still bounded


def safe_plugin_name(name: str) -> bool:
    """True iff `name` (a pluginList.json entry name, from external-author PRs) is
    safe to use as a single path segment - no separators, no ".."/".", not absolute.

    Every script that turns an entry name into a filesystem path (clone_plugins.py's
    clone destination, new_major_release_scan.py's per-plugin issue file) must gate
    on this first - the name never gets a second sanitization pass once it's in hand,
    so this is the one place that decides.
    """
    return bool(
        name and name not in (".", "..")
        and "/" not in name and "\\" not in name
        and not os.path.isabs(name)
    )

# This CI NEVER @-mentions an author (see new_major_release_sync_issues.py,
# new_major_release_scan.py) -- bulk scans pinging authors would be spam. verify_remove_plugin.py's
# unconfirmed-ownership escalation PR is a deliberate, narrow exception: naming the
# registered owner there is closer to "you should know about this" than a bulk scan
# is. Held off for now (plain text, no real notification) until release; flip this
# one flag then -- every caller goes through owner_ref() below.
MENTION_OWNER = False


def _major(v) -> Optional[int]:
    head = str(v).split(".")[0]
    return int(head) if head.isdigit() else None


def compatible_with_major(versions, m: int) -> bool:
    """Is any versions[] entry certified for FPP major `m`?

    Mirrors the Plugin Manager's own logic (D21): an OPEN-ended max ("0"/""/"0.0")
    only certifies the major the entry was built for - an open entry built for an
    OLDER major shows as "untested" on a newer one, not compatible. A CLOSED range
    certifies `m` when min-major <= m <= max-major.
    """
    for v in versions or []:
        if not isinstance(v, dict):
            continue
        mn = _major(v.get("minFPPVersion")) if v.get("minFPPVersion") else None
        if mn is None:
            continue
        mx = v.get("maxFPPVersion")
        if mx in (None, "", "0", "0.0"):
            if mn == m:            # open-ended: certifies only its own major
                return True
        else:
            mxm = _major(mx)
            if mxm is not None and mn <= m <= mxm:
                return True
    return False


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


def filter_by_owner(entries: list, only_owner: Optional[str]) -> list:
    """Keep only pluginList entries whose repo owner matches `only_owner` (case-insensitive).

    Owner is derived from the entry's pluginInfo raw URL (entries[*][1]), the same
    signal clone_plugins.py already uses to pick a clone target - no network call
    needed, so filtering happens before any cloning/scanning work. Falsy `only_owner`
    (None/"") is a no-op, returning `entries` unchanged.
    """
    if not only_owner:
        return entries
    target = only_owner.strip().lower()
    out = []
    for entry in entries:
        info_url = entry[1] if len(entry) > 1 else ""
        owner_repo = parse_raw_github_repo(info_url)
        if owner_repo and owner_repo[0].lower() == target:
            out.append(entry)
    return out


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


def gh_list_branches(owner: str, repo: str, token: Optional[str],
                      max_pages: int = 5) -> tuple[Optional[set[str]], Optional[str]]:
    """All branch names on owner/repo, or (None, error) on failure.

    Paginated (100/page, up to max_pages) - plenty for any real plugin repo,
    which realistically has a handful of branches, not hundreds. Returning
    None (not an empty set) on failure matters: callers must treat "couldn't
    ask GitHub" differently from "asked, and there are truly zero branches" -
    the former should skip the branch-exists check, the latter should never
    happen for a repo that cloned successfully.
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    names: set[str] = set()
    for page in range(1, max_pages + 1):
        api = f"https://api.github.com/repos/{owner}/{repo}/branches?per_page=100&page={page}"
        try:
            req = urllib.request.Request(api, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return None, f"HTTP {e.code}"
        except Exception as e:  # noqa: BLE001
            return None, str(e)
        if not isinstance(data, list) or not data:
            break
        names.update(b["name"] for b in data if isinstance(b, dict) and b.get("name"))
        if len(data) < 100:
            break
    return names, None


def branch_findings(info: dict, existing_branches: Optional[set[str]]) -> list[tuple[str, str, str]]:
    """BLOCKER per versions[] entry whose declared `branch` doesn't exist on the repo.

    A nonexistent branch isn't a style nit - it's the exact shape of bug that
    passes review invisibly: the submission/major-release scanners clone the repo's
    DEFAULT branch to lint it (see clone_repo() in scan_submission.py, clone_target()
    in clone_plugins.py's fallback), so a stale/typo'd `branch` in a versions[] entry
    still lints clean here. The failure only surfaces later, at real end-user install
    time, as FPP's git clone erroring "Remote branch <x> not found in upstream origin" -
    silent in CI, loud in production. `existing_branches=None` (GitHub API unreachable
    or rate-limited) means "couldn't verify" - skip silently rather than false-positive
    a plugin whose branch is actually fine.
    """
    if existing_branches is None:
        return []
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for v in info.get("versions") or []:
        if not isinstance(v, dict):
            continue
        branch = (v.get("branch") or "").strip()
        if not branch or branch in seen or branch in existing_branches:
            continue
        seen.add(branch)
        out.append(("blocker", "branch-not-found",
                    f"pluginInfo.json declares branch `{branch}` (versions[] entry for FPP "
                    f"{v.get('minFPPVersion', '?')}-{v.get('maxFPPVersion') or 'latest'}), but no such "
                    f"branch exists on the repo - installs of this version will fail with "
                    f"\"Remote branch {branch} not found in upstream origin\". Fix the `branch` value "
                    f"or push the missing branch."))
    return out


def gh_get_pr_merged_by(owner: str, repo: str, token: Optional[str],
                         scan_limit: int = 100) -> tuple[dict[str, str], set[str]]:
    """(login -> most recent merged_at ISO date) for everyone who has ever clicked
    merge on owner/repo, plus the set of PR authors PROVEN not to have write access
    there (their own PR was merged by someone else - direct, positive evidence, unlike
    an absence of evidence).

    merged_by is authoritative regardless of merge strategy (squash/rebase/merge
    commit) - it always names whoever actually had merge rights. That's an improvement
    over reading commit.author off the first-parent chain (see gh_get_maintainer_candidates
    below): for a squash- or rebase-merged PR, the resulting mainline commit's `author`
    is the PR's original submitter, not the person who merged it, and a single-parent
    commit can't be told apart from a genuine direct push by shape alone. Confirmed via
    manual audit (2026-07-22) across every FalconChristmas/KulpLights/PulseMeshLabs/
    remote-falcon plugin repo: contributors like NathanKulp and AlexWHughes were
    getting listed as "confirmed committers" on fpp-Capture/fpp-osc/fpp-vastfmt purely
    because dkulp's squash-merges preserved their authorship, despite 100% of their
    PRs there being merged by someone else.

    merged_by is NOT present on the pulls list endpoint (only on GET .../pulls/{n}),
    so this fetches each merged PR individually - bounded by `scan_limit` closed PRs
    examined (audited at ~2-11 calls/repo typically, up to ~94 for an unusually
    PR-heavy repo; still trivial against a 5000/hr authenticated budget). Best-effort -
    returns ({}, set()) on any failure, never raises.
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _get(url):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    try:
        prs = _get(f"https://api.github.com/repos/{owner}/{repo}/pulls"
                   f"?state=closed&per_page={scan_limit}&sort=updated&direction=desc")
    except Exception:  # noqa: BLE001
        return {}, set()
    if not isinstance(prs, list):
        return {}, set()
    merged = sorted((p for p in prs if isinstance(p, dict) and p.get("merged_at")),
                     key=lambda p: p["merged_at"], reverse=True)

    latest: dict[str, str] = {}
    disproven: set[str] = set()
    for p in merged:
        try:
            detail = _get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{p['number']}")
        except Exception:  # noqa: BLE001
            continue
        merger = (detail.get("merged_by") or {}).get("login")
        author = (detail.get("user") or {}).get("login")
        date = p["merged_at"]
        if merger and (merger not in latest or date > latest[merger]):
            latest[merger] = date
        if author and merger and author != merger:
            disproven.add(author)
    return latest, disproven


def gh_get_commit_authors_by_recency(owner: str, repo: str, token: Optional[str],
                                      scan_limit: int = 100) -> dict[str, str]:
    """(login -> most recent commit date) walking first-parent history from HEAD (the
    same mainline `git log --first-parent` shows), over up to `scan_limit` recent
    commits.

    A first-parent commit's `author` proves write access ONLY when it's unambiguous -
    a genuine direct push. It can't be trusted for a merge commit's author on its own
    (see gh_get_pr_merged_by's docstring for why); a caller wanting real evidence
    should treat this purely as a fallback source, filtered against that function's
    `disproven` set before use. One API call, walked locally with no further requests;
    stops early if a parent falls outside the fetched batch. Best-effort - returns {}
    on any failure, never raises.
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
        return {}
    if not isinstance(commits, list) or not commits:
        return {}
    by_sha = {c["sha"]: c for c in commits if isinstance(c, dict) and c.get("sha")}
    latest: dict[str, str] = {}
    seen_shas: set[str] = set()
    cur = commits[0]
    while isinstance(cur, dict) and cur.get("sha") not in seen_shas:
        seen_shas.add(cur["sha"])
        author = cur.get("author") or {}
        login = author.get("login")
        date = cur.get("commit", {}).get("author", {}).get("date")
        if login and author.get("type") != "Bot" and date and (login not in latest or date > latest[login]):
            latest[login] = date
        parents = cur.get("parents") or []
        if not parents:
            break
        cur = by_sha.get(parents[0].get("sha"))
    return latest


def gh_get_maintainer_candidates(owner: str, repo: str, token: Optional[str],
                                  min_names: int = 2, max_names: int = 4,
                                  recency_days: int = 5 * 365) -> list[str]:
    """Ordered (most-recent-first) list of `min_names`-`max_names` GitHub logins
    likely to have real write access to owner/repo - for @-mentioning or authorizing
    commands on a tracking issue.

    gh_get_pr_merged_by is primary evidence (authoritative regardless of merge
    strategy). gh_get_commit_authors_by_recency only fills remaining slots, and NEVER
    for a login in the `disproven` set - a person whose own PR here was proven merged
    by someone else is never used to pad the list out, even if that leaves the repo
    below `min_names`. Prefers activity within the last `recency_days`; only reaches
    further back in time if that window doesn't yield `min_names` names. Validated by
    hand against every FalconChristmas/KulpLights/PulseMeshLabs/remote-falcon plugin
    repo on 2026-07-22 - see gh_get_pr_merged_by's docstring. Best-effort - returns []
    on any failure, never raises.
    """
    merged_by, disproven = gh_get_pr_merged_by(owner, repo, token)
    walked = {login: date for login, date in gh_get_commit_authors_by_recency(owner, repo, token).items()
              if login not in disproven}

    candidates = dict(walked)
    candidates.update(merged_by)  # merged_by wins on overlap - the stronger signal
    if not candidates:
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=recency_days)).date().isoformat()
    ordered = sorted(candidates.items(), key=lambda kv: kv[1], reverse=True)
    recent = [c for c in ordered if c[1][:10] >= cutoff]
    chosen = recent if len(recent) >= min_names else ordered[:max(min_names, len(recent))]
    return [login for login, _ in chosen[:max_names]]


STALE_ISSUE_PR_AGE_MONTHS = 2   # age at which an open issue/PR counts as "stale"
NEEDS_ATTENTION_MIN_STALE = 1   # stale issues+PRs needed to flag needs-attention (tune after real data)


def gh_get_stale_issue_pr_stats(owner: str, repo: str, token: Optional[str]) -> Optional[dict]:
    """Open issue/PR counts for owner/repo, split by staleness (open >=
    STALE_ISSUE_PR_AGE_MONTHS). Returns
    {"open_issues": int, "open_prs": int, "stale_issues": int, "stale_prs": int}
    or None on failure (best-effort - caller treats None like "no signal").
    Flagging itself (NEEDS_ATTENTION_MIN_STALE) is deliberately low: even a
    single issue/PR sitting untouched for STALE_ISSUE_PR_AGE_MONTHS is treated
    as a real signal, not noise - a healthy repo triages fast, so it's a
    stronger indicator than counting raw open issues.

    GitHub's /issues endpoint returns PRs too (each carries a "pull_request"
    key); fetched separately from /pulls to split the two counts. One page
    (100, sorted oldest-first) each - plenty for this repo's issue volume, and
    sorting oldest-first means a repo with more than 100 open items still gets
    an accurate stale count (the stale ones are the oldest, so they're on the
    first page even if some non-stale ones get cut off).
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    cutoff = (datetime.now(timezone.utc) - timedelta(days=STALE_ISSUE_PR_AGE_MONTHS * 30)).isoformat()

    def _get(url):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    try:
        issues = _get(f"https://api.github.com/repos/{owner}/{repo}/issues"
                       f"?state=open&sort=created&direction=asc&per_page=100")
        prs = _get(f"https://api.github.com/repos/{owner}/{repo}/pulls"
                   f"?state=open&sort=created&direction=asc&per_page=100")
    except Exception:  # noqa: BLE001 - best-effort; caller treats this like no data
        return None
    if not isinstance(issues, list) or not isinstance(prs, list):
        return None

    real_issues = [i for i in issues if isinstance(i, dict) and "pull_request" not in i]
    stale_issues = sum(1 for i in real_issues if (i.get("created_at") or "") < cutoff)
    stale_prs = sum(1 for p in prs if isinstance(p, dict) and (p.get("created_at") or "") < cutoff)
    return {
        "open_issues": len(real_issues),
        "open_prs": len(prs),
        "stale_issues": stale_issues,
        "stale_prs": stale_prs,
    }


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
