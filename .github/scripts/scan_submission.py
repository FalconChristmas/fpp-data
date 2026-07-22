"""Plugin check for a brand-new plugin submission issue.

Reuses the same checks as the retroactive fpp<major> new-major-release scan
(lint_plugin.py, the pluginInfo.json schema check, and the repo-metadata checks - all
shared via lib_plugin_schema.py so the two scanners can't quietly drift apart), but
gates HARDER: a plugin that's already listed keeps working if it picks up a
BEST_PRACTICE finding after the fact - new-major-release findings are advisory, they
never block a listing or trigger its removal on their own. A plugin asking to be
listed for the FIRST time has no such grandfathering: here, BEST_PRACTICE findings
block same as BLOCKER, not just advisory. OPTIONAL stays advisory in both cases
(LICENSE/README/icon/bugURL are nice-to-have, not a gate).

repoName and the github.com repo are never taken from the submitter - both are derived
here from pluginInfo.json itself (repoName is a field in the JSON; the repo comes from
its srcURL, falling back to the raw.githubusercontent.com pluginInfo-url). There is
nothing left for a submitter-supplied copy to mismatch against, so unlike the
new-major-release scanner there is no repo-name-mismatch check here.

Usage:
  scan_submission.py --plugininfo-url <raw pluginInfo.json URL> \
      --schema .github/schema/pluginInfo.schema.json --out result.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import (  # noqa: E402
    fetch_json,
    field,
    gh_get_repo,
    list_open_issues,
    load_pluginlist,
    parse_github_repo,
    parse_raw_github_repo,
    repo_metadata_findings,
    schema_validation_error,
)
from lint_plugin import lint_plugin_dir, BLOCKER, BEST_PRACTICE, OPTIONAL  # noqa: E402


def find_duplicate_submission_issues(gh: tuple[str, str] | None, current_issue, gh_repo: str, token) -> list[int]:
    """Other OPEN submission issues naming the same github.com repo.

    Compared by (owner, repo) rather than raw URL text: two submissions for the same
    plugin can legitimately point at different branches/paths, but the repo itself is
    the actual identity. Read cheaply from each candidate's OWN "pluginInfo.json raw
    URL" field (required on every submission, old template or new) - no need to
    re-fetch every open issue's pluginInfo.json just to compare identity.

    No "GitHub repo" field fallback here: that field was purely informational and has
    been removed from plugin-submission.yml (see its comments) since it was editable
    but never actually read - pluginInfo.json raw URL was always the required field,
    so every open issue, regardless of which template version created it, has one.
    """
    if not gh:
        return []
    owner, repo = gh
    dupes = []
    for issue in list_open_issues(gh_repo, "submission", token):
        if str(issue.get("number")) == str(current_issue):
            continue
        body = issue.get("body") or ""
        other = parse_raw_github_repo(field(body, "pluginInfo.json raw URL"))
        if other and other[0].lower() == owner.lower() and other[1].lower() == repo.lower():
            dupes.append(issue["number"])
    return dupes


def already_listed(repo_name: str, plugin_list_path: str) -> bool:
    """Case-insensitive: repoName casing in a resubmission doesn't always match what's
    already stored (same reasoning as verify_remove_plugin.py's resolve_owner) - an
    exact match would let a re-cased resubmission slip past as "new" and, later, past
    add_plugin_entry.py's own (exact-match) already_listed() too, inserting a second,
    case-variant entry for the same plugin."""
    try:
        entries = load_pluginlist(plugin_list_path)
    except (OSError, ValueError):
        return False
    return any(e and e[0].lower() == repo_name.lower() for e in entries if isinstance(e, list))

CLONE_TIMEOUT = 60  # seconds


def clone_repo(owner: str, repo: str, dest: str) -> str | None:
    """Shallow-clone into dest. Returns an error string, or None on success."""
    url = f"https://github.com/{owner}/{repo}.git"
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, dest],
            capture_output=True, text=True, timeout=CLONE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return f"git clone of {owner}/{repo} timed out after {CLONE_TIMEOUT}s"
    if proc.returncode != 0:
        return f"git clone of {owner}/{repo} failed: {proc.stderr.strip()[:300]}"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugininfo-url", required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--plugin-list", default="pluginList.json")
    ap.add_argument("--reporter", default=None, help="GitHub login of the issue's original reporter")
    ap.add_argument("--issue-number", default=None)
    ap.add_argument("--gh-repo", default=None, help="owner/repo this issue lives in, for duplicate-request detection")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    findings = []  # (severity, code, message)

    info, err = fetch_json(args.plugininfo_url)
    if err:
        findings.append((BLOCKER, "plugininfo-fetch", f"cannot fetch pluginInfo.json: {err}"))
        info = {}

    if info:
        with open(args.schema, encoding="utf-8") as f:
            schema = json.load(f)
        schema_err = schema_validation_error(info, schema)
        if schema_err:
            findings.append((BLOCKER, "schema", schema_err))

    gh = parse_github_repo(info.get("srcURL", "") or "") if info else None
    gh = gh or parse_raw_github_repo(args.plugininfo_url)

    # repoName always comes from pluginInfo.json itself, falling back to the github.com
    # repo slug (from srcURL/plugininfo-url) only if the JSON omits it - schema
    # validation above already blocks a submission with no repoName at all, so this
    # fallback just keeps clone/lint working in that already-failing case too.
    repo_name = (info or {}).get("repoName") or (gh[1] if gh else None)

    # --- already listed? short-circuit EVERYTHING else below --------------------
    # Previously this was only caught much later, in add_plugin_entry.py, AFTER a full
    # ownership check + clone + lint had already run for a submission that was always
    # going to be rejected as a duplicate. None of that is useful once we already know
    # the answer is "nothing to do here" - repo-metadata findings, the owner-vs-
    # submitter check, and clone+lint are all skipped, so the result is ONLY the
    # already-listed finding, not a pile of irrelevant blockers.
    already = bool(repo_name and already_listed(repo_name, args.plugin_list))

    # Other OPEN submission issue(s) for the same repo - independent of `already`
    # above, and always worth checking regardless of it (a listed plugin's repo could
    # still have a separate, unrelated pending re-submission open).
    duplicate_issues: list[int] = []
    if gh and args.gh_repo and args.issue_number:
        duplicate_issues = find_duplicate_submission_issues(gh, args.issue_number, args.gh_repo, token)

    owner_confirmed = True
    linted = False
    if already:
        findings.append((BLOCKER, "already-listed",
                          f"`{repo_name}` is already in pluginList.json - nothing to do here."))
    else:
        # --- repo metadata (archived / issues-disabled / bugURL) ----------------
        if gh:
            owner, repo = gh
            meta, _ = gh_get_repo(owner, repo, token)
            if meta:
                findings.extend(repo_metadata_findings(meta, (info or {}).get("bugURL", "")))

        # --- ownership: submitter must own the repo, or prove write access -----
        # Unlike removal (verify_remove_plugin.py), a submission had NO ownership check
        # at all until now - anyone could list anyone else's plugin. Mirrors removal's
        # "delist": true proof-of-control trick: only someone with push access could add
        # a specific string to their OWN pluginInfo.json. The token is tied to this one
        # issue (not a permanent flag like "delist") so an old, already-approved
        # submission's public token can't be replayed as proof for a different request.
        if gh and args.reporter and gh[0].lower() != args.reporter.lower():
            expected = f"fpp-{args.issue_number}"
            got = str((info or {}).get("submissionToken", "")).strip()
            if got != expected:
                owner_confirmed = False
                findings.append((BLOCKER, "owner-unconfirmed",
                    f"submitter @{args.reporter} does not match `{gh[0]}`, this repo's registered owner "
                    f"(from srcURL). Add `\"submissionToken\": \"{expected}\"` to your pluginInfo.json and "
                    f"comment `/recheck` to prove you have write access here - or, if you're submitting on "
                    f"the owner's behalf with their consent, comment `/submit` instead to flag this for a "
                    f"maintainer's judgement rather than auto-verifying."))

        # --- clone + static lint -------------------------------------------------
        if gh:
            owner, repo = gh
            with tempfile.TemporaryDirectory() as tmp:
                dest = os.path.join(tmp, repo)
                clone_err = clone_repo(owner, repo, dest)
                if clone_err:
                    findings.append((BLOCKER, "clone-failed", clone_err))
                else:
                    linted = True
                    for f in lint_plugin_dir(dest, repo_name or repo, info=info):
                        findings.append((f.severity, f.code, f.message))
        else:
            findings.append((BLOCKER, "no-repo-url",
                              "could not determine a github.com repo from srcURL or the pluginInfo.json URL"))

    # --- verdict ---------------------------------------------------------------
    # Stricter than the new-major-release scan: BEST_PRACTICE blocks a new submission, not just BLOCKER.
    blocking = [f for f in findings if f[0] in (BLOCKER, BEST_PRACTICE)]
    advisory = [f for f in findings if f[0] == OPTIONAL]

    result = {
        "pass": not blocking,
        "already_listed": already,
        "linted": linted,
        "owner": gh[0] if gh else None,   # registered owner from srcURL - may differ from the submitter
        "owner_confirmed": owner_confirmed,
        "repo_name": repo_name,
        "repo_url": f"https://github.com/{gh[0]}/{gh[1]}" if gh else None,
        "duplicate_issues": duplicate_issues,
        "findings": [{"severity": s, "code": c, "message": m} for s, c, m in findings],
        "num_blocking": len(blocking),
        "num_advisory": len(advisory),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"{'PASS' if result['pass'] else 'FAIL'} - {len(blocking)} blocking, {len(advisory)} advisory")
    return 0


if __name__ == "__main__":
    sys.exit(main())
