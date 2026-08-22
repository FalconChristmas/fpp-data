"""Daily auto-recheck: for each open new-major-release tracking issue, if the
plugin's repo has new commits since the last check, re-run the single-plugin
scan (same scan_plugin() manual /recheck uses) and post the updated report.

Comment-only, like --mode reconcile: NEVER closes the issue automatically, even
when the result comes back ready_to_close - a maintainer reviews and closes by
hand (2026-08-08 decision, see .wolf/cerebrum.md). As of the same decision this
also matches the manual /recheck workflow (new-major-release-issue-recheck.yml),
which used to auto-close on ready_to_close but no longer does either - nothing
in this pipeline closes a tracking issue unattended; a maintainer always closes
by hand.

"Since the last check" is derived from issue activity, not a separate marker
comment: the posted report (both this script's and manual /recheck's) always
carries the `<!-- plugin:<name> new_major_release:fpp<major> -->` marker at its
top (same one the original issue body has), so the newest comment containing
that marker - or the issue body/creation itself if no such comment exists yet -
is the last known-good checkpoint. Only commits pushed after that checkpoint
count as "new". This piggybacks on an existing signal instead of adding a
second kind of marker to track and keep in sync.

If a plugin's pluginList.json name no longer matches its issue's marker (renamed
since the issue was created), the marker's repo: field is used to re-identify and
adopt the issue under its new name - see lib_plugin_schema.resolve_renamed_repo.

Usage:
  new_major_release_auto_recheck.py --summary out/summary.json \
      --plugin-list pluginList.json --target-major <n> \
      --schema .github/schema/pluginInfo.schema.json [--dry-run] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import (  # noqa: E402
    adopt_renamed_issue, load_pluginlist, parse_plugin_marker, resolve_renamed_repo,
)
from new_major_release_scan import scan_plugin, issue_body  # noqa: E402
from scan_submission import clone_repo  # noqa: E402

API = "https://api.github.com"
UA = "fpp-data-plugin-ci"


def _req(method, url, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "User-Agent": UA,
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8", "replace")
    return json.loads(raw) if raw else {}


def list_tracking_issues(repo, token, label):
    out, page = [], 1
    while True:
        url = f"{API}/repos/{repo}/issues?state=open&labels={label}&per_page=100&page={page}"
        batch = _req("GET", url, token)
        if not batch:
            break
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return out


def last_checkpoint(issue, comments, name, target):
    """ISO timestamp of the newest report (comment or the issue body itself)
    carrying this plugin's marker - the last time we know its actual state was
    verified fresh.

    Matched by name only (not repo:) - a comment posted before a rename-adoption
    still carries the pre-rename name, which is fine here since it's still the
    same plugin's history; adoption itself rewrites the issue body's own marker
    to the new name going forward.
    """
    checkpoint = issue["created_at"]  # issue body always carries the marker
    for c in comments:
        parsed = parse_plugin_marker(c.get("body") or "")
        if (parsed and parsed[0] == name and parsed[3] == target
                and c["created_at"] > checkpoint):
            checkpoint = c["created_at"]
    return checkpoint


def has_new_commits(owner, repo, since_iso, token):
    url = f"{API}/repos/{owner}/{repo}/commits?since={urllib.parse.quote(since_iso)}&per_page=1"
    try:
        commits = _req("GET", url, token)
    except Exception:  # noqa: BLE001 - best-effort; treat lookup failure as "nothing to do"
        return False
    return isinstance(commits, list) and len(commits) > 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", default="out/summary.json")
    ap.add_argument("--plugin-list", required=True)
    ap.add_argument("--target-major", type=int, required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--force", action="store_true",
                     help="Recheck every open tracking issue regardless of new commits. "
                          "One-off remediation tool: use after a bug in reconcile mode let "
                          "status:compatible get set from a metadata-only pass without a real "
                          "lint (see .wolf/cerebrum.md 2026-08-10) - re-verifies every open "
                          "issue with a genuine clone+lint pass and corrects labels/comments "
                          "that were wrong. Not for routine use; the commit-gated path above "
                          "is what the daily workflow runs.")
    args = ap.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not args.dry_run and (not repo or not token):
        raise SystemExit("GITHUB_REPOSITORY and GITHUB_TOKEN required (or use --dry-run)")

    with open(args.summary, encoding="utf-8") as f:
        summary = json.load(f)
    target = args.target_major
    by_name = {p["name"]: p for p in summary["plugins"]}
    by_repo = {(p["owner"].lower(), p["repo"].lower()): p
               for p in summary["plugins"] if p.get("owner") and p.get("repo")}

    with open(args.schema, encoding="utf-8") as f:
        schema = json.load(f)
    entries_by_name = {e[0].lower(): e for e in load_pluginlist(args.plugin_list)}

    label = f"fpp{target}-compat"
    issues = [] if args.dry_run else list_tracking_issues(repo, token, label)
    if args.limit:
        issues = issues[: args.limit]

    rechecked = skipped = noop = adopted = 0
    for issue in issues:
        parsed = parse_plugin_marker(issue.get("body") or "")
        if not parsed:
            continue
        name, m_owner, m_repo, _ = parsed
        r = by_name.get(name)
        if not r and m_owner and m_repo:
            # Plugin's listing name no longer matches this issue's marker - likely
            # renamed (e.g. a reponame-mismatch fix) since the issue was created.
            # Follow GitHub's rename redirect and re-match by current repo instead
            # of leaving this issue to dead-end forever (see sync_issues.py's
            # adoption block - same approach, done here too since auto-recheck can
            # run standalone).
            resolved = resolve_renamed_repo(m_owner, m_repo, token)
            if resolved:
                r = by_repo.get((resolved[0].lower(), resolved[1].lower()))
                if r and r["name"] != name:
                    if args.dry_run:
                        print(f"[dry-run] ADOPT #{issue['number']} {name} -> {r['name']}")
                    else:
                        adopt_renamed_issue(lambda m, u, b=None: _req(m, u, token, b), API, repo,
                                             issue, name, r["name"], resolved[0], resolved[1], target)
                    name = r["name"]
                    adopted += 1
        if not r or not r.get("owner") or not r.get("repo"):
            skipped += 1
            continue

        comments = _req("GET", f"{API}/repos/{repo}/issues/{issue['number']}/comments"
                                f"?per_page=100", token)
        since = last_checkpoint(issue, comments, name, target)

        if not args.force and not has_new_commits(r["owner"], r["repo"], since, token):
            noop += 1
            continue

        entry = entries_by_name.get(name.lower())
        if entry is None:
            skipped += 1
            continue

        if args.dry_run:
            print(f"[dry-run] RECHECK #{issue['number']} {name} (new commits since {since})")
            rechecked += 1
            continue

        with tempfile.TemporaryDirectory() as plugins_dir:
            clone_repo(r["owner"], r["repo"], os.path.join(plugins_dir, name))
            fresh = scan_plugin(entry, target, plugins_dir, token, schema)

        # Unlike a human-triggered /recheck (where the triggering comment itself
        # explains why a fresh report appeared), nothing else in the thread
        # explains this one - so the trigger context is prepended to the SAME
        # report comment instead of following it with a second, mostly-restating
        # comment (dropped 2026-08-08, matching the manual /recheck cleanup): the
        # report itself already carries the full findings and, when ready_to_close,
        # its own "🎉 Congratulations ... A maintainer will review and close this
        # issue" note - nothing left worth saying twice.
        trigger_note = ("🔄 Forced recheck (remediation sweep) - re-verifying with a real "
                         "clone+lint pass after a bug let status be set from a metadata-only "
                         "scan without one." if args.force else
                         "🔄 Auto-rechecked after detecting new commits since the last check.")
        report = trigger_note + "\n\n" + issue_body(fresh, target, draft=False)
        _req("POST", f"{API}/repos/{repo}/issues/{issue['number']}/comments", token,
             {"body": report})

        # Swap only the status:<...> label, same as manual /recheck - a full
        # PATCH with an explicit "labels" list would silently drop unrelated
        # labels (e.g. needs-manual-review) that happen to be set.
        new_status_label = f"status:{fresh['status']}"
        for lb in issue.get("labels", []):
            lname = lb.get("name") if isinstance(lb, dict) else lb
            if lname and lname.startswith("status:") and lname != new_status_label:
                try:
                    _req("DELETE", f"{API}/repos/{repo}/issues/{issue['number']}/labels/{lname}", token)
                except Exception:  # noqa: BLE001 - best-effort, matches manual /recheck's try/catch
                    pass
        _req("POST", f"{API}/repos/{repo}/issues/{issue['number']}/labels", token,
             {"labels": [new_status_label]})
        rechecked += 1

    print(f"\nauto-recheck target=fpp{target} dry_run={args.dry_run} :: "
          f"rechecked {rechecked}, skipped {skipped}, noop {noop}, adopted {adopted}")


if __name__ == "__main__":
    main()
