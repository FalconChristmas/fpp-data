"""Daily auto-recheck: for each open new-major-release tracking issue, if the
plugin's repo has new commits since the last check, re-run the single-plugin
scan (same scan_plugin() manual /recheck uses) and post the updated report.

Comment-only, like --mode reconcile: NEVER closes the issue automatically, even
when the result comes back ready_to_close - a maintainer reviews and closes by
hand (2026-08-08 decision, see .wolf/cerebrum.md). This is deliberately
different from the manual /recheck workflow (new-major-release-issue-recheck.yml),
which DOES auto-close on ready_to_close - that path only fires when a human
(the plugin owner) explicitly asked for it, so a close there reflects a person's
request. Nothing unattended closes a compatibility issue here.

"Since the last check" is derived from issue activity, not a separate marker
comment: the posted report (both this script's and manual /recheck's) always
carries the `<!-- plugin:<name> new_major_release:fpp<major> -->` marker at its
top (same one the original issue body has), so the newest comment containing
that marker - or the issue body/creation itself if no such comment exists yet -
is the last known-good checkpoint. Only commits pushed after that checkpoint
count as "new". This piggybacks on an existing signal instead of adding a
second kind of marker to track and keep in sync.

Usage:
  new_major_release_auto_recheck.py --summary out/summary.json \
      --plugin-list pluginList.json --target-major <n> \
      --schema .github/schema/pluginInfo.schema.json [--dry-run] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import load_pluginlist  # noqa: E402
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


def marker_re(name, target):
    return re.compile(rf"<!--\s*plugin:{re.escape(name)}\s+new_major_release:fpp{target}\s*-->")


def last_checkpoint(issue, comments, name, target):
    """ISO timestamp of the newest report (comment or the issue body itself)
    carrying this plugin's marker - the last time we know its actual state was
    verified fresh."""
    pat = marker_re(name, target)
    checkpoint = issue["created_at"]  # issue body always carries the marker
    for c in comments:
        body = c.get("body") or ""
        if pat.search(body) and c["created_at"] > checkpoint:
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
    args = ap.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not args.dry_run and (not repo or not token):
        raise SystemExit("GITHUB_REPOSITORY and GITHUB_TOKEN required (or use --dry-run)")

    with open(args.summary, encoding="utf-8") as f:
        summary = json.load(f)
    target = args.target_major
    by_name = {p["name"]: p for p in summary["plugins"]}

    with open(args.schema, encoding="utf-8") as f:
        schema = json.load(f)
    entries_by_name = {e[0].lower(): e for e in load_pluginlist(args.plugin_list)}

    label = f"fpp{target}-compat"
    issues = [] if args.dry_run else list_tracking_issues(repo, token, label)
    if args.limit:
        issues = issues[: args.limit]

    rechecked = skipped = noop = 0
    for issue in issues:
        body = issue.get("body") or ""
        m = re.search(r"<!--\s*plugin:(\S+)\s+new_major_release:fpp(\d+)\s*-->", body)
        if not m:
            continue
        name = m.group(1)
        r = by_name.get(name)
        if not r or not r.get("owner") or not r.get("repo"):
            skipped += 1
            continue

        comments = _req("GET", f"{API}/repos/{repo}/issues/{issue['number']}/comments"
                                f"?per_page=100", token)
        since = last_checkpoint(issue, comments, name, target)

        if not has_new_commits(r["owner"], r["repo"], since, token):
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

        report = issue_body(fresh, target, draft=False)
        _req("POST", f"{API}/repos/{repo}/issues/{issue['number']}/comments", token,
             {"body": report})

        summary_line = f"B{fresh['num_blocker']} best-practice {fresh['num_best_practice']} optional {fresh['num_optional']}"
        if fresh["ready_to_close"]:
            note = (f"✅ Auto-rechecked after detecting new commits - now declares FPP {target} "
                    f"compatibility with no outstanding blockers. A maintainer will review and "
                    f"close this issue.")
        else:
            note = (f"🔄 Auto-rechecked after detecting new commits ({summary_line}) - see the "
                    f"updated report above.")
        _req("POST", f"{API}/repos/{repo}/issues/{issue['number']}/comments", token, {"body": note})

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
          f"rechecked {rechecked}, skipped {skipped}, noop {noop}")


if __name__ == "__main__":
    main()
