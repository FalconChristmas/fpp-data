"""Reconcile per-plugin FPP-major tracking issues from a new-major-release scan.

Reads summary.json (produced by new_major_release_scan.py) and, for the current
repo, keeps one tracking issue per plugin in sync. Idempotent: issues are matched by
a hidden marker in the body, so re-runs update rather than duplicate.

Modes:
  --mode create     create a missing issue, or update an existing one's body.
                    (used by the manual new-major-release workflow)
  --mode reconcile  do NOT create anything; for a plugin now compatible, comment
                    and CLOSE its open issue. (used by the daily workflow)

By default, never @-mentions an author: bodies (from new_major_release_scan.issue_body)
render the maintainer handle as plain text, so no one is notified. If the scan that
produced summary.json was run with --mention-owner, `mention_owner: true` is carried
in summary.json and real @-mentions are used instead - opt-in, and only ever applied
to non-draft issue bodies. Same-repo issue writes use the default GITHUB_TOKEN - no
PAT needed.

Usage:
  new_major_release_sync_issues.py --summary out/summary.json --mode create|reconcile [--dry-run] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

from new_major_release_scan import issue_body

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


def list_new_major_release_issues(repo, token, label):
    """OPEN issues carrying the new-major-release label, matched later by marker.

    Closed issues are intentionally excluded: if a plugin's old tracking issue
    was closed (e.g. reconcile mode auto-closing it once compatible), the next
    scan should open a fresh, visible issue rather than silently
    resurrecting/updating the closed one in place, where nobody would see it.
    """
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", default="out/summary.json")
    ap.add_argument("--mode", choices=["create", "reconcile"], required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not args.dry_run and (not repo or not token):
        raise SystemExit("GITHUB_REPOSITORY and GITHUB_TOKEN required (or use --dry-run)")

    with open(args.summary, encoding="utf-8") as f:
        summary = json.load(f)
    target = summary["target_major"]
    mention_owner = summary.get("mention_owner", False)
    plugins = summary["plugins"]
    if args.limit:
        plugins = plugins[: args.limit]

    label = f"fpp{target}-compat"
    existing = {} if args.dry_run else {}
    if not args.dry_run:
        for iss in list_new_major_release_issues(repo, token, label):
            marker = f"<!-- plugin:"
            body = iss.get("body") or ""
            if marker in body:
                # marker line is: <!-- plugin:<name> new_major_release:fpp<major> -->
                nm = body.split("<!-- plugin:", 1)[1].split()[0]
                existing[nm] = iss

    created = updated = closed = noop = 0
    for r in plugins:
        name = r["name"]
        title = f"[FPP {target}] {name} - compatibility & plugin check"
        body = issue_body(r, target, draft=False, mention_owner=mention_owner)
        iss = existing.get(name)

        if args.mode == "reconcile":
            # Only act when the plugin is now compatible with no outstanding blockers
            # and an issue is open. certified alone isn't enough - it only means a
            # versions[] entry declares the target major, not that blocker findings
            # (schema errors, lint failures, etc) have been resolved.
            if r["ready_to_close"] and iss and iss.get("state") == "open":
                if args.dry_run:
                    print(f"[dry-run] CLOSE #{iss['number']} {name} (now FPP {target} compatible, no blockers)")
                else:
                    _req("POST", f"{API}/repos/{repo}/issues/{iss['number']}/comments", token,
                         {"body": f"✅ Detected a `versions[]` entry declaring FPP {target} "
                                  f"support with no outstanding blockers - thanks! Closing automatically."})
                    _req("PATCH", f"{API}/repos/{repo}/issues/{iss['number']}", token,
                         {"state": "closed", "state_reason": "completed"})
                closed += 1
            else:
                noop += 1
            continue

        # mode == create : upsert the tracking issue
        if iss:
            if args.dry_run:
                print(f"[dry-run] UPDATE #{iss['number']} {name} [{r['status']}]")
            else:
                _req("PATCH", f"{API}/repos/{repo}/issues/{iss['number']}", token,
                     {"body": body, "labels": [label, f"status:{r['status']}"]})
            updated += 1
        else:
            if args.dry_run:
                print(f"[dry-run] CREATE {name} [{r['status']}] :: {title}")
            else:
                _req("POST", f"{API}/repos/{repo}/issues", token,
                     {"title": title, "body": body, "labels": [label, f"status:{r['status']}"]})
            created += 1

    print(f"\nmode={args.mode} dry_run={args.dry_run} :: "
          f"created {created}, updated {updated}, closed {closed}, noop {noop}")


if __name__ == "__main__":
    main()
