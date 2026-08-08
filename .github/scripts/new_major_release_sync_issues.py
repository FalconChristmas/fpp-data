"""Reconcile per-plugin FPP-major tracking issues from a new-major-release scan.

Reads summary.json (produced by new_major_release_scan.py) and, for the current
repo, keeps one tracking issue per plugin in sync. Idempotent: issues are matched by
a hidden marker in the body, so re-runs update rather than duplicate.

Modes:
  --mode create     create a missing issue, or update an existing one's body.
                    (used by the manual new-major-release workflow)
  --mode reconcile  do NOT create anything; keeps each open issue's status:<...>
                    label in sync with a fresh daily rescan (a maintainer
                    filters/watches by that label - e.g. status:compatible - to
                    find issues ready to close by hand; never auto-closes).
                    (used by the daily workflow)

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
    was closed (e.g. a maintainer closing it by hand, or the reminder-7 removal-PR
    escalation), the next scan should open a fresh, visible issue rather than
    silently resurrecting/updating the closed one in place, where nobody would see it.
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

    created = updated = relabeled = noop = 0
    for r in plugins:
        name = r["name"]
        title = f"[FPP {target}] {name} - compatibility & plugin check"
        body = issue_body(r, target, draft=False, mention_owner=mention_owner)
        iss = existing.get(name)

        if args.mode == "reconcile":
            # This mode re-derives r["status"] fresh for every plugin daily
            # (metadata-only rescan, no clone/lint) - keep the issue's status:<...>
            # label in sync with it even on days it doesn't otherwise comment.
            # Without this, a plugin that changes status without a NEW commit (e.g.
            # just edits pluginInfo.json's versions[]) never gets its label updated
            # either here or by the commit-triggered auto-recheck, so it can go
            # stale indefinitely. Surgical swap (remove stale status:* labels, add
            # the current one) - same approach as the recheck workflow and
            # new_major_release_auto_recheck.py - so it never touches any other
            # label (needs-manual-review, etc.), unlike a full PATCH labels=[...]
            # replace (see --mode create's own note on this below).
            if iss:
                new_status_label = f"status:{r['status']}"
                current_status_labels = [
                    l["name"] for l in (iss.get("labels") or [])
                    if isinstance(l, dict) and (l.get("name") or "").startswith("status:")]
                if current_status_labels != [new_status_label]:
                    if args.dry_run:
                        print(f"[dry-run] RELABEL #{iss['number']} {name} -> {new_status_label}")
                    else:
                        for old in current_status_labels:
                            if old != new_status_label:
                                try:
                                    _req("DELETE", f"{API}/repos/{repo}/issues/{iss['number']}/labels/{old}", token)
                                except urllib.error.HTTPError:
                                    pass  # already gone - fine
                        _req("POST", f"{API}/repos/{repo}/issues/{iss['number']}/labels", token,
                             {"labels": [new_status_label]})
                    relabeled += 1
                else:
                    noop += 1
            else:
                noop += 1
            # No separate "now compatible" comment (dropped 2026-08-08) - the
            # status:compatible label swap above is the signal a maintainer
            # filters/watches for; a standalone comment restating the same thing
            # added no information the label change didn't already carry. Still
            # never auto-closes either way - a maintainer closes by hand.
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
          f"created {created}, updated {updated}, relabeled {relabeled}, noop {noop}")


if __name__ == "__main__":
    main()
