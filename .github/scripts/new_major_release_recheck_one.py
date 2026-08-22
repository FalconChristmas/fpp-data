"""Re-run the new-major-release scan for ONE plugin, on demand - a tracking issue's
/recheck or /submit comment, rather than waiting for the next bulk scan
(new-major-release-scan.yml) or the daily reconcile sweep (daily-fpp-compat.yml).

Reuses new_major_release_scan.scan_plugin() exactly as the bulk scan does (same
findings, same status logic) so a single-plugin recheck can never disagree with what
the next bulk run would have said. Clones the one repo fresh, same as
scan_submission.py does for a brand-new submission.

If --repo-name isn't in pluginList.json (e.g. the plugin was renamed since the
tracking issue was created) and --marker-owner/--marker-repo are given (from the
issue marker's `repo:` field), falls back to resolving the rename via GitHub's
redirect and matching pluginList.json by current repo instead of dead-ending. On
that path the output JSON's `resolved_name` carries the plugin's NEW pluginList.json
name, so the calling workflow can adopt the issue (retitle + rewrite its marker)
before posting the report.

Usage:
  new_major_release_recheck_one.py --plugin-list pluginList.json --repo-name <name> \
      [--marker-owner <owner> --marker-repo <repo>] \
      --target-major <n> --schema .github/schema/pluginInfo.schema.json --out result.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import (  # noqa: E402
    fetch_json, load_pluginlist, parse_github_repo, resolve_renamed_repo,
)
from new_major_release_scan import scan_plugin, issue_body  # noqa: E402
from scan_submission import clone_repo  # noqa: E402


def find_entry(entries, repo_name, marker_owner, marker_repo, token):
    """Direct name match first; on a miss with marker owner/repo available, resolve
    a possible rename via the GitHub API and match by current repo instead. Returns
    (entry, resolved_name) - resolved_name is only set (and differs from repo_name)
    when the rename-resolution path found the match.
    """
    entry = next((e for e in entries if e and e[0].lower() == repo_name.lower()), None)
    if entry:
        return entry, None
    if not (marker_owner and marker_repo):
        return None, None
    resolved = resolve_renamed_repo(marker_owner, marker_repo, token)
    if not resolved:
        return None, None
    for e in entries:
        info_url = e[1] if len(e) > 1 else None
        info, _ = fetch_json(info_url) if info_url else (None, None)
        src = parse_github_repo((info or {}).get("srcURL", "") or "")
        if src and src[0].lower() == resolved[0].lower() and src[1].lower() == resolved[1].lower():
            return e, e[0]
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", required=True)
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--marker-owner", default="")
    ap.add_argument("--marker-repo", default="")
    ap.add_argument("--target-major", type=int, required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    entry, resolved_name = find_entry(load_pluginlist(args.plugin_list), args.repo_name,
                                       args.marker_owner, args.marker_repo, token)
    if entry is None:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"found": False}, f)
        print(f"'{args.repo_name}' not found in pluginList.json")
        return 0

    with open(args.schema, encoding="utf-8") as f:
        schema = json.load(f)

    with tempfile.TemporaryDirectory() as plugins_dir:
        info_url = entry[1] if len(entry) > 1 else None
        info, _ = fetch_json(info_url) if info_url else (None, None)
        src = parse_github_repo((info or {}).get("srcURL", "") or "")
        if src:
            owner, repo = src
            # Best-effort: scan_plugin() falls back to metadata-only if the clone
            # dir isn't there, same as a bulk run over a plugin clone_plugins.py
            # couldn't fetch.
            clone_repo(owner, repo, os.path.join(plugins_dir, entry[0]))

        r = scan_plugin(entry, args.target_major, plugins_dir, token, schema)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"found": True, "resolved_name": resolved_name, "result": r,
                    "body": issue_body(r, args.target_major, draft=False)}, f, indent=2)

    if resolved_name:
        print(f"resolved rename: '{args.repo_name}' -> '{resolved_name}'")
    print(f"{r['status']}: {r['num_blocker']} blockers, {r['num_best_practice']} best-practice, "
          f"{r['num_optional']} optional"
          f"{'' if r['linted'] else '  (no clone - metadata only)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
