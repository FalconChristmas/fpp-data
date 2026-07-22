"""Re-run the new-major-release scan for ONE plugin, on demand - a tracking issue's
/recheck or /submit comment, rather than waiting for the next bulk scan
(new-major-release-scan.yml) or the daily reconcile sweep (daily-fpp-compat.yml).

Reuses new_major_release_scan.scan_plugin() exactly as the bulk scan does (same
findings, same status logic) so a single-plugin recheck can never disagree with what
the next bulk run would have said. Clones the one repo fresh, same as
scan_submission.py does for a brand-new submission.

Usage:
  new_major_release_recheck_one.py --plugin-list pluginList.json --repo-name <name> \
      --target-major <n> --schema .github/schema/pluginInfo.schema.json --out result.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import load_pluginlist, fetch_json, parse_github_repo  # noqa: E402
from new_major_release_scan import scan_plugin, issue_body  # noqa: E402
from scan_submission import clone_repo  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", required=True)
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--target-major", type=int, required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    entry = next((e for e in load_pluginlist(args.plugin_list)
                  if e and e[0].lower() == args.repo_name.lower()), None)
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
        json.dump({"found": True, "result": r, "body": issue_body(r, args.target_major, draft=False)}, f, indent=2)

    print(f"{r['status']}: B{r['num_blocker']} P{r['num_best_practice']} O{r['num_optional']}"
          f"{'' if r['linted'] else '  (no clone - metadata only)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
