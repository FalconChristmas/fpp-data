"""Print the registered owner (GitHub login) of a pluginList.json entry, from its
srcURL, plus its top contributors.

Used to authorize /recheck and /submit on a new-major-release tracking issue: unlike
a submission or removal issue (opened by the person who then acts on it), a tracking
issue is opened by the new-major-release scan itself - there's no "issue creator" to
restrict those commands to. The plugin's actual registered owner is the right
authority instead - and, since an org-owned repo's "owner" is the org login (no
individual can ever match that), the plugin's own top contributors are also allowed,
same unverified-access caveat as new_major_release_scan.py's maintainer_candidates
(commit history only, not a real collaborator-permission check - fpp-data-ci's token
has no standing to query that on a repo it doesn't own).

Usage: resolve_plugin_owner.py --plugin-list pluginList.json --repo-name <name>
Writes `owner` (empty if unresolvable) and `contributors` (comma-separated logins,
empty if none) to $GITHUB_OUTPUT.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import (  # noqa: E402
    fetch_json, gh_get_contributors, gh_get_pr_mergers, load_pluginlist, parse_github_repo,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", required=True)
    ap.add_argument("--repo-name", required=True)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    owner = ""
    contributors: list[str] = []
    entry = next((e for e in load_pluginlist(args.plugin_list)
                  if e and e[0].lower() == args.repo_name.lower()), None)
    if entry:
        info_url = entry[1] if len(entry) > 1 else None
        info, _ = fetch_json(info_url) if info_url else (None, None)
        src = parse_github_repo((info or {}).get("srcURL", "") or "")
        if src:
            owner, repo = src
            # Same preference as new_major_release_scan.py: people who've merged someone
            # else's PR are a stronger authority signal than raw commit-count contributors,
            # which credit a one-off external submitter the same as an actual maintainer.
            contributors = gh_get_pr_mergers(owner, repo, token) or gh_get_contributors(owner, repo, token)

    print(f"owner={owner or '(unresolved)'} contributors={','.join(contributors) or '(none)'}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"owner={owner}\n")
            f.write(f"contributors={','.join(contributors)}\n")


if __name__ == "__main__":
    main()
