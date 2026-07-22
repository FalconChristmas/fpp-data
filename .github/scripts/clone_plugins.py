"""Shallow-clone every plugin in pluginList.json into <out>/<repoName>.

Derives the clone URL + branch from each entry's pluginInfo URL
(raw.githubusercontent.com/<owner>/<repo>/<ref>/pluginInfo.json). Failures are
reported but don't stop the run - the new-major-release scanner still reports a
plugin it couldn't clone (metadata-only). Used by the plugin-check workflow.

Usage: clone_plugins.py --plugin-list pluginList.json --out plugins [--limit N]
"""

from __future__ import annotations

import argparse
import os
import subprocess
from urllib.parse import urlparse

import lib_plugin_schema as lib


def clone_target(info_url: str):
    """(owner, repo, branch) from a raw pluginInfo URL, else None."""
    parts = [p for p in urlparse(info_url).path.split("/") if p]
    if len(parts) < 3:
        return None
    owner, repo, rest = parts[0], parts[1], parts[2:-1]  # drop pluginInfo.json
    if rest[:2] == ["refs", "heads"]:
        rest = rest[2:]
    branch = rest[0] if rest else "master"
    return owner, repo, branch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", default="pluginList.json")
    ap.add_argument("--out", default="plugins")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    entries = lib.load_pluginlist(args.plugin_list)
    if args.limit:
        entries = entries[: args.limit]

    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    ok = fail = 0
    for entry in entries:
        name = entry[0]
        info_url = entry[1] if len(entry) > 1 else ""
        tgt = clone_target(info_url)
        dest = os.path.join(args.out, name)
        if os.path.isdir(os.path.join(dest, ".git")):
            ok += 1
            continue
        if not tgt:
            print(f"SKIP {name}: cannot derive clone URL from {info_url!r}")
            fail += 1
            continue
        owner, repo, branch = tgt
        url = f"https://github.com/{owner}/{repo}.git"
        r = subprocess.run(["git", "clone", "--depth", "1", "--branch", branch, url, dest],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            r = subprocess.run(["git", "clone", "--depth", "1", url, dest],
                               env=env, capture_output=True, text=True)
        if r.returncode == 0:
            ok += 1
        else:
            fail += 1
            print(f"FAIL {name}: {(r.stderr.strip().splitlines() or ['?'])[-1][:120]}")
    print(f"cloned {ok}, failed {fail}")


if __name__ == "__main__":
    main()
