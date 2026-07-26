"""Remove a verified plugin-removal request's entry from pluginList.json.

Runs after remove-plugin-verify.yml has already labeled the issue `owner-verified`
(personal-repo owner match, an archived/gone repo, or delist:true proof-of-control).
Edits pluginList.json with a minimal line-level diff instead of round-tripping
through json.dump, since the file is hand-formatted (one entry per line, custom
indent) and a full re-dump would rewrite every line.

Reads ISSUE_BODY from the environment to find the "Plugin repoName" form field.
Writes the removed entry's name to $GITHUB_OUTPUT (key `removed`) on success,
or `error` with a message on failure. Exits 0 either way - the caller decides
whether to commit.
"""

from __future__ import annotations

import argparse
import os
import re

import lib_plugin_schema as lib

ENTRY_RE = re.compile(r'^(\s*)\[\s*"([^"]+)"')


def field(body: str, label: str) -> str:
    """Value under a GitHub issue-form '### <label>' heading (first non-empty line)."""
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if line.strip().lstrip("#").strip().lower() == label.lower():
            for nxt in lines[i + 1:]:
                s = nxt.strip()
                if s and not s.startswith("#"):
                    return s
    return ""


def remove_entry(text: str, repo_name: str) -> tuple[str | None, str | None]:
    """(new_text, error). new_text is None if repo_name wasn't found."""
    lines = text.splitlines(keepends=True)
    entry_idx = [i for i, l in enumerate(lines) if ENTRY_RE.match(l)]
    if not entry_idx:
        return None, "no plugin entries found in pluginList.json"

    # Case-insensitive: see resolve_owner()'s docstring in verify_remove_plugin.py --
    # a plugin's declared repoName doesn't always match its repo's URL casing.
    target = None
    for i in entry_idx:
        if ENTRY_RE.match(lines[i]).group(2).lower() == repo_name.lower():
            target = i
            break
    if target is None:
        return None, f"'{repo_name}' is not in pluginList.json (already removed?)"

    # If we're deleting the last entry, drop the trailing comma from the new
    # last entry so the array stays valid JSON.
    if target == entry_idx[-1] and len(entry_idx) > 1:
        prev = entry_idx[-2]
        lines[prev] = re.sub(r",(\s*\n)$", r"\1", lines[prev])

    del lines[target]
    return "".join(lines), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", default="pluginList.json")
    ap.add_argument("--repo-name")
    args = ap.parse_args()

    repo_name = args.repo_name or lib.resolve_repo_name(
        field(os.environ.get("ISSUE_BODY") or "", "Plugin repoName")
        or field(os.environ.get("ISSUE_BODY") or "", "repoName")
    )

    out = os.environ.get("GITHUB_OUTPUT")

    if not repo_name:
        msg = "Could not read a **Plugin repoName** from the form."
        print(f"error: {msg}")
        if out:
            with open(out, "a", encoding="utf-8") as f:
                f.write(f"error={msg}\n")
        return

    with open(args.plugin_list, encoding="utf-8") as f:
        text = f.read()

    new_text, err = remove_entry(text, repo_name)
    if err:
        print(f"error: {err}")
        if out:
            with open(out, "a", encoding="utf-8") as f:
                f.write(f"error={err}\n")
        return

    with open(args.plugin_list, "w", encoding="utf-8") as f:
        f.write(new_text)

    print(f"removed: {repo_name}")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"removed={repo_name}\n")


if __name__ == "__main__":
    main()
