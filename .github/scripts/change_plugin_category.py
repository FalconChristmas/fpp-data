"""Apply a verified category-change request's new category to pluginList.json.

Runs after change-category-verify.yml has already labeled the issue
`category-verified`. Edits pluginList.json as TEXT, replacing just the category field
on the matching entry's line, in the same hand-formatted style
add_plugin_entry.py/remove_plugin_entry.py already use - a full json.dump() round-trip
would reformat the whole file and bury the real change in an unreviewable diff.

Reads ISSUE_BODY from the environment to find the "Plugin repoName"/"New category"
form fields when --repo-name/--new-category aren't passed directly. Writes to
$GITHUB_OUTPUT (`changed`+`old_category`+`new_category` on success, `error` on
failure). Exits 0 either way - the caller decides whether to commit.

Usage:
  change_plugin_category.py --plugin-list pluginList.json --categories pluginCategories.json \
      --repo-name <name> --new-category "<longName from the issue>"
"""

from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import field, load_category_map, resolve_repo_name  # noqa: E402

NAME_RE = re.compile(r'^\s*\[\s*"([^"]*)"')
# Group 1: everything through the third field's opening quote. Group 2: the category
# text itself. Group 3: closing quote through end-of-line, tolerating both a trailing
# comma (every entry but the last) and none (the last entry), and both a space and no
# space before the closing `]` (both styles already exist in pluginList.json).
ENTRY_RE = re.compile(r'^(\s*\[\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*")([^"]*)("\s*\][^\n]*\n?)$')


def change_category(text: str, repo_name: str, new_short: str) -> tuple[str | None, str | None, str | None]:
    """(new_text, old_category, error). new_text is None on any failure."""
    lines = text.splitlines(keepends=True)
    target = None
    for i, line in enumerate(lines):
        m = NAME_RE.match(line)
        if m and m.group(1).lower() == repo_name.lower():
            target = i
            break
    if target is None:
        return None, None, f"'{repo_name}' is not in pluginList.json (already removed?)"

    m = ENTRY_RE.match(lines[target])
    if not m:
        return None, None, f"'{repo_name}'s entry line has an unexpected format - edit pluginList.json by hand"

    old_short = m.group(2)
    if old_short == new_short:
        return None, old_short, f"'{repo_name}' is already in category '{new_short}'"

    lines[target] = m.group(1) + new_short + m.group(3)
    return "".join(lines), old_short, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", default="pluginList.json")
    ap.add_argument("--categories", default="pluginCategories.json")
    ap.add_argument("--repo-name")
    ap.add_argument("--new-category", help="longName from the issue form")
    args = ap.parse_args()

    out = os.environ.get("GITHUB_OUTPUT")

    def fail(msg: str):
        print(f"error: {msg}")
        if out:
            with open(out, "a", encoding="utf-8") as f:
                f.write(f"error={msg}\n")

    body = os.environ.get("ISSUE_BODY") or ""
    repo_name = args.repo_name or resolve_repo_name(
        field(body, "Plugin repoName") or field(body, "repoName"))
    new_category_long = args.new_category or field(body, "New category")

    if not repo_name:
        return fail("Could not read a **Plugin repoName** from the form.")
    if not new_category_long:
        return fail("Could not read a **New category** from the form.")

    cat_map = load_category_map(args.categories)
    new_short = cat_map.get(new_category_long.strip())
    if not new_short:
        return fail(f"{new_category_long.strip()!r} is not a recognized category - valid: {sorted(cat_map)}")

    with open(args.plugin_list, encoding="utf-8") as f:
        text = f.read()

    new_text, old_short, err = change_category(text, repo_name, new_short)
    if err:
        return fail(err)

    with open(args.plugin_list, "w", encoding="utf-8") as f:
        f.write(new_text)

    print(f"changed: {repo_name} ({old_short} -> {new_short})")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"changed={repo_name}\n")
            f.write(f"old_category={old_short}\n")
            f.write(f"new_category={new_short}\n")


if __name__ == "__main__":
    main()
