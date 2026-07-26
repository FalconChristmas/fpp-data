#!/usr/bin/env python3
"""Insert an accepted submission's entry into pluginList.json.

Edits the file as TEXT, appending one compact `[ "name", "url", "category" ]` line in
the same hand-formatted style the file already uses (one entry per line) - a full
json.dump() round-trip would reformat the whole file and bury the real change in an
unreviewable diff.

Every check that would normally gate this entry (schema, repoName match, archived/
issues-disabled) already ran in scan_submission.py before the calling workflow decided
this submission was ready - the one thing left to check here is that the category is
actually one of pluginCategories.json's longNames, since a static Issue Forms dropdown
option is free text as far as this script is concerned.

Exit codes / stdout markers (for the calling workflow to branch on):
  ADDED <name> (<shortCategory>)   - entry inserted, file written, exit 0
  ALREADY_LISTED <name>            - repoName already present; nothing to do, exit 0
  UNKNOWN_CATEGORY <category>      - no matching longName in pluginCategories.json, exit 1

Usage:
  add_plugin_entry.py --plugin-list pluginList.json --categories pluginCategories.json \
      --repo-name <name> --plugininfo-url <url> --category "<longName from the issue>"
"""
from __future__ import annotations

import argparse
import json
import sys


def load_category_map(path: str) -> dict[str, str]:
    """{longName: shortName, ...} - the issue form's dropdown shows longName (see
    check_category_drift.py), but pluginList.json stores shortName."""
    data = json.load(open(path, encoding="utf-8"))
    return {c["longName"]: c["name"] for c in data.get("categories", []) if c.get("longName")}


def already_listed(text: str, repo_name: str) -> bool:
    """Case-insensitive: repoName casing in a resubmission doesn't always match what's
    already stored (see scan_submission.py's already_listed(), which is the primary
    check - this is just a backstop for the rare cross-run race)."""
    data = json.loads(text)
    return any(isinstance(e, list) and e and e[0].lower() == repo_name.lower()
               for e in data.get("pluginList", []))


def insert_entry(text: str, repo_name: str, plugininfo_url: str, category: str) -> str:
    lines = text.splitlines(keepends=True)
    close_idx = next(i for i, l in enumerate(lines) if l.strip() == "]")
    prev_idx = close_idx - 1
    if not lines[prev_idx].rstrip().endswith(","):
        lines[prev_idx] = lines[prev_idx].rstrip("\n") + ",\n"
    new_line = f'            [ "{repo_name}", "{plugininfo_url}", "{category}" ]\n'
    lines.insert(close_idx, new_line)
    return "".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", required=True)
    ap.add_argument("--categories", required=True)
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--plugininfo-url", required=True)
    ap.add_argument("--category", required=True)
    args = ap.parse_args()

    text = open(args.plugin_list, encoding="utf-8").read()

    if already_listed(text, args.repo_name):
        print(f"ALREADY_LISTED {args.repo_name}")
        return 0

    cat_map = load_category_map(args.categories)
    short = cat_map.get(args.category.strip())
    if not short:
        print(f"UNKNOWN_CATEGORY {args.category.strip()!r} - valid: {sorted(cat_map)}")
        return 1

    new_text = insert_entry(text, args.repo_name, args.plugininfo_url, short)
    json.loads(new_text)  # sanity: must still be valid JSON after the text edit

    with open(args.plugin_list, "w", encoding="utf-8") as f:
        f.write(new_text)
    print(f"ADDED {args.repo_name} ({short})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
