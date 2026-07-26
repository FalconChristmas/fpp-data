#!/usr/bin/env python3
"""Validate pluginList.json (and the pluginInfo.json each entry points at).

Run by .github/workflows/validate-pluginlist.yml on PRs that touch pluginList.json.

Design:
  * ERRORS fail the CI check (red X). WARNINGS are reported but pass (green check).
  * By default only NEW or CHANGED entries are hard-validated (diff against the base
    branch), so a PR isn't blocked by a pre-existing problem in an unrelated entry.
    Pre-existing problems on untouched entries are downgraded to warnings.
  * Writes a Markdown report to --output and to $GITHUB_STEP_SUMMARY. The workflow
    posts (and updates) that report as a sticky PR comment.

Usage:
    validate_pluginlist.py \
        --pluginlist pluginList.json \
        --categories pluginCategories.json \
        --schema-dir .github/schema \
        [--base base_pluginList.json] \
        --output validation-report.md
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field

import jsonschema  # provided by the workflow (pip install jsonschema)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_plugin_schema import (  # noqa: E402
    fetch_json,
    gh_get_repo,
    load_categories,
    load_pluginlist,
    parse_github_repo,
)

ERROR = "error"
WARNING = "warning"


@dataclass
class Finding:
    level: str          # ERROR | WARNING
    entry: str          # repoName or "pluginList.json"
    message: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def add(self, level: str, entry: str, message: str) -> None:
        self.findings.append(Finding(level, entry, message))

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.level == ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.level == WARNING]


def changed_repo_names(head: list[list], base: list[list] | None) -> set[str] | None:
    """Return the set of repoNames added or changed vs base. None => validate everything."""
    if base is None:
        return None
    base_by_name = {e[0]: e for e in base if isinstance(e, list) and e}
    changed = set()
    for e in head:
        if not (isinstance(e, list) and e):
            continue
        name = e[0]
        if name not in base_by_name or base_by_name[name] != e:
            changed.add(name)
    return changed


def validate_entry(entry, categories, info_schema, token, is_target, report):
    """Validate one pluginList.json entry. `is_target` => hard errors; else downgrade to warnings."""
    def report_problem(entry_name, message):
        report.add(ERROR if is_target else WARNING, entry_name, message)

    # --- shape ---
    if not isinstance(entry, list) or not (2 <= len(entry) <= 3):
        report.add(ERROR, str(entry)[:60], "entry must be a 2- or 3-element array [name, url, category?]")
        return
    name, url = entry[0], entry[1]
    if not isinstance(name, str) or not name:
        report.add(ERROR, str(entry)[:60], "first element (name) must be a non-empty string")
        return

    # --- category (3rd element) ---
    if len(entry) == 3:
        category = entry[2]
        if category not in categories:
            report_problem(name, f"category '{category}' is not in pluginCategories.json "
                                 f"(allowed: {', '.join(sorted(categories))})")

    if not (isinstance(url, str) and url.startswith(("http://", "https://"))):
        report_problem(name, f"pluginInfo URL is missing or not http(s): {url!r}")
        return

    # --- fetch + schema-validate pluginInfo.json ---
    info, err = fetch_json(url)
    if err:
        report_problem(name, f"cannot fetch pluginInfo.json - {err}")
        return
    try:
        jsonschema.validate(info, info_schema)
    except jsonschema.ValidationError as e:
        loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
        report_problem(name, f"pluginInfo.json fails schema at `{loc}`: {e.message}")
        # keep going for the softer checks below where possible

    if isinstance(info, dict):
        # name must match the list key
        if info.get("repoName") and info["repoName"] != name:
            report_problem(name, f"pluginInfo.json repoName '{info['repoName']}' != list name '{name}'")

        # --- repo existence / visibility / issues (GitHub API when possible) ---
        is_private = bool(info.get("private"))
        src = info.get("srcURL") or info.get("homeURL") or url
        gh = parse_github_repo(src)
        if gh:
            owner, repo = gh
            data, gh_err = gh_get_repo(owner, repo, token)
            if gh_err:
                lvl_msg = f"could not reach GitHub repo {owner}/{repo} ({gh_err})"
                if "404" in gh_err and not is_private:
                    report_problem(name, f"srcURL repo not found or not public: {owner}/{repo}")
                else:
                    report.add(WARNING, name, lvl_msg)
            elif data:
                if data.get("private") and not is_private:
                    report_problem(name, f"srcURL repo {owner}/{repo} is private but pluginInfo does not declare private:true")
                if data.get("archived"):
                    report.add(WARNING, name, f"srcURL repo {owner}/{repo} is archived")
                # bugURL: warn (don't fail) if Issues are disabled - dead 'Report a Bug' link
                bug = parse_github_repo(info.get("bugURL", ""))
                if bug and bug == (owner, repo) and data.get("has_issues") is False:
                    report.add(WARNING, name, f"Issues are disabled on {owner}/{repo} - the bugURL link won't work")

        # --- at least one versions[] entry (schema enforces non-empty; here just note majors) ---
        versions = info.get("versions") or []
        if versions and not any(isinstance(v, dict) and v.get("minFPPVersion") for v in versions):
            report_problem(name, "no versions[] entry declares a minFPPVersion")


def build_markdown(report: Report, num_targets, total) -> str:
    lines = ["## Plugin list validation", ""]
    scope = f"{num_targets} changed" if num_targets is not None else f"all {total}"
    lines.append(f"Checked **{scope}** ent"
                 f"{'ry' if (num_targets == 1) else 'ries'} in `pluginList.json`.")
    lines.append("")
    if not report.findings:
        lines.append("✅ **All checks passed.** Ready for a maintainer to review.")
        return "\n".join(lines) + "\n"

    if report.errors:
        lines.append(f"### ❌ {len(report.errors)} error(s) - must be fixed")
        for f in report.errors:
            lines.append(f"- **{f.entry}** - {f.message}")
        lines.append("")
    if report.warnings:
        lines.append(f"### ⚠️ {len(report.warnings)} warning(s) - please review")
        for f in report.warnings:
            lines.append(f"- **{f.entry}** - {f.message}")
        lines.append("")
    lines.append("_Errors block the check; warnings do not. See "
                 "[PLUGINS.md](../blob/master/PLUGINS.md) for the format._")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pluginlist", required=True)
    ap.add_argument("--categories", required=True)
    ap.add_argument("--schema-dir", required=True)
    ap.add_argument("--base", help="base-branch copy of pluginList.json (enables diff-scoping)")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    report = Report()
    token = os.environ.get("GITHUB_TOKEN")

    # Load the head pluginList.json against the list schema first.
    import json
    with open(os.path.join(args.schema_dir, "pluginList.schema.json"), encoding="utf-8") as f:
        list_schema = json.load(f)
    with open(os.path.join(args.schema_dir, "pluginInfo.schema.json"), encoding="utf-8") as f:
        info_schema = json.load(f)

    try:
        with open(args.pluginlist, encoding="utf-8") as f:
            head_doc = json.load(f)
    except json.JSONDecodeError as e:
        report.add(ERROR, "pluginList.json", f"file is not valid JSON: {e}")
        _finish(report, args.output, None, 0)
        return 1

    try:
        jsonschema.validate(head_doc, list_schema)
    except jsonschema.ValidationError as e:
        loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
        report.add(ERROR, "pluginList.json", f"fails list schema at `{loc}`: {e.message}")

    head = head_doc.get("pluginList", []) if isinstance(head_doc, dict) else []

    # Duplicate repoName check (global - always an error).
    seen = {}
    for e in head:
        if isinstance(e, list) and e and isinstance(e[0], str):
            seen[e[0]] = seen.get(e[0], 0) + 1
    for nm, count in seen.items():
        if count > 1:
            report.add(ERROR, nm, f"duplicate entry - appears {count} times")

    categories = load_categories(args.categories)

    base = None
    if args.base and os.path.exists(args.base):
        try:
            base = load_pluginlist(args.base)
        except Exception:  # noqa: BLE001 - base unreadable => validate everything
            base = None
    targets = changed_repo_names(head, base)

    num_targets = None if targets is None else len(targets)
    for entry in head:
        name = entry[0] if (isinstance(entry, list) and entry) else None
        is_target = targets is None or (name in targets)
        # Only spend network calls on targets when diff-scoped; still schema-check shape of all.
        if targets is not None and not is_target:
            continue
        validate_entry(entry, categories, info_schema, token, is_target, report)

    _finish(report, args.output, num_targets, len(head))
    return 1 if report.errors else 0


def _finish(report: Report, output: str, num_targets, total: int) -> None:
    md = build_markdown(report, num_targets, total)
    with open(output, "w", encoding="utf-8") as f:
        f.write(md)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(md)
    # Also echo to the log.
    print(md)


if __name__ == "__main__":
    raise SystemExit(main())
