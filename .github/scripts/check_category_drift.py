#!/usr/bin/env python3
"""Assert the Issue Form's category dropdown still matches pluginCategories.json.

WHY THIS EXISTS
---------------
pluginCategories.json is the single source of truth, but any Issue Form's dropdown
(currently plugin-submission.yml and change_plugin_category.yml) can't read it at
render time - GitHub Issue Forms are static YAML - so each is a hand-kept copy. Add a
category upstream and a form silently offers a stale list forever, with no error
anywhere. This check is what stops that. Exits non-zero on any mismatch, across every
--form given.

The dropdown shows longName, not name: a static YAML dropdown has no separate
label/value, so its options ARE what gets submitted, and GitHub Issue Forms cannot
prefill a dropdown field via query parameters under any circumstances - so there's no
"submit shortName, display longName" trick available here like there is for other
input fields. Whoever transcribes an accepted submission into pluginList.json maps
longName back to shortName via pluginCategories.json.

(The guided page at docs/submit_new_plugin/ used to keep a second hand copy for its
own dropdown, but no longer touches categories at all, for the same prefill-limitation
reason - the submitter picks Category on the real GitHub form instead.)

Usage:
  check_category_drift.py --categories pluginCategories.json \
      --form .github/ISSUE_TEMPLATE/plugin-submission.yml \
      --form .github/ISSUE_TEMPLATE/change_plugin_category.yml
"""
import argparse
import json
import sys

import yaml


def load_source_of_truth_long(path):
    """Long names - what the Issue Form dropdown shows (short name isn't
    representable in a static Issue Forms dropdown, see plugin-submission.yml)."""
    data = json.load(open(path))
    arr = data if isinstance(data, list) else (data.get("categories") or data.get("pluginCategories") or [])
    long_names = [c["longName"] if isinstance(c, dict) else c for c in arr]
    if not long_names:
        sys.exit(f"FATAL: no categories found in {path}")
    return long_names


def load_form_dropdown(path):
    doc = yaml.safe_load(open(path))
    for block in doc.get("body", []):
        if block.get("id") == "category" and block.get("type") == "dropdown":
            return list(block["attributes"]["options"])
    sys.exit(f"FATAL: no 'category' dropdown found in {path} - did the field id change?")


def report(label, truth, actual, errors):
    missing = [c for c in truth if c not in actual]     # in truth, not in the copy
    extra = [c for c in actual if c not in truth]       # in the copy, not in truth
    if not missing and not extra:
        print(f"  ✅ {label}: in sync ({len(actual)} categories)")
        return
    print(f"  ❌ {label}: OUT OF SYNC")
    for c in missing:
        print(f"       missing (add it): {c!r}")
        errors.append(f"{label} is missing category {c!r}")
    for c in extra:
        print(f"       unknown (remove or add to pluginCategories.json): {c!r}")
        errors.append(f"{label} has unknown category {c!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--categories", required=True)
    ap.add_argument("--form", required=True, action="append",
                     help="path to an Issue Form YAML with a 'category' dropdown; repeatable")
    args = ap.parse_args()

    truth_long = load_source_of_truth_long(args.categories)
    print(f"pluginCategories.json (source of truth): {len(truth_long)} categories")
    print(f"  {', '.join(truth_long)}\n")

    errors = []
    for form_path in args.form:
        report(form_path, truth_long, load_form_dropdown(form_path), errors)

    if errors:
        print("\nCategory lists have drifted. pluginCategories.json is the source of truth -")
        print("update the copy to match it (or add the category there first).")
        return 1
    print("\nAll category copies match pluginCategories.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
