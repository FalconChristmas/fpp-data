#!/usr/bin/env python3
"""dateAdded (the 4th element of a pluginList.json entry) - shared rules, and the
check .github/workflows/pluginlist-dates-guard.yml runs after every push to master.

dateAdded is the date a plugin was first listed: ISO YYYY-MM-DD, UTC, set when the
listing PR is prepared and never changed afterwards. validate_pluginlist.py enforces
that on pull requests, but a PR can edit the validator along with the list, and
admin merges, direct pushes and the removal bot never run it. This script compares
two versions of the list and reports any date that changed or disappeared, plus any
malformed date, so a change on master that skipped the PR check still shows up as a
failed run. The guard workflow runs the PARENT commit's copy of this script, so a
push can't weaken the check that judges it.

Stdlib only: the guard runs it without installing anything.

Usage:
    check_listing_dates.py --old OLD_pluginList.json --new NEW_pluginList.json
Exit 1 when there is a violation.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys

# ASCII digits only: Python's \\d also matches other scripts' digits, and strptime
# accepts them ("２０２４-01-01" would parse as 2024-01-01).
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
DATE_IDX = 3  # [name, url, category, dateAdded] - positional, so a date needs a category
# A date is "in the future" only past tomorrow (UTC): someone east of UTC adding
# their own local date is up to a day ahead.
FUTURE_SLACK = datetime.timedelta(days=1)


def today_utc() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_date_added(value) -> tuple[datetime.date | None, str | None]:
    """(date, error) for a dateAdded value - a real calendar date written exactly
    YYYY-MM-DD with ASCII digits (no spaces, no trailing newline)."""
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        return None, f"dateAdded {value!r} is not an ISO YYYY-MM-DD date"
    try:
        parsed = datetime.date.fromisoformat(value)
    except ValueError:
        return None, f"dateAdded {value!r} is not a real calendar date"
    if parsed.isoformat() != value:
        return None, f"dateAdded {value!r} is not an ISO YYYY-MM-DD date"
    return parsed, None


def date_error(value, today: datetime.date | None = None) -> str | None:
    """parse_date_added()'s error, or one for a date after tomorrow (UTC)."""
    parsed, err = parse_date_added(value)
    if err:
        return err
    today = today or today_utc()
    if parsed > today + FUTURE_SLACK:
        return f"dateAdded {value} is in the future (today is {today.isoformat()} UTC)"
    return None


def entries(doc) -> list[list]:
    lst = doc.get("pluginList", []) if isinstance(doc, dict) else []
    return [e for e in lst if isinstance(e, list) and e and isinstance(e[0], str)]


def date_of(entry: list):
    return entry[DATE_IDX] if len(entry) > DATE_IDX else None


def by_name(lst: list[list]) -> dict[str, list]:
    """Entries keyed by lower-cased name (first one wins) - a change of case is the
    same plugin, so it must keep its date."""
    out: dict[str, list] = {}
    for e in lst:
        out.setdefault(e[0].lower(), e)
    return out


def date_violations(old: list[list], new: list[list], today: datetime.date | None = None) -> list[str]:
    """Every dateAdded in `new` that is malformed, or that changed or disappeared
    from `old` for the same plugin (matched by name, ignoring case)."""
    out = []
    old_by = by_name(old)
    for e in new:
        date = date_of(e)
        if date is not None:
            err = date_error(date, today)
            if err:
                out.append(f"{e[0]}: {err}")
        prev = old_by.get(e[0].lower())
        prev_date = date_of(prev) if prev is not None else None
        if prev_date is None:
            continue
        if date is None:
            out.append(f"{e[0]}: dateAdded {prev_date} was removed")
        elif date != prev_date:
            out.append(f"{e[0]}: dateAdded changed from {prev_date} to {date}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    args = ap.parse_args(argv)
    with open(args.old, encoding="utf-8") as f:
        old = entries(json.load(f))
    with open(args.new, encoding="utf-8") as f:
        new = entries(json.load(f))
    problems = date_violations(old, new)
    for p in problems:
        print(f"::error::{p}")
    if problems:
        print(f"\n{len(problems)} dateAdded problem(s). dateAdded is the date a plugin was first "
              f"listed and does not change; if this was a deliberate correction, note it here.")
        return 1
    print("dateAdded: no changes to existing dates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
