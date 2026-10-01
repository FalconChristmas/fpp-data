"""Unit tests for the pluginList.json tooling's handling of the 4th element,
dateAdded. Run from this directory:
    python3 -m unittest test_pluginlist_tools
"""
from __future__ import annotations

import contextlib
import datetime
import io
import json
import os
import sys
import unittest

import jsonschema

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import add_plugin_entry as A  # noqa: E402
import change_plugin_category as C  # noqa: E402
import check_listing_dates as D  # noqa: E402
import remove_plugin_entry as R  # noqa: E402
import validate_pluginlist as V  # noqa: E402

URL = "https://raw.githubusercontent.com/o/r/master/pluginInfo.json"
TODAY = datetime.date(2026, 10, 1)


def list_schema() -> dict:
    with open(os.path.join(HERE, "..", "schema", "pluginList.schema.json"), encoding="utf-8") as f:
        return json.load(f)


class ListSchema(unittest.TestCase):
    def ok(self, *entries) -> bool:
        try:
            jsonschema.validate({"pluginList": list(entries)}, list_schema(),
                                format_checker=jsonschema.FormatChecker())
            return True
        except jsonschema.ValidationError:
            return False

    def test_all_four_elements_required(self):
        self.assertTrue(self.ok(["a", URL, "Audio", "2024-01-31"]))
        self.assertFalse(self.ok(["a", URL]))
        self.assertFalse(self.ok(["a", URL, "Audio"]))

    def test_rejects_bad_date_shape(self):
        for bad in ("2024-1-31", "31/01/2024", "2024-01-31T00:00:00Z", "2024-01-31\n",
                    "\uff12\uff10\uff12\uff14-01-31", "2025-02-30"):
            self.assertFalse(self.ok(["a", URL, "Audio", bad]), repr(bad))

    def test_rejects_5_elements(self):
        self.assertFalse(self.ok(["a", URL, "Audio", "2024-01-31", "x"]))

    def test_current_pluginlist_still_valid(self):
        with open(os.path.join(HERE, "..", "..", "pluginList.json"), encoding="utf-8") as f:
            jsonschema.validate(json.load(f), list_schema(), format_checker=jsonschema.FormatChecker())


class ParseDate(unittest.TestCase):
    def test_strict_iso(self):
        self.assertEqual(D.parse_date_added("2024-02-29")[0], datetime.date(2024, 2, 29))
        for bad in ("2025-02-29", "\u0662\u0660\u0662\u0664-01-01", "\uff12\uff10\uff12\uff14-01-01",
                    "2024-01-01\n", " 2024-01-01", "2024-01-01 ", 20240101, None):
            self.assertIsNotNone(D.parse_date_added(bad)[1], repr(bad))

    def test_one_day_ahead_of_utc_is_allowed(self):
        self.assertIsNone(D.date_error("2026-10-02", TODAY))
        self.assertIn("future", D.date_error("2026-10-03", TODAY))


class DateRules(unittest.TestCase):
    def run_check(self, head, base, targets="auto"):
        if targets == "auto":
            targets = V.changed_repo_names(head, base)
        report = V.Report()
        V.check_dates(head, base, targets, report, today=TODAY)
        return [(f.level, f.entry) for f in report.findings], report

    def test_new_entry_needs_date(self):
        base = [["old", URL, "Audio", "2020-01-01"]]
        got, _ = self.run_check(base + [["new", URL, "Audio"]], base)
        self.assertEqual(got, [(V.ERROR, "new")])

    def test_new_entry_with_date_passes(self):
        base = [["old", URL, "Audio", "2020-01-01"]]
        got, _ = self.run_check(base + [["new", URL, "Audio", "2026-10-01"]], base)
        self.assertEqual(got, [])

    def test_bad_calendar_date(self):
        got, r = self.run_check([["new", URL, "Audio", "2025-02-30"]], [])
        self.assertEqual(got, [(V.ERROR, "new")])
        self.assertIn("real calendar date", r.findings[0].message)

    def test_bad_shape_date(self):
        got, _ = self.run_check([["new", URL, "Audio", "2025-2-3"]], [])
        self.assertEqual(got, [(V.ERROR, "new")])

    def test_future_date(self):
        got, _ = self.run_check([["new", URL, "Audio", "2026-10-02"]], [])
        self.assertEqual(got, [])   # a day ahead of UTC: someone's local date
        got, r = self.run_check([["new", URL, "Audio", "2026-10-03"]], [])
        self.assertEqual(got, [(V.ERROR, "new")])
        self.assertIn("future", r.findings[0].message)

    def test_changed_date_is_error(self):
        base = [["p", URL, "Audio", "2020-05-01"]]
        got, r = self.run_check([["p", URL, "Show", "2021-05-01"]], base)
        self.assertEqual(got, [(V.ERROR, "p")])
        self.assertIn("must not change", r.findings[0].message)

    def test_date_only_correction_is_a_warning(self):
        base = [["p", URL, "Audio", "2020-05-01"], ["q", URL, "Audio", "2020-06-01"]]
        got, r = self.run_check([["p", URL, "Audio", "2019-05-01"], base[1]], base)
        self.assertEqual(got, [(V.WARNING, "p")])
        self.assertIn("maintainer must confirm", r.findings[0].message)
        # ...but not when the same PR changes anything else.
        got, _ = self.run_check([["p", URL, "Audio", "2019-05-01"], ["q", URL, "Show", "2020-06-01"]], base)
        self.assertEqual(got, [(V.ERROR, "p")])

    def test_removed_date_is_error(self):
        base = [["p", URL, "Audio", "2020-05-01"]]
        got, _ = self.run_check([["p", URL, "Audio"]], base)
        self.assertEqual(got, [(V.ERROR, "p")])

    def test_case_change_keeps_the_date(self):
        base = [["fpp-Foo", URL, "Audio", "2015-01-01"]]
        got, _ = self.run_check([["fpp-foo", URL, "Audio", "2026-09-30"]], base)
        self.assertEqual(got, [(V.ERROR, "fpp-foo")])
        got, _ = self.run_check([["fpp-foo", URL, "Audio", "2015-01-01"]], base)
        self.assertEqual(got, [])

    def test_category_change_keeping_date_passes(self):
        base = [["p", URL, "Audio", "2020-05-01"]]
        got, _ = self.run_check([["p", URL, "Show", "2020-05-01"]], base)
        self.assertEqual(got, [])

    def test_missing_date_on_existing_entry_is_error(self):
        base = [["p", URL, "Audio"]]
        got, _ = self.run_check([["p", URL, "Show"]], base)
        self.assertEqual(got, [(V.ERROR, "p")])

    def test_backfill_adding_dates_passes(self):
        base = [["p", URL, "Audio"], ["q", URL, "Show"]]
        got, _ = self.run_check([["p", URL, "Audio", "2019-12-01"], ["q", URL, "Show", "2014-07-24"]], base)
        self.assertEqual(got, [])

    def test_untouched_bad_date_warns(self):
        base = [["p", URL, "Audio", "2025-02-30"], ["q", URL, "Audio", "2020-01-01"]]
        got, _ = self.run_check(list(base), base)
        self.assertEqual(got, [(V.WARNING, "p")])

    def test_bulk_change_still_catches_changed_date(self):
        # A PR that rewrites every entry: a date already set stays immutable.
        base = [["p", URL, "Audio"], ["q", URL, "Audio", "2020-01-01"]]
        head = [["p", URL, "Show", "2018-03-03"], ["q", URL, "Audio", "2020-01-02"]]
        got, _ = self.run_check(head, base)
        self.assertEqual(got, [(V.ERROR, "q")])

    def test_shape_must_be_4(self):
        for entry in (["p", URL, "Audio"], ["p", URL, "Audio", "2020-01-01", "x"]):
            r = V.Report()
            V.validate_entry(entry, set(), {}, None, True, r)
            self.assertEqual([(f.level, f.message.startswith("entry must be a 4-element"))
                              for f in r.findings], [(V.ERROR, True)], entry)


class PushGuard(unittest.TestCase):
    """check_listing_dates.date_violations, run on every push to master."""

    def test_violations(self):
        old = [["p", URL, "Audio", "2020-05-01"], ["q", URL, "Audio", "2020-06-01"], ["r", URL, "Audio", "2020-07-01"]]
        new = [["P", URL, "Audio", "2020-05-01"], ["q", URL, "Audio", "2021-06-01"], ["r", URL, "Audio"],
               ["s", URL, "Audio", "2026-13-01"]]
        got = D.date_violations(old, new, TODAY)
        self.assertEqual(len(got), 3, got)
        self.assertTrue(got[0].startswith("q: dateAdded changed"))
        self.assertTrue(got[1].startswith("r: dateAdded 2020-07-01 was removed"))
        self.assertTrue(got[2].startswith("s: dateAdded"))
        self.assertEqual(D.date_violations(old, old + [["t", URL, "Audio", "2026-10-01"]], TODAY), [])

    def test_main_exit_code(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for n, lst in (("old", [["p", URL, "Audio", "2020-05-01"]]), ("new", [["p", URL, "Audio", "2020-05-02"]])):
                paths.append(os.path.join(tmp, n + ".json"))
                with open(paths[-1], "w", encoding="utf-8") as f:
                    json.dump({"pluginList": lst}, f)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(D.main(["--old", paths[0], "--new", paths[1]]), 1)
                self.assertEqual(D.main(["--old", paths[0], "--new", paths[0]]), 0)


class BaseFile(unittest.TestCase):
    def test_unreadable_base_is_an_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            head, base, out = (os.path.join(tmp, n) for n in ("head.json", "base.json", "out.md"))
            with open(head, "w", encoding="utf-8") as f:
                json.dump({"pluginList": []}, f)
            open(base, "w").close()   # what a failed `git show ... > base` leaves behind
            argv = ["validate_pluginlist.py", "--pluginlist", head, "--categories",
                    os.path.join(HERE, "..", "..", "pluginCategories.json"),
                    "--schema-dir", os.path.join(HERE, "..", "schema"), "--base", base, "--output", out]
            old = sys.argv
            try:
                sys.argv = argv
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(V.main(), 1)
            finally:
                sys.argv = old
            with open(out, encoding="utf-8") as f:
                self.assertIn("could not read the base branch", f.read())


SAMPLE = """{
        "pluginList": [
            [ "fpp-a", "https://raw.githubusercontent.com/o/fpp-a/master/pluginInfo.json", "Audio" ],
            [ "fpp-b", "https://raw.githubusercontent.com/o/fpp-b/master/pluginInfo.json", "Audio", "2021-07-04" ],
            [ "fpp-c", "https://raw.githubusercontent.com/o/fpp-c/master/pluginInfo.json", "Show", "2022-01-02" ]
        ]
}
"""


class AddEntry(unittest.TestCase):
    def test_writes_given_date(self):
        out = A.insert_entry(SAMPLE, "fpp-d", URL, "Audio", "2026-10-01")
        self.assertIn(f'            [ "fpp-d", "{URL}", "Audio", "2026-10-01" ]\n', out)
        self.assertEqual(json.loads(out)["pluginList"][-1], ["fpp-d", URL, "Audio", "2026-10-01"])

    def test_defaults_to_today_utc(self):
        before = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        out = A.insert_entry(SAMPLE, "fpp-d", URL, "Audio")
        after = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        self.assertIn(json.loads(out)["pluginList"][-1][3], (before, after))


class ChangeCategory(unittest.TestCase):
    def test_keeps_date_on_middle_entry(self):
        out, old, err = C.change_category(SAMPLE, "fpp-b", "Show")
        self.assertIsNone(err)
        self.assertEqual(old, "Audio")
        self.assertIn('"Show", "2021-07-04" ],\n', out)
        self.assertEqual(json.loads(out)["pluginList"][1][2:], ["Show", "2021-07-04"])

    def test_keeps_date_on_last_entry(self):
        out, old, err = C.change_category(SAMPLE, "fpp-c", "Audio")
        self.assertIsNone(err)
        self.assertEqual(json.loads(out)["pluginList"][2][2:], ["Audio", "2022-01-02"])

    def test_three_element_entry_still_works(self):
        out, old, err = C.change_category(SAMPLE, "fpp-a", "Show")
        self.assertIsNone(err)
        self.assertEqual(json.loads(out)["pluginList"][0], ["fpp-a", "https://raw.githubusercontent.com/o/fpp-a/master/pluginInfo.json", "Show"])

    def test_only_category_line_changes(self):
        out, _, _ = C.change_category(SAMPLE, "fpp-b", "Show")
        diff = [(a, b) for a, b in zip(SAMPLE.splitlines(), out.splitlines()) if a != b]
        self.assertEqual(len(diff), 1)


class RemoveEntry(unittest.TestCase):
    def test_remove_last_dated_entry_keeps_valid_json(self):
        out, err = R.remove_entry(SAMPLE, "fpp-c")
        self.assertIsNone(err)
        self.assertEqual(json.loads(out)["pluginList"][-1][3], "2021-07-04")


if __name__ == "__main__":
    unittest.main()
