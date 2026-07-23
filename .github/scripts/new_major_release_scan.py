"""Major-release plugin check & certification scanner (new-major-release backbone).

For a target FPP major, walks every entry in pluginList.json and, per plugin:
  * evaluates whether any versions[] entry declares compatibility with the major
    (the implicit "certified for FPP <major>" signal - D21),
  * runs the static plugin linter (lint_plugin.py) over its cloned tree,
  * gathers repo metadata (Issues enabled?, archived?, last push) best-effort
    from the GitHub API,
and emits:
  * dashboard.md   - one status row per plugin,
  * issues/<repo>.md - a per-plugin draft tracking-issue body,
  * summary.json   - machine-readable results.

DRY RUN BY DESIGN: this never creates issues and never @-mentions an author.
Maintainer handles are written as plain text (no leading @), so even if a body
were posted by hand nobody is pinged. Real notification is a later, gated step.

Usage:
  new_major_release_scan.py --target-major 10 --plugin-list pluginList.json \
      --plugins-dir <dir-of-clones> --out out/
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

import lib_plugin_schema as lib
from lint_plugin import lint_plugin_dir, BLOCKER, BEST_PRACTICE, OPTIONAL

GUIDELINES = "https://github.com/FalconChristmas/fpp-plugin-Template/blob/master/PLUGIN_GUIDELINES.md"
REMOVAL_FORM = "https://github.com/FalconChristmas/fpp-data/issues/new?template=submit_remove_plugin.yml"
REMOVAL_GUIDED_PAGE = "https://falconchristmas.github.io/fpp-data/submit_remove_plugin/"
SUBMISSION_GUIDED_PAGE = "https://falconchristmas.github.io/fpp-data/submit_new_plugin/"
STALE_MONTHS = 18


def _major(v) -> int | None:
    head = str(v).split(".")[0]
    return int(head) if head.isdigit() else None


def compatible_with_major(versions, m: int) -> bool:
    """Is any versions[] entry certified for FPP major `m`?

    Mirrors the Plugin Manager's own logic (D21): an OPEN-ended max ("0"/""/"0.0")
    only certifies the major the entry was built for - an open entry built for an
    OLDER major shows as "untested" on a newer one, not compatible. A CLOSED range
    certifies `m` when min-major <= m <= max-major.
    """
    for v in versions or []:
        if not isinstance(v, dict):
            continue
        mn = _major(v.get("minFPPVersion")) if v.get("minFPPVersion") else None
        if mn is None:
            continue
        mx = v.get("maxFPPVersion")
        if mx in (None, "", "0", "0.0"):
            if mn == m:            # open-ended: certifies only its own major
                return True
        else:
            mxm = _major(mx)
            if mxm is not None and mn <= m <= mxm:
                return True
    return False


def highest_supported_major(versions) -> int | None:
    """Highest FPP major any versions[] entry certifies for, open- or closed-ended.

    None if there are no usable versions[] entries at all.
    """
    highest = None
    for v in versions or []:
        if not isinstance(v, dict):
            continue
        mn = _major(v.get("minFPPVersion")) if v.get("minFPPVersion") else None
        if mn is None:
            continue
        mx = v.get("maxFPPVersion")
        cand = mn if mx in (None, "", "0", "0.0") else (_major(mx) or mn)
        if highest is None or cand > highest:
            highest = cand
    return highest


def months_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int((datetime.now(timezone.utc) - dt).days / 30)


def load_plugininfo(entry_url, plugin_dir):
    """Prefer the local clone's pluginInfo.json; fall back to the URL."""
    if plugin_dir:
        p = os.path.join(plugin_dir, "pluginInfo.json")
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    return json.load(f), None
            except (OSError, json.JSONDecodeError) as e:
                return None, f"local pluginInfo.json unreadable: {e}"
    if entry_url:
        return lib.fetch_json(entry_url)
    return None, "no pluginInfo source"


def scan_plugin(entry, target, plugins_dir, token, schema):
    name = entry[0]
    info_url = entry[1] if len(entry) > 1 else None
    plugin_dir = os.path.join(plugins_dir, name) if plugins_dir else None
    if plugin_dir and not os.path.isdir(plugin_dir):
        plugin_dir = None

    info, err = load_plugininfo(info_url, plugin_dir)
    info = info or {}
    findings = []          # (severity, code, message)
    if err:
        findings.append((BLOCKER, "plugininfo", err))

    # Schema validation - shared with scan_submission.py (and validate_pluginlist.py's
    # ERROR/WARNING model separately) via lib_plugin_schema.schema_validation_error().
    if info and schema:
        schema_err = lib.schema_validation_error(info, schema)
        if schema_err:
            findings.append((BLOCKER, "schema", schema_err))

    # --- author-requested removal (machine signal / proof-of-control) --------
    # NOTE: "delist" is pluginInfo.schema.json's actual field name (an external
    # contract plugin authors' own repos already use) - do not rename the key itself,
    # only the surrounding prose/identifiers.
    #
    # `is True` on purpose, not `bool(...)`: "delist" has no schema presence
    # (additionalProperties: true), so it could be any JSON type, and bool() on a
    # non-empty STRING is always True regardless of content - a mistaken
    # `"delist": "false"` would `bool()` to True. Same fix as verify_remove_plugin.py.
    removal_requested = info.get("delist") is True
    if removal_requested:
        findings.append((OPTIONAL, "removal-requested",
                         "author set \"delist\": true in pluginInfo.json - plugin removal requested"))

    # --- version compatibility (the primary new-major-release signal) -------
    versions = info.get("versions") or []
    certified = compatible_with_major(versions, target)
    last_major = highest_supported_major(versions)
    if last_major is not None and last_major < target:
        findings.append((BLOCKER, "stale-major",
                         f"Highest FPP major version declared is {last_major}, "
                         f"behind the current target FPP {target}"))

    # --- repo metadata (best-effort) ----------------------------------------
    owner = None
    owner_is_org = False
    maintainer_candidates = []
    meta = {}
    repo = None
    src = lib.parse_github_repo(info.get("srcURL", "") or "")
    if src:
        owner, repo = src
        data, merr = lib.gh_get_repo(owner, repo, token)
        if data:
            meta = data
            findings.extend(lib.repo_metadata_findings(meta, info.get("bugURL", "")))
            # An org login isn't a person - nobody gets notified by mentioning it (an
            # org member has to already be watching the repo). Surface the repo's own
            # top contributors instead, as the individuals actually likely to see this.
            owner_is_org = (meta.get("owner") or {}).get("type") == "Organization"
            if owner_is_org:
                maintainer_candidates = lib.gh_get_maintainer_candidates(owner, repo, token)

    # --- static plugin lint (needs a clone) -----------------------------
    linted = False
    if plugin_dir:
        linted = True
        for f in lint_plugin_dir(plugin_dir, name, info=info):
            findings.append((f.severity, f.code, f.message))

    # --- status --------------------------------------------------------------
    stale = months_since(meta.get("pushed_at"))
    if removal_requested:
        status = "removal-requested"
    elif certified:
        status = "compatible"
    elif meta.get("archived") or (stale is not None and stale >= STALE_MONTHS):
        status = "unmaintained"
    else:
        status = "needs-update"

    num_blocker = sum(1 for s, _, _ in findings if s == BLOCKER)
    num_best_practice = sum(1 for s, _, _ in findings if s == BEST_PRACTICE)
    num_optional = sum(1 for s, _, _ in findings if s == OPTIONAL)
    return {
        "name": name,
        # pluginInfo.json's OWN "name" field - the human-readable title shown on the
        # Plugin Manager card (e.g. "Live Follow"), distinct from `name` above (the
        # repoName, e.g. "fpp-live-follow", used for the issue heading/title). Not
        # every plugin's repoName reads as an obvious display name, so this is worth
        # surfacing separately for a maintainer skimming the issue.
        "display_name": (info.get("name") or "").strip() or None,
        "owner": owner,
        "repo": repo,
        "owner_is_org": owner_is_org,
        "maintainer_candidates": maintainer_candidates,
        "status": status,
        "certified": certified,
        "last_major": last_major,
        # certified only means "declares a versions[] entry for the target major" -
        # it says nothing about outstanding findings (schema errors, lint failures,
        # best-practice nits, etc). ready_to_close is the actual gate for auto-closing
        # a tracking issue: declared compatible AND zero findings of ANY severity, not
        # just blockers - a plugin with open best-practice/optional items still has
        # something for the maintainer to see, so the issue should stay open.
        "ready_to_close": (certified and num_blocker == 0
                           and num_best_practice == 0 and num_optional == 0),
        "removal_requested": removal_requested,
        "issues_enabled": meta.get("has_issues"),
        "archived": meta.get("archived"),
        "months_since_push": stale,
        "linted": linted,
        "findings": findings,
        "num_blocker": num_blocker,
        "num_best_practice": num_best_practice,
        "num_optional": num_optional,
    }


ICON = {"compatible": "✅", "needs-update": "🔧", "unmaintained": "💤",
        "removal-requested": "🗑️"}


def issue_body(r, target, draft=True, mention_owner=False):
    L = []
    L.append(f"<!-- plugin:{r['name']} new_major_release:fpp{target} -->")
    if draft:
        L.append(f"> **DRY RUN - draft only. The maintainer has NOT been notified.**")
        L.append("")
    L.append(f"## {r['name']} - FPP {target} readiness")
    if r.get("display_name") and r["display_name"] != r["name"]:
        L.append(f"Plugin name: {r['display_name']}")
    if r.get("owner") and r.get("repo"):
        L.append(f"Repo: https://github.com/{r['owner']}/{r['repo']}")
    if r["owner"]:
        # mention_owner is opt-in (workflow input) and only takes effect on real,
        # non-draft issues - draft bodies (uploaded as a review artifact, never
        # posted) always stay plain text so a reviewer can't accidentally trigger
        # a notification by pasting one into GitHub by hand.
        do_mention = mention_owner and not draft
        mention = "not @-mentioned in this dry run" if draft else (
            "not @-mentioned automatically" if not mention_owner else None)
        if r.get("owner_is_org"):
            # An org login isn't a person - @-mentioning it doesn't notify anyone
            # who isn't already watching the repo. maintainer_candidates
            # (lib.gh_get_maintainer_candidates) are backed by PR merged_by evidence -
            # authoritative regardless of merge strategy, and never include someone
            # proven NOT to have access (their own PR here was merged by someone
            # else) - but fpp-data-ci's token still has no standing to query real
            # collaborator permissions on a repo it doesn't own, so this is strong
            # evidence, not a literal permissions check. Even with mention_owner on,
            # we only @-mention individuals we have this evidence for, never the org
            # login itself.
            if r.get("maintainer_candidates"):
                if do_mention:
                    names = ", ".join(f"@{c}" for c in r["maintainer_candidates"])
                    L.append(f"Maintainer: `{r['owner']}` org. Confirmed committers: {names}")
                else:
                    names = ", ".join(f"`{c}`" for c in r["maintainer_candidates"])
                    L.append(f"Maintainer: `{r['owner']}` org (org mentions don't reliably notify anyone). "
                             f"Confirmed committers: {names} *({mention})*")
            else:
                L.append(f"Maintainer: `{r['owner']}` org (no individual maintainer could be identified) "
                         f"*({mention})*")
        elif do_mention:
            L.append(f"Maintainer: @{r['owner']}")
        else:
            L.append(f"Maintainer: `{r['owner']}` (https://github.com/{r['owner']}) *({mention})*")
    L.append("")
    L.append(f"> ℹ️ FPP's plugin **submission** and **removal** process has been streamlined - see the "
             f"[Plugin Guidelines]({GUIDELINES}) for what's expected of a listed plugin. Adding another "
             f"plugin? Start at [Submit a plugin]({SUBMISSION_GUIDED_PAGE}).")
    L.append("")
    if r["status"] == "unmaintained":
        push = f"{r['months_since_push']} months" if r["months_since_push"] is not None else "a long time"
        L.append(f"> 💤 No activity in {push} - if you'd like to remove this plugin instead of "
                 f"updating it, start at [Request Plugin Removal]({REMOVAL_GUIDED_PAGE}) and we'll "
                 f"remove it from the list, no update needed.")
        L.append("")
    L.append(f"As part of this new process, in the lead up to each new version release we will create "
             f"a GitHub issue like this one and ask that you review compatibility of your plugin with "
             f"the new version and outline any new best practices for plugins. Please review this "
             f"information and update your plugin accordingly.")
    L.append("")
    # compatibility
    if r["certified"]:
        L.append(f"### ✅ Compatibility\nA `versions[]` entry already declares FPP {target} support.")
    else:
        L.append(f"### 🔧 Please declare FPP {target} compatibility")
        L.append(f"**Please start testing `{r['name']}` on FPP {target}** if you haven't already, then add "
                 f"a `versions[]` entry to your `pluginInfo.json` once it's confirmed working:")
        L.append("```json\n{\n"
                 f'    "minFPPVersion": "{target}.0",\n'
                 '    "maxFPPVersion": "0",\n'
                 '    "branch": "master",\n'
                 '    "sha": ""\n}\n```')
        L.append(f"Until then the Plugin Manager shows your plugin as *untested with FPP {target}*.")
    L.append("")
    # findings
    if r["findings"]:
        L.append("### Areas of concern / optimisation")
        order = {BLOCKER: 0, BEST_PRACTICE: 1, OPTIONAL: 2}
        badge = {BLOCKER: "🛑", BEST_PRACTICE: "⚠️", OPTIONAL: "💡"}
        label = {BLOCKER: "Blocker", BEST_PRACTICE: "Best practice", OPTIONAL: "Optional"}
        for sev, code, msg in sorted(r["findings"], key=lambda f: order.get(f[0], 3)):
            L.append(f"- {badge.get(sev, '')} **{label.get(sev, sev)} - {code}** - {msg}")
        L.append("")
    L.append(f"If you disagree with the assessment, please comment `/submit` and explain why you "
             f"disagree or believe your plugin deserves an exception, for the FPP maintainers to evaluate.")
    L.append("")
    L.append(f"Once you have updated your plugin, please comment `/recheck` on this issue and we will "
             f"automatically scan your plugin and comment the new results here.")
    L.append("")
    L.append(f"Want to sunset this plugin? [Request Plugin Removal]({REMOVAL_GUIDED_PAGE})")
    return "\n".join(L)


def build_dashboard(results, target):
    total = len(results)
    by = lambda s: sum(1 for r in results if r["status"] == s)
    L = [f"# FPP {target} plugin readiness - {datetime.now(timezone.utc):%Y-%m-%d}",
         "",
         f"{total} plugins · ✅ {by('compatible')} compatible · "
         f"🔧 {by('needs-update')} need update · 💤 {by('unmaintained')} unmaintained",
         "",
         "| Plugin | Status | FPP-compat | Issues | Last push | 🛑 Blocker | ⚠️ Best practice | 💡 Optional |",
         "|---|---|---|---|---|--:|--:|--:|"]
    for r in sorted(results, key=lambda r: (r["status"] != "needs-update", r["name"].lower())):
        issues = {True: "on", False: "**off**", None: "?"}[r["issues_enabled"]]
        push = f"{r['months_since_push']}mo" if r["months_since_push"] is not None else "?"
        L.append(f"| {r['name']} | {ICON.get(r['status'], '')} {r['status']} | "
                 f"{'yes' if r['certified'] else 'no'} | {issues} | {push} | "
                 f"{r['num_blocker'] or ''} | {r['num_best_practice'] or ''} | {r['num_optional'] or ''} |")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-major", type=int, required=True)
    ap.add_argument("--plugin-list", default="pluginList.json")
    ap.add_argument("--plugins-dir", default=None, help="dir of cloned plugins (named by repoName)")
    ap.add_argument("--schema", default=None, help="pluginInfo.schema.json (omit to skip schema validation)")
    ap.add_argument("--out", default="out")
    ap.add_argument("--limit", type=int, default=0, help="scan only first N (testing)")
    ap.add_argument("--only-owner", default="", help="scan only plugins owned by this GitHub account (case-insensitive)")
    ap.add_argument("--mention-owner", action="store_true",
                     help="@-mention the repo owner in real (non-draft) tracking issues, notifying them")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    schema = None
    if args.schema:
        with open(args.schema, encoding="utf-8") as f:
            schema = json.load(f)
    entries = lib.load_pluginlist(args.plugin_list)
    entries = lib.filter_by_owner(entries, args.only_owner)
    if args.limit:
        entries = entries[: args.limit]

    os.makedirs(os.path.join(args.out, "issues"), exist_ok=True)
    results = []
    for entry in entries:
        r = scan_plugin(entry, args.target_major, args.plugins_dir, token, schema)
        results.append(r)
        with open(os.path.join(args.out, "issues", f"{r['name']}.md"), "w", encoding="utf-8") as f:
            f.write(issue_body(r, args.target_major))
        print(f"{ICON.get(r['status'],'')} {r['name']:34} {r['status']:13} "
              f"B{r['num_blocker']} P{r['num_best_practice']} O{r['num_optional']}"
              f"{'' if r['linted'] else '  (no clone - metadata only)'}")

    with open(os.path.join(args.out, "dashboard.md"), "w", encoding="utf-8") as f:
        f.write(build_dashboard(results, args.target_major))
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump({"target_major": args.target_major, "mention_owner": args.mention_owner,
                   "plugins": results}, f, indent=2)
    print(f"\nWrote {args.out}/dashboard.md, {len(results)} issue drafts, summary.json")


if __name__ == "__main__":
    main()
