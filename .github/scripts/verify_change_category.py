"""Verify + prep a Request Plugin Category Change issue.

Runs when a `category-change-request` issue is opened/edited. GitHub has already
AUTHENTICATED the issue author, so ISSUE_AUTHOR is their real login - the job is to
decide whether that login owns the named plugin's repo, and whether the requested
category is even a real change.

Verdicts:
  verified        - issue author == the repo owner parsed from the plugin's registered
                     pluginInfo.json URL (personal repo).
  unconfirmed     - repo is org-owned or the author isn't the owner. Unlike removal's
                     delist:true, there's no self-proof field for this one - but unlike
                     removal, that's fine here: change-category-verify.yml opens a PR
                     either way (verified or unconfirmed), never a direct commit, so a
                     maintainer always makes the actual call. This verdict only changes
                     what the PR body says about ownership, not whether one gets opened.
  not_found       - the named repoName isn't in pluginList.json at all.
  same_category   - the requested category already matches what's on file; nothing to do.
  unknown_category- the "New category" value isn't one of pluginCategories.json's
                     longNames. Shouldn't happen from the real dropdown - this is a
                     backstop for a hand-edited issue body or a stale form.
  error           - couldn't resolve the plugin/repo for some other reason. Two
                     flavors: transient (pluginInfo.json fetch failed - just needs a
                     `/recheck`) and structural (can't determine owner/repo at all).

Reads ISSUE_AUTHOR and ISSUE_BODY from the environment. Writes a Markdown comment to
--output and the verdict + related fields to $GITHUB_OUTPUT.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_plugin_schema as lib  # noqa: E402

field = lib.field


def resolve_repo_name_field(body: str) -> str:
    return lib.resolve_repo_name(field(body, "Plugin repoName") or field(body, "repoName"))


def find_duplicate_change_issues(repo_name: str, current_issue: str, gh_repo: str, token) -> list[int]:
    """Other OPEN category-change-request issues asking about the same repoName
    (case-insensitive, matching resolve_owner()'s own casing tolerance)."""
    dupes = []
    for issue in lib.list_open_issues(gh_repo, "category-change-request", token):
        if str(issue.get("number")) == str(current_issue):
            continue
        other_name = resolve_repo_name_field(issue.get("body") or "")
        if other_name and other_name.lower() == repo_name.lower():
            dupes.append(issue["number"])
    return dupes


def resolve_owner(repo_name: str, plugin_list_path: str, token):
    """(owner, repo, current_category, error, not_found, transient) for a listed plugin.

    Mirrors verify_remove_plugin.py's resolve_owner() but drops the delist-flag and
    archived-implies-verified branches - neither maps onto "who may recategorize this"
    the way they map onto "who may delist this". owner/repo come from the plugin's OWN
    registered infoURL (entry[1]) first, same trust reasoning as removal: we just
    fetched `info` from that URL successfully, so it's a link we already trust, rather
    than depending on the author having filled in srcURL correctly.
    """
    for entry in lib.load_pluginlist(plugin_list_path):
        if entry and entry[0].lower() == repo_name.lower():
            info_url = entry[1] if len(entry) > 1 else ""
            current_category = entry[2] if len(entry) > 2 else ""
            info, err = lib.fetch_json(info_url)
            if err:
                return None, None, current_category, f"couldn't fetch pluginInfo.json: {err}", False, True
            info = info or {}
            src = lib.parse_raw_github_repo(info_url) or lib.parse_github_repo(info.get("srcURL", "") or "")
            if not src:
                return None, None, current_category, \
                    "couldn't determine the plugin's GitHub owner/repo from its listing", False, False
            owner, repo = src
            return owner, repo, current_category, None, False, False
    return None, None, "", f"'{repo_name}' is not in pluginList.json", True, False


def field_block(repo_name: str, current_category: str = "", new_category: str = "",
                 owner: str | None = None, repo: str | None = None) -> str:
    lines = [f"**Plugin:** {repo_name}"]
    if current_category:
        lines.append(f"**Current category:** {current_category}")
    if new_category:
        lines.append(f"**Requested category:** {new_category}")
    if owner and repo:
        lines.append(f"**Repo:** https://github.com/{owner}/{repo}")
        lines.append(f"**Owner:** `{owner}`")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-list", default="pluginList.json")
    ap.add_argument("--categories", default="pluginCategories.json")
    ap.add_argument("--output", default="category-verify.md")
    ap.add_argument("--gh-repo", default=None, help="owner/repo this issue lives in, for duplicate-request detection")
    ap.add_argument("--current-issue", default=None)
    args = ap.parse_args()

    author = (os.environ.get("ISSUE_AUTHOR") or "").strip()
    body = os.environ.get("ISSUE_BODY") or ""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo_name = resolve_repo_name_field(body)
    new_category_long = (field(body, "New category") or "").strip()
    # "Are you the plugin's author/maintainer?" is NOT read here, same reasoning as
    # verify_remove_plugin.py's identical field: it's a self-declaration for a human
    # reader, not a signal this script acts on. Ownership is always verified the same
    # way regardless of the answer.

    owner = None
    repo = None
    new_category_short = ""
    if not repo_name:
        verdict, msg = "error", "Could not read a **Plugin repoName** from the form."
    else:
        owner, repo, current_category, err, not_found, transient = resolve_owner(
            repo_name, args.plugin_list, token)
        cat_map = lib.load_category_map(args.categories)
        if not_found:
            verdict, msg = "not_found", (
                f"{field_block(repo_name)}\n\n"
                f"`{repo_name}` is not currently listed in `pluginList.json`, so there's no entry to "
                f"recategorize.")
        elif transient:
            verdict, msg = "error", (
                f"{field_block(repo_name)}\n\n"
                f"Could not verify this right now: {err}\n\n"
                f"This is likely transient - comment `/recheck` in a bit and we'll try again. No "
                f"need to open a new issue.")
        elif err:
            verdict, msg = "error", (
                f"{field_block(repo_name)}\n\n"
                f"Could not verify this: {err}\n\n"
                f"Fixed the repoName (typo, casing, etc.)? Edit this issue's description with the "
                f"correct value and we'll automatically re-check - no need to open a new issue.")
        elif not new_category_long or new_category_long not in cat_map:
            verdict, msg = "unknown_category", (
                f"{field_block(repo_name, current_category)}\n\n"
                f"`{new_category_long or '(empty)'}` isn't one of the recognized categories. Edit "
                f"this issue's description and pick one from the **New category** dropdown, then "
                f"comment `/recheck`.")
        elif cat_map[new_category_long] == current_category:
            new_category_short = cat_map[new_category_long]
            verdict, msg = "same_category", (
                f"{field_block(repo_name, current_category, new_category_long)}\n\n"
                f"`{repo_name}` is already filed under **{new_category_long}** - nothing to change.")
        else:
            new_category_short = cat_map[new_category_long]
            if author and owner and author.lower() == owner.lower():
                verdict, msg = "verified", (
                    f"{field_block(repo_name, current_category, new_category_long, owner, repo)}\n\n"
                    f"✅ Ownership confirmed: **@{author}** is the owner. Opening a pull request to "
                    f"apply this - a maintainer still needs to merge it.")
            else:
                verdict, msg = "unconfirmed", (
                    f"{field_block(repo_name, current_category, new_category_long, owner, repo)}\n\n"
                    f"⚠️ **@{author}** is not the direct owner (it may be org-owned). Opening a pull "
                    f"request anyway, noting that ownership could not be automatically confirmed - a "
                    f"maintainer will decide whether to merge it.")

    dupes: list[int] = []
    if repo_name and args.gh_repo and args.current_issue:
        dupes = find_duplicate_change_issues(repo_name, args.current_issue, args.gh_repo, token)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"### Plugin category-change check - `{verdict}`\n\n{msg}\n")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"verdict={verdict}\n")
            f.write(f"repo_name={repo_name}\n")
            f.write(f"owner={owner or ''}\n")
            f.write(f"repo={repo or ''}\n")
            f.write(f"new_category={new_category_short}\n")
            f.write(f"new_category_long={new_category_long}\n")
            f.write(f"duplicate_issues={','.join(str(n) for n in dupes)}\n")
    print(f"{verdict}: {msg}")


if __name__ == "__main__":
    main()
