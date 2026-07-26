# Plugin Guidelines

Everything you need to know to get your plugin listed in FPP's Plugin Manager -
and to keep it there. Inclusion is at the FPP developers' discretion and is
**not guaranteed**. Due to the increasing number of AI-generated plugins, please
read this carefully before submitting.

Building the plugin itself is covered elsewhere - see
[fpp-plugin-Template](https://github.com/FalconChristmas/fpp-plugin-Template)'s
[`PLUGIN_GUIDELINES.md`](https://github.com/FalconChristmas/fpp-plugin-Template/blob/master/PLUGIN_GUIDELINES.md)
(how a plugin should behave) and
[`PLUGININFO_FORMAT.md`](https://github.com/FalconChristmas/fpp-plugin-Template/blob/master/PLUGININFO_FORMAT.md)
(the `pluginInfo.json` metadata format). This document only covers this repo's
own rules and data format.

---

## Before you submit

- **Announce your plugin** to the FPP community (via the
  [FPP Facebook group](https://www.facebook.com/groups/1554782254796752)) and
  consider feedback before submitting.
- **Test it** on the latest released FPP **and** the current nightly build.
- **Include a license** in your repository.
- **Avoid subscription-locked features** - plugins that require a paid
  subscription to unlock functionality are discouraged.
- **Follow FPP's UI conventions and general Linux best practice** - safe shell
  scripting, no dangerous host commands (`reboot`, `sudo`, `curl | bash`),
  correct logging, and only installing/enabling what the target hardware can
  actually support. These are enforced in detail by the plugin check, not
  just suggested - see `PLUGIN_GUIDELINES.md`'s UI, Menu entries, Logging, and
  "Don't destabilize the host" sections, and `PLUGININFO_FORMAT.md`'s
  resource-hints / `platforms` sections, for exactly what's expected and how to
  declare it.

## After you submit a plugin

Within a minute or two, an automated plugin check runs and comments on your issue:

**Plugin check** - clones your repo and runs the automated checks. Findings show up on the issue as:
- 🛑 **Blocker** - must be fixed before the check passes.
- ⚠️ **Best practice** - also must be fixed for a first-time submission
  (already-listed plugins get more leeway here; yours doesn't yet).
- 💡 **Optional** - won't block your listing, but please fix these too where
  you can - they're small polish items (license, README, icon, `bugURL`, ...)
  that make your plugin nicer to use and easier for maintainers to review.

If the check reports Blocker or Best practice findings, push a fix to your repo
and comment `/recheck` on the issue (no need to edit the issue itself) to re-run
it. If you disagree with a finding, comment `/submit` instead to ask a maintainer
to look anyway.

Once the check passes (or you `/submit` over it), this automatically opens a
listing Pull Request adding your plugin to FPP's plugin list. A maintainer
still reviews it by hand - category fit - before merging. Once merged, your
plugin appears in everyone's Plugin Manager.

## After your plugin is listed

- From time to time and especially leading up to new FPP version releases, a new automated plugin check will be run on your plugin. An issue will be created in
  the fpp-data repo and tag you in it for you to review and make the required changes.
- Plugins that are not updated and maintained will be flagged for potential removal.
- The FPP developers reserve the right to remove any plugin from the list at any
  time, with or without notice for any reason.
