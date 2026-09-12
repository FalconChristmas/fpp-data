# fpp-data

This repository is the data backing FPP's Plugin Manager:

- **`pluginList.json`** - the master index of community plugins. Each entry
  points at a plugin's `pluginInfo.json` (hosted in the plugin's own repo),
  which FPP fetches to list, version-check, and install it.
- **`pluginCategories.json`** - the canonical category list plugins can tag
  themselves with.

## Get your plugin listed

Start at **[Submit a plugin](https://falconchristmas.github.io/fpp-data/submit_new_plugin/)**

See **[PLUGINS.md](PLUGINS.md)** for the submission guidelines and what
the automated plugin check covers.

Building the plugin itself? Start at
[fpp-plugin-Template](https://github.com/FalconChristmas/fpp-plugin-Template) -
it has the `pluginInfo.json` format reference, the plugin guidelines, and a
working skeleton to fork.

## Tools for plugin authors

Two browser-only pages (nothing leaves your browser except reads of your own
public repo) that help get `pluginInfo.json` right before you submit:

- [**Privacy declaration builder**](https://falconchristmas.github.io/fpp-data/plugin_privacy_builder/) -
  a guided form that writes the `privacy` block for you. Give it your repo (or
  paste your `pluginInfo.json`) and it pre-fills the plugin name and any block
  you already have, walks through the eight keys one at a time with the same
  wording and rules the plugin check uses, and hands back the block on its own
  or merged into your whole file. Deep link: `?repo=owner/repo`.
- [**Plugin preview**](https://falconchristmas.github.io/fpp-data/plugin_preview/) -
  renders your `pluginInfo.json` exactly as FPP's Plugin Manager will show it:
  the card with its six privacy dots and the install dialog with the headline,
  lights and Install button. It runs FPP's own renderer, so what you see is
  what an FPP user sees. Deep link: `?repo=owner/repo` once the file is
  pushed, or paste the JSON.

The preview only shows what you *declared*. The plugin check that compares the
declaration with your code runs on the submission issue, not in the browser.

## Removing a plugin

Start at [**Request Plugin Removal**](https://falconchristmas.github.io/fpp-data/submit_remove_plugin/). Existing installs are unaffected; the entry is just removed from `pluginList.json`.

## Changing a plugin's category

Start at [**Request Category Change**](https://falconchristmas.github.io/fpp-data/change_plugin_category/), which lets you pick a new category from the canonical list in `pluginCategories.json`.
