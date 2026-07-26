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

## Removing a plugin

Start at [**Request Plugin Removal**](https://falconchristmas.github.io/fpp-data/submit_remove_plugin/). Existing installs are unaffected; the entry is just removed from `pluginList.json`.

## Changing a plugin's category

Start at [**Request Category Change**](https://falconchristmas.github.io/fpp-data/change_plugin_category/), which lets you pick a new category from the canonical list in `pluginCategories.json`.
