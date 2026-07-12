# FPP Plugin Submission Guidelines

This repository holds `pluginList.json`, the master index of community plugins
shown in FPP's Plugin Manager. Each entry is a `[ name, pluginInfo-URL ]` pair
pointing at your plugin's `pluginInfo.json`. To have your plugin listed, submit
a Pull Request adding your entry to `pluginList.json`.

Due to the increasing number of AI-generated plugins, please review the
following guidelines before submitting a Pull Request.

1. **Announce your plugin**
   - Share it with the FPP community on the
     [FPP Facebook group](https://www.facebook.com/groups/1554782254796752).
   - Consider community feedback and address reasonable suggestions before
     submitting your Pull Request.

2. **Test your plugin**
   - Verify it functions correctly on:
     - The latest released version of FPP.
     - The current nightly build.

3. **Follow the FPP user interface conventions**
   - Create no more than **one** menu item in each of the following menus:
     - Status/Control
     - Content Setup
     - Input/Output Setup
     - Help
   - Menu entries should use the name of your plugin.
   - Match the overall FPP look and feel.
   - Preserve the standard FPP top navigation menus and bottom status bar.

4. **Do not impact core FPP functionality**
   - Plugins must not interfere with FPP's core functionality, stability, or
     real-time sequence playback.
   - Keep performance in mind: several supported platforms have very limited
     CPU, memory, and storage. Design and test your plugin so that, even when
     idle, it does not degrade the system.

5. **Only install and run on platforms where it is appropriate**
   - FPP runs across a wide range of hardware with very different capabilities.
     Your plugin should detect the platform it is running on and only install,
     enable, or advertise features that the hardware can actually support.
   - Rough capability tiers to consider:
     - **Low-resource / headless controllers** — BeagleBone Black (BBB),
       PocketBeagle (PB), and older Raspberry Pi models
       (Pi Zero / 1 / 2 / 3). Assume tight CPU, RAM, and flash. Heavyweight
       plugins (video processing, large web UIs, extra background services)
       generally should **not** install here, or should install in a
       reduced/disabled state.
     - **Capable single-board computers** — Raspberry Pi 4 / Pi 5. Suitable for
       most plugins, but still avoid interfering with playback.
     - **Desktop / development targets** — FPP also builds and installs
       natively on macOS and on a generic Debian (x86_64) PC, and can be run
       inside Docker on macOS, Windows, or Linux. None of these are officially
       "supported" (only Raspberry Pi and BeagleBone SBCs are), and they are
       used mainly for development and testing. Ensure your plugin fails
       gracefully (or is hidden) where a feature depends on hardware or GPIO
       that isn't present on a PC, a Mac, or inside a container.
   - If your plugin cannot run correctly on a given platform, it should refuse
     to install cleanly and explain why, rather than installing and breaking.

6. **Avoid subscription-based features**
   - Plugins that require paid subscriptions or recurring fees to unlock plugin
     functionality or related website features are strongly discouraged.

7. **Acceptance is at the discretion of the FPP developers**
   - Inclusion in `pluginList.json` is not guaranteed.
   - The FPP developers reserve the right to reject or remove any plugin from
     the list at any time, with or without notice.

## Submitting an entry

Add a single line to the `pluginList` array in `pluginList.json`, keeping the
existing formatting:

    [ "your-plugin-name", "https://raw.githubusercontent.com/<you>/<your-plugin>/<branch>/pluginInfo.json" ]

Your `pluginInfo.json` declares the plugin metadata and supported FPP versions
via the `versions` array (`minFPPVersion` / `maxFPPVersion`, `branch`, `sha`,
and optional `dependencies`). See
[`fpp-plugin-Template`](https://github.com/FalconChristmas/fpp-plugin-Template)
for a working example.
