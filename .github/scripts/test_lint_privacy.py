"""Tests for lint_plugin.py's privacy rule family and the pluginInfo.schema.json
`privacy` block. Stdlib unittest, synthetic plugin trees in a tempdir, no network.

    cd .github/scripts && python3 test_lint_privacy.py
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lint_plugin as L  # noqa: E402

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema", "pluginInfo.schema.json")

BASE_INFO = {
    "repoName": "fpp-synthetic", "name": "Synthetic", "author": "test", "description": "test plugin",
    "homeURL": "https://github.com/example/fpp-synthetic",
    "srcURL": "https://github.com/example/fpp-synthetic.git",
    "bugURL": "https://github.com/example/fpp-synthetic/issues",
    "versions": [{"minFPPVersion": "9.0", "maxFPPVersion": "0", "branch": "main", "sha": ""}],
}

# A block declaring nothing - the "runs on this device only" plugin.
EMPTY_PRIVACY = {
    "summary": "Runs on this device only.",
    "sends": [], "collects": [], "sensors": [], "remoteAccess": "none", "systemChanges": [],
    "closedCode": False, "other": "none",
}

# A block declaring everything the FULL_PLUGIN_FILES below do.
FULL_PRIVACY = {
    "summary": "Sends visitor SMS to Twilio, checks them with NeutrinoAPI, shows a camera preview.",
    "sends": [
        {"to": "api.twilio.com", "what": "visitor phone numbers and messages", "why": "deliver SMS", "alwaysOn": True},
        {"to": "neutrinoapi.com", "what": "message text", "why": "profanity check", "alwaysOn": False},
        {"to": "cdn.jsdelivr.net", "what": "your browser's IP address", "why": "loads a chart library", "alwaysOn": True},
        {"to": "api.stripe.com", "what": "visitor card payments", "why": "takes payments", "alwaysOn": False},
    ],
    "collects": [{"what": "visitor phone numbers and messages", "about": "visitors", "keptDays": 30, "canDelete": True,
                  "where": "plugindata/fpp-synthetic/db"}],
    "sensors": [{"type": "camera", "stored": False}, {"type": "microphone", "stored": False}],
    "remoteAccess": "lan",
    "systemChanges": [
        {"kind": "package-source", "what": "adds the NodeSource apt source (deb.nodesource.com) for nodejs"},
        {"kind": "download", "what": "downloads a face model from huggingface.co and installs python3-paho-mqtt and requests"},
        {"kind": "download", "what": "updates itself from GitHub at every install"},
        {"kind": "service", "what": "installs and enables fpp-synthetic.service"},
        {"kind": "service", "what": "enables smbd"},
        {"kind": "core-settings", "what": "writes config/gpio.json, the MQTTHost setting and /etc/samba/smb.conf"},
        {"kind": "reads-core-credentials", "what": "reads FPP's MQTT password for the broker"},
        {"kind": "privilege", "what": "adds fpp to the video group"},
    ],
    "closedCode": False,
    "other": "Takes visitor payments through Stripe.",
}

FULL_PLUGIN_FILES = {
    "scripts/fpp_install.sh": """#!/bin/bash
set -e
apt-get install -y python3-paho-mqtt
pip3 install --break-system-packages requests
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
curl -sL -o /home/fpp/media/plugindata/fpp-synthetic/model.bin https://huggingface.co/x/model.bin
cp fpp-synthetic.service /etc/systemd/system/fpp-synthetic.service
systemctl enable --now fpp-synthetic.service
systemctl enable smbd
sed -i 's/^workgroup.*/workgroup = FPP/' /etc/samba/smb.conf
usermod -aG video fpp
git -C /home/fpp/media/plugins/fpp-synthetic pull
""",
    "api.php": """<?php
$ch = curl_init("https://api.twilio.com/2010-04-01/Accounts");
$check = file_get_contents('https://neutrinoapi.com/bad-word-filter?content=' . urlencode($m));
$token = ReadSettingFromFile('TwilioAuthToken', 'fpp-synthetic');
$pw = ReadSettingFromFile('MQTTPassword');
WriteSettingToFile('MQTTHost', $host);
file_put_contents('/home/fpp/media/config/gpio.json', $json);
$stripe = new \\Stripe\\StripeClient($key); $r = file_get_contents("https://api.stripe.com/v1/charges");
""",
    "content.php": """<?php
echo "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>";
echo "<input type='password' name='TwilioAuthToken'>";
$r = file_get_contents("http://localhost/api/system/status");
""",
    "listener.py": """import socket, cv2, pyaudio
cap = cv2.VideoCapture('/dev/video0')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 9000))
""",
}


def write_tree(root: str, files: dict[str, str], info: dict | None) -> None:
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    if info is not None:
        with open(os.path.join(root, "pluginInfo.json"), "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)


def privacy_findings(files: dict[str, str], privacy: dict | None, extra_info: dict | None = None) -> list[L.Finding]:
    info = copy.deepcopy(BASE_INFO)
    if extra_info:
        info.update(extra_info)
    if privacy is not None:
        info["privacy"] = copy.deepcopy(privacy)
    with tempfile.TemporaryDirectory() as tmp:
        write_tree(tmp, files, info)
        return L._privacy_findings(tmp, info, "example")


def codes(findings) -> list[str]:
    return sorted(f.code for f in findings)


class PrivacyMissing(unittest.TestCase):
    def test_no_block_is_one_blocker(self):
        fs = privacy_findings({"content.php": "<?php echo 1;"}, None)
        self.assertEqual([(f.severity, f.code) for f in fs], [(L.BLOCKER, "privacy-missing")])
        self.assertIn("blocks the listing", fs[0].message)

    def test_template_placeholder_is_one_blocker(self):
        # The block fpp-plugin-Template ships: structurally the do-nothing answer,
        # with the placeholder still in summary and other.
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["summary"] = ("TEMPLATE TEXT - replace me. Say what this plugin sends, keeps, senses, opens and "
                         "changes - if truly none of those, write: Runs on this device only.")
        pv["other"] = "TEMPLATE TEXT - replace me (write \"none\" if there is nothing to add)."
        fs = privacy_findings({"content.php": "<?php echo 1;"}, pv)
        self.assertEqual([(f.severity, f.code) for f in fs], [(L.BLOCKER, "privacy-template-text")])
        self.assertIn("`privacy.summary` and `privacy.other`", fs[0].message)
        # Half-edited (only `other` left, different case) still trips it, naming just that key.
        pv["summary"] = "Runs on this device only."
        pv["other"] = "template text - replace me"
        fs = privacy_findings({"content.php": "<?php echo 1;"}, pv)
        self.assertEqual(codes(fs), ["privacy-template-text"])
        self.assertIn("`privacy.other` still", fs[0].message)
        # The honest do-nothing block is clean.
        self.assertEqual(codes(privacy_findings({"content.php": "<?php echo 1;"}, EMPTY_PRIVACY)), [])

    def test_no_pluginInfo_at_all_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, {"content.php": "<?php echo 1;"}, None)
            self.assertEqual(L._privacy_findings(tmp, None, None), [])


class Vocabulary(unittest.TestCase):
    def test_v2_block_is_one_unknown_key_blocker(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["schemaVersion"] = 2
        pv["recipients"] = []
        pv["hostChanges"] = {"services": []}
        fs = privacy_findings({"a.php": "<?php echo 1;"}, pv)
        self.assertEqual([(f.severity, f.code) for f in fs], [(L.BLOCKER, "privacy-unknown-key")])
        self.assertIn("`recipients` (now `sends`)", fs[0].message)
        self.assertIn("`hostChanges`", fs[0].message)

    def test_unknown_key_inside_an_item(self):
        pv = copy.deepcopy(FULL_PRIVACY)
        pv["sends"][1]["policyURL"] = "https://x"
        pv["systemChanges"][0]["reverted"] = True
        fs = [f for f in privacy_findings({"a.php": "<?php echo 1;"}, pv) if f.code == "privacy-unknown-key"]
        self.assertEqual(len(fs), 1)
        self.assertIn("sends[1].policyURL", fs[0].message)
        self.assertIn("systemChanges[0].reverted", fs[0].message)

    def test_length_caps_are_best_practice(self):
        pv = copy.deepcopy(FULL_PRIVACY)
        pv["summary"] = "s" * 201
        pv["sends"][0]["what"] = "w" * 101
        pv["collects"][0]["what"] = "c" * 100  # exactly at the cap: fine
        pv["systemChanges"][0]["what"] = "x" * 121
        fs = privacy_findings({"a.php": "<?php echo 1;"}, pv)
        self.assertEqual([(f.severity, f.code) for f in fs], [(L.BEST_PRACTICE, "privacy-text-length")])
        self.assertIn("summary (201 > 200)", fs[0].message)
        self.assertIn("sends[0].what (101 > 100)", fs[0].message)
        self.assertIn("systemChanges[0].what (121 > 120)", fs[0].message)
        self.assertNotIn("collects[0]", fs[0].message)
        self.assertEqual(codes(privacy_findings({"a.php": "<?php echo 1;"}, FULL_PRIVACY)), [])


class DeclaredMatchesCode(unittest.TestCase):
    def test_full_block_covers_full_plugin(self):
        fs = privacy_findings(FULL_PLUGIN_FILES, FULL_PRIVACY)
        # No contradiction; the only finding is the closedCode: false reviewer nudge
        # for the pip package and the fetched model.bin (best practice, never blocks).
        self.assertEqual([(f.severity, f.code) for f in fs], [(L.BEST_PRACTICE, "privacy-closedcode-unverified")],
                         [f.message for f in fs])

    def test_empty_block_on_quiet_plugin(self):
        files = {"content.php": "<?php\n$r = file_get_contents('http://localhost/api/system/status');\n"
                                "// see https://example.com/docs\n"
                                "echo '<a href=\"https://github.com/example/fpp-synthetic\">home</a>';\n"
                                "$x = ReadSettingFromFile('Mode', 'fpp-synthetic');\n"
                                "$k = ReadSettingFromFile('ApiKey', 'fpp-synthetic');\n",
                 "scripts/fpp_uninstall.sh": "#!/bin/bash\nrm -f /etc/apt/sources.list.d/old.list\nrm -f /etc/sudoers.d/fpp-synthetic\n"
                                            "sudo cp -rf /etc/mpd.conf /home/fpp/media/plugindata/backup.conf\n"}
        fs = privacy_findings(files, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), [], [f.message for f in fs])

    def test_own_repo_and_project_hosts_are_not_recipients(self):
        files = {"scripts/fpp_install.sh": "#!/bin/bash\ncurl -sL https://raw.githubusercontent.com/example/fpp-synthetic/main/x.json -o x.json\n"
                                          "git clone https://github.com/FalconChristmas/fpp-plugin-Template.git /tmp/t\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])

    def test_host_declared_by_registrable_domain_free_text_and_http_prefix(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["sends"] = [{"to": "oauth.zettle.com / pusher.izettle.com and twilio.com", "what": "x", "why": "y", "alwaysOn": False},
                       {"to": "http://api.plainhost.org", "what": "x", "why": "y", "alwaysOn": False}]
        files = {"a.php": "<?php $a = 'https://lookups.twilio.com/v1'; $b = \"https://purchase.izettle.com/x\"; $c = 'http://api.plainhost.org/p';"}
        self.assertEqual(codes(privacy_findings(files, pv)), [])

    def test_phrase_to_covers_operator_entered_destination(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["sends"] = [{"to": "your MQTT broker", "what": "show status", "why": "home automation", "alwaysOn": False}]
        files = {"a.py": "import paho.mqtt.client as mqtt\nc.publish(topic, payload)\n"}
        self.assertEqual(codes(privacy_findings(files, pv)), [])
        # ...but not a literal host: that is a fixed destination the block has to name
        files = {"a.py": "requests.post('https://api.openweathermap.org/data', json=x)\n"}
        self.assertEqual(codes(privacy_findings(files, pv)), ["privacy-undeclared-recipients"])

    def test_generic_download_covers_any_install_fetch(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "download", "what": "downloads a prebuilt binary at install"}]
        files = {"scripts/fpp_install.sh": "#!/bin/bash\nwget -q https://models.vendor-cdn.net/face.bin -O face.bin\n"}
        self.assertEqual(codes(privacy_findings(files, pv)), ["privacy-closedcode-unverified"])  # the nudge only, no contradiction
        pv["systemChanges"] = [{"kind": "download", "what": "downloads a prebuilt binary from other-cdn.net"}]
        self.assertEqual(codes(privacy_findings(files, pv)), ["privacy-closedcode-unverified", "privacy-undeclared-install"])


class Contradictions(unittest.TestCase):
    def one(self, files, pv=EMPTY_PRIVACY, extra_info=None):
        # The closedCode: false reviewer nudge (best practice) is tested on its own
        # below; here only the contradiction matters.
        fs = [f for f in privacy_findings(files, pv, extra_info) if f.code != "privacy-closedcode-unverified"]
        self.assertEqual(len(fs), 1, [f.message for f in fs])
        self.assertEqual(fs[0].severity, L.BLOCKER)
        return fs[0]

    def test_undeclared_recipient(self):
        f = self.one({"a.php": "<?php $r = file_get_contents('https://api.openweathermap.org/data');"})
        self.assertEqual(f.code, "privacy-undeclared-recipients")
        self.assertIn("api.openweathermap.org", f.message)
        self.assertIn("`sends` entry", f.message)

    def test_url_in_prose_is_not_a_recipient(self):
        files = {"a.php": "<?php echo '<p>Try a stream such as https://radio.example-stream.org:8000/radio.mp3 as the URL</p>';"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])

    def test_install_fetch_is_install_category(self):
        f = self.one({"scripts/fpp_install.sh": "#!/bin/bash\nwget -q https://models.vendor-cdn.net/face.bin -O face.bin\n"})
        self.assertEqual(f.code, "privacy-undeclared-install")
        self.assertIn("\"download\"", f.message)

    def test_outbound_helper_with_empty_sends(self):
        f = self.one({"src/Plugin.cpp": "void send() { CurlManager::INSTANCE.add(url, \"POST\", body); }"})
        self.assertEqual(f.code, "privacy-undeclared-recipients")
        self.assertIn("sends nothing", f.message)

    def test_localhost_constant_is_resolved(self):
        files = {"d.py": "HOST = '127.0.0.1'\nPORT = 5003\n_API = 'http://localhost/api/x'\n" + "\n" * 30 +
                         "server = HTTPServer((HOST, PORT), Handler)\n" + "\n" * 30 +
                         "req = urllib.request.Request(_API, data=d)\nurllib.request.urlopen(req, timeout=3)\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])
        files = {"d.py": "HOST = '0.0.0.0'\nPORT = 5003\n" + "\n" * 30 + "server = HTTPServer((HOST, PORT), Handler)\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), ["privacy-undeclared-listeners"])

    def test_outbound_helper_to_localhost_is_fine(self):
        files = {"a.py": "import requests\nurl = 'http://localhost/api/fppd/status'\nr = requests.get(url)\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])

    def test_apt_pip_installs_are_not_downloads(self):
        files = {"scripts/fpp_install.sh": "#!/bin/bash\nsudo apt-get install -y libltc-dev\npip3 install --break-system-packages requests\n"}
        fs = privacy_findings(files, EMPTY_PRIVACY)
        self.assertEqual([f.code for f in fs if f.severity == L.BLOCKER], [])
        self.assertEqual(codes(fs), ["privacy-closedcode-unverified"])  # the pip package gets the reviewer nudge only

    def test_package_source_undeclared(self):
        src = {"scripts/fpp_install.sh": "#!/bin/bash\ncurl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg\n"}
        fs = privacy_findings(src, EMPTY_PRIVACY)
        # two facts: the host fetched at install, and a package source added
        self.assertEqual(codes(fs), ["privacy-undeclared-install", "privacy-undeclared-install"])
        self.assertTrue(any("package source" in f.message and "\"package-source\"" in f.message for f in fs))
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "package-source", "what": "adds an apt source (deb.othervendor.com)"}]
        self.assertEqual(codes(privacy_findings(src, pv)), ["privacy-undeclared-install"])  # a source is declared, but not this host
        pv["systemChanges"][0]["what"] = "adds the NodeSource apt source (deb.nodesource.com)"
        self.assertEqual(codes(privacy_findings(src, pv)), [])
        pv["systemChanges"][0]["what"] = "adds the NodeSource apt source"  # no host named: generic, covers it
        self.assertEqual(codes(privacy_findings(src, pv)), [])

    def test_remote_script(self):
        # two facts: the host fetched at install, and that its output is executed
        fs = privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\ncurl -fsSL https://get.docker.com | sh\n"}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-install", "privacy-undeclared-install"])
        self.assertTrue(any("interpreter" in f.message for f in fs))
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "download", "what": "runs the Docker installer from get.docker.com as root"}]
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\ncurl -fsSL https://get.docker.com | sh\n"}, pv)), [])

    def test_self_update_in_hook(self):
        f = self.one({"scripts/preStart.sh": "#!/bin/bash\ngit -C \"$DIR\" pull --quiet || true\n"})
        self.assertEqual(f.code, "privacy-undeclared-selfupdate")
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "download", "what": "pulls its own latest code from GitHub at install"}]
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\ngit reset --hard origin/main\n"}, pv)), [])
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["other"] = "The install script updates the checkout to the newest commit on the branch."
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\ngit reset --hard origin/main\n"}, pv)), [])

    def test_camera(self):
        f = self.one({"cam.py": "cap = cv2.VideoCapture(0)\n"})
        self.assertEqual(f.code, "privacy-undeclared-sensors")
        self.assertIn("camera", f.message)

    def test_word_whisper_is_not_a_microphone(self):
        self.assertEqual(codes(privacy_findings({"icons.js": 'var names = ["whisper", "wind"];'}, EMPTY_PRIVACY)), [])

    def test_listener_needs_remote_access(self):
        f = self.one({"srv.py": "s.bind(('', 5005))\n"})
        self.assertEqual(f.code, "privacy-undeclared-listeners")
        self.assertIn("5005", f.message)
        for level in ("lan", "internet-authenticated", "internet-open", "exposes-fpp", "tunnel"):
            pv = copy.deepcopy(EMPTY_PRIVACY)
            pv["remoteAccess"] = level
            self.assertEqual(codes(privacy_findings({"srv.py": "s.bind(('', 5005))\n"}, pv)), [], level)
        self.assertEqual(codes(privacy_findings({"srv.py": "s.bind(('127.0.0.1', 5005))\n"}, EMPTY_PRIVACY)), [])

    def test_network_or_tunnel_change_declares_listener(self):
        # A-16: the port may be declared as what was opened (systemChanges) rather
        # than by its reach (remoteAccess); either covers the listener.
        for kind in ("network", "tunnel"):
            pv = copy.deepcopy(EMPTY_PRIVACY)
            pv["systemChanges"] = [{"kind": kind, "what": "opens UDP port 5005 on the LAN"}]
            self.assertEqual(codes(privacy_findings({"srv.py": "s.bind(('', 5005))\n"}, pv)), [], kind)
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "service", "what": "installs a unit"}]
        fs = privacy_findings({"srv.py": "s.bind(('', 5005))\n"}, pv)
        self.assertEqual(codes(fs), ["privacy-undeclared-listeners"])
        self.assertIn("\"network\"", fs[0].message)

    def test_service(self):
        f = self.one({"scripts/fpp_install.sh": "#!/bin/bash\nsystemctl enable --now fpp-synthetic.service\n"})
        self.assertEqual(f.code, "privacy-undeclared-services")
        self.assertIn("fpp-synthetic", f.message)
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "network", "what": "enables fpp-synthetic"}]  # wrong kind does not count
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\nsystemctl enable --now fpp-synthetic.service\n"}, pv)), ["privacy-undeclared-services"])
        pv["systemChanges"][0]["kind"] = "service"
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\nsystemctl enable --now fpp-synthetic.service\n"}, pv)), [])

    def test_cron_job(self):
        f = self.one({"svc.py": "cron = CronTab(user=True)\ncron.write()\n"})
        self.assertEqual(f.code, "privacy-undeclared-services")

    def test_core_setting_write(self):
        f = self.one({"a.php": "<?php WriteSettingToFile('MQTTHost', $h);"})
        self.assertEqual(f.code, "privacy-undeclared-core-config")
        self.assertIn("MQTTHost", f.message)
        # 3-arg form writes the plugin's own file - never a core write
        self.assertEqual(codes(privacy_findings({"a.php": "<?php WriteSettingToFile('MQTTHost', $h, 'fpp-synthetic');"}, EMPTY_PRIVACY)), [])
        self.assertEqual(codes(privacy_findings({"a.php": "<?php WriteSettingToFile('restartFlag', 1);"}, EMPTY_PRIVACY)), [])
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "core-settings", "what": "sets FPP's MQTTHost to the broker you enter"}]
        self.assertEqual(codes(privacy_findings({"a.php": "<?php WriteSettingToFile('MQTTHost', $h);"}, pv)), [])

    def test_etc_write_matches_services_text(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        files = {"scripts/fpp_install.sh": "#!/bin/bash\nln -sf \"$CONF\" /etc/apache2/conf-enabled/fpp-synthetic.conf\n"}
        self.assertEqual(privacy_findings(files, pv)[0].code, "privacy-undeclared-core-config")
        pv["systemChanges"] = [{"kind": "service", "what": "adds an apache2 conf rule"}]
        self.assertEqual(codes(privacy_findings(files, pv)), [])

    def test_etc_path_in_page_prose_is_not_a_write(self):
        # fpp-plugin-RemoteBackup: `<code>/etc/fpp</code>` in a settings-page label -
        # the tag's `>` is not a shell redirect. A real redirect still fires.
        files = {"config.php": "<label>Also back up system config (<code>/etc/fpp</code>, hostname) alongside each backup</label>\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])
        files = {"scripts/fpp_install.sh": "#!/bin/bash\necho 'x' >/etc/fpp/synthetic.conf\n"}
        self.assertEqual(privacy_findings(files, EMPTY_PRIVACY)[0].code, "privacy-undeclared-core-config")

    def test_commands_in_page_prose_are_not_run(self):
        # A command the page SHOWS the operator (Statistics-Fpp-Plugin's mosquitto
        # warning, Dynamic_RDS's dtoverlay help, fpp-zettle's curl|python placeholder)
        # is not one the plugin runs; the same text in exec() or a shell file is.
        prose = {
            "warn.inc.php": '<p>Run <code style="padding:2px">sudo systemctl start mosquitto</code> first.</p>\n',
            "help.php": "<?php $h = 'check <code>/boot/firmware/config.txt</code> and add <code>dtoverlay=pwm</code>';\n",
            "sub.php": '<input type="text" placeholder="curl -s https://agent.vendorcloud.io/agent.py | sudo python">\n',
        }
        self.assertEqual(codes(privacy_findings(prose, EMPTY_PRIVACY)), [])
        self.assertEqual(self.one({"a.php": "<?php exec('sudo systemctl start mosquitto');"}).code, "privacy-undeclared-services")
        self.assertEqual(self.one({"scripts/fpp_install.sh": "#!/bin/bash\necho 'dtoverlay=pwm' >> /boot/firmware/config.txt\n"}).code, "privacy-undeclared-privileges")
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\ncurl -s https://agent.vendorcloud.io/agent.py | sudo python\n"}, EMPTY_PRIVACY)),
                         ["privacy-undeclared-install", "privacy-undeclared-install"])  # the host, then the pipe

    def test_own_credential_setting_is_not_a_declaration_matter(self):
        files = {"a.php": "<?php $k = ReadSettingFromFile('ApiKey', 'fpp-synthetic'); echo \"<input type='password'>\";"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])

    def test_core_credential_read(self):
        f = self.one({"a.php": "<?php $p = ReadSettingFromFile('MQTTPassword');"})
        self.assertEqual(f.code, "privacy-undeclared-credentials")
        self.assertIn("MQTTPassword", f.message)
        f = self.one({"a.php": "<?php $p = $settings['MQTTUsername'];"})
        self.assertEqual(f.code, "privacy-undeclared-credentials")
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "reads-core-credentials", "what": "reads FPP's MQTT password for the broker"}]
        self.assertEqual(codes(privacy_findings({"a.php": "<?php $p = ReadSettingFromFile('MQTTPassword');"}, pv)), [])
        # MQTTHost is not a credential
        self.assertEqual(codes(privacy_findings({"a.php": "<?php $p = ReadSettingFromFile('MQTTHost');"}, EMPTY_PRIVACY)), [])

    def test_payment_processor_is_just_a_recipient(self):
        fs = privacy_findings({"a.php": "<?php $r = file_get_contents('https://api.sumup.com/v0.1/checkouts');"}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"])

    def test_privileges(self):
        f = self.one({"scripts/fpp_install.sh": "#!/bin/bash\necho 'fpp ALL=(ALL) NOPASSWD: /bin/systemctl' > /etc/sudoers.d/fpp-synthetic\n"})
        self.assertEqual(f.code, "privacy-undeclared-privileges")
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "privilege", "what": "sudoers.d rule for systemctl"}]
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\nusermod -aG video fpp\n"}, pv)), ["privacy-undeclared-privileges"])
        pv["systemChanges"].append({"kind": "service", "what": "adds fpp to the video group"})  # wrong kind
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\nusermod -aG video fpp\n"}, pv)), ["privacy-undeclared-privileges"])
        pv["systemChanges"][-1]["kind"] = "privilege"
        self.assertEqual(codes(privacy_findings({"scripts/fpp_install.sh": "#!/bin/bash\nusermod -aG video fpp\n"}, pv)), [])


class ClosedCodeUnverified(unittest.TestCase):
    """privacy-closedcode-unverified (review-C-policy item 13): closedCode: false
    with a pip/npm/cpan package or a fetched binary is a one-time "confirm the
    source is public" nudge; never with closedCode: true; never for apt alone."""
    PIP = {"scripts/fpp_install.sh": "#!/bin/bash\npip3 install --break-system-packages python-kasa\n"}

    def test_pip_install_with_closedcode_false_nudges(self):
        fs = privacy_findings(self.PIP, EMPTY_PRIVACY)
        self.assertEqual([(f.severity, f.code) for f in fs], [(L.BEST_PRACTICE, "privacy-closedcode-unverified")])
        self.assertIn("the source of pip3 package `python-kasa` is public at https://pypi.org/project/python-kasa/", fs[0].message)
        files = {"scripts/fpp_install.sh": "#!/bin/bash\ncurl -sL -o /tmp/sdk.tar.gz https://dl.vendor.com/sdk-1.2.tar.gz\n"}
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["systemChanges"] = [{"kind": "download", "what": "downloads the vendor SDK from dl.vendor.com"}]
        fs = privacy_findings(files, pv)
        self.assertEqual(codes(fs), ["privacy-closedcode-unverified"])
        self.assertIn("sdk-1.2.tar.gz is public at https://dl.vendor.com/sdk-1.2.tar.gz", fs[0].message)

    def test_pip_install_with_closedcode_true_is_silent(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["closedCode"] = True
        self.assertEqual(codes(privacy_findings(self.PIP, pv)), [])

    def test_apt_only_is_silent(self):
        files = {"scripts/fpp_install.sh": "#!/bin/bash\nsudo apt-get install -y libltc-dev python3-requests\ndpkg -i ./local.deb\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])


class BrowserLoads(unittest.TestCase):
    """A CDN, font or badge host the plugin's own page makes the operator's browser
    load is a `sends` recipient like any other hostname (spec §1, decided 14 Sep) -
    when the load happens. FPP serves plugin pages under its own Content-Security-
    Policy (script-src/style-src/font-src/img-src 'self', default-src 'self'), so a
    host the plugin does not whitelist with `ManageApacheContentPolicy.sh add` (or
    serve from its own listener, remoteAccess != none) is a dead tag: best practice
    "blocked - bundle or remove", not a blocker."""

    @staticmethod
    def csp_add(directive, host):
        return {"scripts/fpp_install.sh": f"#!/bin/bash\nset -e\n${{FPPDIR}}/scripts/ManageApacheContentPolicy.sh add {directive} https://{host}\n"}

    def hit(self, files, host, directive):
        """Whitelisted + undeclared -> blocker."""
        fs = privacy_findings({**files, **self.csp_add(directive, host)}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"], [f.message for f in fs])
        self.assertIn(f"loads https://{host} (browser-side", fs[0].message)
        self.assertIn("your browser's address", fs[0].message)
        self.assertEqual(fs[0].severity, L.BLOCKER)
        return fs[0]

    def blocked(self, files, host, directive):
        """No whitelist -> best practice, and the fix text names the directive."""
        fs = privacy_findings(files, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-csp-blocked-load"], [f.message for f in fs])
        self.assertEqual(fs[0].severity, L.BEST_PRACTICE)
        self.assertIn(f"loads https://{host} (", fs[0].message)
        self.assertIn("Content-Security-Policy blocks it, so it never loads", fs[0].message)
        # the fix text names a key the script accepts: frame/media loads are
        # governed by default-src on FPP's policy and the script has no such key
        add_key = directive if directive in L._PRIV_CSP_SCRIPT_KEYS else "default-src"
        self.assertIn(f"served under `{directive} 'self'`", fs[0].message)
        self.assertIn(f"ManageApacheContentPolicy.sh add {add_key} https://{host}", fs[0].message)
        self.assertIn("declare it in privacy.sends", fs[0].message)
        return fs[0]

    CDN = {"index.php": "<?php include 'common.php'; ?>\n<script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n"}

    def test_script_src_cdn_without_csp_add_is_best_practice(self):
        f = self.blocked(self.CDN, "cdn.jsdelivr.net", "script-src")
        self.assertIn("index.php:2 loads", f.message)
        self.assertIn("bundle the file with the plugin or remove the tag", f.message.lower())

    def test_script_src_cdn_with_csp_add_is_blocker(self):
        f = self.hit(self.CDN, "cdn.jsdelivr.net", "script-src")
        self.assertIn("index.php:2 loads", f.message)

    def test_csp_add_and_declared_is_clean(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["sends"] = [{"to": "cdn.jsdelivr.net", "what": "your browser's address", "why": "chart library", "alwaysOn": True}]
        fs = privacy_findings({**self.CDN, **self.csp_add("script-src", "cdn.jsdelivr.net")}, pv)
        self.assertEqual(codes(fs), [], [f.message for f in fs])

    def test_csp_add_wrong_directive_is_still_blocked(self):
        # img-src does not let a <script> through; nor does default-src once script-src is set
        for d in ("img-src", "default-src"):
            fs = privacy_findings({**self.CDN, **self.csp_add(d, "cdn.jsdelivr.net")}, EMPTY_PRIVACY)
            self.assertEqual(codes(fs), ["privacy-csp-blocked-load"], d)

    def test_csp_add_wildcard_and_variable(self):
        fs = privacy_findings({**self.CDN, **self.csp_add("script-src", "*.jsdelivr.net")}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"])
        # a host the linter cannot resolve is taken to cover anything in that directive
        files = {**self.CDN, "scripts/fpp_install.sh": "#!/bin/bash\nCDN=$(cat cdn.txt)\n${FPPDIR}/scripts/ManageApacheContentPolicy.sh add script-src $CDN\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), ["privacy-undeclared-recipients"])

    def test_csp_add_in_a_comment_does_not_count(self):
        # fpp-plugin-Template ships the call as a commented example
        files = {**self.CDN, "scripts/fpp_install.sh": "#!/bin/bash\n# ${FPPDIR}/scripts/ManageApacheContentPolicy.sh add script-src https://cdn.jsdelivr.net\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), ["privacy-csp-blocked-load"])

    def test_own_listener_page_is_real(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["remoteAccess"] = "lan"
        fs = privacy_findings(self.CDN, pv)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"], [f.message for f in fs])
        self.assertIn("browser-side", fs[0].message)

    def test_declared_but_blocked_says_so(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["sends"] = [{"to": "cdn.jsdelivr.net", "what": "your browser's address", "why": "chart library", "alwaysOn": True}]
        fs = privacy_findings(self.CDN, pv)
        self.assertEqual(codes(fs), ["privacy-csp-blocked-load"])
        self.assertIn("privacy.sends already names it", fs[0].message)

    def test_link_href_font(self):
        files = {"page.html": '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">\n'}
        self.blocked(files, "fonts.googleapis.com", "style-src")
        self.hit(files, "fonts.googleapis.com", "style-src")

    def test_img_badge(self):
        # shields.io is a doc host for a server-side literal, but a page loading a badge is a load
        files = {"status.php": "<?php echo '<img src=\"https://img.shields.io/badge/fpp-ok-green\">';\n"}
        self.blocked(files, "img.shields.io", "img-src")
        self.hit(files, "img.shields.io", "img-src")

    def test_iframe_and_media_fall_back_to_default_src(self):
        files = {"p.php": '<iframe src="https://embed.vendor-frames.net/x"></iframe>\n'}
        self.blocked(files, "embed.vendor-frames.net", "frame-src")
        fs = privacy_findings({**files, **self.csp_add("default-src", "embed.vendor-frames.net")}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"])
        files = {"p.php": '<audio src="https://stream.vendor-radio.net/live.mp3"></audio>\n'}
        self.blocked(files, "stream.vendor-radio.net", "media-src")

    def test_css_url_and_import(self):
        files = {"style.css": "body { background: url(https://static.vendor-assets.net/bg.png); }\n"}
        self.blocked(files, "static.vendor-assets.net", "img-src")
        self.hit(files, "static.vendor-assets.net", "img-src")
        files = {"style.css": '@import "https://fonts.bunny.net/css?family=inter";\n'}
        self.blocked(files, "fonts.bunny.net", "style-src")
        files = {"style.css": '@font-face { src: url("https://fonts.vendor-type.net/inter.woff2") format("woff2"); }\n'}
        self.blocked(files, "fonts.vendor-type.net", "font-src")
        self.hit(files, "fonts.vendor-type.net", "font-src")

    def test_browser_fetch_literal(self):
        files = {"ui.js": "fetch('https://api.weather-vendor.com/v1/now').then(r => r.json());\n"}
        self.blocked(files, "api.weather-vendor.com", "connect-src")
        self.hit(files, "api.weather-vendor.com", "connect-src")

    def test_fetch_to_fpp_whitelisted_host_is_real(self):
        # FPP's own connect-src already names kulplights.com
        fs = privacy_findings({"ui.js": "fetch('https://kulplights.com/api/x');\n"}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"])

    def test_server_side_hit_outranks_blocked_load(self):
        files = {**self.CDN, "api.php": "<?php $r = file_get_contents('https://cdn.jsdelivr.net/npm/chart.js');\n"}
        fs = privacy_findings(files, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"])
        self.assertIn("the code contacts `cdn.jsdelivr.net`", fs[0].message)

    def test_anchor_href_is_not_a_load(self):
        files = {"index.php": "<?php echo '<a href=\"https://example.com\">docs</a> <a href=\"https://vendor-forum.net/help\">forum</a>';\n"}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])
        self.assertEqual(codes(privacy_findings({**files, **self.csp_add("script-src", "vendor-forum.net")}, EMPTY_PRIVACY)), [])

    def test_github_io_is_never_a_send(self):
        files = {"index.php": '<script src="https://example.github.io/lib/lib.min.js"></script>\n'
                              '<img src="https://raw.githubusercontent.com/example/fpp-synthetic/main/logo.png">\n'}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])

    def test_relative_and_local_src_are_not_loads(self):
        files = {"index.php": '<script src="js/app.js"></script>\n<script src="/plugin.php?plugin=fpp-synthetic&file=x.js"></script>\n'
                              '<link href="../css/x.css" rel="stylesheet">\n<img src="http://localhost/api/status.png">\n'
                              '<iframe src="http://fpp.internal/status"></iframe>\n<img src="http://player.localdomain/x.png">\n'}
        self.assertEqual(codes(privacy_findings(files, EMPTY_PRIVACY)), [])

    def test_csp_script_src(self):
        # The plugin's own header()/meta policy names the host because the page loads
        # from it: counts as real without a ManageApacheContentPolicy.sh call
        for files, host in (({"index.php": "<?php header(\"Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.vendor-scripts.net\");\n"}, "cdn.vendor-scripts.net"),
                            ({"index.html": "<meta http-equiv=\"Content-Security-Policy\" content=\"font-src fonts.gstatic.com; img-src 'self' data:\">\n"}, "fonts.gstatic.com")):
            fs = privacy_findings(files, EMPTY_PRIVACY)
            self.assertEqual(codes(fs), ["privacy-undeclared-recipients"], [f.message for f in fs])
            self.assertIn(f"loads https://{host} (browser-side", fs[0].message)

    def test_declared_in_sends_is_fine(self):
        pv = copy.deepcopy(EMPTY_PRIVACY)
        pv["sends"] = [{"to": "cdn.jsdelivr.net", "what": "your browser's address", "why": "chart library", "alwaysOn": True},
                       {"to": "googleapis.com", "what": "your browser's address", "why": "page font", "alwaysOn": True}]
        files = {"index.php": '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n'
                              '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">\n'
                              "<?php header(\"Content-Security-Policy: script-src https://cdn.jsdelivr.net\");\n",
                 "scripts/fpp_install.sh": "#!/bin/bash\n${FPPDIR}/scripts/ManageApacheContentPolicy.sh add script-src https://cdn.jsdelivr.net\n"
                                           "${FPPDIR}/scripts/ManageApacheContentPolicy.sh add style-src 'https://fonts.googleapis.com'\n"}
        self.assertEqual(codes(privacy_findings(files, pv)), [])

    def test_shell_src_assignment_is_server_side(self):
        # `src=https://` in a script is a plain literal: worded as the code contacting the host
        fs = privacy_findings({"run.sh": "#!/bin/bash\nsrc=https://feeds.vendor-cdn.net/x.json\ncurl -s $src\n"}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), ["privacy-undeclared-recipients"])
        self.assertIn("the code contacts `feeds.vendor-cdn.net`", fs[0].message)


class PrivacySettings(unittest.TestCase):
    def test_write_is_blocker(self):
        for line in ("<?php WriteSettingToFile('statsPublish', '1');",
                     "<?php WriteSettingToFile(\"ShareCrashData\", 0);",
                     "<?php $settings['SendVendorSerial'] = 1;",
                     "<?php setSetting('LegalJurisdiction', 'US');"):
            fs = privacy_findings({"a.php": line}, EMPTY_PRIVACY)
            self.assertEqual([(f.severity, f.code) for f in fs], [(L.BLOCKER, "privacy-setting-write")], line)
        for files in ({"a.sh": "#!/bin/bash\ncurl -X PUT -d 1 http://localhost/api/settings/statsPublish\n"},
                      {"a.sh": "#!/bin/bash\nsed -i 's/^statsPublish.*/statsPublish = \"1\"/' /home/fpp/media/settings\n"},
                      {"a.py": "requests.put('http://localhost/api/settings/privacyConsent', data='x')\n"},
                      {"a.sh": "#!/bin/bash\necho 'FetchVendorLogos = \"1\"' >> /home/fpp/media/settings\n"}):
            fs = privacy_findings(files, EMPTY_PRIVACY)
            self.assertIn("privacy-setting-write", codes(fs), files)

    def test_read_is_best_practice(self):
        for files in ({"a.php": "<?php $s = ReadSettingFromFile('statsPublish');"},
                      {"a.php": "<?php if ($settings['ShareCrashData'] == 1) { }"},
                      {"a.sh": "#!/bin/bash\ncurl -s http://localhost/api/settings/statsPublishUrl\n"},
                      {"src/x.cpp": "if (getSettingInt(\"SendVendorLogos\")) {}"}):
            fs = privacy_findings(files, EMPTY_PRIVACY)
            self.assertEqual([(f.severity, f.code) for f in fs], [(L.BEST_PRACTICE, "privacy-setting-read")], files)

    def test_three_arg_write_is_plugins_own_key(self):
        fs = privacy_findings({"a.php": "<?php WriteSettingToFile('statsPublish', '1', 'fpp-synthetic');"}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), [])

    def test_comment_and_docs_do_not_count(self):
        fs = privacy_findings({"a.php": "<?php\n// never touch statsPublish\n", "README.md": "statsPublish"}, EMPTY_PRIVACY)
        self.assertEqual(codes(fs), [])

    def test_runs_without_a_block(self):
        fs = privacy_findings({"a.php": "<?php WriteSettingToFile('statsPublish', '1');"}, None)
        self.assertEqual(codes(fs), ["privacy-missing", "privacy-setting-write"])


class Helpers(unittest.TestCase):
    def test_split_args(self):
        self.assertEqual(L._priv_split_args("'a', f(b, c), \"x,y\")"), ["'a'", "f(b, c)", '"x,y"'])
        self.assertEqual(L._priv_split_args("'a')"), ["'a'"])
        self.assertIsNone(L._priv_split_args("'a', "))

    def test_reg_domain(self):
        self.assertEqual(L._priv_reg_domain("api.twilio.com"), "twilio.com")
        self.assertEqual(L._priv_reg_domain("fpp-zettle.s3.dualstack.eu-west-2.amazonaws.com"), "amazonaws.com")
        self.assertEqual(L._priv_reg_domain("www.fpp-zettle.co.uk"), "fpp-zettle.co.uk")

    def test_private_hosts(self):
        for h in ("localhost", "127.0.0.1", "10.1.2.3", "192.168.1.50", "172.20.0.1", "239.255.255.250", "fpp.local"):
            self.assertTrue(L._priv_private_host(h), h)
        for h in ("8.8.8.8", "api.twilio.com", "172.32.0.1"):
            self.assertFalse(L._priv_private_host(h), h)


@unittest.skipIf(L.schema_validation_error is None, "jsonschema not installed")
class Schema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_PATH, encoding="utf-8") as f:
            cls.schema = json.load(f)

    def check(self, info):
        return L.schema_validation_error(info, self.schema)

    def test_manifest_without_block_still_passes(self):
        self.assertIsNone(self.check(copy.deepcopy(BASE_INFO)))

    def test_full_and_empty_blocks_pass(self):
        for pv in (EMPTY_PRIVACY, FULL_PRIVACY):
            info = copy.deepcopy(BASE_INFO)
            info["privacy"] = copy.deepcopy(pv)
            self.assertIsNone(self.check(info))

    def test_every_key_required(self):
        for key in EMPTY_PRIVACY:
            info = copy.deepcopy(BASE_INFO)
            info["privacy"] = copy.deepcopy(EMPTY_PRIVACY)
            del info["privacy"][key]
            self.assertIn(f"'{key}' is a required property", self.check(info) or "", key)

    def test_strict_and_enumerated(self):
        def bad(mutate):
            info = copy.deepcopy(BASE_INFO)
            info["privacy"] = copy.deepcopy(FULL_PRIVACY)
            mutate(info["privacy"])
            self.assertIsNotNone(self.check(info))
        bad(lambda p: p.update(schemaVersion=2))
        bad(lambda p: p.update(extra="x"))
        bad(lambda p: p.update(recipients=[]))
        bad(lambda p: p["sends"][0].update(operator="commercial"))
        bad(lambda p: p["sends"][0].pop("alwaysOn"))
        bad(lambda p: p["sends"][0].update(alwaysOn="yes"))
        bad(lambda p: p["collects"][0].update(about="robots"))
        bad(lambda p: p["collects"][0].update(keptDays="30"))
        bad(lambda p: p["collects"][0].update(storedIn=["x"]))
        bad(lambda p: p["sensors"][0].update(type="lidar"))
        bad(lambda p: p["sensors"][0].update(streamed="LAN only"))
        bad(lambda p: p.update(remoteAccess="wan"))
        bad(lambda p: p["systemChanges"][0].update(kind="listener"))
        bad(lambda p: p["systemChanges"][0].update(reverted=True))
        bad(lambda p: p.update(closedCode="no"))
        bad(lambda p: p.update(other=""))
        bad(lambda p: p.update(summary=""))

    def test_null_keptDays_and_empty_arrays_pass(self):
        info = copy.deepcopy(BASE_INFO)
        info["privacy"] = copy.deepcopy(FULL_PRIVACY)
        info["privacy"]["collects"][0]["keptDays"] = None
        self.assertIsNone(self.check(info))

    def test_length_is_not_a_schema_matter(self):
        info = copy.deepcopy(BASE_INFO)
        info["privacy"] = copy.deepcopy(EMPTY_PRIVACY)
        info["privacy"]["summary"] = "x" * 500
        self.assertIsNone(self.check(info))




class SplitTagDirective(unittest.TestCase):
    """A tag whose src=/href= sits on a continuation line still gets the
    directive of its tag, not connect-src (fpp-jukebox locked.html:46, 2026-09)."""

    def hits(self, text: str, rel: str = "page.php"):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, os.path.dirname(rel)) or tmp, exist_ok=True)
            with open(os.path.join(tmp, rel), "w") as f:
                f.write(text)
            return {h: (v[3], v[4]) for h, v in L._priv_host_hits(tmp, None, {}, False).items()}

    def test_img_split_over_lines_is_img_src(self):
        self.assertEqual(self.hits('<img class="x"\n     alt="y"\n     src="https://placehold.co/500x500">\n'),
                         {"placehold.co": ("blocked", "img-src")})

    def test_script_split_over_lines_is_script_src(self):
        self.assertEqual(self.hits('<script\n    src="https://code.jquery.com/jquery.js"></script>\n'),
                         {"code.jquery.com": ("blocked", "script-src")})

    def test_anchor_split_over_lines_stays_a_link(self):
        self.assertEqual(self.hits('<a class="btn"\n   href="https://example.com/docs">docs</a>\n'), {})

    def test_closed_tag_on_earlier_line_is_not_pulled_in(self):
        # the <img> is complete; the bare src= below belongs to nothing we can see
        out = self.hits('<img src="x.png">\nvar u = "https://api.example.com/v1";\n')
        self.assertEqual(out.get("api.example.com", (None, None))[1], None)


if __name__ == "__main__":
    unittest.main()
