"""Honeybee 单元测试：协议解析、清理、验证、拆分与打包。"""
from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from honeybee import clean, collect, convert, split, verify
from honeybee.build import build, inspect_bundle, read_bundle

ROOT = Path(__file__).resolve().parent.parent


def b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


class UriTests(unittest.TestCase):
    def test_ss_sip002(self):
        uri = "ss://" + b64("aes-256-gcm:pass123") + "@1.2.3.4:8388#US-01"
        node = convert.parse_line(uri)
        self.assertEqual(node["type"], "shadowsocks")
        self.assertEqual(node["server"], "1.2.3.4")
        self.assertEqual(node["server_port"], 8388)
        self.assertEqual(node["password"], "pass123")
        self.assertEqual(node["tag"], "US-01")

    def test_ss_legacy(self):
        uri = "ss://" + b64("chacha20-ietf-poly1305:pwd@5.6.7.8:9999")
        node = convert.parse_line(uri)
        self.assertEqual(node["server"], "5.6.7.8")
        self.assertEqual(node["method"], "chacha20-ietf-poly1305")

    def test_vmess_json(self):
        item = {
            "v": "2", "ps": "VM-01", "add": "9.9.9.9", "port": 443,
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": 0,
            "net": "ws", "type": "none", "host": "cdn.example.com",
            "path": "/ws", "tls": "tls", "sni": "cdn.example.com",
        }
        node = convert.parse_line("vmess://" + b64(json.dumps(item)))
        self.assertEqual(node["type"], "vmess")
        self.assertEqual(node["transport"]["path"], "/ws")
        self.assertTrue(node["tls"]["enabled"])

    def test_vless_reality(self):
        uri = ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@8.8.4.4:443"
               "?security=reality&encryption=none&type=tcp&sni=www.microsoft.com"
               "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd"
               "&fp=chrome#REALITY")
        node = convert.parse_line(uri)
        self.assertEqual(node["type"], "vless")
        self.assertTrue(node["tls"]["reality"]["enabled"])
        self.assertEqual(node["tls"]["server_name"], "www.microsoft.com")

    def test_trojan_ws(self):
        uri = ("trojan://secret@10.0.0.1:443?type=ws&path=%2Ftrojan"
               "&host=trojan.example.com&sni=trojan.example.com#TJ")
        node = convert.parse_line(uri)
        self.assertEqual(node["type"], "trojan")
        self.assertEqual(node["transport"]["type"], "ws")
        self.assertEqual(node["transport"]["headers"]["Host"], "trojan.example.com")

    def test_hysteria2_and_tuic(self):
        hy2 = convert.parse_line(
            "hysteria2://pass@11.22.33.44:8443?sni=hy.example.com&obfs=salamander"
            "&obfs-password=obfspwd#HY2")
        self.assertEqual(hy2["type"], "hysteria2")
        self.assertEqual(hy2["obfs"]["type"], "salamander")
        self.assertEqual(hy2["tls"]["alpn"], ["h3"])
        tuic = convert.parse_line(
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pwd@12.12.12.12:443"
            "?congestion_control=bbr&alpn=h3&sni=tuic.example.com#TUIC")
        self.assertEqual(tuic["type"], "tuic")
        self.assertEqual(tuic["congestion_control"], "bbr")

    def test_wireguard(self):
        uri = ("wireguard://PRIVATEKEY@13.13.13.13:51820"
               "?publickey=PEERKEY&ip=10.0.0.2&reserved=1,2,3#WG")
        node = convert.parse_line(uri)
        self.assertEqual(node["type"], "wireguard")
        self.assertEqual(node["local_address"], ["10.0.0.2/32"])
        self.assertEqual(node["reserved"], [1, 2, 3])

    def test_bad_lines_are_ignored(self):
        for line in ("", "# comment", "totally not a proxy",
                     "ssr://anything", "vmess://notbase64!!",
                     "vless://notauuid@1.2.3.4:443"):
            self.assertIsNone(convert.parse_line(line), line)

    def test_control_characters_in_tag(self):
        uri = "ss://" + b64("aes-128-gcm:pwd") + "@1.2.3.4:1000#Bad\x01Name"
        node = convert.parse_line(uri)
        self.assertNotIn("\x01", node["tag"])


class ClashTests(unittest.TestCase):
    def test_clash_ss(self):
        node = convert.parse_clash_proxy({
            "name": "SS-CLASH", "type": "ss", "server": "1.1.1.1",
            "port": 8388, "cipher": "aes-256-gcm", "password": "pwd",
        })
        self.assertEqual(node["type"], "shadowsocks")
        self.assertEqual(node["tag"], "SS-CLASH")

    def test_clash_vless_reality(self):
        node = convert.parse_clash_proxy({
            "name": "RL", "type": "vless", "server": "r.example.com",
            "port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "tls": True, "servername": "www.microsoft.com",
            "client-fingerprint": "chrome",
            "reality-opts": {"public-key": "KEY", "short-id": "ab"},
            "network": "tcp",
        })
        self.assertEqual(node["tls"]["reality"]["public_key"], "KEY")
        self.assertEqual(node["tls"]["server_name"], "www.microsoft.com")

    def test_clash_hysteria2(self):
        node = convert.parse_clash_proxy({
            "name": "HY2", "type": "hysteria2", "server": "h.example.com",
            "port": 443, "password": "pwd", "up": "50", "down": "200",
            "sni": "h.example.com", "obfs": "salamander", "obfs-password": "o",
        })
        self.assertEqual(node["up_mbps"], 50)
        self.assertEqual(node["down_mbps"], 200)
        self.assertEqual(node["obfs"]["type"], "salamander")

    def test_unsupported(self):
        self.assertIsNone(convert.parse_clash_proxy({"type": "ssr"}))
        self.assertIsNone(convert.parse_clash_proxy("not a dict"))


class DecodeTests(unittest.TestCase):
    def test_base64_subscription(self):
        payload = b64(
            "ss://YWVzLTI1Ni1nY206cHdk@1.2.3.4:8388#A\n"
            "trojan://pwd@2.3.4.5:443#T"
        )
        entries = collect.decode(payload)
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0].startswith("ss://"))

    def test_clash_yaml(self):
        text = ("port: 7890\nproxies:\n"
                "  - {name: A, server: 1.2.3.4, port: 8388, type: ss, "
                "cipher: aes-256-gcm, password: pwd}\n"
                "  - {name: B, server: 5.6.7.8, port: 443, type: trojan, password: pwd}\n")
        entries = collect.decode(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["name"], "A")

    def test_json_list(self):
        entries = collect.decode(json.dumps({"proxies": [{"type": "ss"}, "ss://abc"]}))
        self.assertEqual(len(entries), 2)


class CleanTests(unittest.TestCase):
    SETTINGS = {"clean": {
        "allowed_protocols": ["shadowsocks", "vless", "trojan"],
        "max_tag_length": 60,
        "drop_private_server": True,
        "drop_reserved_ports": False,
    }}

    def _node(self, **kwargs):
        node = {"type": "shadowsocks", "tag": "N", "server": "1.2.3.4",
                "server_port": 8388, "method": "aes-256-gcm", "password": "pwd"}
        node.update(kwargs)
        return node

    def test_dedup_and_tags(self):
        nodes = [self._node(), self._node(tag="Other"), self._node(tag="\x01X")]
        kept, stats = clean.clean_nodes(nodes, self.SETTINGS)
        self.assertEqual(len(kept), 1)
        self.assertEqual(stats["duplicate"], 2)

    def test_drop_private_and_bad_port(self):
        nodes = [self._node(server="127.0.0.1"), self._node(server_port=70000),
                 self._node(server="8.8.8.8", password="other")]
        kept, _ = clean.clean_nodes(nodes, self.SETTINGS)
        self.assertEqual(len(kept), 1)

    def test_protocol_filter(self):
        kept, _ = clean.clean_nodes([self._node(type="hysteria2")], self.SETTINGS)
        self.assertEqual(kept, [])


class VerifySplitTests(unittest.TestCase):
    def test_verify_config(self):
        base = json.loads((ROOT / "config" / "base.json").read_text(encoding="utf-8"))
        nodes = [{
            "type": "vless", "tag": "N1", "server": "1.2.3.4", "server_port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
        }]
        config = split.render_config(base, nodes)
        self.assertEqual(verify.verify_config(config), [])
        self.assertEqual(config["outbounds"][1]["outbounds"], ["N1"])

    def test_verify_rejects_missing_field(self):
        bad = {"type": "vless", "tag": "X", "server": "1.2.3.4",
               "server_port": 443}
        valid, issues = verify.verify_nodes([bad])
        self.assertEqual(valid, [])
        self.assertIn("uuid", issues[0][1])

    def test_split_chunks(self):
        nodes = [{"tag": f"N{i}"} for i in range(12)]
        groups = split.chunks(nodes, 5)
        self.assertEqual([len(group) for group in groups], [5, 5, 2])


class BuildTests(unittest.TestCase):
    def test_offline_bundle_is_deterministic_and_valid(self):
        sample = (
            "ss://" + b64("aes-256-gcm:pwd") + "@1.2.3.4:8388#A\n"
            "trojan://pwd@2.3.4.5:443?sni=t.example.com#T\n"
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@3.3.3.3:443"
            "?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "&sni=www.microsoft.com#R\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            sample_path = os.path.join(folder, "sample.txt")
            Path(sample_path).write_text(sample, encoding="utf-8")
            output = os.path.join(folder, "bundle.tar.gz")
            report = build(
                sources_path=str(ROOT / "config" / "sources.json"),
                settings_path=str(ROOT / "config" / "settings.json"),
                base_path=str(ROOT / "config" / "base.json"),
                output=output, max_per_file=2, offline=sample_path, verbose=False,
            )
            self.assertEqual(report["total_nodes"], 3)
            self.assertEqual(report["files"], 2)
            files = read_bundle(output)
            self.assertIn("manifest.json", files)
            self.assertIn("honeybee-001.json", files)
            self.assertEqual(json.loads(files["manifest.json"])["total_nodes"], 3)
            summary = inspect_bundle(output)
            self.assertEqual(summary["problems"], [])
            self.assertEqual(summary["config_nodes"], 3)
            first_bytes = Path(output).read_bytes()
            build(
                sources_path=str(ROOT / "config" / "sources.json"),
                settings_path=str(ROOT / "config" / "settings.json"),
                base_path=str(ROOT / "config" / "base.json"),
                output=output, max_per_file=2, offline=sample_path, verbose=False,
            )
            self.assertEqual(first_bytes, Path(output).read_bytes())


if __name__ == "__main__":
    unittest.main()
