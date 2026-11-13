"""验证：静态结构校验，可选调用 sing-box check 做最终确认。

静态校验是 O(n)，一次性剔除不合规节点；不再像旧脚本那样
反复调用 sing-box check 逐个删除 outbound。
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from . import sanitize
from .convert import SUPPORTED_TYPES
from .util import UUID_RE

REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "shadowsocks": ("server", "server_port", "method", "password"),
    "vmess": ("server", "server_port", "uuid"),
    "vless": ("server", "server_port", "uuid"),
    "trojan": ("server", "server_port", "password"),
    "hysteria": ("server", "server_port"),
    "hysteria2": ("server", "server_port", "password"),
    "tuic": ("server", "server_port", "uuid", "password"),
    "wireguard": ("server", "server_port", "private_key",
                  "peer_public_key", "local_address"),
    "socks": ("server", "server_port"),
    "http": ("server", "server_port"),
    "anytls": ("server", "server_port", "password"),
}

GROUP_TYPES = {"selector", "urltest"}
BUILTIN_TYPES = {"direct", "block", "dns"}


def verify_node(node: dict) -> str:
    """返回错误说明；空字符串表示合规。"""
    if not isinstance(node, dict):
        return "not an object"
    kind = node.get("type")
    if kind in GROUP_TYPES or kind in BUILTIN_TYPES:
        return ""
    if kind not in SUPPORTED_TYPES:
        return f"unsupported type {kind}"
    for key in REQUIRED_FIELDS.get(kind, ()):
        value = node.get(key)
        if value is None or value == "" or value == []:
            return f"missing {key}"
    port = node.get("server_port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return "invalid server_port"
    if not node.get("tag"):
        return "missing tag"
    if kind in ("vmess", "vless", "tuic"):
        if not UUID_RE.match(str(node.get("uuid", ""))):
            return "invalid uuid"
    tls = node.get("tls")
    if tls is not None:
        if not isinstance(tls, dict) or not tls.get("enabled"):
            return "invalid tls"
        utls = tls.get("utls")
        if isinstance(utls, dict) and not sanitize.valid_utls(utls.get("fingerprint")):
            return "invalid utls fingerprint"
        reality = tls.get("reality")
        if isinstance(reality, dict) and reality.get("enabled"):
            if not sanitize.valid_public_key(reality.get("public_key")):
                return "invalid reality public_key"
    transport = node.get("transport")
    if transport is not None:
        if not isinstance(transport, dict) or transport.get("type") not in (
                "ws", "grpc", "http", "httpupgrade", "quic"):
            return "invalid transport"
        path = transport.get("path")
        if path and sanitize.fix_path(path) != path:
            return "invalid percent escape in transport path"
    if not sanitize.valid_obfs(node.get("obfs")):
        return "invalid obfs"
    if not sanitize.valid_ss_key(node):
        return "invalid shadowsocks-2022 key"
    if kind in ("vless", "vmess"):
        if node.get("packet_encoding") not in (None, "", "xudp", "packetaddr"):
            return "invalid packet_encoding"
        if node.get("flow") and node["flow"] != "xtls-rprx-vision":
            return "invalid flow"
    return ""


def verify_nodes(nodes: list[dict]) -> tuple[list[dict], list[tuple[str, str]]]:
    """返回 (合规节点, [(tag, 原因)])。"""
    valid: list[dict] = []
    issues: list[tuple[str, str]] = []
    for node in nodes:
        reason = verify_node(node)
        if reason:
            issues.append((str(node.get("tag", "?")), reason))
        else:
            valid.append(node)
    return valid, issues


def verify_config(config: dict) -> list[str]:
    """校验一份完整 sing-box 配置：tag 唯一、分组引用闭合、节点字段。"""
    problems: list[str] = []
    if not isinstance(config, dict):
        return ["config is not an object"]
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        return ["missing outbounds"]
    tags: list[str] = []
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            problems.append("outbound is not an object")
            continue
        tag = outbound.get("tag")
        if not tag:
            problems.append("outbound without tag")
        else:
            tags.append(tag)
        reason = verify_node(outbound)
        if reason:
            problems.append(f"{tag or '?'}: {reason}")
    duplicates = {tag for tag in tags if tags.count(tag) > 1}
    for tag in sorted(duplicates):
        problems.append(f"duplicate tag: {tag}")
    known = set(tags)
    for outbound in outbounds:
        if not isinstance(outbound, dict) or outbound.get("type") not in GROUP_TYPES:
            continue
        for referenced in outbound.get("outbounds", []):
            if referenced not in known and referenced != "{all}":
                problems.append(f"{outbound.get('tag')} references missing {referenced}")
    return problems


def singbox_check(config_path: str, binary: str = "sing-box") -> tuple[bool, str]:
    """可选：用官方 sing-box 二进制做一次 check。没有安装时直接跳过。"""
    executable = shutil.which(binary)
    if executable is None and os.path.isfile(binary) and os.access(binary, os.X_OK):
        executable = binary
    if not executable:
        return True, "sing-box not installed, skipped"
    try:
        result = subprocess.run(
            [executable, "check", "-c", config_path],
            capture_output=True, text=True, timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except (OSError, subprocess.SubprocessError) as exc:
        return True, f"sing-box check skipped: {exc}"
