"""sing-box 兼容性规范化。

公开订阅里常有脏字段：乱写的 uTLS 指纹、非 base64 的 reality 公钥、
带半个百分号转义的 ws path、不支持的 obfs 模式。这些字段能让
`sing-box check` 直接拒绝整份配置，所以在进入产物前统一处理。
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from .util import clean_text

# sing-box / uTLS 认可的 ClientHello 指纹；其它值一律不写 utls 字段
UTLS_FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized", "chrome_psk", "chrome_psk_shuffle",
    "chrome_padding_psk_shuffle", "chrome_conrad",
}

_ILLEGAL_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_SHORT_ID = re.compile(r"^[0-9a-fA-F]{0,16}$")


def valid_public_key(value: Any) -> bool:
    """reality public_key 必须是 32 字节的 base64(url-safe)。"""
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip().replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def fix_path(value: Any) -> str:
    """把非法的 % 转义成 %25，避免 sing-box 解析 URL 时报错。"""
    text = str(value if value is not None else "/")
    return _ILLEGAL_PERCENT.sub("%25", text) or "/"


def valid_utls(fingerprint: Any) -> bool:
    return isinstance(fingerprint, str) and fingerprint.strip().lower() in UTLS_FINGERPRINTS


def valid_obfs(obfs: Any) -> bool:
    """sing-box 的 hysteria2 只接受 salamander，且必须给密码。"""
    if obfs is None:
        return True
    if not isinstance(obfs, dict):
        return False
    return obfs.get("type") == "salamander" and bool(obfs.get("password"))


def valid_ss_key(node: dict) -> bool:
    """Shadowsocks 2022 系列要求密钥长度与算法匹配。"""
    method = str(node.get("method") or "")
    if not method.startswith("2022-blake3"):
        return True
    password = str(node.get("password") or "")
    try:
        text = password + "=" * (-len(password) % 4)
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return False
    expected = 16 if "aes-128" in method else 32
    return len(raw) == expected


def sanitize_node(node: dict) -> dict | None:
    """就地规范化；返回 None 表示这个节点不该进入产物。"""
    if not isinstance(node, dict):
        return None

    tls = node.get("tls")
    if isinstance(tls, dict):
        utls = tls.get("utls")
        if isinstance(utls, dict):
            fingerprint = str(utls.get("fingerprint") or "").strip().lower()
            if not valid_utls(fingerprint):
                tls.pop("utls", None)
            else:
                utls["fingerprint"] = fingerprint
        reality = tls.get("reality")
        if isinstance(reality, dict):
            if not valid_public_key(reality.get("public_key")):
                return None  # 公钥不可用，节点必然连不上
            short_id = str(reality.get("short_id") or "")
            if short_id and not _SHORT_ID.match(short_id):
                reality.pop("short_id", None)
        alpn = tls.get("alpn")
        if isinstance(alpn, list):
            cleaned_alpn = [clean_text(item) for item in alpn if clean_text(item)]
            if cleaned_alpn:
                tls["alpn"] = cleaned_alpn
            else:
                tls.pop("alpn", None)

    transport = node.get("transport")
    if isinstance(transport, dict):
        if transport.get("path") is not None:
            transport["path"] = fix_path(transport["path"])
        headers = transport.get("headers")
        if isinstance(headers, dict):
            transport["headers"] = {
                str(key): clean_text(value)
                for key, value in headers.items() if clean_text(value)
            }
            if not transport["headers"]:
                transport.pop("headers", None)

    if not valid_obfs(node.get("obfs")):
        node.pop("obfs", None)

    if not valid_ss_key(node):
        return None

    # sing-box 1.12 的 vless/vmess 只认 "" / "xudp" / "packetaddr"；
    # 传别的字符串会让它在错误信息里对指针做格式化，直接 panic。
    if node.get("type") in ("vless", "vmess"):
        if node.get("packet_encoding") not in (None, "", "xudp", "packetaddr"):
            node["packet_encoding"] = "xudp"
        flow = node.get("flow")
        if flow and flow != "xtls-rprx-vision":
            node.pop("flow", None)

    return node
