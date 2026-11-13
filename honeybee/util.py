"""公共工具：base64、文本清洗、主机/端口解析、布尔与数值转换。"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any, Iterable

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\ufeff]")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def clean_text(value: Any, limit: int = 0) -> str:
    """去掉控制字符、零宽字符，压平空白；limit>0 时截断。"""
    if value is None:
        return ""
    text = CONTROL_CHARS.sub("", str(value))
    text = re.sub(r"\s+", " ", text).strip()
    if limit and len(text) > limit:
        text = text[:limit].rstrip()
    return text


def b64decode(value: str) -> bytes | None:
    """宽松 base64：兼容 urlsafe、缺 padding、混入空白与换行。"""
    if not value:
        return None
    raw = re.sub(r"\s+", "", value.strip())
    raw = raw.replace("-", "+").replace("_", "/")
    raw = raw.rstrip("=")
    if not raw or len(raw) < 4:
        return None
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError):
        return None


def b64text(value: str) -> str | None:
    data = b64decode(value)
    if data is None:
        return None
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y", "t")


def as_int(value: Any, default: int | None = None) -> int | None:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    match = re.search(r"-?\d+", str(value))
    return int(match.group()) if match else default


def first(*values: Any, default: Any = None) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return default


def split_host_port(value: str) -> tuple[str, int | None]:
    """解析 host:port，兼容 IPv6 的 [::1]:443 与裸 IPv6。"""
    value = (value or "").strip().strip("/")
    if not value:
        return "", None
    if value.startswith("["):
        end = value.find("]")
        if end > 0:
            host = value[1:end]
            rest = value[end + 1:]
            port = as_int(rest.lstrip(":"), None)
            return normalise_host(host), port
    # 裸 IPv6 不带端口时无法安全切分，交给调用方按 ':' 数量判断
    if value.count(":") == 1:
        host, _, port_s = value.rpartition(":")
        return normalise_host(host), as_int(port_s, None)
    return normalise_host(value), None


def normalise_host(value: Any) -> str:
    host = clean_text(value).strip("[]")
    if not host:
        return ""
    # 去掉常见误粘贴的前缀
    host = re.sub(r"^(?:https?|tcp|udp)://", "", host, flags=re.I)
    return host.lower() if re.match(r"^[0-9a-f:]+\.[0-9a-f.]+$", host, re.I) is None else host


def is_public_host(host: str) -> bool:
    """过滤本地/保留地址；域名一律放行。"""
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return True  # 域名
    return not (addr.is_loopback or addr.is_private or addr.is_link_local
                or addr.is_multicast or addr.is_unspecified or addr.is_reserved)


def unique_tags(nodes: Iterable[dict], max_len: int = 120,
                reserved: Iterable[str] = ()) -> list[dict]:
    """保证 tag 非空、唯一、长度受限，且不撞上模板内置的 tag。"""
    seen: set[str] = set(reserved)
    result: list[dict] = []
    for node in nodes:
        tag = clean_text(node.get("tag"), max_len) or f"{node.get('type', 'node')}-{len(result) + 1:04d}"
        base = tag
        i = 2
        while tag in seen:
            suffix = f"-{i}"
            tag = base[:max_len - len(suffix)] + suffix
            i += 1
        seen.add(tag)
        node["tag"] = tag
        result.append(node)
    return result


def compact(node: dict) -> dict:
    """丢弃空值字段，保持输出干净。"""
    return {k: v for k, v in node.items() if v is not None and v != "" and v != [] and v != {}}
