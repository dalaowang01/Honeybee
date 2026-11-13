"""清理：控制字符、无效字段、私有地址、协议白名单、去重、tag 规范化。"""
from __future__ import annotations

from typing import Any, Iterable

from .sanitize import sanitize_node
from .util import (UUID_RE, as_int, clean_text, compact, is_public_host,
                   normalise_host, unique_tags)

CREDENTIAL_KEYS = ("password", "uuid", "private_key", "peer_public_key",
                   "auth_str", "pre_shared_key")
# 只挡明显的系统服务端口；80/443/8080/8443/1080/9090 等是公开节点常用端口，不拦
RESERVED_PORTS = {0, 1, 7, 9, 13, 19, 21, 22, 23, 25, 53, 110, 143, 161,
                  445, 465, 587, 993, 995, 1194, 1433, 1723, 3306, 3389,
                  5432, 6379, 9200, 11211, 27017}


def scrub(value: Any) -> Any:
    """递归清除所有字符串里的控制字符。"""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, dict):
        return {clean_text(key): scrub(item) for key, item in value.items()}
    return value


def fingerprint(node: dict) -> tuple:
    """节点身份：协议 + 端点 + 凭据（忽略名称），用于跨源去重。"""
    credential = "|".join(
        str(node.get(key) or "") for key in CREDENTIAL_KEYS
    )
    extras = ""
    if isinstance(node.get("transport"), dict):
        extras += str(node["transport"].get("path") or "")
    if isinstance(node.get("tls"), dict):
        extras += str(node["tls"].get("server_name") or "")
    return (node.get("type"), node.get("server"), node.get("server_port"),
            credential, extras)


def _basic_valid(node: dict, allowed: set[str], drop_private: bool,
                 drop_reserved_ports: bool) -> str:
    """返回丢弃原因；空字符串表示通过。"""
    kind = node.get("type")
    if kind not in allowed:
        return "protocol"
    host = node.get("server")
    if not host or len(host) > 253:
        return "host"
    if drop_private and not is_public_host(host):
        return "private"
    port = node.get("server_port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return "port"
    if drop_reserved_ports and port in RESERVED_PORTS:
        return "reserved_port"
    tag = node.get("tag")
    if not tag:
        return "tag"
    if kind in ("vmess", "vless", "tuic"):
        uuid = str(node.get("uuid") or "")
        if not UUID_RE.match(uuid):
            return "uuid"
    if kind in ("trojan", "hysteria2", "anytls", "shadowsocks") and not node.get("password"):
        return "password"
    if kind == "wireguard":
        if not node.get("private_key") or not node.get("peer_public_key"):
            return "wireguard"
        if not node.get("local_address"):
            return "wireguard"
    return ""


def clean_nodes(nodes: list[dict], settings: dict,
                reserved_tags: Iterable[str] = (), max_nodes: int | None = None
                ) -> tuple[list[dict], dict[str, int]]:
    """返回 (干净节点列表, 各环节丢弃计数)。"""
    config = settings.get("clean", {})
    allowed = set(config.get("allowed_protocols") or [])
    max_tag = int(config.get("max_tag_length", 120))
    drop_private = bool(config.get("drop_private_server", True))
    drop_reserved = bool(config.get("drop_reserved_ports", True))

    stats = {"input": len(nodes), "invalid": 0, "duplicate": 0,
             "protocol": 0, "host": 0, "private": 0, "port": 0,
             "reserved_port": 0, "tag": 0, "uuid": 0, "password": 0,
             "wireguard": 0}
    seen: set[tuple] = set()
    kept: list[dict] = []
    for raw in nodes:
        if not isinstance(raw, dict):
            stats["invalid"] += 1
            continue
        node = sanitize_node(compact(scrub(raw)))
        if node is None:
            stats["invalid"] += 1
            continue
        node["server"] = normalise_host(node.get("server"))
        node["server_port"] = as_int(node.get("server_port"), None)
        reason = _basic_valid(node, allowed, drop_private, drop_reserved)
        if reason:
            stats[reason] = stats.get(reason, 0) + 1
            continue
        key = fingerprint(node)
        if key in seen:
            stats["duplicate"] += 1
            continue
        seen.add(key)
        kept.append(node)
        if max_nodes and len(kept) >= max_nodes:
            stats["truncated"] = len(nodes) - len(kept)
            break
    kept = unique_tags(kept, max_tag, reserved_tags)
    stats["output"] = len(kept)
    return kept, stats
