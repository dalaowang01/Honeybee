"""订阅 URI / Clash YAML 代理 -> sing-box outbound。

纯标准库实现，替代仓库里原先的 clash2singbox 二进制
和第三方 sing-box-subscribe 脚本。所有解析都允许失败：
一条坏数据只会被丢弃，不会中断整批转换。
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Callable

from .util import (UUID_RE, as_bool, as_int, b64text, clean_text, compact,
                   first, normalise_host, split_host_port)

SUPPORTED_TYPES = {
    "shadowsocks", "vmess", "vless", "trojan", "hysteria", "hysteria2",
    "tuic", "wireguard", "http", "socks", "anytls",
}

_VMESS_SECURITY = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}
_SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb",
    "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none",
}


# ---------------------------------------------------------------------------
# URI 通用解析
# ---------------------------------------------------------------------------

def split_uri(uri: str) -> tuple[str, str, dict[str, str], str]:
    """手动切分，避开 urlsplit 对畸形订阅链接的误判。

    返回 (scheme, main, query, fragment)。
    """
    scheme, _, rest = uri.partition("://")
    fragment = ""
    if "#" in rest:
        rest, _, raw_fragment = rest.partition("#")
        fragment = urllib.parse.unquote(raw_fragment)
    if "?" in rest:
        main, _, query_string = rest.partition("?")
    else:
        main, query_string = rest, ""
    query = {
        key.lower(): values[0]
        for key, values in urllib.parse.parse_qs(query_string, keep_blank_values=False).items()
    }
    return scheme.lower(), main.strip(), query, fragment


def endpoint(main: str) -> tuple[str, str, int | None]:
    """从 userinfo@host:port 中取出三部分。"""
    if "@" in main:
        userinfo, _, address = main.rpartition("@")
    else:
        userinfo, address = "", main
    host, port = split_host_port(address.rstrip("/"))
    return urllib.parse.unquote(userinfo.strip()), host, port


def make_tag(fragment: str, fallback: str) -> str:
    return clean_text(fragment, 100) or f"{fallback}"


def _alpn(value: Any) -> list[str] | None:
    if not value:
        return None
    if isinstance(value, (list, tuple)):
        items = [clean_text(v) for v in value]
    else:
        items = [v.strip() for v in re.split(r"[,{}]", str(value))]
    items = [v.strip('"\' ') for v in items if v and v.strip('"\' ')]
    return items or None


def _tls(query: dict[str, str], *, force: bool = False,
         default_insecure: bool = False) -> dict | None:
    security = str(first(query.get("security"), query.get("mode"), "")).lower()
    enabled = (force or security in ("tls", "reality", "xtls")
               or as_bool(query.get("tls")) or as_bool(query.get("tls-enabled")))
    if not enabled:
        return None
    tls: dict[str, Any] = {"enabled": True}
    sni = first(query.get("sni"), query.get("peer"), query.get("servername"), "")
    if sni and str(sni).lower() != "none":
        tls["server_name"] = clean_text(sni)
    insecure = default_insecure or as_bool(first(
        query.get("allowinsecure"), query.get("insecure"),
        query.get("allow_insecure"), query.get("skip-cert-verify")))
    if insecure or not tls.get("server_name"):
        tls["insecure"] = True
    fingerprint = first(query.get("fp"), query.get("fingerprint"))
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": clean_text(fingerprint)}
    alpn = _alpn(query.get("alpn"))
    if alpn:
        tls["alpn"] = alpn
    if security == "reality" or query.get("pbk"):
        reality: dict[str, Any] = {"enabled": True}
        if query.get("pbk"):
            reality["public_key"] = query["pbk"]
        if query.get("sid"):
            reality["short_id"] = query["sid"]
        tls["reality"] = reality
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return tls


def _transport(query: dict[str, str]) -> dict | None:
    network = str(first(query.get("type"), query.get("net"),
                        query.get("obfs"), query.get("network"), "")).lower()
    path = str(first(query.get("path"), "/"))
    host = first(query.get("host"), query.get("obfsparam"), "")
    if network in ("ws", "websocket"):
        transport: dict[str, Any] = {"type": "ws"}
        match = re.search(r"\?ed=(\d+)$", path)
        if match:
            path = path[:match.start()]
            transport["max_early_data"] = int(match.group(1))
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["path"] = path or "/"
        if host:
            transport["headers"] = {"Host": clean_text(host)}
        return transport
    if network in ("grpc", "gun"):
        return compact({"type": "grpc",
                        "service_name": first(query.get("servicename"),
                                              query.get("service_name"),
                                              query.get("path"), "")})
    if network in ("h2", "http", "http2"):
        return compact({"type": "http",
                        "host": [clean_text(host)] if host else None,
                        "path": path or "/"})
    if network == "httpupgrade":
        return compact({"type": "httpupgrade",
                        "host": clean_text(host) or None, "path": path or "/"})
    return None


# ---------------------------------------------------------------------------
# URI: 各协议
# ---------------------------------------------------------------------------

def _ss(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    method = password = None
    host, port = "", None
    if "@" in main:
        left, _, right = main.rpartition("@")
        decoded = b64text(left)
        if decoded and ":" in decoded:
            method, password = decoded.split(":", 1)
        elif ":" in left:
            method, password = left.split(":", 1)
            method, password = urllib.parse.unquote(method), urllib.parse.unquote(password)
        else:
            return None
        host, port = split_host_port(right)
    else:
        decoded = b64text(main)
        if not decoded or "@" not in decoded:
            return None
        credentials, _, address = decoded.rpartition("@")
        if ":" not in credentials:
            return None
        method, password = credentials.split(":", 1)
        host, port = split_host_port(address)
    method = clean_text(method).lower()
    if method not in _SS_METHODS or not password:
        return None
    node = compact({
        "type": "shadowsocks",
        "tag": make_tag(fragment, f"ss-{host}"),
        "server": host, "server_port": port,
        "method": method, "password": password,
    })
    plugin = str(query.get("plugin") or "").lower()
    if plugin.startswith("simple-obfs") or plugin.startswith("obfs-local"):
        parts = dict(
            item.split("=", 1) for item in plugin.split(";") if "=" in item
        )
        node["plugin"] = "obfs-local"
        node["plugin_opts"] = f"obfs={parts.get('obfs', 'http')};obfs-host={parts.get('obfs-host', host)};"
    elif plugin.startswith("v2ray-plugin"):
        node["plugin"] = "v2ray-plugin"
        node["plugin_opts"] = f"mode=websocket;host={query.get('host', host)};path={query.get('path', '/')};"
    return node


def _vmess(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    decoded = b64text(main)
    if not decoded:
        return None
    if decoded.lstrip().startswith("{"):
        try:
            item = json.loads(decoded)
        except (ValueError, TypeError):
            return None
        host = normalise_host(item.get("add"))
        port = as_int(item.get("port"))
        uuid = item.get("id")
        security = str(first(item.get("scy"), item.get("security"), "auto")).lower()
        tls_on = (str(item.get("tls", "")).lower() in ("tls", "true", "1")
                  or str(item.get("security", "")).lower() == "tls")
        network = str(first(item.get("net"), item.get("network"), "tcp")).lower()
        sni = first(item.get("sni"), item.get("host"), "")
        path = str(first(item.get("path"), "/"))
        host_header = first(item.get("host"), "")
        fingerprint = first(item.get("fp"), item.get("client-fingerprint"))
        pseudo = {
            "security": "tls" if tls_on else "none",
            "sni": sni, "type": network, "path": path, "host": host_header,
            "alpn": item.get("alpn"), "fp": fingerprint,
            "allowInsecure": "1" if as_bool(item.get("verify-cert") is False or
                                            item.get("skip-cert-verify")) else "",
        }
        label = fragment or clean_text(item.get("ps"))
        aid = as_int(first(item.get("aid"), item.get("alterId"), 0), 0)
    else:
        # 非标准的 security:uuid@host:port 形式
        if "@" not in decoded or ":" not in decoded:
            return None
        credentials, _, address = decoded.rpartition("@")
        security, uuid = credentials.split(":", 1)
        host, port = split_host_port(address)
        pseudo = dict(query)
        label = fragment
        aid = 0
    if security not in _VMESS_SECURITY:
        security = "auto"
    node = compact({
        "type": "vmess", "tag": make_tag(label, f"vmess-{host}"),
        "server": host, "server_port": port, "uuid": uuid,
        "security": security, "alter_id": aid, "packet_encoding": "xudp",
    })
    tls = _tls(pseudo)
    if tls:
        node["tls"] = tls
    transport = _transport(pseudo)
    if transport:
        node["transport"] = transport
    return node


def _vless(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    userinfo, host, port = endpoint(main)
    uuid = userinfo or query.get("uuid")
    if not uuid:
        return None
    security = str(first(query.get("security"), "none")).lower()
    node = compact({
        "type": "vless", "tag": make_tag(fragment, f"vless-{host}"),
        "server": host, "server_port": port, "uuid": uuid,
        "packet_encoding": first(query.get("packetencoding"), "xudp"),
    })
    flow = query.get("flow")
    if flow and "vision" in flow.lower():
        node["flow"] = "xtls-rprx-vision"
    tls = _tls(query, force=security in ("tls", "reality", "xtls"))
    if tls:
        node["tls"] = tls
    transport = _transport(query)
    if transport:
        node["transport"] = transport
    return node


def _trojan(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    password, host, port = endpoint(main)
    if not password:
        return None
    node = compact({
        "type": "trojan", "tag": make_tag(fragment, f"trojan-{host}"),
        "server": host, "server_port": port, "password": password,
    })
    node["tls"] = _tls(query, force=True) or {"enabled": True, "insecure": True}
    transport = _transport(query)
    if transport:
        node["transport"] = transport
    return node


def _hy2_tls(query: dict[str, str]) -> dict:
    sni = first(query.get("sni"), query.get("peer"), "")
    tls: dict[str, Any] = {"enabled": True}
    if sni:
        tls["server_name"] = clean_text(sni)
    if not sni or as_bool(first(query.get("insecure"), query.get("allowinsecure"))):
        tls["insecure"] = True
    tls["alpn"] = _alpn(query.get("alpn")) or ["h3"]
    return tls


def _hysteria2(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    userinfo, host, port = endpoint(main)
    password = first(query.get("auth"), query.get("password"), userinfo)
    if not password:
        return None
    node = compact({
        "type": "hysteria2", "tag": make_tag(fragment, f"hy2-{host}"),
        "server": host, "server_port": port, "password": password,
        "up_mbps": as_int(first(query.get("upmbps"), query.get("up")), None),
        "down_mbps": as_int(first(query.get("downmbps"), query.get("down")), None),
    })
    node["tls"] = _hy2_tls(query)
    obfs = query.get("obfs")
    if obfs and obfs.lower() != "none":
        node["obfs"] = {
            "type": obfs,
            "password": first(query.get("obfs-password"), query.get("obfs_password"),
                              query.get("obfspassword"), ""),
        }
    return node


def _hysteria(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    _, host, port = endpoint(main)
    auth = first(query.get("auth"), query.get("auth-str"), query.get("auth_str"))
    node = compact({
        "type": "hysteria", "tag": make_tag(fragment, f"hy-{host}"),
        "server": host, "server_port": port,
        "up_mbps": as_int(first(query.get("upmbps"), query.get("up")), None),
        "down_mbps": as_int(first(query.get("downmbps"), query.get("down")), None),
        "auth_str": auth, "obfs": query.get("obfs"),
    })
    node["tls"] = _hy2_tls(query)
    return node


def _tuic(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    userinfo, host, port = endpoint(main)
    if ":" in userinfo:
        uuid, password = userinfo.split(":", 1)
    else:
        uuid = userinfo
        password = first(query.get("password"), query.get("token"), "")
    if not uuid or not password:
        return None
    node = compact({
        "type": "tuic", "tag": make_tag(fragment, f"tuic-{host}"),
        "server": host, "server_port": port, "uuid": uuid, "password": password,
        "congestion_control": first(query.get("congestion_control"),
                                    query.get("congestion-controller"), "bbr"),
        "udp_relay_mode": first(query.get("udp_relay_mode"),
                                query.get("udp-relay-mode")),
    })
    node["tls"] = _hy2_tls(query)
    if query.get("sni"):
        node["tls"]["server_name"] = query["sni"]
    return node


def _reserved(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return list(value)
    parts = [p.strip() for p in str(value).split(",")]
    if all(p.isdigit() for p in parts):
        return [int(p) for p in parts]
    return str(value)


def _wireguard(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    userinfo, host, port = endpoint(main)
    private = first(query.get("privatekey"), query.get("private_key"), userinfo)
    peer = first(query.get("publickey"), query.get("public_key"),
                 query.get("peer_public_key"))
    if not private or not peer:
        return None
    addresses = []
    raw = first(query.get("ip"), query.get("address"), query.get("local_address"), "")
    for part in re.split(r"[,;]", str(raw)):
        part = part.strip().replace(" ", "+")
        if not part:
            continue
        if "/" not in part:
            part += "/128" if ":" in part else "/32"
        addresses.append(part)
    if not addresses:
        return None
    return compact({
        "type": "wireguard", "tag": make_tag(fragment, f"wg-{host}"),
        "server": host, "server_port": port,
        "private_key": urllib.parse.unquote(str(private)),
        "peer_public_key": urllib.parse.unquote(str(peer)),
        "local_address": addresses,
        "pre_shared_key": first(query.get("presharedkey"), query.get("pre_shared_key")),
        "reserved": _reserved(query.get("reserved")),
        "mtu": as_int(query.get("mtu"), None),
    })


def _simple(uri: str, kind: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    userinfo, host, port = endpoint(main)
    if ":" in userinfo:
        username, password = userinfo.split(":", 1)
    else:
        username, password = userinfo, query.get("password", "")
    # 有些 socks 订阅把 user:pass 整体做了 base64
    if (not password and len(username) >= 8
            and re.fullmatch(r"[A-Za-z0-9+/=_-]+", username)):
        decoded = b64text(username)
        if decoded and ":" in decoded and all(32 <= ord(char) < 127 for char in decoded):
            username, password = decoded.split(":", 1)
    node = compact({
        "type": kind, "tag": make_tag(fragment, f"{kind}-{host}"),
        "server": host, "server_port": port,
        "username": username or None, "password": password or None,
    })
    if kind == "socks":
        node["version"] = "5"
    tls = _tls(query)
    if tls:
        node["tls"] = tls
    return node


def _anytls(uri: str) -> dict | None:
    _, main, query, fragment = split_uri(uri)
    password, host, port = endpoint(main)
    if not password:
        return None
    node = compact({
        "type": "anytls", "tag": make_tag(fragment, f"anytls-{host}"),
        "server": host, "server_port": port, "password": password,
    })
    tls = _tls(query, force=True)
    if tls:
        node["tls"] = tls
    return node


_URI_HANDLERS: dict[str, Callable[[str], dict | None]] = {
    "ss": _ss,
    "vmess": _vmess,
    "vless": _vless,
    "trojan": _trojan,
    "hysteria2": _hysteria2,
    "hy2": _hysteria2,
    "hysteria": _hysteria,
    "hy": _hysteria,
    "tuic": _tuic,
    "wireguard": _wireguard,
    "wg": _wireguard,
    "socks": lambda u: _simple(u, "socks"),
    "socks5": lambda u: _simple(u, "socks"),
    "http": lambda u: _simple(u, "http"),
    "https": lambda u: _simple(u, "http"),
    "anytls": _anytls,
}


def minimally_valid(node: dict) -> bool:
    """解析阶段的最低门槛：端点、端口、UUID 必须成立。"""
    if not node.get("server") or not isinstance(node.get("server_port"), int):
        return False
    if not 1 <= node["server_port"] <= 65535:
        return False
    if node.get("type") in ("vmess", "vless", "tuic"):
        if not UUID_RE.match(str(node.get("uuid", ""))):
            return False
    return True


def parse_line(line: str) -> dict | None:
    """解析一条订阅行；任何异常都视为无效数据。"""
    text = clean_text(line)
    if not text or text.startswith(("#", "//", ";")):
        return None
    scheme, _, _ = text.partition("://")
    handler = _URI_HANDLERS.get(scheme.lower())
    if handler is None:
        return None
    try:
        node = handler(text)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        return None
    if not isinstance(node, dict) or node.get("type") not in SUPPORTED_TYPES:
        return None
    node = compact(node)
    return node if minimally_valid(node) else None


# ---------------------------------------------------------------------------
# Clash / Clash.Meta YAML proxies
# ---------------------------------------------------------------------------

def _clash_common(proxy: dict, kind: str, extra: dict) -> dict:
    host = normalise_host(proxy.get("server"))
    node = {
        "type": kind,
        "tag": clean_text(proxy.get("name"), 100) or f"{kind}-{host}",
        "server": host,
        "server_port": as_int(proxy.get("port")),
    }
    node.update(compact(extra))
    return node


def _clash_tls(proxy: dict, *, force: bool = False) -> dict | None:
    security = str(first(proxy.get("security"), "")).lower()
    enabled = (force or as_bool(proxy.get("tls"))
               or security in ("tls", "reality"))
    if not enabled:
        return None
    tls: dict[str, Any] = {"enabled": True}
    sni = first(proxy.get("sni"), proxy.get("servername"),
                proxy.get("server-name"), proxy.get("peer"))
    if sni:
        tls["server_name"] = clean_text(sni)
    if as_bool(first(proxy.get("skip-cert-verify"), proxy.get("insecure"))):
        tls["insecure"] = True
    fingerprint = first(proxy.get("client-fingerprint"), proxy.get("fingerprint"))
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": clean_text(fingerprint)}
    alpn = _alpn(proxy.get("alpn"))
    if alpn:
        tls["alpn"] = alpn
    reality = proxy.get("reality-opts") or proxy.get("reality_opts") or {}
    if isinstance(reality, dict) and (reality.get("public-key") or reality.get("public_key")):
        tls["reality"] = compact({
            "enabled": True,
            "public_key": first(reality.get("public-key"), reality.get("public_key")),
            "short_id": first(reality.get("short-id"), reality.get("short_id")),
        })
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return tls


def _clash_transport(proxy: dict) -> dict | None:
    network = str(first(proxy.get("network"), proxy.get("net"), "tcp")).lower()
    if network in ("ws", "websocket"):
        opts = proxy.get("ws-opts") or proxy.get("ws_opts") or {}
        headers = opts.get("headers") or {}
        path = str(first(opts.get("path"), proxy.get("ws-path"), "/"))
        host = first(headers.get("Host"), headers.get("host"), "")
        transport: dict[str, Any] = {"type": "ws"}
        match = re.search(r"\?ed=(\d+)$", path)
        if match:
            path = path[:match.start()]
            transport["max_early_data"] = int(match.group(1))
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["path"] = path or "/"
        if host:
            transport["headers"] = {"Host": clean_text(host)}
        return transport
    if network == "grpc":
        opts = proxy.get("grpc-opts") or proxy.get("grpc_opts") or {}
        return compact({"type": "grpc",
                        "service_name": first(opts.get("grpc-service-name"),
                                              opts.get("grpc_service_name"), "")})
    if network in ("h2", "http", "http2"):
        opts = proxy.get("h2-opts") or proxy.get("h2_opts") or {}
        hosts = opts.get("host") or []
        if isinstance(hosts, str):
            hosts = [hosts]
        return compact({"type": "http", "host": hosts or None,
                        "path": first(opts.get("path"), proxy.get("path"), "/")})
    if network == "httpupgrade":
        opts = proxy.get("ws-opts") or {}
        return compact({"type": "httpupgrade",
                        "host": clean_text(opts.get("Host") or proxy.get("host")) or None,
                        "path": opts.get("path") or "/"})
    return None


def _attach(node: dict, proxy: dict, *, tls_force: bool = False) -> dict:
    tls = _clash_tls(proxy, force=tls_force)
    if tls:
        node["tls"] = tls
    transport = _clash_transport(proxy)
    if transport:
        node["transport"] = transport
    return node


def _c_ss(proxy: dict) -> dict | None:
    method = str(first(proxy.get("cipher"), proxy.get("method"), "")).lower()
    if method not in _SS_METHODS:
        return None
    node = _clash_common(proxy, "shadowsocks", {
        "method": method, "password": proxy.get("password"),
    })
    plugin = str(first(proxy.get("plugin"), "")).lower()
    opts = proxy.get("plugin-opts") or proxy.get("plugin_opts") or {}
    if plugin in ("obfs", "simple-obfs", "obfs-local"):
        node["plugin"] = "obfs-local"
        node["plugin_opts"] = (
            f"obfs={first(opts.get('mode'), opts.get('obfs'), 'http')};"
            f"obfs-host={opts.get('host', node['server'])};"
        )
    elif plugin == "v2ray-plugin":
        node["plugin"] = "v2ray-plugin"
        node["plugin_opts"] = (
            f"mode={opts.get('mode', 'websocket')};"
            f"host={opts.get('host', node['server'])};"
            f"path={opts.get('path', '/')};"
            + ("tls;" if as_bool(opts.get("tls")) else "")
        )
    return node


def _c_vmess(proxy: dict) -> dict | None:
    security = str(first(proxy.get("cipher"), proxy.get("security"), "auto")).lower()
    node = _clash_common(proxy, "vmess", {
        "uuid": proxy.get("uuid"),
        "security": security if security in _VMESS_SECURITY else "auto",
        "alter_id": as_int(first(proxy.get("alterId"), proxy.get("alter_id"), 0), 0),
        "packet_encoding": first(proxy.get("packet-encoding"),
                                 proxy.get("packet_encoding"), "xudp"),
    })
    return _attach(node, proxy)


def _c_vless(proxy: dict) -> dict | None:
    node = _clash_common(proxy, "vless", {
        "uuid": proxy.get("uuid"),
        "flow": proxy.get("flow"),
        "packet_encoding": first(proxy.get("packet-encoding"),
                                 proxy.get("packet_encoding"), "xudp"),
    })
    return _attach(node, proxy, tls_force=as_bool(proxy.get("tls")))


def _c_trojan(proxy: dict) -> dict | None:
    node = _clash_common(proxy, "trojan", {"password": proxy.get("password")})
    tls = _clash_tls(proxy, force=True) or {"enabled": True}
    tls.setdefault("insecure", True)
    node["tls"] = tls
    transport = _clash_transport(proxy)
    if transport:
        node["transport"] = transport
    return node


def _c_hysteria2(proxy: dict) -> dict | None:
    node = _clash_common(proxy, "hysteria2", {
        "password": proxy.get("password"),
        "up_mbps": as_int(first(proxy.get("up"), proxy.get("up_mbps")), None),
        "down_mbps": as_int(first(proxy.get("down"), proxy.get("down_mbps")), None),
    })
    pseudo = {
        "sni": first(proxy.get("sni"), proxy.get("servername"), ""),
        "alpn": proxy.get("alpn"),
        "insecure": "1" if as_bool(proxy.get("skip-cert-verify")) else "",
    }
    node["tls"] = _hy2_tls(pseudo)
    obfs = proxy.get("obfs")
    if obfs and str(obfs).lower() != "none":
        node["obfs"] = {"type": obfs,
                        "password": first(proxy.get("obfs-password"),
                                          proxy.get("obfs_password"), "")}
    return node


def _c_hysteria(proxy: dict) -> dict | None:
    node = _clash_common(proxy, "hysteria", {
        "auth_str": first(proxy.get("auth-str"), proxy.get("auth_str"), proxy.get("auth")),
        "up_mbps": as_int(first(proxy.get("up"), proxy.get("up_mbps")), None),
        "down_mbps": as_int(first(proxy.get("down"), proxy.get("down_mbps")), None),
        "obfs": proxy.get("obfs"),
    })
    node["tls"] = _hy2_tls({
        "sni": first(proxy.get("sni"), proxy.get("servername"), ""),
        "alpn": proxy.get("alpn"),
        "insecure": "1" if as_bool(proxy.get("skip-cert-verify")) else "",
    })
    return node


def _c_tuic(proxy: dict) -> dict | None:
    node = _clash_common(proxy, "tuic", {
        "uuid": first(proxy.get("uuid"), proxy.get("token")),
        "password": proxy.get("password"),
        "congestion_control": first(proxy.get("congestion-controller"),
                                    proxy.get("congestion_control"), "bbr"),
        "udp_relay_mode": first(proxy.get("udp-relay-mode"), proxy.get("udp_relay_mode")),
        "zero_rtt_handshake": True if as_bool(proxy.get("reduce-rtt")) else None,
    })
    node["tls"] = _hy2_tls({
        "sni": first(proxy.get("sni"), proxy.get("servername"), ""),
        "alpn": proxy.get("alpn"),
        "insecure": "1" if as_bool(proxy.get("skip-cert-verify")) else "",
    })
    return node


def _c_wireguard(proxy: dict) -> dict | None:
    private = first(proxy.get("private-key"), proxy.get("private_key"))
    peer = first(proxy.get("public-key"), proxy.get("public_key"),
                 proxy.get("peer-public-key"))
    if not private or not peer:
        return None
    addresses = []
    for value in (proxy.get("ip"), proxy.get("ipv6"), proxy.get("local-address")):
        if not value:
            continue
        value = str(value).strip()
        if "/" not in value:
            value += "/128" if ":" in value else "/32"
        addresses.append(value)
    if not addresses:
        return None
    return compact(_clash_common(proxy, "wireguard", {
        "private_key": private, "peer_public_key": peer,
        "local_address": addresses,
        "pre_shared_key": first(proxy.get("pre-shared-key"),
                                proxy.get("pre_shared_key")),
        "reserved": _reserved(proxy.get("reserved")),
        "mtu": as_int(proxy.get("mtu"), None),
    }))


def _c_simple(proxy: dict, kind: str) -> dict | None:
    return compact(_clash_common(proxy, kind, {
        "username": proxy.get("username"), "password": proxy.get("password"),
        **({"version": "5"} if kind == "socks" else {}),
    }))


def _c_anytls(proxy: dict) -> dict | None:
    node = _clash_common(proxy, "anytls", {"password": proxy.get("password")})
    tls = _clash_tls(proxy, force=True)
    if tls:
        node["tls"] = tls
    return node


_CLASH_HANDLERS: dict[str, Callable[[dict], dict | None]] = {
    "ss": _c_ss,
    "shadowsocks": _c_ss,
    "vmess": _c_vmess,
    "vless": _c_vless,
    "trojan": _c_trojan,
    "hysteria": _c_hysteria,
    "hysteria2": _c_hysteria2,
    "tuic": _c_tuic,
    "wireguard": _c_wireguard,
    "socks5": lambda p: _c_simple(p, "socks"),
    "socks": lambda p: _c_simple(p, "socks"),
    "http": lambda p: _c_simple(p, "http"),
    "anytls": _c_anytls,
}


def parse_clash_proxy(proxy: Any) -> dict | None:
    """解析 Clash YAML 中的一条 proxies 记录。"""
    if not isinstance(proxy, dict):
        return None
    kind = str(first(proxy.get("type"), "")).lower().replace("_", "-")
    handler = _CLASH_HANDLERS.get(kind)
    if handler is None:
        return None
    try:
        node = handler(proxy)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        return None
    if not isinstance(node, dict) or node.get("type") not in SUPPORTED_TYPES:
        return None
    node = compact(node)
    return node if minimally_valid(node) else None
