"""订阅收集：并发抓取、解压与内容识别。

识别四类载荷：Clash YAML / JSON、base64 订阅、纯 URI 列表、
以及少量 JSON 节点列表。输出统一的 (字符串 | 字典) 条目流。
"""
from __future__ import annotations

import gzip
import json
import re
import urllib.error
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Iterable

from .util import b64text, clean_text

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML 由 requirements.txt 提供
    yaml = None

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0.0.0 Safari/537.36 Honeybee/2.0")

_URI_LINE = re.compile(r"^\s*[a-zA-Z][a-zA-Z0-9+.-]*://", re.I | re.M)
_B64_LINE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


@dataclass
class Source:
    name: str
    url: str
    kind: str = "auto"
    enabled: bool = True


@dataclass
class FetchResult:
    source: Source
    ok: bool
    entries: list[Any] = field(default_factory=list)
    error: str = ""
    raw_bytes: int = 0


def load_sources(path: str) -> list[Source]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return [
        Source(
            name=item.get("name") or item["url"],
            url=item["url"],
            kind=item.get("kind", "auto"),
            enabled=bool(item.get("enabled", True)),
        )
        for item in data.get("sources", [])
    ]


def fetch(url: str, *, timeout: float = 15.0, max_bytes: int = 8 * 1024 * 1024,
          user_agent: str = DEFAULT_UA, retries: int = 1) -> tuple[str, str, int]:
    """返回 (text, error, bytes)。失败时 text 为空。"""
    last_error = ""
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
            })
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    return "", "response too large", len(raw)
                encoding = (response.headers.get("Content-Encoding") or "").lower()
                if encoding == "gzip":
                    raw = gzip.decompress(raw)
                elif encoding == "deflate":
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                text = raw.decode("utf-8", errors="replace")
            return text, "", len(raw)
        except (urllib.error.URLError, OSError, ValueError, EOFError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
    return "", last_error, 0


def _yaml_proxies(text: str) -> list[dict] | None:
    if yaml is None or not re.search(r"^\s*proxies\s*:", text, re.M):
        return None
    # 公开订阅里常见的脏字符，先做无损清洗再交给解析器
    text = text.replace("!<str>", "")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    try:
        data = yaml.safe_load(text)
    except Exception:
        return None
    if isinstance(data, dict):
        proxies = data.get("proxies")
    elif isinstance(data, list):
        proxies = data
    else:
        proxies = None
    if not isinstance(proxies, list):
        return None
    return [item for item in proxies if isinstance(item, dict)]


def _json_payload(text: str) -> list[Any] | None:
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        data = json.loads(stripped)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict):
        for key in ("proxies", "nodes", "outbounds", "data", "list"):
            value = data.get(key)
            if isinstance(value, list) and value and isinstance(value[0], (dict, str)):
                return list(value)
        return None
    if isinstance(data, list):
        return [item for item in data if isinstance(item, (dict, str))]
    return None


def _looks_base64(text: str) -> bool:
    stripped = re.sub(r"\s+", "", text)
    return len(stripped) >= 16 and bool(_B64_LINE.match(stripped))


def decode(text: str, kind: str = "auto") -> list[Any]:
    """把一份订阅正文拆成可转换的条目。"""
    text = (text or "").strip()
    if not text:
        return []

    # base64 订阅（可能带 URL-safe 字符、缺 padding）
    if kind in ("auto", "base64") and _looks_base64(text):
        decoded = b64text(text)
        if decoded and (_URI_LINE.search(decoded) or "proxies" in decoded[:2000]):
            text = decoded
        elif kind == "base64":
            return []

    if kind in ("auto", "json"):
        json_entries = _json_payload(text)
        if json_entries:
            return json_entries

    if kind in ("auto", "clash"):
        proxies = _yaml_proxies(text)
        if proxies:
            return proxies

    lines = []
    for raw_line in text.replace("\r\n", "\n").splitlines():
        line = clean_text(raw_line)
        if line and not line.startswith(("#", "//", ";")):
            lines.append(line)
    return lines


def collect(sources: Iterable[Source], *, workers: int = 12,
            timeout: float = 15.0, max_bytes: int = 8 * 1024 * 1024,
            user_agent: str = DEFAULT_UA, retries: int = 1,
            fetcher=fetch) -> list[FetchResult]:
    """并发抓取并解码所有启用的源。"""
    active = [source for source in sources if source.enabled]
    results: list[FetchResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(fetcher, source.url, timeout=timeout, max_bytes=max_bytes,
                        user_agent=user_agent, retries=retries): source
            for source in active
        }
        for future in as_completed(futures):
            source = futures[future]
            try:
                text, error, size = future.result()
            except Exception as exc:  # 单个源失败不影响整体
                results.append(FetchResult(source, False, error=f"{type(exc).__name__}: {exc}"))
                continue
            if error or not text.strip():
                results.append(FetchResult(source, False, error=error or "empty response",
                                           raw_bytes=size))
                continue
            try:
                entries = decode(text, source.kind)
            except Exception as exc:
                results.append(FetchResult(source, False,
                                           error=f"decode: {type(exc).__name__}: {exc}",
                                           raw_bytes=size))
                continue
            results.append(FetchResult(source, True, entries=entries,
                                       error="" if entries else "no usable entries",
                                       raw_bytes=size))
    return results
