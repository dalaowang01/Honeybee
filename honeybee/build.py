"""编排：收集 -> 解析 -> 清理 -> 验证 -> 拆分 -> 压缩为单个文件。

产物是一个 tar.gz，内含若干份完整 sing-box JSON 与一份 manifest.json。
输出做确定性压缩（tar/gzip mtime 固定为 0），节点没变化时产物字节不变，
因此 CI 不会因为时间戳差异制造无意义的提交。
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
from collections import Counter
from typing import Any, Callable

from . import clean, collect, convert, split, verify


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_bundle(output: str, files: dict[str, str]) -> int:
    """把 {文件名: 文本} 写成一个确定性 gzip 压缩的 tar。"""
    parent = os.path.dirname(os.path.abspath(output))
    os.makedirs(parent, exist_ok=True)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            data = files[name].encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    payload = archive.getvalue()
    with open(output, "wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9,
                          mtime=0, fileobj=handle) as zipped:
            zipped.write(payload)
    return os.path.getsize(output)


def read_bundle(path: str) -> dict[str, str]:
    with gzip.open(path, "rb") as zipped:
        raw = zipped.read()
    result: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            handle = tar.extractfile(member)
            if handle is not None:
                result[member.name] = handle.read().decode("utf-8")
    return result


def inspect_bundle(path: str) -> dict:
    """读取压缩包并做一次静态校验，返回摘要。"""
    files = read_bundle(path)
    problems: list[str] = []
    node_total = 0
    for name, text in files.items():
        if not name.endswith(".json") or name == "manifest.json":
            continue
        config = json.loads(text)
        problems.extend(f"{name}: {problem}" for problem in verify.verify_config(config))
        node_total += sum(
            1 for outbound in config.get("outbounds", [])
            if outbound.get("type") in verify.REQUIRED_FIELDS
        )
    manifest = json.loads(files["manifest.json"]) if "manifest.json" in files else {}
    return {
        "files": sorted(files),
        "config_nodes": node_total,
        "manifest_nodes": manifest.get("total_nodes"),
        "content_hash": manifest.get("content_hash"),
        "problems": problems,
    }


def verify_with_singbox(bundle_path: str, binary: str) -> tuple[int, list[str]]:
    """用官方 sing-box 逐份复核压缩包里的配置。二进制没装时只做跳过。"""
    import tempfile

    files = read_bundle(bundle_path)
    problems: list[str] = []
    checked = 0
    with tempfile.TemporaryDirectory() as folder:
        for name in sorted(files):
            if not name.endswith(".json") or name == "manifest.json":
                continue
            path = os.path.join(folder, os.path.basename(name))
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(files[name])
            ok, output = verify.singbox_check(path, binary)
            checked += 1
            if not ok:
                problems.append(f"{name}: {output.strip()[:400]}")
    return checked, problems


def build(*, sources_path: str, settings_path: str, base_path: str, output: str,
          max_per_file: int | None = None, offline: str | None = None,
          fetcher: Callable | None = None, verbose: bool = True) -> dict:
    """跑完整条流水线并返回统计报告。"""
    settings = load_json(settings_path)
    base = load_json(base_path)
    request = settings.get("request", {})
    limit = int(max_per_file or settings.get("split", {}).get("max_per_file", 500))
    prefix = settings.get("split", {}).get("prefix", "honeybee")

    if offline:
        with open(offline, "r", encoding="utf-8") as handle:
            entries = collect.decode(handle.read())
        results = [collect.FetchResult(
            collect.Source("offline", os.path.basename(offline)), True,
            entries=entries, raw_bytes=len(entries),
        )]
    else:
        sources = collect.load_sources(sources_path)
        kwargs = dict(
            workers=int(request.get("workers", 12)),
            timeout=float(request.get("timeout", 15)),
            max_bytes=int(request.get("max_bytes", 8 * 1024 * 1024)),
            user_agent=request.get("user_agent", collect.DEFAULT_UA),
            retries=int(request.get("retries", 1)),
        )
        if fetcher is not None:
            kwargs["fetcher"] = fetcher
        results = collect.collect(sources, **kwargs)

    per_source_limit = int(settings.get("collect", {}).get("max_entries_per_source", 0))
    chunks: list[list[Any]] = []
    source_report: list[dict] = []
    for result in sorted(results, key=lambda item: item.source.name):
        chunk = result.entries
        if per_source_limit and len(chunk) > per_source_limit:
            chunk = chunk[:per_source_limit]
        chunks.append(chunk)
        source_report.append({
            "name": result.source.name,
            "url": result.source.url,
            "ok": bool(result.ok and result.entries),
            "entries": len(result.entries),
            "used": len(chunk),
            "error": result.error,
        })

    # 各源轮流取样：全局 max_nodes 才不会只吃到字母序靠前的几个源
    entries: list[Any] = []
    for index in range(max((len(chunk) for chunk in chunks), default=0)):
        for chunk in chunks:
            if index < len(chunk):
                entries.append(chunk[index])

    parsed: list[dict] = []
    for entry in entries:
        node = (convert.parse_clash_proxy(entry) if isinstance(entry, dict)
                else convert.parse_line(entry))
        if node:
            parsed.append(node)

    reserved_tags = {
        item["tag"]
        for section in ("outbounds", "inbounds", "endpoints")
        for item in base.get(section, [])
        if isinstance(item, dict) and item.get("tag")
    }
    max_nodes = int(settings.get("clean", {}).get("max_nodes", 0)) or None
    cleaned, clean_stats = clean.clean_nodes(
        parsed, settings, reserved_tags=reserved_tags, max_nodes=max_nodes)
    valid, issues = verify.verify_nodes(cleaned)

    if not valid:
        raise RuntimeError(
            "没有拿到任何可用节点，保留现有产物不覆盖。"
            f" 抓取 {len(entries)} 条，解析 {len(parsed)} 条，源失败 "
            f"{sum(1 for item in source_report if not item['ok'])} 个。"
        )

    configs = split.split_configs(base, valid, limit, prefix)
    files: dict[str, str] = {}
    file_report: list[dict] = []
    for name, config, count in configs:
        files[name] = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
        file_report.append({"name": name, "nodes": count})

    canonical = json.dumps(valid, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    manifest = {
        "format": "honeybee/2",
        "content_hash": content_hash,
        "total_nodes": len(valid),
        "max_per_file": limit,
        "protocols": dict(sorted(Counter(node["type"] for node in valid).items())),
        "files": file_report,
        "sources": source_report,
        "stats": {
            "sources_total": len(source_report),
            "sources_ok": sum(1 for item in source_report if item["ok"]),
            "entries": len(entries),
            "parsed": len(parsed),
            "clean": clean_stats,
            "verify_dropped": len(issues),
            "verify_issues": issues[:20],
        },
    }
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"

    bundle_bytes = write_bundle(output, files)
    report = {
        "output": output,
        "bytes": bundle_bytes,
        "total_nodes": len(valid),
        "files": len(configs),
        "sources_total": len(source_report),
        "sources_ok": sum(1 for item in source_report if item["ok"]),
        "entries": len(entries),
        "parsed": len(parsed),
        "clean_dropped": clean_stats["input"] - clean_stats["output"],
        "verify_dropped": len(issues),
        "protocols": manifest["protocols"],
        "content_hash": content_hash,
    }
    if verbose:
        print(f"[honeybee] sources  {report['sources_ok']}/{report['sources_total']} ok")
        print(f"[honeybee] entries  {report['entries']} -> parsed {report['parsed']}")
        print(f"[honeybee] dropped  clean {report['clean_dropped']}, verify {report['verify_dropped']}")
        print(f"[honeybee] nodes    {report['total_nodes']} -> {report['files']} configs")
        print(f"[honeybee] protocols {manifest['protocols']}")
        print(f"[honeybee] bundle   {output} ({bundle_bytes} bytes)")
        for item in source_report:
            if not item["ok"]:
                print(f"[honeybee]   ! {item['name']}: {item['error']}")
    return report
