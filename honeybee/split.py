"""拆分：按节点数上限生成多份可直接使用的完整 sing-box 配置。

每份配置都自带 selector / urltest / direct / block，并把 {all}
占位符替换成本片的节点 tag，不会出现引用悬空。
"""
from __future__ import annotations

import copy
from typing import Any


def chunks(nodes: list[dict], max_per_file: int) -> list[list[dict]]:
    size = max(1, int(max_per_file))
    return [nodes[i:i + size] for i in range(0, len(nodes), size)]


def render_config(base: dict, nodes: list[dict]) -> dict:
    """把一组节点注入基础模板，展开分组引用。"""
    config = copy.deepcopy(base)
    tags = [node["tag"] for node in nodes]
    outbounds = config.setdefault("outbounds", [])
    for outbound in outbounds:
        if not isinstance(outbound, dict) or not isinstance(outbound.get("outbounds"), list):
            continue
        expanded: list[str] = []
        for reference in outbound["outbounds"]:
            if reference == "{all}":
                expanded.extend(tags)
            else:
                expanded.append(reference)
        outbound["outbounds"] = list(dict.fromkeys(expanded))
        if outbound["outbounds"] and outbound["outbounds"] == ["{all}"]:
            outbound["outbounds"] = []
    outbounds.extend(copy.deepcopy(nodes))
    return config


def split_configs(base: dict, nodes: list[dict], max_per_file: int = 500,
                  prefix: str = "honeybee") -> list[tuple[str, dict, int]]:
    """返回 [(文件名, 配置, 节点数)]。"""
    groups = chunks(nodes, max_per_file)
    width = max(3, len(str(len(groups))))
    return [
        (f"{prefix}-{index + 1:0{width}d}.json",
         render_config(base, group), len(group))
        for index, group in enumerate(groups)
    ]
