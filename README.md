# Honeybee

收集公开代理订阅 → 清理 → 检查验证 → 拆分 → 转换为 sing-box JSON → 压缩成**一个文件**。

产物固定落在 [`sub/sub.tar.gz`](sub/sub.tar.gz)，可直接在 sing-box 里使用压缩包内的任意一份 JSON。

## 流水线

| 阶段 | 实现 | 做什么 |
| --- | --- | --- |
| 收集 | `honeybee/collect.py` | 并发抓取 `config/sources.json` 里的订阅，自动识别 Clash YAML / JSON / base64 / 纯 URI 列表，单个源失败不影响整体 |
| 解析 | `honeybee/convert.py` | 纯 Python 把 URI 与 Clash proxies 转成 sing-box 1.12 outbound，**不再下载 clash2singbox 二进制、不再跑 subconverter 容器** |
| 清理 | `honeybee/clean.py` | 去控制字符、过滤私有/保留地址与非法端口、按协议白名单过滤、跨源按端点+凭据去重、tag 唯一化 |
| 规范化 | `honeybee/sanitize.py` | 修掉订阅里常见的脏字段：非法 uTLS 指纹、非 base64 的 reality 公钥、坏的 `%` 转义、不兼容的 obfs / packet_encoding |
| 验证 | `honeybee/verify.py` | 必填字段、UUID、端口、TLS/transport 结构、分组引用闭合；一次性剔除坏节点。CI 里再用官方 `sing-box check` 逐份复核 |
| 拆分 | `honeybee/split.py` | 按 `max_per_file` 切片，每片都是完整配置，自动重建 `selector` / `urltest` 引用 |
| 打包 | `honeybee/build.py` | 生成 `honeybee-001.json`… 与 `manifest.json`，用确定性 gzip 打成 **一个** `sub.tar.gz` |

默认输出协议：`shadowsocks`、`vmess`、`vless`、`trojan`、`hysteria2`、`tuic`、`anytls`、`socks`、`http`。
`ssr`、`hysteria v1` 不被 sing-box 支持，`wireguard` 的 legacy outbound 在 1.12 已弃用，默认都不进产物。
解析器仍然认识它们，需要时可在 `config/settings.json` 的 `allowed_protocols` 里放开。

## 快速开始

```bash
pip install -r requirements.txt          # 只依赖 PyYAML
python -m unittest discover -s tests -v # 跑测试
python -m honeybee build                # 联网跑完整流水线，产出 sub/sub.tar.gz
python -m honeybee inspect              # 检查压缩包内容与配置合法性

# 不联网、只转换一份本地样本（排障用）
python -m honeybee build --offline sample.txt --output /tmp/try.tar.gz --max-per-file 50
```

`sub/sub.tar.gz` 内容：

```
manifest.json          节点总数、协议分布、各源抓取结果、内容 sha256
honeybee-001.json      完整 sing-box 配置（≤ max_per_file 个节点）
honeybee-002.json      ...
```

用 `config/base.json` 定制 DNS、路由、入站与分组；`{all}` 占位符会被替换成本片所有节点 tag。
需要 sing-box **1.12 或更新版本**（`route.final`、`action` 等字段为 1.11+ 写法）。

## 配置

| 文件 | 用途 |
| --- | --- |
| `config/sources.json` | 订阅源清单。改 `enabled`、`kind`（`auto` / `clash` / `base64` / `json`）或直接增删条目即可 |
| `config/settings.json` | 抓取并发/超时、协议白名单、清洗规则、分片大小 |
| `config/base.json` | sing-box 基础配置模板 |

源失效会自动记录到 `manifest.json` 的 `sources[].error`，不会中断构建。
`collect.max_entries_per_source`（默认 3000）与 `clean.max_nodes`（默认 30000）控制总量，
各源**轮流取样**，避免某个大订阅独占产物；想全量收集把这两个值调大即可。
如果**一个可用节点都没抓到**，构建会报错并保持已有产物不变，避免推空配置。

产物经过官方 `sing-box 1.12.1 check` 逐份复核（本地可跑
`python -m honeybee verify-bundle --sing-box /path/to/sing-box`）；官方二进制只在运行时下载，不入库。

## GitHub Actions

只有一个工作流：`.github/workflows/build.yml`。

```
定时（每 3 小时）、手动触发，或 push/PR 且只改动以下路径时：
  honeybee/** · config/** · tests/** · requirements.txt · .github/workflows/build.yml
```

- 产物 `sub/sub.tar.gz` 的自动回写**不会**再次触发流水线（`paths` 过滤 + `GITHUB_TOKEN` 推送的防循环规则双保险）。
- 不再有 `workflow_run` 串联：`Download → conversion → verification → management` 那条链已删除。
- `concurrency` 保证同一时刻只有一个构建，新任务会取消旧任务。
- 构建后会用官方 sing-box 1.12.1 逐份 `check`，二进制运行时下载、不入库；下载失败不阻塞（静态校验已完成）。
- 手动触发可指定 `max_per_file` 与 `dry_run`（只构建、不写回仓库）。

> 旧仓库 8 个 workflow 都挂在 `push: main` 上，又互相用 `workflow_run` 触发，
> 加上每次运行都自动 commit 产物，形成了自我触发的循环——历史里堆了四万多次提交。
> 现在源码改动之外的任何文件变动都不会拉起流水线。

## 相比旧仓库清掉了什么

| 删除 | 原因 |
| --- | --- |
| `clash2singbox`（5.6 MB 二进制）、`sing-box`（44 MB × 2）、`GeoLite2-Country.mmdb`、`pup_*.zip` | 二进制不该入库；转换改由纯 Python 完成，官方 sing-box 只在需要时运行时下载 |
| `sing-box-sub/` 整个第三方项目（含 `__pycache__`、重复的 `sing-box-subscribe-no-flask-2.8.0/` 副本） | 与 `newmain.py` 重复，依赖 Flask / ruamel.yaml / paramiko，维护成本高 |
| `newmain.py`、`filter*.py`、`run.sh`、`eop-clean.sh`、`sbfrom*.sh`、`check_clean.sh`、`large_config_split.py` 等 | 逻辑分散在多份脚本里，URL 硬编码，且拆分/校验实现有缺陷；已由 `honeybee/` 包统一替代 |
| `sub/` 下几十个 yaml/json/txt 中间产物、`sub.txt`、旧 `sub.tar.gz` 之外的文件 | 中间产物不再入库，只保留最终压缩包 |
| `requirements.txt` 里的 `paramiko` / `scp` / `flask` / `chardet` / `ruamel.yaml` | 全部不再需要，现在只有一个 PyYAML |

订阅源从四份 shell 脚本里汇总成 `config/sources.json` 一处维护；
原来依赖的第三方 subconverter 服务（`api-suc.0z.gs` 等）也已去掉，直接抓原始源。

## 目录

```
.github/workflows/build.yml   唯一工作流
honeybee/                    流水线源码（标准库 + PyYAML）
config/                      源清单、清洗规则、sing-box 模板
tests/                       单元测试
sub/sub.tar.gz               唯一交付产物
```
