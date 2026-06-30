# AGENTS.md

本文件适用于整个仓库。若下层目录后续新增自己的 `AGENTS.md` 或 `AGENTS.override.md`，该文件应在子树内收窄或覆盖此处规则。

## 项目概览

- `traffic-monitor` 是一个 Go 单二进制服务：定时轮询 Mihomo 的 `/connections`，把流量增量先聚合到内存，再按分钟桶批量写入 SQLite，并通过内嵌 Web 页面提供设备 / 域名 / IP / 代理维度的统计与链路明细。
- 后端与前端同仓同发，无前端构建步骤。`web/` 下是纯静态资源，由 Go 在编译期内嵌。
- 全部后端逻辑集中在单个 `main.go`（约 3000 行，`package main`），没有拆分包。测试集中在 `main_test.go`。

## 关键文件

- `main.go`：程序入口、HTTP 路由、SQLite 逻辑、Mihomo 集成、内嵌资源服务。架构入口。
- `main_test.go`：主要自动化测试，既测后端逻辑，也断言内嵌 HTML/JS/CSS 的字符串内容。
- `web/index.html` / `web/styles.css` / `web/app.js`：内嵌 UI 的结构 / 样式 / 行为，三者强耦合。
- `README.md`：面向用户的行为与运维说明，行为有实质变化时同步更新。
- `Dockerfile` / `.github/workflows/{build,release}.yml`：构建与发布真相来源。

## 构建与测试（最重要的陷阱）

- **CGO 是硬性依赖**：依赖 `github.com/mattn/go-sqlite3` 是 CGO 驱动。`go build` 和 `go test` 都必须 `CGO_ENABLED=1` 且本机有 C 编译器（`gcc`），否则必然失败。Dockerfile 里 `apk add gcc musl-dev`、CI 里都显式 `CGO_ENABLED=1` 即为此。
- **Go 版本固定 1.21**（`go.mod` 与所有 workflow 均锁定 `1.21`），不要随意升级。
- 交叉编译需配对正确的 `CC`（见 `.github/workflows/build.yml`：linux/arm64 用 `aarch64-linux-gnu-gcc`，windows 用 `x86_64-w64-mingw32-gcc`，alpine/musl arm64 在容器内构建）。
- 改动 `web/` 静态资源后，必须重新编译二进制才会生效（资源是 `//go:embed LICENSE web/*` 编译期内嵌的）。

```bash
# 构建（默认 CGO_ENABLED=1，需本机有 gcc）
go build -o traffic-monitor main.go

# 运行全部测试（同样需要 CGO + gcc）
go test ./...

# 跑单个测试 / 单个用例
go test ./... -run TestAutoSwitchCreatesRestoreSession
go test ./... -run TestAutoRestore -run "restore happens after quiet minutes"
```

## 环境变量（注意 `.env.example` 已过时）

代码实际只读取这三个环境变量（见 `main.go` `loadConfig` / `getenv`）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MIHOMO_URL` | 空 | Mihomo Controller 地址，未设时可在页面首次打开后填写并持久化到 SQLite |
| `MIHOMO_SECRET` | 空 | Mihomo Bearer Token |
| `TRAFFIC_MONITOR_LISTEN` | `:8080` | 服务监听地址 |

**`.env.example` 里列出的 `TRAFFIC_MONITOR_DB`、`TRAFFIC_MONITOR_POLL_INTERVAL_MS`、`TRAFFIC_MONITOR_RETENTION_DAYS`、`TRAFFIC_MONITOR_ALLOWED_ORIGIN` 当前并未接入环境变量**，不要误以为设置它们会生效：

- 数据库路径由运行环境自动判定，不可通过环境变量配置（见下）。
- 轮询间隔是常量 `defaultPollInterval = 5s`，硬编码。
- 保留天数、域名分组等是存放在 SQLite `app_settings` 表、通过页面 / API 配置的，不是环境变量。
- `README.md` 的“常用配置”表才是准确的环境变量清单。

## 设备身份解析

通过 OpenWrt ubus HTTP RPC 将源 IP 解析为 MAC + hostname，以 MAC 为设备稳定唯一标识归并设备维度流量。

### 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `OPENWRT_UBUS_URL` | 空 | OpenWrt ubus HTTP RPC 地址（如 `http://192.168.1.1/ubus`），未配置时整个功能关闭 |
| `OPENWRT_UBUS_USERNAME` | 空 | ubus 账户用户名 |
| `OPENWRT_UBUS_PASSWORD` | 空 | ubus 账户密码 |

**降级策略**：`OPENWRT_UBUS_URL` 未配置（空）= 功能关闭，行为与之前完全一致，零影响。

### 数据源与优先级

4 源策略，按字段类型分优先级合并，以 MAC 为锚点：

**hostname 优先级**（高→低）：
1. `uci get dhcp` host 段 `name`：用户自定义静态租约名，最稳定最可信
2. `luci-rpc.getHostHints` `name`：LuCI 聚合的 hostname
3. `luci-rpc.getDHCPLeases` `hostname`：DHCPv4 租约中设备报告的 hostname

**MAC 来源**（取并集）：
1. `luci-rpc.getHostHints`：直接 MAC→{v4[],v6[]} 关联，覆盖面最广
2. `file exec ip neigh`：邻居表，补充 SLAAC/静态 IP 设备（过滤 FAILED/INCOMPLETE 或空 lladdr 条目）
3. `uci get dhcp` host 段：仅静态租约 IP 的 MAC

合并策略：以 MAC 为锚点，hostname 取最高优先级非空值，IP 列表取所有源并集。任一源失败不阻断其他源。

### 触发时机

- **事件驱动**：`processConnections` 发现新 source_ip（不在内存映射缓存中）时主动触发全量刷新，防抖间隔 30 秒（距上次刷新不足 30s 则跳过）。
- **定期兜底**：独立 goroutine 每 5 分钟全量刷新一次，覆盖"IP 没变但 MAC 已变"场景。
- 刷新结果异步写入内存映射表（`map[string]*deviceMapping`）和 SQLite `device_mappings` 表。

### 映射持久化

新增 `device_mappings` 表，PK(ip, mac) 支持时段管理：

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `ip` | TEXT | 源 IP 字符串（规范化为压缩 IPv6 形式） |
| `mac` | TEXT | MAC 地址 |
| `hostname` | TEXT | 主机名（可能为空） |
| `first_seen` | DATETIME | 该映射首次出现时间 |
| `last_seen` | DATETIME | 该映射最近刷新时间 |

- PK(ip, mac)：允许同一 IP 在不同时段对应不同设备（DHCP 重新分配、IP 复用）。
- 刷新 upsert：IP+MAC 已存在则更新 `last_seen` 和 hostname；IP 存在但 MAC 变化则旧记录截止，插入新记录。
- 查询时段匹配：设备维度查询时带时间范围，`device_mappings` 用 `first_seen/last_seen` 匹配有效映射，同一 IP 多条匹配时选 `last_seen` 最大的。无匹配回退纯 IP。
- 清理与 retention 一致：删除 `traffic_aggregated` 过期数据时，同时清理 `last_seen` 早于 retention 截止时间的记录。

### 展示层映射（不改存储层）

- 所有设备维度 API 先按 `source_ip` 分组聚合，再用 `device_mappings` 表按时间段批量匹配并归一为 MAC，按 MAC 二次聚合。
- API 返回的 `aggregatedData` 增加 `mac` 字段。
- 前端 label 格式：主行 hostname，副行 MAC（小字 muted）；下钻参数存 MAC（data-primary），后端用 MAC 反查关联 IP 过滤。
- `OPENWRT_UBUS_URL` 未配置或 `device_mappings` 为空时跳过映射流程，零开销。

## 数据库与存储

- 路径自动判定：检测到 `/.dockerenv`（容器运行时）→ `/data/traffic_monitor.db`；否则 → `./data/traffic_monitor.db`。父目录会自动创建。
- 只持久化分钟级聚合表 `traffic_aggregated`，默认保留 30 天；`traffic_logs` 表为历史遗留结构，当前不再写入逐条原始连接。
- 采集增量先进内存缓冲，每 10 分钟（`aggregateFlushInterval`）批量刷盘；查询会把已落盘聚合与当前内存缓冲合并，故最近几分钟也能查到。异常退出最多丢失最近 10 分钟未刷盘数据。
- SQLite schema 改动尽量向后兼容；改了持久化行为或 schema 必须同步更新 `main_test.go`。

## HTTP 路由

路由集中在 `service.routes()`：`/health`（docker healthcheck 用）、`/LICENSE`、`/api/settings/{mihomo,domain-grouping,retention}`、`/api/auto-switch/{settings,groups,events}`、`/api/traffic/{aggregate,substats,proxy-stats,devices-by-host,devices-by-proxy-host,details,trend,logs}`。新增接口沿用现有 `mux.HandleFunc` + `writeJSON` 模式，不要引入并行抽象。

## 自动切换行为

- 触发单位是“某域名命中的策略组在 1 分钟窗口内累计流量超阈值”，不是任意域名超阈值就全局触发。
- 命中策略组需在自动切换配置中启用才会切换；若目标本身也是已启用策略组则递归切换，直到目标不是已启用策略组（遇循环会检测并停止）。
- 只控制 Mihomo 的 `select` 与 `fallback` 策略组；支持冷却时间与“自动恢复原节点”（静默恢复按分钟桶计算，手动改节点会取消待恢复任务，原节点已不在候选里则记录恢复失败并清理任务）。
- 保持 Mihomo 相关行为显式可观测：自动切换 / 恢复的日志要清晰，避免黑盒控制流。这块测试覆盖很密，改动前先看 `main_test.go` 中 `TestAutoSwitch*` / `TestAutoRestore*`。

## UI 与前端规则

- 把 `web/index.html`、`web/styles.css`、`web/app.js` 当作一个整体一起改。
- 优先小幅度 HTML 改动和 CSS 优先方案，再考虑加 JavaScript。
- **`main_test.go` 会断言内嵌 UI 的字符串内容**（如 `TestEmbeddedIndexDisablesPeriodicAutoRefresh`、`TestEmbeddedAppScriptIncludesContextualDashboardLabels`、`TestEmbeddedStylesConstrainDashboardHeight`、`TestEmbeddedIndexIncludesGithubAndLicenseFooter` 等）。改 UI 文案 / 标签 / 选择器时，务必同步检查并更新对应断言，避免留下失配标签或死选择器。
- UI 风格保持紧凑、运维向，这是监控控制台，不是营销页。调整桌面布局时保留移动端表现。
- 不引入 Node 工具链、前端打包器或新生产依赖，除非明确要求。

## 工作约定

- 改动保持外科手术式，修一个问题时不要顺手重构无关区域。
- 保留现有架构：Go 单二进制 + 内嵌静态前端 + SQLite 持久化。优先扩展现有模式而非新增分层或框架。
- 除非任务需要，否则不改持久化行为、API 负载或数据库默认值；改了就更新测试。

## 验证

- 改动后跑 `go test ./...`（需 `CGO_ENABLED=1` + `gcc`）。
- 改了 HTTP handler、持久化规则或自动切换行为，在 `main_test.go` 增补或更新测试。
- 改了 UI 文案或布局，把相关 HTML/CSS/JS 一起核对，并检查上述 UI 字符串断言。

## 提交范围

- 不要提交无关的未跟踪文件（本地笔记、临时文档、`.claude/`、`.codex/` 等），除非用户明确要求。`.gitignore` 已忽略 `CLAUDE.md`、`data/`、`*.db*`、`vendor/`、`release/`、`dist/` 等。
- 提交按用户可见结果分组，不按文件类型分组。历史提交使用 Conventional Commits 风格（`feat:` / `fix:` / `chore:`），中文提交信息可接受。

## 发布版本

- 当前版本：`v2.2.3`（见 `web/index.html` 页脚 `版本：v2.2.3`）。
- 发布时保持 git tag 与页脚版本字符串一致，tag 加 `v` 前缀。
- 升版本时同步修改 `web/index.html` 页脚的版本字符串，再打对应 tag。
- 发布产物由 `.github/workflows/release.yml` 构建（linux amd64/arm64、linux arm64 musl、windows amd64、macos arm64、多架构 Docker 镜像）。
