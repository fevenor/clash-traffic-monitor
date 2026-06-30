# Traffic Monitor

`Traffic Monitor` 是一个独立运行的 Clash 流量监控服务。

它会定时读取 Clash 的 `/connections` 数据，把流量增量先聚合到内存，再按分钟桶批量写入 SQLite，并提供一个内置 Web 页面，用来查看设备、域名、IP、代理维度的流量统计和链路明细。

<p align="center">
  轻量、直接、适合单机和 OpenWrt 场景的 Clash / Mihomo 流量监控服务
</p>

<p align="center">
  <a href="https://github.com/fevenor/clash-traffic-monitor/stargazers">
    <img src="https://img.shields.io/github/stars/fevenor/clash-traffic-monitor?style=flat-square&color=yellow" alt="Stars" />
  </a>
  <a href="https://github.com/fevenor/clash-traffic-monitor/pkgs/container/clash-traffic-monitor">
    <img src="https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square&logo=docker" alt="Docker ghcr.io" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21-00ADD8?style=flat-square&logo=go" alt="Go 1.21" />
  <img src="https://img.shields.io/badge/SQLite-embedded-003B57?style=flat-square&logo=sqlite" alt="SQLite embedded" />
  <img src="https://img.shields.io/badge/OpenWrt-friendly-00B5E2?style=flat-square" alt="OpenWrt Friendly" />
</p>

<p align="center">
  <a href="#页面预览">页面预览</a> ·
  <a href="#功能特性">功能特性</a> ·
  <a href="#项目现状">项目现状</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#常用配置">常用配置</a> ·
  <a href="#项目定位">项目定位</a>
</p>

## 页面预览

![Traffic Monitor 页面预览](./readmeImg/image.png)

## 功能特性

- 按域名、IP、节点、代理等维度查看流量，方便快速定位异常流量来源。
- 可以直观看到连接是否走代理，辅助你调整 Mihomo / Clash 规则。
- 支持按 1 分钟窗口检测异常大流量域名，并自动把选定策略组切换到预设节点。
- 支持在大流量结束后按静默时间自动恢复到原始节点，并记录恢复结果。
- 使用分钟级聚合落盘到 SQLite，磁盘占用更可控，查询也更直接。
- 提供内置 Web 页面，无需额外部署前端服务或数据库。
- 支持本地二进制直接运行，也支持 Docker 部署，适合单机和 OpenWrt 场景。

## 项目现状

这个项目目前已经基本完成了我最初的目标：

- 观察哪些域名的流量偏大
- 判断流量是否走了代理，并据此调整规则,自动切换节点
- 查看节点维度的流量
- 查看 IP 维度的流量

对我来说，它已经够用了。

如果后续还有新的需求，更建议直接 fork 之后按自己的场景继续扩展；也可以结合下面这两个项目，再配合 AI 辅助开发，补上你真正需要的功能。

参考项目：

- [foru17/neko-master](https://github.com/foru17/neko-master)
- [MetaCubeX/metacubexd](https://github.com/MetaCubeX/metacubexd)

## 快速开始

### 本地运行

推荐直接从 [Releases](https://github.com/fevenor/clash-traffic-monitor/releases/latest) 下载对应平台的二进制文件运行。

#### Windows

下载文件：`traffic-monitor-windows-amd64.exe`

```powershell
.\traffic-monitor-windows-amd64.exe
```

#### Linux

下载文件：

- `traffic-monitor-linux-amd64`
- `traffic-monitor-linux-arm64`

```bash
chmod +x ./traffic-monitor-linux-amd64
./traffic-monitor-linux-amd64
```

```bash
chmod +x ./traffic-monitor-linux-arm64
./traffic-monitor-linux-arm64
```

#### macOS

下载文件：`traffic-monitor-macos-arm64`

```bash
chmod +x ./traffic-monitor-macos-arm64
./traffic-monitor-macos-arm64
```

如果你是从源码本地编译，也可以直接这样运行：

```bash
go build -o traffic-monitor main.go
./traffic-monitor
```

启动后访问：

```text
http://localhost:8080/
```

如果本地还没有保存过 Mihomo 配置，首次打开页面会提示填写：

- `Mihomo URL`
- `Secret`（如果 Mihomo 没有设置密钥，可以留空）

保存后会立即生效，并持久化到本地 SQLite。后续也可以在页面右上角继续修改这两个值。

### Docker 运行

```bash
mkdir -p data

docker run -d \
  --name traffic-monitor \
  --restart unless-stopped \
  -p 8080:8080 \
  -e MIHOMO_URL=http://host.docker.internal:9090 \
  -e MIHOMO_SECRET=your-secret \
  -v "$(pwd)/data:/data" \
  ghcr.io/fevenor/clash-traffic-monitor:latest
```

如果 Mihomo 没有设置密钥，可以把 `MIHOMO_SECRET` 留空。

升级兼容说明：

- 旧版 Docker 用户升级后，如果启动参数里仍然传了 `MIHOMO_URL` / `MIHOMO_SECRET`，新版本会继续直接使用这些值，不会影响启动。
- 启动时只要环境变量里有值，就会以环境变量为准，并自动保存到数据库。
- 如果后续移除了环境变量，但保留了 `/data` 挂载目录，服务会回退使用数据库里上次保存的值。

## 常用配置

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `MIHOMO_URL` | 空 | 启动时优先使用的 Mihomo Controller 地址；未设置时可在页面首次打开后填写 |
| `MIHOMO_SECRET` | 空 | Mihomo Bearer Token |
| `TRAFFIC_MONITOR_LISTEN` | `:8080` | 服务监听地址 |
| `OPENWRT_UBUS_URL` | 空 | OpenWrt ubus HTTP RPC 地址（如 `http://192.168.1.1/ubus`），未配置时设备身份解析功能关闭 |
| `OPENWRT_UBUS_USERNAME` | 空 | ubus 账户用户名 |
| `OPENWRT_UBUS_PASSWORD` | 空 | ubus 账户密码 |

## 自动切换

页面内新增了“自动切换”配置区，用来处理“某个域名通过某个策略组时，在 1 分钟内流量突然特别大”的场景。

- 触发条件不是“任意域名一超阈值就全局触发”，而是“某个域名命中的策略组，在 1 分钟窗口内累计流量超过阈值”。
- 只有当这次流量实际命中的策略组，也在自动切换配置里启用时，才会触发切换。
- 触发后会先切换这次命中的策略组；如果它的目标本身也是一个已启用的策略组，则会继续递归切换，直到目标不是已启用策略组为止。
- 如果递归过程中遇到的目标是一个策略组，但这个组没有在自动切换里启用，则会停在这个组上，并将本次切换视为成功。
- 不需要维护域名列表，也不会修改你原有的 Mihomo 规则判断逻辑。
- 只展示并控制 Mihomo 的 `select` 和 `fallback` 策略组。
- 你可以勾选多个策略组，并为每个策略组单独指定一个目标节点。
- 支持配置冷却时间，避免频繁重复切换。
- 可选开启“自动恢复原节点”。
  - 每次成功自动切换时，会记录当时该策略组原本选中的节点。
  - 如果后续持续一段“静默恢复时间”都没有新的大流量触发，就会尝试恢复到最初记录的原节点。
  - 静默恢复时间按分钟桶计算，新的大流量触发会刷新等待时间。
  - 如果你在 Mihomo 里手动把策略组改到别的节点，待恢复任务会自动取消，避免覆盖人工操作。
  - 如果原始节点已经不在当前策略组选项里，系统会记录一次恢复失败事件，并清理对应恢复任务。

## 设备身份解析

设备身份解析通过 OpenWrt 的 ubus HTTP RPC 接口，将设备流量中的源 IP 解析为稳定的 MAC 地址和设备主机名（hostname），以 MAC 作为设备稳定唯一标识来归并同一设备多个 IP 的流量。

- **解析链路**：IP → MAC → hostname，以 MAC 为锚点归并同设备多 IP 流量。
- **展示方式**：有映射的设备显示 hostname + MAC（副行），无映射的设备显示原始 IP，两者混合共存。
- **数据源**：同时调用 `luci-rpc.getHostHints`、`luci-rpc.getDHCPLeases`、`ip neigh`、`uci get dhcp` 四个源，取并集合并。
- **hostname 优先级**：`uci` 静态租约名 > `getHostHints` > `getDHCPLeases`。
- **降级行为**：路由器不可达时使用 `device_mappings` 表中的历史映射；无映射的 IP 显示原始 IP。
- **功能开关**：未配置 `OPENWRT_UBUS_URL` 时功能完全关闭，行为与之前一致。

### 环境变量

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `OPENWRT_UBUS_URL` | 空 | OpenWrt ubus HTTP RPC 地址（如 `http://192.168.1.1/ubus`），配置后启用设备身份解析 |
| `OPENWRT_UBUS_USERNAME` | 空 | ubus 账户用户名 |
| `OPENWRT_UBUS_PASSWORD` | 空 | ubus 账户密码 |

### ACL 权限要求

ubus 账户需在 OpenWrt `/etc/config/rpcd` 中授权以下权限：

- `luci-rpc` 对象：`read` 权限（用于 `getHostHints`、`getDHCPLeases`）
- `file` 对象：`exec` 权限，白名单含 `/sbin/ip`（用于 `ip -[46] -j neigh show`）
- `uci` 对象：`read` 权限（用于读取 DHCP 静态租约）

### Docker 配置示例

```bash
docker run -d \
  --name traffic-monitor \
  --restart unless-stopped \
  -p 8080:8080 \
  -e MIHOMO_URL=http://host.docker.internal:9090 \
  -e MIHOMO_SECRET=your-secret \
  -e OPENWRT_UBUS_URL=http://192.168.1.1/ubus \
  -e OPENWRT_UBUS_USERNAME=monitor \
  -e OPENWRT_UBUS_PASSWORD=your-password \
  -v "$(pwd)/data:/data" \
  ghcr.io/fevenor/clash-traffic-monitor:latest
```

## 存储策略

- 只把分钟级聚合数据写入 `traffic_aggregated`，不再持久化逐条原始连接日志。
- 聚合数据固定保留 30 天。
- 本地直接运行时，默认数据库文件是 `./data/traffic_monitor.db`。
- Docker 容器内运行时，默认数据库文件是 `/data/traffic_monitor.db`。
- 采集增量先进入内存缓冲，每 10 分钟批量刷盘一次。
- 正常运行时，页面查询会把已落盘聚合数据和当前内存缓冲一起合并，所以最近几分钟也能查到。
- 如果服务异常退出，最近最多 10 分钟、尚未刷盘的数据可能丢失。

## 项目定位

如果你已经看过 [foru17/neko-master](https://github.com/foru17/neko-master)，那你看到的是一个先做出来、而且已经非常完善的产品。它的定位更完整，覆盖了更丰富的网络流量可视化和部署能力。

这个项目没有打算和它做“功能越多越好”的正面竞争，而是走另一条路线：更轻、更直给、更适合单机或 OpenWrt 场景。

- 更轻量：Go 单二进制 + SQLite，本地就能跑起来，不需要额外的 Node.js 运行时或独立数据库。
- 更省心：前端资源直接内嵌在程序里，部署时就是一个服务或一个容器，升级和迁移都更简单。
- 更聚焦：核心目标就是盯住  Clash 的 `/connections` 流量，把设备、主机、出口节点和明细钻取做好。
- 更适合小设备：更贴近旁路由、软路由、OpenWrt 这类“资源有限但想快速看流量”的使用场景。
- 更容易二次定制：代码结构短、依赖少，想自己加维度、调样式、改展示逻辑会更直接。
- 更省磁盘 IO：运行时只持久化 30 天分钟级聚合数据，最近最多 10 分钟保存在内存缓冲里统一刷盘。

## 备注

因为这个项目主要监控运行在 OpenWrt 路由器环境的 Clash，当前默认移除了进程维度相关展示。

如果你需要进程模块，可以在此基础上自行 fork 后补充。

## 致谢

- 页面接口参考了 [MetaCubeX/metacubexd](https://github.com/MetaCubeX/metacubexd)。
- [LinuxDO](https://linux.do) - the community where it all began
