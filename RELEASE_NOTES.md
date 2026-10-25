# Traffic Monitor v2.6.0

## 新功能

- Windows 版本改为托盘程序：启动后不再显示控制台窗口，通知区域提供「打开统计页」「开机自动启动」「退出」三个菜单项。退出会停止采集、写入内存聚合并生成汇总后关闭服务。
- 开机自动启动写入当前用户注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，无需管理员权限；取消勾选即移除。
- 同一登录会话内单实例运行：重复启动不会出现端口冲突，只会打开已运行实例的统计页。

## Windows 行为变化

- 数据库与日志固定位于 exe 旁的 `data` 目录（`traffic_monitor.db`、`traffic-monitor.log`），不再依赖启动时的工作目录；旧版本留在工作目录的数据库会在首次运行时通过 SQLite Online Backup 自动迁移，旧文件保留作备份，迁移失败不会生成空数据库。
- 日志按 5 MiB 轮转，保留一份 `.1` 备份；致命启动错误会以原生对话框提示，并记录到日志文件。
- 程序移动位置后需要重新勾选「开机自动启动」。

## 其他平台

- Linux、macOS 与 Docker 保持原有 headless 行为：配置、API、数据库 schema 与采集逻辑均不变，镜像不新增任何图形依赖。

## 构建

- 所有构建入口从单文件构建改为包构建（`go build .`），Windows 发布二进制使用 `-H=windowsgui` 子系统，其余平台标志不变，产物命名不变。
