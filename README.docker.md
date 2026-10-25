# Traffic Monitor

`Traffic Monitor` 是一个独立运行的 Clash Mihomo 内核 流量监控服务。

它会定时读取  Clash Mihomo 内核 的 `/connections` 数据，把流量增量先聚合到内存，再按分钟桶批量写入 SQLite，并提供一个内置 Web 页面，用来查看设备、主机、代理维度的流量统计和链路明细。
## 怎么用

```bash
docker run -d \
  --name traffic-monitor \
  --restart unless-stopped \
  -p 8080:8080 \
  -v "$(pwd)/data:/data" \
  zhf883680/clash-traffic-monitor:latest
```

启动后访问：

```text
http://localhost:8080/
```

## 页面预览

![Traffic Monitor 页面预览](https://raw.githubusercontent.com/zhf883680/clash-traffic-monitor/main/readmeImg/image.png)
