package main

// 本文件集中 fork 专属「ubus 设备识别」在应用装配 / HTTP handler 中的挂钩点，
// 使 main.go 仅保留最少的 fork-ubus 调用行，降低未来与上游 merge 的冲突面。
// 设备识别本体（ubus RPC 客户端、映射刷新、MAC 归并）见 device_resolution.go。

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"
)

// 设备身份解析相关常量（fork-ubus）
const (
	deviceMappingRefreshInterval  = 5 * time.Minute
	deviceMappingDebounceInterval = 30 * time.Second
	deviceMappingPeriodicInterval = 5 * time.Minute
)

// initUbusFromConfig 初始化 ubus 客户端并预热历史设备映射（fork-ubus 装配钩子）。
// 仅在配置了 OPENWRT_UBUS_URL 时生效；未配置时整个功能关闭，零开销。
func (s *service) initUbusFromConfig(cfg config) {
	s.deviceMappings = make(map[string]*deviceMapping)
	if cfg.UbusURL == "" {
		return
	}
	s.ubusCli = &ubusClient{
		url:      cfg.UbusURL,
		username: cfg.UbusUsername,
		password: cfg.UbusPassword,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
	// 从 device_mappings 表加载历史映射到内存
	if err := s.loadDeviceMappingsFromDB(); err != nil {
		log.Printf("加载历史设备映射失败: %v", err)
	} else {
		log.Printf("已从数据库加载 %d 条设备映射", len(s.deviceMappings))
	}
}

// startUbusWorkers 在应用启动时挂入 fork-ubus 后台任务：
// ubus 已配置时启动周期设备映射刷新 goroutine（随 ctx 取消退出）。
func (s *service) startUbusWorkers(ctx context.Context) {
	if !s.ubusEnabled() {
		return
	}
	go s.runPeriodicDeviceRefresh(ctx)
}

// notifyNewSourceIPs 从采集到的连接日志中提取 source_ip 列表，
// 发现新 IP 时异步触发设备映射刷新（带防抖，见 checkNewIPs）。
func (s *service) notifyNewSourceIPs(logs []trafficLog) {
	sourceIPs := make([]string, 0, len(logs))
	for _, log := range logs {
		if log.SourceIP != "" {
			sourceIPs = append(sourceIPs, log.SourceIP)
		}
	}
	if len(sourceIPs) > 0 {
		s.checkNewIPs(sourceIPs)
	}
}

// cleanupDeviceMappings 清理 last_seen 早于 retention 截止时间的设备映射
// （与 traffic_aggregated 的保留期清理对齐）。
func (s *service) cleanupDeviceMappings(cutoff int64) error {
	_, err := s.db.Exec(`DELETE FROM device_mappings WHERE last_seen < ?`, cutoff)
	return err
}

// applyUbusDeviceView 对指定维度应用设备 label 增强和 MAC 归并
// （仅 sourceIP 维度；未启用 ubus 时原样返回）。
func (s *service) applyUbusDeviceView(data []aggregatedData, dimension string, start, end int64) []aggregatedData {
	if dimension != "sourceIP" {
		return data
	}
	return s.applyDeviceLabelAndMACAggregate(data, start, end)
}

// trySubstatsByMAC 处理 sourceIP 维度以 MAC 地址传入的子统计下钻：
// 反查关联 IP 后按 IP 查询。汇总模式（summary=1）下查询 summary 表并按
// querySummaryByDimension 的合并语义补齐 raw 窗口；非汇总模式只读 raw 表。
// 返回 true 表示已写出响应（含错误响应），调用方应直接 return；
// 返回 false 表示未命中 MAC 分支（或非汇总模式下解析不到 IP），走原查询路径。
func (s *service) trySubstatsByMAC(w http.ResponseWriter, r *http.Request, dimension, label string, start, end int64) bool {
	if dimension != "sourceIP" || !s.ubusEnabled() || !looksLikeMAC(label) {
		return false
	}

	ips := s.resolveMACToIPs(label, start, end)
	if len(ips) == 0 {
		// 汇总模式下 MAC 解析不到关联 IP（如映射已被 retention 清理）：
		// 直接返回空数组，避免把 MAC 当 IP 对 summary/raw 表做恒空查询
		if r.URL.Query().Get("summary") == "1" {
			writeJSON(w, http.StatusOK, []aggregatedData{})
			return true
		}
		return false
	}

	var (
		data []aggregatedData
		err  error
	)
	if r.URL.Query().Get("summary") == "1" {
		data, err = s.querySummarySecondaryByIPs(ips, start, end)
	} else {
		data, err = s.querySubstatsByIPs(dimension, ips, start, end)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return true
	}
	writeJSON(w, http.StatusOK, data)
	return true
}

// tryConnectionDetailsByMAC 处理 sourceIP 维度以 MAC 地址传入的连接明细查询：
// 反查关联 IP 后按 IP 列表查询明细。返回 true 表示已写出响应，调用方应直接 return。
func (s *service) tryConnectionDetailsByMAC(w http.ResponseWriter, dimension, primary, secondary string, start, end int64) bool {
	if dimension != "sourceIP" || !s.ubusEnabled() || !looksLikeMAC(primary) {
		return false
	}

	ips := s.resolveMACToIPs(primary, start, end)
	if len(ips) == 0 {
		return false
	}

	data, err := s.queryConnectionDetailsByIPs(ips, secondary, start, end)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return true
	}
	writeJSON(w, http.StatusOK, data)
	return true
}

// querySummarySecondaryByIPs 在汇总模式下按 MAC 反查出的多个源 IP 查询子统计。
// 合并语义与 querySummaryByDimension / querySummarySecondary 一致：
// summary 表覆盖 [start, end] 全窗口（4 倍保留期），raw 聚合表仅补 summary
// 覆盖终点之后（fallbackStart = max(summaryCoveredEnd, start)）的部分，
// 内存缓冲补 [start, end]，保证 MAC 下钻数字与父级汇总行一致。
func (s *service) querySummarySecondaryByIPs(ips []string, start, end int64) ([]aggregatedData, error) {
	placeholders := make([]string, len(ips))
	args := make([]any, 0, len(ips))
	for i, ip := range ips {
		placeholders[i] = "?"
		args = append(args, ip)
	}
	inList := strings.Join(placeholders, ",")

	detailStart, err := s.summaryCoveredEnd()
	if err != nil {
		return nil, err
	}
	fallbackStart := detailStart
	if fallbackStart < start {
		fallbackStart = start
	}

	rows, err := s.querySummaryRows("source_ip", "secondary_label", " AND label IN ("+inList+")", args, start, end)
	if err != nil {
		return nil, err
	}
	merged := make(map[string]*aggregatedData)
	mergeAggregatedDataRows(merged, rows)

	bufferFilter := "source_ip IN (" + inList + ")"
	detailRows, err := s.queryByFiltersFromAggregates("host", bufferFilter, args, fallbackStart, end)
	if err != nil {
		return nil, err
	}
	mergeAggregatedDataRows(merged, detailRows)
	mergeAggregatedDataRows(merged, s.queryByFiltersFromBuffer("host", bufferFilter, args, start, end))
	return sortedAggregatedDataRows(merged), nil
}
