package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// deviceMapping represents an IP→MAC→hostname mapping with time range.
type deviceMapping struct {
	IP        string
	MAC       string
	Hostname  string
	FirstSeen int64
	LastSeen  int64
}

// ubusClient is an OpenWrt ubus HTTP RPC client (JSON-RPC 2.0 over HTTP).
type ubusClient struct {
	url      string
	username string
	password string
	mu       sync.Mutex
	token    string
	client   *http.Client
}

// ubusRPCRequest is a JSON-RPC 2.0 request for ubus.
type ubusRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

// ubusRPCResponse is a JSON-RPC 2.0 response from ubus.
type ubusRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ubusRPCError   `json:"error,omitempty"`
}

// ubusRPCError represents a JSON-RPC error object.
type ubusRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ubusHostHintInfo represents a getHostHints entry (MAC→info).
type ubusHostHintInfo struct {
	IPAddrs  []string `json:"ipaddrs"`
	IP6Addrs []string `json:"ip6addrs"`
	Name     string   `json:"name"`
}

// ubusDHCPLease represents a DHCP lease entry.
type ubusDHCPLease struct {
	Expires  int    `json:"expires"`
	Hostname string `json:"hostname"`
	MACAddr  string `json:"macaddr"`
	IPAddr   string `json:"ipaddr"`
}

// ubusDHCPLeasesData is the data payload of getDHCPLeases.
type ubusDHCPLeasesData struct {
	DHCPLeases  []ubusDHCPLease `json:"dhcp_leases"`
	DHCP6Leases []ubusDHCPLease `json:"dhcp6_leases"`
}

// ubusFileExecData is the data payload of file exec.
type ubusFileExecData struct {
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
}

// ipNeighEntry represents one neighbor table entry.
type ipNeighEntry struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	Lladdr string   `json:"lladdr"`
	State  []string `json:"state"`
}

// ubusUCIHostEntryRaw is used to unmarshal uci get dhcp host entries (mac may be string or array).
type ubusUCIHostEntryRaw struct {
	Type string      `json:".type"`
	Name string      `json:"name"`
	IP   string      `json:"ip"`
	MAC  interface{} `json:"mac"`
}

// ubusUCIDHCPData is the data payload of uci get dhcp.
type ubusUCIDHCPData struct {
	Values map[string]ubusUCIHostEntryRaw `json:"values"`
}

// ---------------------------------------------------------------------------
// 设备身份解析：ubus HTTP RPC 客户端
// ---------------------------------------------------------------------------

// ubusEnabled 检查 ubus 客户端是否已配置。
func (s *service) ubusEnabled() bool {
	return s.ubusCli != nil
}

// login 执行 session.login 获取 token 并缓存。
func (u *ubusClient) login() (string, error) {
	reqBody := ubusRPCRequest{
		JSONRPC: "2.0",
		Method:  "call",
		Params:  []any{"00000000000000000000000000000000", "session", "login", map[string]string{"username": u.username, "password": u.password}},
		ID:      1,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	httpResp, err := u.client.Post(u.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer httpResp.Body.Close()

	var rpcResp ubusRPCResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&rpcResp); err != nil {
		return "", err
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("login rpc error: code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var resultArr []json.RawMessage
	if err := json.Unmarshal(rpcResp.Result, &resultArr); err != nil {
		return "", err
	}
	if len(resultArr) < 2 {
		return "", errors.New("login result unexpected format")
	}

	var loginResult struct {
		Token string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(resultArr[1], &loginResult); err != nil {
		return "", err
	}
	if loginResult.Token == "" {
		return "", errors.New("login failed: empty token")
	}

	u.mu.Lock()
	u.token = loginResult.Token
	u.mu.Unlock()

	return loginResult.Token, nil
}

// doCall 执行一次 ubus RPC call，返回结果数据（result 数组第二元素）。
// 若 RPC 层返回错误，返回 rpcErr。
func (u *ubusClient) doCall(token, object, method string, params map[string]any) (json.RawMessage, *ubusRPCError, error) {
	callParams := []any{token, object, method}
	if params != nil {
		callParams = append(callParams, params)
	}

	reqBody := ubusRPCRequest{
		JSONRPC: "2.0",
		Method:  "call",
		Params:  callParams,
		ID:      1,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, err
	}

	httpResp, err := u.client.Post(u.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	defer httpResp.Body.Close()

	var rpcResp ubusRPCResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&rpcResp); err != nil {
		return nil, nil, err
	}

	if rpcResp.Error != nil {
		return nil, rpcResp.Error, nil
	}

	var resultArr []json.RawMessage
	if err := json.Unmarshal(rpcResp.Result, &resultArr); err != nil {
		return nil, nil, err
	}
	if len(resultArr) < 2 {
		return nil, nil, errors.New("ubus result unexpected format")
	}

	// resultArr[0] 是 ubus 返回码（0=成功）
	var ubusCode int
	if err := json.Unmarshal(resultArr[0], &ubusCode); err != nil {
		return nil, nil, err
	}
	if ubusCode != 0 {
		return resultArr[1], &ubusRPCError{Code: ubusCode, Message: "ubus call returned non-zero code"}, nil
	}

	return resultArr[1], nil, nil
}

// call 是统一的 ubus RPC call，带 token 过期自动重登。
func (u *ubusClient) call(object, method string, params map[string]any) (json.RawMessage, error) {
	// 最多尝试 2 次（首次 + token 过期重试）
	for attempt := 0; attempt < 2; attempt++ {
		u.mu.Lock()
		token := u.token
		u.mu.Unlock()

		if token == "" && attempt == 0 {
			var err error
			token, err = u.login()
			if err != nil {
				return nil, fmt.Errorf("ubus 首次登录失败: %w", err)
			}
		}

		result, rpcErr, err := u.doCall(token, object, method, params)
		if err != nil {
			return nil, err
		}

		// token 过期（-32002），自动重登并重试
		if rpcErr != nil && rpcErr.Code == -32002 && attempt == 0 {
			log.Printf("ubus token 过期，重新登录并重试")
			newToken, loginErr := u.login()
			if loginErr != nil {
				return nil, fmt.Errorf("ubus 重新登录失败: %w", loginErr)
			}
			token = newToken
			continue
		}

		if rpcErr != nil {
			return nil, fmt.Errorf("ubus rpc 错误: code=%d message=%s", rpcErr.Code, rpcErr.Message)
		}

		return result, nil
	}

	return nil, errors.New("ubus call failed after retry")
}

// getHostHints 调用 luci-rpc.getHostHints，返回 MAC→hostname/IP 映射。
func (u *ubusClient) getHostHints() (map[string]ubusHostHintInfo, error) {
	data, err := u.call("luci-rpc", "getHostHints", map[string]any{})
	if err != nil {
		return nil, err
	}

	var hints map[string]ubusHostHintInfo
	if err := json.Unmarshal(data, &hints); err != nil {
		return nil, err
	}
	return hints, nil
}

// getDHCPLeases 调用 luci-rpc.getDHCPLeases，返回 DHCP 租约列表。
func (u *ubusClient) getDHCPLeases() (*ubusDHCPLeasesData, error) {
	data, err := u.call("luci-rpc", "getDHCPLeases", map[string]any{})
	if err != nil {
		return nil, err
	}

	var leases ubusDHCPLeasesData
	if err := json.Unmarshal(data, &leases); err != nil {
		return nil, err
	}
	return &leases, nil
}

// getIPNeigh 执行 ip -4 -j neigh show 和 ip -6 -j neigh show，返回邻居表条目。
func (u *ubusClient) getIPNeigh() ([]ipNeighEntry, error) {
	var allEntries []ipNeighEntry

	for _, family := range []string{"-4", "-6"} {
		params := map[string]any{
			"command": "/sbin/ip",
			"params":  []string{family, "-j", "neigh", "show"},
		}
		data, err := u.call("file", "exec", params)
		if err != nil {
			log.Printf("ip neigh %s 调用失败: %v", family, err)
			continue
		}

		var execData ubusFileExecData
		if err := json.Unmarshal(data, &execData); err != nil {
			log.Printf("解析 ip neigh %s 响应失败: %v", family, err)
			continue
		}

		if execData.Code != 0 {
			log.Printf("ip neigh %s 执行返回非零码: %d", family, execData.Code)
			continue
		}

		if execData.Stdout == "" {
			continue
		}

		var entries []ipNeighEntry
		if err := json.Unmarshal([]byte(execData.Stdout), &entries); err != nil {
			log.Printf("解析 ip neigh %s stdout 失败: %v", family, err)
			continue
		}
		allEntries = append(allEntries, entries...)
	}

	return allEntries, nil
}

// getUCIDHCP 执行 uci get dhcp，返回静态租约 host 段。
func (u *ubusClient) getUCIDHCP() (*ubusUCIDHCPData, error) {
	params := map[string]any{
		"config": "dhcp",
	}
	data, err := u.call("uci", "get", params)
	if err != nil {
		return nil, err
	}

	var result ubusUCIDHCPData
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ---------------------------------------------------------------------------
// IP 规范化
// ---------------------------------------------------------------------------

// normalizeIP 用 net.ParseIP 解析 IP，成功后用 .String() 统一格式化。
// 解析失败则原样返回。
func normalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	return parsed.String()
}

// ---------------------------------------------------------------------------
// 设备映射表管理
// ---------------------------------------------------------------------------

// loadDeviceMappingsFromDB 从 device_mappings 表加载历史映射到内存。
// 每个 IP 取 last_seen 最大的记录。
func (s *service) loadDeviceMappingsFromDB() error {
	rows, err := s.db.Query(`
		SELECT ip, mac, hostname, first_seen, last_seen
		FROM device_mappings
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return fmt.Errorf("查询设备映射表失败: %w", err)
	}
	defer rows.Close()

	s.deviceMappingMu.Lock()
	defer s.deviceMappingMu.Unlock()

	// 清空并重新加载
	s.deviceMappings = make(map[string]*deviceMapping)
	seen := make(map[string]bool) // 记录已取过 last_seen 最大的 IP

	for rows.Next() {
		var dm deviceMapping
		if err := rows.Scan(&dm.IP, &dm.MAC, &dm.Hostname, &dm.FirstSeen, &dm.LastSeen); err != nil {
			return fmt.Errorf("扫描设备映射行失败: %w", err)
		}
		normIP := normalizeIP(dm.IP)
		if seen[normIP] {
			continue
		}
		seen[normIP] = true
		entry := dm
		entry.IP = normIP
		s.deviceMappings[normIP] = &entry
	}

	return rows.Err()
}

// getDeviceMapping 从内存映射表查询指定 IP 的映射（线程安全）。
func (s *service) getDeviceMapping(ip string) *deviceMapping {
	normIP := normalizeIP(ip)
	s.deviceMappingMu.RLock()
	defer s.deviceMappingMu.RUnlock()
	dm, ok := s.deviceMappings[normIP]
	if !ok {
		return nil
	}
	return dm
}

// refreshDeviceMappings 统一刷新函数：获取数据源→合并→upsert 持久化→替换内存表。
// 供事件驱动和定期刷新共用，互斥锁防并发重复执行。
func (s *service) refreshDeviceMappings() error {
	s.deviceRefreshMu.Lock()
	defer s.deviceRefreshMu.Unlock()

	if !s.ubusEnabled() {
		return nil
	}

	// 1. 从四个数据源获取原始数据
	type sourceResult struct {
		name string
		data interface{}
		err  error
	}

	results := make(chan sourceResult, 4)

	go func() {
		hints, err := s.ubusCli.getHostHints()
		results <- sourceResult{name: "getHostHints", data: hints, err: err}
	}()

	go func() {
		leases, err := s.ubusCli.getDHCPLeases()
		results <- sourceResult{name: "getDHCPLeases", data: leases, err: err}
	}()

	go func() {
		neigh, err := s.ubusCli.getIPNeigh()
		results <- sourceResult{name: "ipNeigh", data: neigh, err: err}
	}()

	go func() {
		uci, err := s.ubusCli.getUCIDHCP()
		results <- sourceResult{name: "uciDHCP", data: uci, err: err}
	}()

	// 收集结果（单数据源失败不阻断其他源）
	var getHostHintsData map[string]ubusHostHintInfo
	var getDHCPLeasesData *ubusDHCPLeasesData
	var ipNeighData []ipNeighEntry
	var uciDHCPData *ubusUCIDHCPData

	for i := 0; i < 4; i++ {
		res := <-results
		if res.err != nil {
			log.Printf("设备映射数据源 %s 获取失败: %v", res.name, res.err)
			continue
		}
		switch res.name {
		case "getHostHints":
			getHostHintsData = res.data.(map[string]ubusHostHintInfo)
		case "getDHCPLeases":
			getDHCPLeasesData = res.data.(*ubusDHCPLeasesData)
		case "ipNeigh":
			ipNeighData = res.data.([]ipNeighEntry)
		case "uciDHCP":
			uciDHCPData = res.data.(*ubusUCIDHCPData)
		}
	}

	// 2. 以 MAC 为锚点合并映射
	// MAC → {IP set, hostname[优先级]}
	type macEntry struct {
		ips      map[string]struct{}
		hostname string // 当前最高优先级 hostname
	}

	macMap := make(map[string]*macEntry)

	// 处理 getHostHints
	if getHostHintsData != nil {
		for mac, info := range getHostHintsData {
			entry, ok := macMap[strings.ToUpper(mac)]
			if !ok {
				entry = &macEntry{ips: make(map[string]struct{})}
				macMap[strings.ToUpper(mac)] = entry
			}
			for _, ip := range info.IPAddrs {
				entry.ips[normalizeIP(ip)] = struct{}{}
			}
			for _, ip := range info.IP6Addrs {
				entry.ips[normalizeIP(ip)] = struct{}{}
			}
			if info.Name != "" && entry.hostname == "" {
				entry.hostname = info.Name
			}
		}
	}

	// 处理 getDHCPLeases
	if getDHCPLeasesData != nil {
		for _, lease := range getDHCPLeasesData.DHCPLeases {
			mac := strings.ToUpper(strings.TrimSpace(lease.MACAddr))
			if mac == "" {
				continue
			}
			entry, ok := macMap[mac]
			if !ok {
				entry = &macEntry{ips: make(map[string]struct{})}
				macMap[mac] = entry
			}
			if lease.IPAddr != "" {
				entry.ips[normalizeIP(lease.IPAddr)] = struct{}{}
			}
			// DHCPLeases hostname 优先级最低，仅当尚无 hostname 时使用
			if lease.Hostname != "" && entry.hostname == "" {
				entry.hostname = lease.Hostname
			}
		}
	}

	// 处理 ip neigh（过滤 FAILED/INCOMPLETE 或 lladdr 空的条目）
	if ipNeighData != nil {
		for _, neigh := range ipNeighData {
			lladdr := strings.TrimSpace(neigh.Lladdr)
			if lladdr == "" {
				continue
			}
			// 检查 state 是否含 FAILED/INCOMPLETE
			skip := false
			for _, state := range neigh.State {
				state = strings.ToUpper(strings.TrimSpace(state))
				if state == "FAILED" || state == "INCOMPLETE" {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			mac := strings.ToUpper(lladdr)
			entry, ok := macMap[mac]
			if !ok {
				entry = &macEntry{ips: make(map[string]struct{})}
				macMap[mac] = entry
			}
			if neigh.Dst != "" {
				entry.ips[normalizeIP(neigh.Dst)] = struct{}{}
			}
		}
	}

	// 处理 uci get dhcp host 段（最高 hostname 优先级）
	if uciDHCPData != nil {
		for _, host := range uciDHCPData.Values {
			if host.Type != "host" {
				continue
			}
			mac := ""
			switch v := host.MAC.(type) {
			case string:
				mac = strings.TrimSpace(v)
			case []interface{}:
				if len(v) > 0 {
					mac = fmt.Sprint(v[0])
				}
			}
			mac = strings.ToUpper(mac)
			if mac == "" || host.IP == "" {
				continue
			}
			entry, ok := macMap[mac]
			if !ok {
				entry = &macEntry{ips: make(map[string]struct{})}
				macMap[mac] = entry
			}
			entry.ips[normalizeIP(host.IP)] = struct{}{}
			// uci 的 hostname 优先级最高，无条件覆盖
			if host.Name != "" {
				entry.hostname = host.Name
			}
		}
	}

	// 3. 构建 IP→MAC→hostname 映射表
	now := time.Now().UnixMilli()
	ipToMapping := make(map[string]*deviceMapping)

	for mac, entry := range macMap {
		for ip := range entry.ips {
			ipToMapping[ip] = &deviceMapping{
				IP:        ip,
				MAC:       mac,
				Hostname:  entry.hostname,
				FirstSeen: now,
				LastSeen:  now,
			}
		}
	}

	// 4. upsert 到 device_mappings 表
	if err := s.upsertDeviceMappings(ipToMapping, now); err != nil {
		return fmt.Errorf("upsert 设备映射失败: %w", err)
	}

	// 5. 替换内存表
	s.deviceMappingMu.Lock()
	s.deviceMappings = ipToMapping
	s.deviceMappingMu.Unlock()

	s.mu.Lock()
	s.lastDeviceRefresh = time.Now()
	s.mu.Unlock()

	log.Printf("设备映射刷新完成: %d 个 MAC, %d 个 IP 映射", len(macMap), len(ipToMapping))
	return nil
}

// upsertDeviceMappings 将新映射写入 device_mappings 表。
// IP+MAC 已存在 → 更新 last_seen 和 hostname
// IP 存在但 MAC 变化 → 保留旧记录（不更新 last_seen），插入新记录
// IP 不存在 → 插入新记录
func (s *service) upsertDeviceMappings(newMappings map[string]*deviceMapping, now int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 查询现有记录：每个 IP 对应的所有 MAC
	rows, err := tx.Query(`SELECT ip, mac, hostname, first_seen, last_seen FROM device_mappings`)
	if err != nil {
		return err
	}

	existing := make(map[string]map[string]*deviceMapping) // ip → {mac → dm}
	for rows.Next() {
		var dm deviceMapping
		if err := rows.Scan(&dm.IP, &dm.MAC, &dm.Hostname, &dm.FirstSeen, &dm.LastSeen); err != nil {
			rows.Close()
			return err
		}
		ipMap, ok := existing[dm.IP]
		if !ok {
			ipMap = make(map[string]*deviceMapping)
			existing[dm.IP] = ipMap
		}
		entry := dm
		ipMap[dm.MAC] = &entry
	}
	rows.Close()

	upsertStmt, err := tx.Prepare(`
		INSERT INTO device_mappings (ip, mac, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip, mac) DO UPDATE SET
			hostname = excluded.hostname,
			last_seen = excluded.last_seen
	`)
	if err != nil {
		return err
	}
	defer upsertStmt.Close()

	for _, newDM := range newMappings {
		ipMap, ipExists := existing[newDM.IP]

		if ipExists {
			if existingDM, macMatch := ipMap[newDM.MAC]; macMatch {
				// IP+MAC 已存在：更新 last_seen 和 hostname
				if _, err := upsertStmt.Exec(newDM.IP, newDM.MAC, newDM.Hostname, existingDM.FirstSeen, now); err != nil {
					return err
				}
			} else {
				// IP 存在但 MAC 变化：插入新记录（旧记录的 last_seen 保持不动）
				if _, err := upsertStmt.Exec(newDM.IP, newDM.MAC, newDM.Hostname, now, now); err != nil {
					return err
				}
			}
		} else {
			// IP 不存在：插入新记录
			if _, err := upsertStmt.Exec(newDM.IP, newDM.MAC, newDM.Hostname, now, now); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// ---------------------------------------------------------------------------
// 事件驱动映射获取
// ---------------------------------------------------------------------------

// checkNewIPs 检查一列 source_ip 是否有新 IP，若有则异步触发刷新。
// 同轮询多新 IP 只触发一次，防抖 30 秒。
func (s *service) checkNewIPs(sourceIPs []string) {
	if !s.ubusEnabled() {
		return
	}

	hasNew := false
	for _, ip := range sourceIPs {
		if ip == "" {
			continue
		}
		dm := s.getDeviceMapping(ip)
		if dm == nil {
			hasNew = true
			break
		}
	}

	if !hasNew {
		return
	}

	// 防抖检查
	s.mu.Lock()
	lastRefresh := s.lastDeviceRefresh
	s.mu.Unlock()

	if !lastRefresh.IsZero() && time.Since(lastRefresh) < deviceMappingDebounceInterval {
		// log.Printf("设备映射刷新防抖: 距上次刷新不足 %v, 跳过", deviceMappingDebounceInterval)
		return
	}

	// 异步触发刷新
	go func() {
		log.Printf("发现新 IP，异步触发设备映射刷新")
		if err := s.refreshDeviceMappings(); err != nil {
			log.Printf("事件驱动设备映射刷新失败: %v", err)
		}
	}()
}

// ---------------------------------------------------------------------------
// 定期全量刷新
// ---------------------------------------------------------------------------

// runPeriodicDeviceRefresh 按固定间隔定期执行全量映射刷新。
func (s *service) runPeriodicDeviceRefresh(ctx context.Context) {
	ticker := time.NewTicker(deviceMappingPeriodicInterval)
	defer ticker.Stop()

	// 启动后立即执行一次初始刷新
	log.Printf("开始初始设备映射刷新（间隔 %v）", deviceMappingPeriodicInterval)
	if err := s.refreshDeviceMappings(); err != nil {
		log.Printf("初始设备映射刷新失败: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// log.Printf("定期设备映射刷新开始")
			if err := s.refreshDeviceMappings(); err != nil {
				log.Printf("定期设备映射刷新失败: %v", err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 查询后处理：label 增强 + MAC 聚合 + 下钻 MAC 反查
// ---------------------------------------------------------------------------

// applyDeviceLabelAndMACAggregate 对 aggregatedData 列表应用 label 增强和 MAC 二次聚合。
// 按查询 start/end 时间范围从 device_mappings 表匹配有效映射，按 MAC 合并。
// 降级时（ubus 关闭或无映射）直接返回原始结果。
func (s *service) applyDeviceLabelAndMACAggregate(data []aggregatedData, start, end int64) []aggregatedData {
	if !s.ubusEnabled() || len(data) == 0 {
		return data
	}

	// 收集所有 source_ip
	ips := make([]string, 0, len(data))
	for _, d := range data {
		if d.Label != "" {
			ips = append(ips, d.Label)
		}
	}
	if len(ips) == 0 {
		return data
	}

	// 批量查 device_mappings（时段匹配）
	mappingByIP := s.queryMappingsForIPs(ips, start, end)

	// 如果没有映射，返回原始结果
	if len(mappingByIP) == 0 {
		return data
	}

	// 按 MAC 二次聚合
	macAgg := make(map[string]*aggregatedData) // key = MAC 或原始 IP（无映射）
	for _, d := range data {
		dm, hasMapping := mappingByIP[d.Label]
		key := d.Label
		mac := ""
		label := d.Label
		if hasMapping {
			key = dm.MAC
			mac = dm.MAC
			if dm.Hostname != "" {
				label = dm.Hostname
			} else {
				label = dm.MAC
			}
		}

		existing, ok := macAgg[key]
		if !ok {
			item := aggregatedData{
				Label:    label,
				Mac:      mac,
				Upload:   d.Upload,
				Download: d.Download,
				Total:    d.Total,
				Count:    d.Count,
			}
			macAgg[key] = &item
		} else {
			existing.Upload += d.Upload
			existing.Download += d.Download
			existing.Total += d.Total
			existing.Count += d.Count
		}
	}

	// 转为列表并按 total 降序
	result := make([]aggregatedData, 0, len(macAgg))
	for _, item := range macAgg {
		result = append(result, *item)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Total == result[j].Total {
			return result[i].Label < result[j].Label
		}
		return result[i].Total > result[j].Total
	})

	return result
}

// queryMappingsForIPs 批量查询 device_mappings 表，返回 IP→deviceMapping 映射。
// 时段匹配：WHERE ip IN (...) AND first_seen <= end AND last_seen >= start
// 同一 IP 多条匹配时选 last_seen 最大的。
func (s *service) queryMappingsForIPs(ips []string, start, end int64) map[string]*deviceMapping {
	if len(ips) == 0 {
		return nil
	}

	// 构建 IN 子句
	placeholders := make([]string, len(ips))
	args := make([]any, 0, len(ips)+2)
	for i, ip := range ips {
		placeholders[i] = "?"
		args = append(args, ip)
	}
	args = append(args, end, start)

	query := fmt.Sprintf(`
		SELECT ip, mac, hostname, first_seen, last_seen
		FROM device_mappings
		WHERE ip IN (%s) AND first_seen <= ? AND last_seen >= ?
		ORDER BY last_seen DESC
	`, strings.Join(placeholders, ","))

	rows, err := s.db.Query(query, args...)
	if err != nil {
		log.Printf("查询设备映射失败: %v", err)
		return nil
	}
	defer rows.Close()

	result := make(map[string]*deviceMapping)
	seen := make(map[string]bool) // IP 已取过 last_seen 最大的

	for rows.Next() {
		var dm deviceMapping
		if err := rows.Scan(&dm.IP, &dm.MAC, &dm.Hostname, &dm.FirstSeen, &dm.LastSeen); err != nil {
			log.Printf("扫描设备映射行失败: %v", err)
			return nil
		}
		if seen[dm.IP] {
			continue
		}
		seen[dm.IP] = true
		entry := dm
		result[dm.IP] = &entry
	}

	return result
}

// formatDeviceLabel 格式化单个 source_ip 的显示 label。
// 有 hostname → label=hostname，有 MAC 无 hostname → label=MAC，无映射 → label=原始IP。
// 返回 (label, mac)。
func (s *service) formatDeviceLabel(sourceIP string) (string, string) {
	dm := s.getDeviceMapping(sourceIP)
	if dm == nil {
		return sourceIP, ""
	}
	if dm.Hostname != "" {
		return dm.Hostname, dm.MAC
	}
	return dm.MAC, dm.MAC
}

// resolveMACToIPs 根据 MAC 地址查询 device_mappings 表，返回关联的所有 IP 列表。
// 用于下钻时从 MAC 反查所有 IP。
func (s *service) resolveMACToIPs(mac string, start, end int64) []string {
	rows, err := s.db.Query(`
		SELECT DISTINCT ip
		FROM device_mappings
		WHERE mac = ? AND first_seen <= ? AND last_seen >= ?
	`, mac, end, start)
	if err != nil {
		log.Printf("MAC 反查 IP 失败: %v", err)
		return nil
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			log.Printf("扫描 MAC 反查结果失败: %v", err)
			return nil
		}
		ips = append(ips, ip)
	}
	return ips
}

// looksLikeMAC 简单检查字符串是否像 MAC 地址（格式：XX:XX:XX:XX:XX:XX）。
func looksLikeMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i := 0; i < 17; i++ {
		if i%3 == 2 {
			if s[i] != ':' {
				return false
			}
		} else {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// 查询辅助：按 IP 列表查询子统计和连接明细（用于 MAC 反查下钻）
// ---------------------------------------------------------------------------

// querySubstatsByIPs 按多个 source_ip 查询子统计（用于 MAC 反查）。
func (s *service) querySubstatsByIPs(dimension string, ips []string, start, end int64) ([]aggregatedData, error) {
	if _, err := dimensionColumn(dimension); err != nil {
		return nil, err
	}

	placeholders := make([]string, len(ips))
	args := make([]any, 0, len(ips))
	for i, ip := range ips {
		placeholders[i] = "?"
		args = append(args, ip)
	}

	filter := fmt.Sprintf("source_ip IN (%s)", strings.Join(placeholders, ","))
	return s.queryByFilters("host", filter, args, start, end)
}

// queryConnectionDetailsByIPs 使用 source_ip IN (...) 查询连接明细（用于 MAC 反查）。
func (s *service) queryConnectionDetailsByIPs(ips []string, host string, start, end int64) ([]connectionDetail, error) {
	placeholders := make([]string, len(ips))
	args := make([]any, 0, len(ips)+1)
	for i, ip := range ips {
		placeholders[i] = "?"
		args = append(args, ip)
	}
	args = append(args, host)

	rows, err := s.db.Query(`
		SELECT destination_ip,
		       source_ip,
		       process,
		       outbound,
		       chains,
		       COALESCE(SUM(upload), 0) AS upload,
		       COALESCE(SUM(download), 0) AS download,
		       COALESCE(SUM(upload + download), 0) AS total,
		       COALESCE(SUM(count), 0) AS count
		FROM traffic_aggregated
		WHERE bucket_end > ? AND bucket_start <= ?
		  AND source_ip IN (`+strings.Join(placeholders, ",")+`) AND host = ?
		GROUP BY destination_ip, source_ip, process, outbound, chains
	`, append([]any{start, end}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	merged := make(map[string]*connectionDetail)
	for rows.Next() {
		var (
			item      connectionDetail
			chainsRaw string
		)
		if err := rows.Scan(
			&item.DestinationIP,
			&item.SourceIP,
			&item.Process,
			&item.Outbound,
			&chainsRaw,
			&item.Upload,
			&item.Download,
			&item.Total,
			&item.Count,
		); err != nil {
			return nil, err
		}
		item.Chains = parseChains(chainsRaw)
		mergeConnectionDetailRows(merged, []connectionDetail{item})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 从 buffer 查
	bufferFilter := fmt.Sprintf("source_ip IN (%s)", strings.Join(placeholders, ","))
	bufferArgs := make([]any, len(ips))
	copy(bufferArgs, args[:len(ips)])
	mergeConnectionDetailRows(merged, s.queryConnectionDetailsFromBuffer(bufferFilter+" AND host = ?", append(bufferArgs, host), start, end))

	return sortedConnectionDetailRows(merged), nil
}
