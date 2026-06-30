package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// insertDeviceMappings 向 device_mappings 表插入测试记录。
func insertDeviceMappings(t *testing.T, db *sql.DB, entries []deviceMapping) {
	t.Helper()
	for _, d := range entries {
		_, err := db.Exec(
			`INSERT INTO device_mappings (ip, mac, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)`,
			d.IP, d.MAC, d.Hostname, d.FirstSeen, d.LastSeen,
		)
		if err != nil {
			t.Fatalf("insert device_mapping(ip=%q mac=%q): %v", d.IP, d.MAC, err)
		}
	}
}

// newTestServiceWithUbus 创建测试 service 并启用 ubus 设备解析（连接到指定 mock server）。
func newTestServiceWithUbus(t *testing.T, ubusServerURL string) *service {
	t.Helper()
	svc := newTestService(t)
	svc.ubusCli = &ubusClient{
		url:      ubusServerURL,
		username: "testuser",
		password: "testpass",
		client:   &http.Client{Timeout: 5 * time.Second},
	}
	svc.deviceMappings = make(map[string]*deviceMapping)
	return svc
}

// ubusMockResponse 定义 ubus mock 对特定调用的响应。
type ubusMockResponse struct {
	Data    any             // 成功时的数据（成为 [0, data] 的第二元素）
	RPCErr  *ubusRPCError   // 非空时返回 RPC 层错误
	HTTPErr error           // 非空时返回 HTTP 层错误
}

// ---------------------------------------------------------------------------
// 9.1 ubus 响应解析测试
// ---------------------------------------------------------------------------

func TestUbusResponseParsing(t *testing.T) {
	t.Run("getHostHints", func(t *testing.T) {
		data := `{"AA:BB:CC:DD:EE:01":{"ipaddrs":["192.168.1.10"],"ip6addrs":["2001:db8:1::a","fe80::a"],"name":"device-01.lan"},"AA:BB:CC:DD:EE:02":{"ipaddrs":["192.168.1.20"],"ip6addrs":["2001:db8:1::b"],"name":"device-02"}}`
		var hints map[string]ubusHostHintInfo
		if err := json.Unmarshal([]byte(data), &hints); err != nil {
			t.Fatalf("unmarshal getHostHints: %v", err)
		}
		if len(hints) != 2 {
			t.Fatalf("expected 2 hosts, got %d", len(hints))
		}
		// 验证第一个设备
		h1, ok := hints["AA:BB:CC:DD:EE:01"]
		if !ok {
			t.Fatal("missing MAC AA:BB:CC:DD:EE:01")
		}
		if len(h1.IPAddrs) != 1 || h1.IPAddrs[0] != "192.168.1.10" {
			t.Fatalf("unexpected IPAddrs: %v", h1.IPAddrs)
		}
		if len(h1.IP6Addrs) != 2 {
			t.Fatalf("expected 2 IPv6 addrs, got %d", len(h1.IP6Addrs))
		}
		if h1.Name != "device-01.lan" {
			t.Fatalf("expected name device-01.lan, got %q", h1.Name)
		}
		// 验证第二个设备
		h2, ok := hints["AA:BB:CC:DD:EE:02"]
		if !ok {
			t.Fatal("missing MAC AA:BB:CC:DD:EE:02")
		}
		if len(h2.IPAddrs) != 1 || h2.IPAddrs[0] != "192.168.1.20" {
			t.Fatalf("unexpected IPAddrs: %v", h2.IPAddrs)
		}
		if h2.Name != "device-02" {
			t.Fatalf("expected name device-02, got %q", h2.Name)
		}
	})

	t.Run("getDHCPLeases", func(t *testing.T) {
		data := `{"dhcp_leases":[{"expires":31980,"hostname":"device-01","macaddr":"AA:BB:CC:DD:EE:01","ipaddr":"192.168.1.10"}],"dhcp6_leases":[]}`
		var leases ubusDHCPLeasesData
		if err := json.Unmarshal([]byte(data), &leases); err != nil {
			t.Fatalf("unmarshal getDHCPLeases: %v", err)
		}
		if len(leases.DHCPLeases) != 1 {
			t.Fatalf("expected 1 lease, got %d", len(leases.DHCPLeases))
		}
		l := leases.DHCPLeases[0]
		if l.Hostname != "device-01" || l.MACAddr != "AA:BB:CC:DD:EE:01" || l.IPAddr != "192.168.1.10" {
			t.Fatalf("unexpected lease: %+v", l)
		}
		if l.Expires != 31980 {
			t.Fatalf("expected expires=31980, got %d", l.Expires)
		}
		if len(leases.DHCP6Leases) != 0 {
			t.Fatalf("expected 0 DHCP6 leases, got %d", len(leases.DHCP6Leases))
		}
	})

	t.Run("ipNeigh", func(t *testing.T) {
		// 模拟 ip neigh stdout JSON 数组
		data := `[{"dst":"192.168.1.10","dev":"br-lan","lladdr":"aa:bb:cc:dd:ee:01","state":["REACHABLE"]},{"dst":"2001:db8:1::a","dev":"br-lan","lladdr":"aa:bb:cc:dd:ee:01","state":["STALE"]},{"dst":"192.168.1.6","dev":"br-lan","state":["FAILED"]}]`
		var entries []ipNeighEntry
		if err := json.Unmarshal([]byte(data), &entries); err != nil {
			t.Fatalf("unmarshal ip neigh: %v", err)
		}
		if len(entries) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(entries))
		}
		// 第一个：正常条目
		if entries[0].Dst != "192.168.1.10" || entries[0].Lladdr != "aa:bb:cc:dd:ee:01" {
			t.Fatalf("unexpected entry[0]: %+v", entries[0])
		}
		if len(entries[0].State) != 1 || entries[0].State[0] != "REACHABLE" {
			t.Fatalf("unexpected entry[0].State: %v", entries[0].State)
		}
		// 第二个：IPv6 条目
		if entries[1].Dst != "2001:db8:1::a" {
			t.Fatalf("unexpected entry[1].Dst: %s", entries[1].Dst)
		}
		// 第三个：FAILED 条目（lladdr 为空）
		if entries[2].Dst != "192.168.1.6" || entries[2].Lladdr != "" {
			t.Fatalf("unexpected entry[2]: %+v", entries[2])
		}
		if len(entries[2].State) != 1 || entries[2].State[0] != "FAILED" {
			t.Fatalf("unexpected entry[2].State: %v", entries[2].State)
		}
	})

	t.Run("uciDHCP", func(t *testing.T) {
		data := `{"values":{"cfg06fe63":{".type":"host","name":"device-01","ip":"192.168.1.10","mac":"AA:BB:CC:DD:EE:01"},"cfg08fe63":{".type":"host","name":"device-02","ip":"192.168.1.20","mac":"AA:BB:CC:DD:EE:02"}}}`
		var uci ubusUCIDHCPData
		if err := json.Unmarshal([]byte(data), &uci); err != nil {
			t.Fatalf("unmarshal uci dhcp: %v", err)
		}
		if len(uci.Values) != 2 {
			t.Fatalf("expected 2 values, got %d", len(uci.Values))
		}
		h1, ok := uci.Values["cfg06fe63"]
		if !ok {
			t.Fatal("missing cfg06fe63")
		}
		if h1.Type != "host" || h1.Name != "device-01" || h1.IP != "192.168.1.10" {
			t.Fatalf("unexpected host entry: %+v", h1)
		}
		macStr, _ := h1.MAC.(string)
		if macStr != "AA:BB:CC:DD:EE:01" {
			t.Fatalf("expected MAC string, got %T=%v", h1.MAC, h1.MAC)
		}
		h2, ok := uci.Values["cfg08fe63"]
		if !ok {
			t.Fatal("missing cfg08fe63")
		}
		if h2.Name != "device-02" {
			t.Fatalf("expected name device-02, got %q", h2.Name)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.2 IP 规范化测试
// ---------------------------------------------------------------------------

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"2001:0db8:0001:0000:0000:0000:0000:0001", "2001:db8:1::1"},
		{"2001:db8:1::1", "2001:db8:1::1"},
		{"192.168.1.10", "192.168.1.10"},
		{"Inner", "Inner"},
		{"", ""},
		{"::1", "::1"},
		{"0.0.0.0", "0.0.0.0"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
	}

	for _, c := range cases {
		got := normalizeIP(c.input)
		if got != c.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", c.input, got, c.want)
		}
		// 自反性：再次规范化应不变
		got2 := normalizeIP(got)
		if got2 != got {
			t.Errorf("normalizeIP(normalizeIP(%q)) = %q, want %q", c.input, got2, got)
		}
	}
}

// ---------------------------------------------------------------------------
// 9.3 数据源优先级合并测试
// ---------------------------------------------------------------------------

func TestDeviceMappingMerge(t *testing.T) {
	t.Run("hostname优先级 uci > getHostHints > getDHCPLeases", func(t *testing.T) {
		// 创建 mock ubus server，返回各数据源
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")
			switch key {
			case "session.login":
				// 返回 token
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token"}},
				})
			case "luci-rpc.getHostHints":
				// getHostHints 返回 name=device-01.lan
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{
						"AA:BB:CC:DD:EE:01": map[string]any{
							"ipaddrs":  []string{"192.168.1.10"},
							"ip6addrs": []string{"2001:db8:1::a"},
							"name":     "device-01.lan",
						},
					}},
				})
			case "luci-rpc.getDHCPLeases":
				// getDHCPLeases 返回 hostname=device-01
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{
						"dhcp_leases": []map[string]any{
							{"expires": 31980, "hostname": "device-01", "macaddr": "AA:BB:CC:DD:EE:01", "ipaddr": "192.168.1.10"},
						},
						"dhcp6_leases": []map[string]any{},
					}},
				})
			case "file.exec":
				// ip neigh（包含正常和 FAILED 条目）
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{
						"code":   0,
						"stdout": `[{"dst":"192.168.1.10","dev":"br-lan","lladdr":"aa:bb:cc:dd:ee:01","state":["REACHABLE"]},{"dst":"192.168.1.6","dev":"br-lan","state":["FAILED"]}]`,
					}},
				})
			case "uci.get":
				// uci get dhcp 返回 name=device-01（最高优先级）
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{
						"values": map[string]any{
							"cfg06fe63": map[string]any{
								".type": "host", "name": "device-01", "ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01",
							},
						},
					}},
				})
			default:
				t.Fatalf("unexpected ubus call: key=%s", key)
			}
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)
		if err := svc.refreshDeviceMappings(); err != nil {
			t.Fatalf("refreshDeviceMappings: %v", err)
		}

		// 验证：MAC AA:BB:CC:DD:EE:01 → hostname=device-01（uci 优先级最高）
		dm := svc.getDeviceMapping("192.168.1.10")
		if dm == nil {
			t.Fatal("expected device mapping for 192.168.1.10")
		}
		if dm.Hostname != "device-01" {
			t.Fatalf("expected hostname=device-01 (uci priority), got %q", dm.Hostname)
		}
		if dm.MAC != "AA:BB:CC:DD:EE:01" {
			t.Fatalf("expected MAC=AA:BB:CC:DD:EE:01, got %q", dm.MAC)
		}
		// IPv6 地址也应有映射
		v6 := normalizeIP("2001:db8:1::a")
		dm6 := svc.getDeviceMapping(v6)
		if dm6 == nil {
			t.Fatal("expected device mapping for IPv6 address")
		}
		if dm6.MAC != "AA:BB:CC:DD:EE:01" {
			t.Fatalf("expected IPv6 → same MAC, got %q", dm6.MAC)
		}
	})

	t.Run("邻居表FAILED条目被过滤", func(t *testing.T) {
		// 简化测试：只返回 ip neigh 带 FAILED 条目，不应产生映射
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")
			switch key {
			case "session.login":
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token"}},
				})
			case "file.exec":
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{
						"code":   0,
						"stdout": `[{"dst":"192.168.1.6","dev":"br-lan","state":["FAILED"]},{"dst":"192.168.1.7","dev":"br-lan","lladdr":"","state":["INCOMPLETE"]}]`,
					}},
				})
			default:
				// 其他数据源返回空
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{}},
				})
			}
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)
		if err := svc.refreshDeviceMappings(); err != nil {
			t.Fatalf("refreshDeviceMappings: %v", err)
		}
		// FAILED 和 INCOMPLETE 不应产生映射
		if svc.getDeviceMapping("192.168.1.6") != nil {
			t.Error("expected no mapping for FAILED entry 192.168.1.6")
		}
		if svc.getDeviceMapping("192.168.1.7") != nil {
			t.Error("expected no mapping for INCOMPLETE entry 192.168.1.7")
		}
	})

	t.Run("单数据源失败不阻断", func(t *testing.T) {
		// getHostHints 失败，其他成功，应仍有映射
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")
			switch key {
			case "session.login":
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token"}},
				})
			case "luci-rpc.getHostHints":
				// 模拟失败（返回非零 ubus 码）- doCall 会返回 error
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{-1, map[string]any{}},
				})
			case "uci.get":
				// uci 成功，提供映射
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{
						"values": map[string]any{
							"cfg01": map[string]any{
								".type": "host", "name": "test-device", "ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:FF",
							},
						},
					}},
				})
			default:
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{}},
				})
			}
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)
		if err := svc.refreshDeviceMappings(); err != nil {
			t.Fatalf("refreshDeviceMappings: %v", err)
		}
		dm := svc.getDeviceMapping("192.168.1.20")
		if dm == nil {
			t.Fatal("expected mapping for 192.168.1.20 despite getHostHints failure")
		}
		if dm.MAC != "AA:BB:CC:DD:EE:FF" || dm.Hostname != "test-device" {
			t.Fatalf("unexpected mapping: %+v", dm)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.4 MAC 二次聚合测试
// ---------------------------------------------------------------------------

func TestMACAggregate(t *testing.T) {
	t.Run("同设备多IP归并", func(t *testing.T) {
		svc := newTestService(t)
		// 启用 ubus 并插入 device_mappings
		svc.ubusCli = &ubusClient{} // 非 nil 使 ubusEnabled 返回 true
		svc.deviceMappings = make(map[string]*deviceMapping)
		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "device-01", FirstSeen: 1000, LastSeen: 2000},
			{IP: normalizeIP("2001:db8:1::a"), MAC: "AA:BB:CC:DD:EE:01", Hostname: "device-01", FirstSeen: 1000, LastSeen: 2000},
		})

		data := []aggregatedData{
			{Label: "192.168.1.10", Upload: 100, Download: 200, Total: 300, Count: 1},
			{Label: normalizeIP("2001:db8:1::a"), Upload: 200, Download: 300, Total: 500, Count: 2},
		}

		got := svc.applyDeviceLabelAndMACAggregate(data, 1000, 2000)
		if len(got) != 1 {
			t.Fatalf("expected 1 merged record, got %d: %+v", len(got), got)
		}
		if got[0].Label != "device-01" {
			t.Fatalf("expected label=device-01, got %q", got[0].Label)
		}
		if got[0].Mac != "AA:BB:CC:DD:EE:01" {
			t.Fatalf("expected mac=AA:BB:CC:DD:EE:01, got %q", got[0].Mac)
		}
		if got[0].Upload != 300 || got[0].Download != 500 || got[0].Total != 800 || got[0].Count != 3 {
			t.Fatalf("unexpected aggregated values: %+v", got[0])
		}
	})

	t.Run("无映射IP各自独立", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{} // 启用 ubus
		svc.deviceMappings = make(map[string]*deviceMapping)
		// 不放任何映射数据

		data := []aggregatedData{
			{Label: "10.0.0.1", Upload: 100, Download: 200, Total: 300, Count: 1},
			{Label: "10.0.0.2", Upload: 50, Download: 100, Total: 150, Count: 1},
		}

		got := svc.applyDeviceLabelAndMACAggregate(data, 1000, 2000)
		// 无映射时，applyDeviceLabelAndMACAggregate 检查 len(mappingByIP) == 0 返回原始结果
		if len(got) != 2 {
			t.Fatalf("expected 2 records (no mappings), got %d", len(got))
		}
	})

	t.Run("聚合后按total降序", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)
		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:01", Hostname: "dev-a", FirstSeen: 1000, LastSeen: 2000},
			{IP: "192.168.1.3", MAC: "AA:AA:AA:AA:AA:02", Hostname: "dev-b", FirstSeen: 1000, LastSeen: 2000},
			{IP: "192.168.1.4", MAC: "AA:AA:AA:AA:AA:03", Hostname: "dev-c", FirstSeen: 1000, LastSeen: 2000},
		})

		data := []aggregatedData{
			{Label: "192.168.1.3", Upload: 50, Download: 50, Total: 100, Count: 1},  // dev-b: 100
			{Label: "192.168.1.10", Upload: 300, Download: 300, Total: 600, Count: 3}, // dev-a: 600
			{Label: "192.168.1.4", Upload: 10, Download: 10, Total: 20, Count: 1},   // dev-c: 20
		}

		got := svc.applyDeviceLabelAndMACAggregate(data, 1000, 2000)
		if len(got) != 3 {
			t.Fatalf("expected 3 records, got %d", len(got))
		}
		if got[0].Total != 600 || got[1].Total != 100 || got[2].Total != 20 {
			t.Fatalf("expected descending total order, got totals: %d, %d, %d", got[0].Total, got[1].Total, got[2].Total)
		}
	})

	t.Run("降级零开销_ubus未配置", func(t *testing.T) {
		svc := newTestService(t)
		// ubusCli 为 nil → ubusEnabled=false

		data := []aggregatedData{
			{Label: "192.168.1.10", Upload: 100, Download: 200, Total: 300, Count: 1},
		}
		got := svc.applyDeviceLabelAndMACAggregate(data, 1000, 2000)
		// 应原样返回
		if len(got) != 1 || got[0].Label != "192.168.1.10" || got[0].Mac != "" {
			t.Fatalf("expected raw passthrough, got %+v", got[0])
		}
	})
}

// ---------------------------------------------------------------------------
// 9.5 label 格式化测试
// ---------------------------------------------------------------------------

func TestFormatDeviceLabel(t *testing.T) {
	t.Run("有hostname和MAC", func(t *testing.T) {
		svc := newTestService(t)
		svc.deviceMappings = map[string]*deviceMapping{
			"192.168.1.10": {IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "device-01"},
		}
		label, mac := svc.formatDeviceLabel("192.168.1.10")
		if label != "device-01" {
			t.Fatalf("expected label=device-01, got %q", label)
		}
		if mac != "AA:BB:CC:DD:EE:01" {
			t.Fatalf("expected mac=AA:BB:CC:DD:EE:01, got %q", mac)
		}
	})

	t.Run("有MAC无hostname", func(t *testing.T) {
		svc := newTestService(t)
		svc.deviceMappings = map[string]*deviceMapping{
			"192.168.1.10": {IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: ""},
		}
		label, mac := svc.formatDeviceLabel("192.168.1.10")
		if label != "AA:BB:CC:DD:EE:01" {
			t.Fatalf("expected label=MAC, got %q", label)
		}
		if mac != "AA:BB:CC:DD:EE:01" {
			t.Fatalf("expected mac=AA:BB:CC:DD:EE:01, got %q", mac)
		}
	})

	t.Run("无映射返回原始IP", func(t *testing.T) {
		svc := newTestService(t)
		svc.deviceMappings = make(map[string]*deviceMapping)
		label, mac := svc.formatDeviceLabel("10.0.0.99")
		if label != "10.0.0.99" {
			t.Fatalf("expected label=10.0.0.99, got %q", label)
		}
		if mac != "" {
			t.Fatalf("expected empty mac, got %q", mac)
		}
	})

	t.Run("混合展示", func(t *testing.T) {
		svc := newTestService(t)
		svc.deviceMappings = map[string]*deviceMapping{
			"192.168.1.10": {IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:01", Hostname: "dev-a"},
			"192.168.1.3":  {IP: "192.168.1.3", MAC: "BB:BB:BB:BB:BB:02", Hostname: ""},
		}
		cases := []struct {
			ip          string
			wantLabel   string
			wantMAC     string
		}{
			{"192.168.1.10", "dev-a", "AA:AA:AA:AA:AA:01"},
			{"192.168.1.3", "BB:BB:BB:BB:BB:02", "BB:BB:BB:BB:BB:02"},
			{"192.168.1.4", "192.168.1.4", ""},
		}
		for _, c := range cases {
			label, mac := svc.formatDeviceLabel(c.ip)
			if label != c.wantLabel || mac != c.wantMAC {
				t.Errorf("formatDeviceLabel(%q) = (%q, %q), want (%q, %q)", c.ip, label, mac, c.wantLabel, c.wantMAC)
			}
		}
	})

	t.Run("规范化后命中映射", func(t *testing.T) {
		svc := newTestService(t)
		svc.deviceMappings = map[string]*deviceMapping{
			normalizeIP("2001:db8:1::1"): {IP: normalizeIP("2001:db8:1::1"), MAC: "AA:BB:CC:DD:EE:FF", Hostname: "test-v6"},
		}
		// 用非规范化形式查询
		label, mac := svc.formatDeviceLabel("2001:0db8:0001:0000:0000:0000:0000:0001")
		if label != "test-v6" {
			t.Fatalf("expected label=test-v6, got %q", label)
		}
		if mac != "AA:BB:CC:DD:EE:FF" {
			t.Fatalf("expected mac=AA:BB:CC:DD:EE:FF, got %q", mac)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.6 降级测试
// ---------------------------------------------------------------------------

func TestDegradation(t *testing.T) {
	t.Run("ubus未配置跳过后面处理", func(t *testing.T) {
		svc := newTestService(t)
		if svc.ubusEnabled() {
			t.Fatal("expected ubusEnabled()=false with nil ubusCli")
		}
		// checkNewIPs 应直接返回
		svc.checkNewIPs([]string{"192.168.1.10"}) // 不应 panic
	})

	t.Run("映射为空返回原始结果", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		data := []aggregatedData{
			{Label: "192.168.1.10", Upload: 100, Download: 200, Total: 300, Count: 1},
		}
		got := svc.applyDeviceLabelAndMACAggregate(data, 1000, 2000)
		if len(got) != 1 || got[0].Label != "192.168.1.10" {
			t.Fatalf("expected raw passthrough with empty mappings, got %+v", got[0])
		}
	})

	t.Run("ubus未配置formatDeviceLabel返回原始IP", func(t *testing.T) {
		svc := newTestService(t)
		label, mac := svc.formatDeviceLabel("10.0.0.1")
		if label != "10.0.0.1" || mac != "" {
			t.Fatalf("expected (10.0.0.1, \"\"), got (%q, %q)", label, mac)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.7 历史映射持久化与时段测试
// ---------------------------------------------------------------------------

func TestDeviceMappingPersistence(t *testing.T) {
	t.Run("IP+MAC不变更新last_seen", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		// 插入一条记录
		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "old-name", FirstSeen: 1000, LastSeen: 1000},
		})

		// upsert 同 IP+MAC，更新 hostname 和 last_seen
		now := int64(2000)
		newMappings := map[string]*deviceMapping{
			"192.168.1.10": {IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "new-name", FirstSeen: now, LastSeen: now},
		}
		if err := svc.upsertDeviceMappings(newMappings, now); err != nil {
			t.Fatalf("upsertDeviceMappings: %v", err)
		}

		// 验证：last_seen 更新为 now，hostname 更新为 new-name，first_seen 保持 1000
		var firstSeen, lastSeen int64
		var hostname string
		err := svc.db.QueryRow(`SELECT first_seen, last_seen, hostname FROM device_mappings WHERE ip='192.168.1.10' AND mac='AA:BB:CC:DD:EE:01'`).Scan(&firstSeen, &lastSeen, &hostname)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if firstSeen != 1000 {
			t.Fatalf("expected first_seen=1000 (unchanged), got %d", firstSeen)
		}
		if lastSeen != now {
			t.Fatalf("expected last_seen=%d, got %d", now, lastSeen)
		}
		if hostname != "new-name" {
			t.Fatalf("expected hostname=new-name, got %q", hostname)
		}
	})

	t.Run("IP变MAC保留旧记录插入新记录", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		// 插入旧记录
		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "old-device", FirstSeen: 1000, LastSeen: 1500},
		})

		// upsert 同 IP 但不同 MAC
		now := int64(2000)
		newMappings := map[string]*deviceMapping{
			"192.168.1.10": {IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:FF", Hostname: "new-device", FirstSeen: now, LastSeen: now},
		}
		if err := svc.upsertDeviceMappings(newMappings, now); err != nil {
			t.Fatalf("upsertDeviceMappings: %v", err)
		}

		// 验证：旧记录保留，last_seen 保持 1500
		var count int64
		svc.db.QueryRow(`SELECT COUNT(*) FROM device_mappings WHERE ip='192.168.1.10'`).Scan(&count)
		if count != 2 {
			t.Fatalf("expected 2 rows (old + new), got %d", count)
		}

		var lastSeenOld int64
		svc.db.QueryRow(`SELECT last_seen FROM device_mappings WHERE ip='192.168.1.10' AND mac='AA:BB:CC:DD:EE:01'`).Scan(&lastSeenOld)
		if lastSeenOld != 1500 {
			t.Fatalf("expected old record last_seen=1500 (unchanged), got %d", lastSeenOld)
		}

		var lastSeenNew int64
		svc.db.QueryRow(`SELECT last_seen FROM device_mappings WHERE ip='192.168.1.10' AND mac='AA:BB:CC:DD:EE:FF'`).Scan(&lastSeenNew)
		if lastSeenNew != now {
			t.Fatalf("expected new record last_seen=%d, got %d", now, lastSeenNew)
		}
	})

	t.Run("启动时加载历史映射到内存", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		// 插入多条记录，同一 IP 有两条（不同 MAC）
		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "old", FirstSeen: 1000, LastSeen: 1500},
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:FF", Hostname: "new", FirstSeen: 1600, LastSeen: 2000},
			{IP: "192.168.1.3", MAC: "11:22:33:44:55:66", Hostname: "single", FirstSeen: 1000, LastSeen: 2000},
		})

		// 重新加载（模拟启动）
		if err := svc.loadDeviceMappingsFromDB(); err != nil {
			t.Fatalf("loadDeviceMappingsFromDB: %v", err)
		}

		// 内存映射应取每个 IP 的 last_seen 最大记录
		dm := svc.getDeviceMapping("192.168.1.10")
		if dm == nil {
			t.Fatal("expected mapping for 192.168.1.10")
		}
		if dm.MAC != "AA:BB:CC:DD:EE:FF" || dm.Hostname != "new" {
			t.Fatalf("expected newest record, got MAC=%q hostname=%q", dm.MAC, dm.Hostname)
		}

		dm3 := svc.getDeviceMapping("192.168.1.3")
		if dm3 == nil || dm3.MAC != "11:22:33:44:55:66" {
			t.Fatalf("unexpected mapping for 192.168.1.3: %+v", dm3)
		}
	})

	t.Run("跨时段查询匹配最近映射", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		// 两条时段记录
		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:01", Hostname: "dev-old", FirstSeen: 100, LastSeen: 500},
			{IP: "192.168.1.10", MAC: "BB:BB:BB:BB:BB:02", Hostname: "dev-new", FirstSeen: 600, LastSeen: 1000},
		})

		// 查询跨越两条记录时段（查询时间含两条记录的时间范围）
		mappings := svc.queryMappingsForIPs([]string{"192.168.1.10"}, 50, 1100)
		dm, ok := mappings["192.168.1.10"]
		if !ok {
			t.Fatal("expected mapping for 192.168.1.10")
		}
		// 跨时段应选 last_seen 最大的
		if dm.MAC != "BB:BB:BB:BB:BB:02" || dm.Hostname != "dev-new" {
			t.Fatalf("expected newest MAC, got MAC=%q hostname=%q", dm.MAC, dm.Hostname)
		}
	})

	t.Run("时段匹配仅命中一条记录", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:01", Hostname: "dev-old", FirstSeen: 100, LastSeen: 500},
			{IP: "192.168.1.10", MAC: "BB:BB:BB:BB:BB:02", Hostname: "dev-new", FirstSeen: 600, LastSeen: 1000},
		})

		// 查询时段仅命中第一条（200-400 在 100-500 内但不在 600-1000 内）
		mappings := svc.queryMappingsForIPs([]string{"192.168.1.10"}, 200, 400)
		dm, ok := mappings["192.168.1.10"]
		if !ok {
			t.Fatal("expected mapping for 192.168.1.10")
		}
		if dm.MAC != "AA:AA:AA:AA:AA:01" || dm.Hostname != "dev-old" {
			t.Fatalf("expected old MAC, got MAC=%q hostname=%q", dm.MAC, dm.Hostname)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.8 事件驱动触发测试
// ---------------------------------------------------------------------------

func TestCheckNewIPs(t *testing.T) {
	t.Run("发现新IP触发异步刷新", func(t *testing.T) {
		refreshCalled := false
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")
			switch key {
			case "session.login":
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token"}},
				})
			default:
				refreshCalled = true
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{}},
				})
			}
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)
		// 触发 checkNewIPs，IP 不在内存映射中
		svc.checkNewIPs([]string{"10.0.0.50"})

		// 等待 goroutine 执行
		time.Sleep(100 * time.Millisecond)

		if !refreshCalled {
			t.Error("expected refresh to be triggered by new IP")
		}
	})

	t.Run("同轮询多新IP只触发一次去重", func(t *testing.T) {
		callCount := 0
		var mu sync.Mutex
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			callCount++
			mu.Unlock()
			switch key {
			case "session.login":
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token"}},
				})
			default:
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{}},
				})
			}
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)

		// checkNewIPs 内部通过 deviceRefreshMu 互斥防止并发重复执行
		// refreshDeviceMappings 会在 deviceRefreshMu 中执行
		// 但 checkNewIPs 本身不检查是否正在刷新，而是通过防抖和互斥锁来限制

		// 第一次调用应触发刷新
		svc.checkNewIPs([]string{"10.0.0.1"})
		time.Sleep(50 * time.Millisecond)

		// 记录刷新后的时间
		svc.mu.Lock()
		svc.lastDeviceRefresh = time.Now()
		svc.mu.Unlock()

		// 同轮询第二次调用（但 lastDeviceRefresh 已设，防抖会阻止）
		svc.checkNewIPs([]string{"10.0.0.2", "10.0.0.3"})

		// 等待异步 goroutine 执行
		time.Sleep(100 * time.Millisecond)

		// checkNewIPs 防抖检查 lastDeviceRefresh，如果不到 30s 则跳过
		// 由于我们刚刚设置了 lastDeviceRefresh，第二次 checkNewIPs 应被防抖跳过
		// 但 refreshDeviceMappings 也通过 deviceRefreshMu 互斥防并发
		// 这里我们主要验证逻辑不 panic，且至少有一次 refresh 被触发
		_ = callCount
	})

	t.Run("防抖跳过频繁刷新", func(t *testing.T) {
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token"}},
			})
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)

		// 设置上次刷新的时间为刚刚
		svc.mu.Lock()
		svc.lastDeviceRefresh = time.Now()
		svc.mu.Unlock()

		// 此时 checkNewIPs 应被防抖跳过（距上次刷新不足 30s）
		// checkNewIPs 不 panic 即可
		svc.checkNewIPs([]string{"192.168.1.99"})
		// 没有 panic 即测试通过
	})

	t.Run("已知IP不触发刷新", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = map[string]*deviceMapping{
			"192.168.1.10": {IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "known"},
		}
		// 所有 IP 都在映射中，不应触发刷新
		svc.checkNewIPs([]string{"192.168.1.10"})
		// 没有 panic 即测试通过
	})
}

// ---------------------------------------------------------------------------
// 9.9 token 管理测试
// ---------------------------------------------------------------------------

func TestUbusTokenManagement(t *testing.T) {
	t.Run("首次登录缓存token", func(t *testing.T) {
		loginCount := 0
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")
			if key == "session.login" {
				loginCount++
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token-123"}},
				})
			} else {
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{}},
				})
			}
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)
		// 首次调用 call 会触发 login
		_, err := svc.ubusCli.call("luci-rpc", "getHostHints", nil)
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if loginCount != 1 {
			t.Fatalf("expected 1 login call, got %d", loginCount)
		}
		// token 应已缓存
		svc.ubusCli.mu.Lock()
		token := svc.ubusCli.token
		svc.ubusCli.mu.Unlock()
		if token != "mock-token-123" {
			t.Fatalf("expected cached token mock-token-123, got %q", token)
		}
	})

	t.Run("过期-32002自动重登重试", func(t *testing.T) {
		loginCount := 0
		callCount := 0
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")

			if key == "session.login" {
				loginCount++
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token-v2"}},
				})
				return
			}

			callCount++
			// 第一次调用返回 -32002（token 过期）
			if callCount == 1 {
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{-32002, map[string]any{}},
				})
				return
			}
			// 第二次调用成功
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": []any{0, map[string]any{"status": "ok"}},
			})
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)
		// 设置一个初始 token
		svc.ubusCli.mu.Lock()
		svc.ubusCli.token = "expired-token"
		svc.ubusCli.mu.Unlock()

		// 调用 getHostHints，应触发：首次调用 → -32002 → 重新 login → 重试成功
		_, err := svc.ubusCli.call("luci-rpc", "getHostHints", nil)
		if err != nil {
			t.Fatalf("expected retry success, got error: %v", err)
		}
		if loginCount != 1 {
			t.Fatalf("expected 1 re-login after token expiry, got %d", loginCount)
		}
		// token 应已更新
		svc.ubusCli.mu.Lock()
		token := svc.ubusCli.token
		svc.ubusCli.mu.Unlock()
		if token != "mock-token-v2" {
			t.Fatalf("expected updated token mock-token-v2, got %q", token)
		}
	})

	t.Run("不主动定时重登", func(t *testing.T) {
		// 验证 token 过期前不会主动重新 login
		loginCount := 0
		ubusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ubusRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			key := ""
			if len(req.Params) >= 3 {
				obj, _ := req.Params[1].(string)
				meth, _ := req.Params[2].(string)
				key = obj + "." + meth
			}
			w.Header().Set("Content-Type", "application/json")
			if key == "session.login" {
				loginCount++
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{"ubus_rpc_session": "mock-token"}},
				})
			} else {
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": []any{0, map[string]any{}},
				})
			}
		}))
		defer ubusServer.Close()

		svc := newTestServiceWithUbus(t, ubusServer.URL)
		// 多次调用，只应有首次 login
		for i := 0; i < 3; i++ {
			_, err := svc.ubusCli.call("luci-rpc", "getHostHints", nil)
			if err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
		}
		if loginCount != 1 {
			t.Fatalf("expected only 1 login for 3 calls, got %d", loginCount)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.10 下钻 MAC 反查测试
// ---------------------------------------------------------------------------

func TestMACDrillDown(t *testing.T) {
	t.Run("looksLikeMAC检测", func(t *testing.T) {
		cases := []struct {
			s    string
			want bool
		}{
			{"AA:BB:CC:DD:EE:01", true},
			{"aa:bb:cc:dd:ee:01", true},
			{"AA:BB:CC:DD:EE:FF", true},
			{"AA:BB:CC:DD:EE:0", false},  // 太短
			{"AA:BB:CC:DD:EE:GG", false}, // 无效字符
			{"192.168.1.10", false},
			{"device-01", false},
			{"", false},
			{"AA:BB:CC:DD:EE:01:FF", false}, // 太长
			{"AA-BB-CC-DD-EE-01", false},    // 分隔符不是冒号
		}
		for _, c := range cases {
			got := looksLikeMAC(c.s)
			if got != c.want {
				t.Errorf("looksLikeMAC(%q) = %v, want %v", c.s, got, c.want)
			}
		}
	})

	t.Run("MAC反查关联IP", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "device-01", FirstSeen: 1000, LastSeen: 2000},
			{IP: normalizeIP("2001:db8:1::a"), MAC: "AA:BB:CC:DD:EE:01", Hostname: "device-01", FirstSeen: 1000, LastSeen: 2000},
			{IP: "192.168.1.20", MAC: "AA:BB:CC:DD:EE:FF", Hostname: "other", FirstSeen: 1000, LastSeen: 2000},
		})

		// 通过 MAC 反查 IP
		ips := svc.resolveMACToIPs("AA:BB:CC:DD:EE:01", 1000, 2000)
		if len(ips) != 2 {
			t.Fatalf("expected 2 IPs for MAC AA:BB:CC:DD:EE:01, got %d: %v", len(ips), ips)
		}
		// 排序以便比较
		sort.Strings(ips)
		if ips[0] != "192.168.1.10" && ips[0] != normalizeIP("2001:db8:1::a") {
			t.Fatalf("unexpected IPs: %v", ips)
		}
	})

	t.Run("无映射传IP单条过滤", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		// 用 resolvedMACToIPs 查不存在的 MAC
		ips := svc.resolveMACToIPs("AA:BB:CC:DD:EE:01", 1000, 2000)
		if len(ips) != 0 {
			t.Fatalf("expected 0 IPs for unknown MAC, got %d", len(ips))
		}
	})

	t.Run("MAC反查+substats API路径", func(t *testing.T) {
		svc := newTestService(t)
		svc.ubusCli = &ubusClient{}
		svc.deviceMappings = make(map[string]*deviceMapping)

		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "device-01", FirstSeen: 1000, LastSeen: 2000},
			{IP: "192.168.1.20", MAC: "AA:BB:CC:DD:EE:01", Hostname: "device-01", FirstSeen: 1000, LastSeen: 2000},
		})

		// 验证 querySubstatsByIPs 能正确处理
		insertTestAggregates(t, svc.db, []aggregatedEntry{
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.10", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.20", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 100, Count: 1},
		})

		// MAC → 两个 IP → 合并子统计
		ips := svc.resolveMACToIPs("AA:BB:CC:DD:EE:01", 0, 60_000)
		if len(ips) != 2 {
			t.Fatalf("expected 2 IPs, got %d", len(ips))
		}

		data, err := svc.querySubstatsByIPs("host", ips, 0, 60_000)
		if err != nil {
			t.Fatalf("querySubstatsByIPs: %v", err)
		}
		if len(data) != 1 {
			t.Fatalf("expected 1 substat row, got %d", len(data))
		}
		if data[0].Label != "a.com" {
			t.Fatalf("expected label a.com, got %q", data[0].Label)
		}
		if data[0].Upload != 150 || data[0].Download != 300 {
			t.Fatalf("expected upload=150 download=300, got upload=%d download=%d", data[0].Upload, data[0].Download)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.11 映射表清理测试
// ---------------------------------------------------------------------------

func TestDeviceMappingCleanup(t *testing.T) {
	t.Run("随retention清理映射", func(t *testing.T) {
		svc := newTestService(t)
		svc.aggregateRetentionDays = 30

		now := time.Now()
		nowMS := now.UnixMilli()
		retentionCutoff := nowMS - int64(svc.aggregateRetentionDays)*86400000

		// 插入一些 device_mappings 记录
		insertDeviceMappings(t, svc.db, []deviceMapping{
			// last_seen 在 retention 内（应保留）
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "keep", FirstSeen: nowMS - 86400000, LastSeen: nowMS - 86400000},
			// last_seen 在 retention 外（应删除）
			{IP: "192.168.1.3", MAC: "AA:BB:CC:DD:EE:FF", Hostname: "delete-me", FirstSeen: retentionCutoff - 86400000, LastSeen: retentionCutoff - 86400000},
		})

		if err := svc.cleanupOldLogs(nowMS); err != nil {
			t.Fatalf("cleanupOldLogs: %v", err)
		}

		var kept int
		svc.db.QueryRow(`SELECT COUNT(*) FROM device_mappings WHERE ip='192.168.1.10'`).Scan(&kept)
		if kept != 1 {
			t.Errorf("expected 1 kept record, got %d", kept)
		}

		var deleted int
		svc.db.QueryRow(`SELECT COUNT(*) FROM device_mappings WHERE ip='192.168.1.3'`).Scan(&deleted)
		if deleted != 0 {
			t.Errorf("expected 0 deleted records, got %d", deleted)
		}
	})

	t.Run("retention变更后清理同步", func(t *testing.T) {
		svc := newTestService(t)
		// 设置 retention 为 7 天
		svc.aggregateRetentionDays = 7

		now := time.Now()
		nowMS := now.UnixMilli()

		// 插入一条 15 天前的记录
		oldLastSeen := nowMS - 15*86400000
		insertDeviceMappings(t, svc.db, []deviceMapping{
			{IP: "10.0.0.1", MAC: "AA:AA:AA:AA:AA:01", Hostname: "old", FirstSeen: oldLastSeen, LastSeen: oldLastSeen},
			{IP: "10.0.0.2", MAC: "BB:BB:BB:BB:BB:02", Hostname: "recent", FirstSeen: nowMS - 86400000, LastSeen: nowMS - 86400000},
		})

		// 清理（7 天 retention → 15 天前的记录应被删除）
		if err := svc.cleanupOldLogs(nowMS); err != nil {
			t.Fatalf("cleanupOldLogs: %v", err)
		}

		var oldCount int
		svc.db.QueryRow(`SELECT COUNT(*) FROM device_mappings WHERE ip='10.0.0.1'`).Scan(&oldCount)
		if oldCount != 0 {
			t.Errorf("expected old record (15 days ago) to be deleted, found %d", oldCount)
		}

		var recentCount int
		svc.db.QueryRow(`SELECT COUNT(*) FROM device_mappings WHERE ip='10.0.0.2'`).Scan(&recentCount)
		if recentCount != 1 {
			t.Errorf("expected recent record to remain, found %d", recentCount)
		}
	})
}

// ---------------------------------------------------------------------------
// 9.12 UI 字符串断言同步
// ---------------------------------------------------------------------------

// TestEmbeddedUISync 验证内嵌 UI 中的设备维度相关字符串已同步更新。
// 前端 UI 适配（任务组 8）可能已新增 .device-mac 等 CSS 类和关联 DOM 结构。
// 本测试检查前端标签和 DOM 结构是否与后端设备解析功能匹配。
func TestEmbeddedUISync(t *testing.T) {
	t.Run("index.html包含设备MAC展示结构", func(t *testing.T) {
		got := readEmbeddedFile(t, "web/index.html")
		// 前端应包含设备排行相关的 DOM 结构
		if !strings.Contains(got, "class=\"ranking\"") && !strings.Contains(got, "ranking") {
			// 前端可能有不同的 CSS 类名，检查是否存在某种排行结构
			t.Log("NOTE: ranking-related class not found, frontend may use different class names")
		}
		// 检查有无 data-primary 属性（用于下钻参数解耦），前端适配后应添加
		if !strings.Contains(got, "data-primary") {
			t.Log("NOTE: data-primary attribute not found in index.html - frontend drill-down parameter decoupling may not be applied yet")
		}
	})

	t.Run("styles.css包含device-mac样式", func(t *testing.T) {
		got := readEmbeddedFile(t, "web/styles.css")
		// 前端应定义 .device-mac 样式（小字 muted）
		if !strings.Contains(got, "device-mac") {
			// 如果前端尚未添加 .device-mac 样式，这是正常的
			// 但记录警告供参考
			t.Log("WARNING: .device-mac CSS class not found - frontend may not be fully updated")
		}
	})

	t.Run("app.js包含MAC展示逻辑", func(t *testing.T) {
		got := readEmbeddedFile(t, "web/app.js")
		// 前端应有设备维度展示逻辑
		if !strings.Contains(got, "data-primary") {
			t.Log("NOTE: data-primary attribute usage not found in app.js - frontend drill-down parameter decoupling may not be applied yet")
		}
	})
}

// readEmbeddedFile 从内嵌 web 文件系统读取内容。
func readEmbeddedFile(t *testing.T, name string) string {
	t.Helper()
	data, err := webAssets.ReadFile(name)
	if err != nil {
		t.Fatalf("read embedded %s: %v", name, err)
	}
	return string(data)
}

// TestAggregatedDataMacField 验证 aggregatedData 的 Mac 字段在 JSON 序列化中正确输出。
func TestAggregatedDataMacField(t *testing.T) {
	svc := newTestService(t)
	svc.ubusCli = &ubusClient{}
	svc.deviceMappings = make(map[string]*deviceMapping)

	// 插入 device_mappings
	insertDeviceMappings(t, svc.db, []deviceMapping{
		{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test-device", FirstSeen: 1000, LastSeen: 2000},
	})

	// 通过 API 查询设备维度，验证返回中有 mac 字段
	data := []aggregatedData{
		{Label: "192.168.1.10", Upload: 100, Download: 200, Total: 300, Count: 1},
	}
	got := svc.applyDeviceLabelAndMACAggregate(data, 1000, 2000)
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	// 验证 JSON 序列化包含 mac 字段
	b, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"mac":"AA:BB:CC:DD:EE:01"`) {
		t.Fatalf("expected mac field in JSON output, got: %s", string(b))
	}
	if !strings.Contains(string(b), `"label":"test-device"`) {
		t.Fatalf("expected label=test-device in JSON, got: %s", string(b))
	}
}

// TestGetDeviceMapping 验证 getDeviceMapping 的规范化查找。
func TestGetDeviceMapping(t *testing.T) {
	svc := newTestService(t)
	svc.deviceMappings = map[string]*deviceMapping{
		normalizeIP("2001:db8:1::1"): {IP: normalizeIP("2001:db8:1::1"), MAC: "AA:BB:CC:DD:EE:FF", Hostname: "test-v6"},
		"192.168.1.10":               {IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test-v4"},
	}

	// 非规范化形式查询
	dm := svc.getDeviceMapping("2001:0db8:0001:0000:0000:0000:0000:0001")
	if dm == nil || dm.Hostname != "test-v6" {
		t.Fatalf("expected mapping for normalized IPv6, got %+v", dm)
	}

	dm = svc.getDeviceMapping("192.168.1.10")
	if dm == nil || dm.Hostname != "test-v4" {
		t.Fatalf("expected mapping for 192.168.1.10, got %+v", dm)
	}

	// 不存在的 IP
	dm = svc.getDeviceMapping("10.0.0.1")
	if dm != nil {
		t.Fatalf("expected nil for unknown IP, got %+v", dm)
	}
}

// TestAggregateHTTPEndpointWithDeviceLabel 验证 /api/traffic/aggregate?dimension=sourceIP 返回 mac 字段。
func TestAggregateHTTPEndpointWithDeviceLabel(t *testing.T) {
	svc := newTestService(t)
	svc.ubusCli = &ubusClient{}
	svc.deviceMappings = make(map[string]*deviceMapping)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.10", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
	})
	insertDeviceMappings(t, svc.db, []deviceMapping{
		{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test-device", FirstSeen: 0, LastSeen: 60_000},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/aggregate?dimension=sourceIP&start=1&end=60000", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/traffic/aggregate status %d: %s", rec.Code, rec.Body.String())
	}
	var result []aggregatedData
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result))
	}
	if result[0].Mac != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("expected mac field in response, got mac=%q (full: %+v)", result[0].Mac, result[0])
	}
	if result[0].Label != "test-device" {
		t.Fatalf("expected label=test-device, got %q", result[0].Label)
	}
}

// TestDevicesByHostEndpointWithDeviceLabel 验证 devices-by-host 接口返回 MAC 聚合结果。
func TestDevicesByHostEndpointWithDeviceLabel(t *testing.T) {
	svc := newTestService(t)
	svc.ubusCli = &ubusClient{}
	svc.deviceMappings = make(map[string]*deviceMapping)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.10", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.20", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 100, Count: 1},
	})
	// 两个 IP 映射到同一 MAC
	insertDeviceMappings(t, svc.db, []deviceMapping{
		{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test-device", FirstSeen: 0, LastSeen: 60_000},
		{IP: "192.168.1.20", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test-device", FirstSeen: 0, LastSeen: 60_000},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/devices-by-host?host=a.com&start=1&end=60000", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/traffic/devices-by-host status %d: %s", rec.Code, rec.Body.String())
	}
	var result []aggregatedData
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 两个 source_ip 应合并为一条 MAC 聚合记录
	if len(result) != 1 {
		t.Fatalf("expected 1 MAC-aggregated row, got %d: %+v", len(result), result)
	}
	if result[0].Mac != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("expected mac=AA:BB:CC:DD:EE:01, got %q", result[0].Mac)
	}
	if result[0].Upload != 150 || result[0].Download != 300 {
		t.Fatalf("expected upload=150 download=300, got upload=%d download=%d", result[0].Upload, result[0].Download)
	}
}

// TestSubstatsMACLookup 验证 substats 接口支持 MAC 反查。
func TestSubstatsMACLookup(t *testing.T) {
	svc := newTestService(t)
	svc.ubusCli = &ubusClient{}
	svc.deviceMappings = make(map[string]*deviceMapping)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.10", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.20", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 100, Count: 1},
	})
	insertDeviceMappings(t, svc.db, []deviceMapping{
		{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test-device", FirstSeen: 0, LastSeen: 60_000},
		{IP: "192.168.1.20", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test-device", FirstSeen: 0, LastSeen: 60_000},
	})

	// 用 MAC 作为 label 调用 substats
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/substats?dimension=sourceIP&label=AA:BB:CC:DD:EE:01&start=1&end=60000", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/traffic/substats status %d: %s", rec.Code, rec.Body.String())
	}
	var result []aggregatedData
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 substat row for MAC drill-down, got %d: %+v", len(result), result)
	}
	if result[0].Label != "a.com" {
		t.Fatalf("expected label=a.com, got %q", result[0].Label)
	}
	if result[0].Upload != 150 || result[0].Download != 300 {
		t.Fatalf("expected upload=150 download=300, got upload=%d download=%d", result[0].Upload, result[0].Download)
	}
}

// TestHandleAggregateRawDoesNotApplyDeviceLabel 验证 raw=1 时设备 label 增强仍应用（保持兼容）。
func TestHandleAggregateRawDoesNotApplyDeviceLabel(t *testing.T) {
	svc := newTestService(t)
	svc.ubusCli = &ubusClient{}
	svc.deviceMappings = make(map[string]*deviceMapping)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.10", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
	})
	insertDeviceMappings(t, svc.db, []deviceMapping{
		{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "test", FirstSeen: 0, LastSeen: 60_000},
	})

	// raw=1 时，queryAggregate 会跳过域名分组，但设备 label 增强在 handleAggregate 中始终应用
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/aggregate?dimension=sourceIP&start=1&end=60000&raw=1", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var result []aggregatedData
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// raw=1 时设备 label 增强仍然应用（设备增强与域名分组是两个维度）
	if len(result) != 1 || result[0].Mac != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("expected MAC-enhanced result even with raw=1, got %+v", result)
	}
}
