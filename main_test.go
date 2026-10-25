package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQueryAggregate(t *testing.T) {
	svc := newTestService(t)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
		{BucketStart: 60_000, BucketEnd: 120_000, SourceIP: "192.168.1.2", Host: "b.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 20, Count: 1},
		{BucketStart: 60_000, BucketEnd: 120_000, SourceIP: "192.168.1.3", Host: "a.com", Process: "curl", Outbound: "DIRECT", Chains: `["DIRECT"]`, Upload: 10, Download: 30, Count: 1},
	})

	got, err := svc.queryAggregate("sourceIP", 1, 120_000, false)
	if err != nil {
		t.Fatalf("queryAggregate: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(got))
	}
	if got[0].Label != "192.168.1.2" || got[0].Upload != 150 || got[0].Download != 220 || got[0].Total != 370 {
		t.Fatalf("unexpected first row: %+v", got[0])
	}
}

func TestQueryTrendFillsEmptyBuckets(t *testing.T) {
	svc := newTestService(t)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
		{BucketStart: 120_000, BucketEnd: 180_000, SourceIP: "192.168.1.2", Host: "b.com", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 20, Count: 1},
	})

	got, err := svc.queryTrend(0, 180_000, 60_000)
	if err != nil {
		t.Fatalf("queryTrend: %v", err)
	}

	if len(got) != 4 {
		t.Fatalf("expected 4 buckets, got %d", len(got))
	}
	if got[1].Timestamp != 60_000 || got[1].Upload != 0 || got[1].Download != 0 {
		t.Fatalf("expected empty middle bucket, got %+v", got[1])
	}
	if got[2].Timestamp != 120_000 || got[2].Upload != 50 || got[2].Download != 20 {
		t.Fatalf("unexpected populated bucket: %+v", got[2])
	}
}

func TestOpenDatabaseAddsDetailColumns(t *testing.T) {
	svc := newTestService(t)

	rows, err := svc.db.Query(`PRAGMA table_info(traffic_logs)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()

	columns := map[string]bool{}
	for rows.Next() {
		var (
			cid        int
			name       string
			typeName   string
			notNull    int
			defaultV   any
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typeName, &notNull, &defaultV, &primaryKey); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		columns[name] = true
	}

	for _, name := range []string{"destination_ip", "chains"} {
		if !columns[name] {
			t.Fatalf("expected column %q to exist", name)
		}
	}
}

func TestLoadConfigDefaultsRetentionPolicy(t *testing.T) {
	for _, key := range []string{
		"TRAFFIC_MONITOR_LISTEN",
		"MIHOMO_URL",
		"MIHOMO_SECRET",
		"TRAFFIC_MONITOR_DB",
		"TRAFFIC_MONITOR_POLL_INTERVAL_MS",
		"TRAFFIC_MONITOR_RETENTION_DAYS",
		"TRAFFIC_MONITOR_AGG_RETENTION_DAYS",
		"TRAFFIC_MONITOR_ALLOWED_ORIGIN",
	} {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unsetenv %s: %v", key, err)
		}
	}

	if err := os.Setenv("CLASH_API", "http://10.0.0.2:9090"); err != nil {
		t.Fatalf("setenv CLASH_API: %v", err)
	}
	if err := os.Setenv("CLASH_SECRET", "legacy-secret"); err != nil {
		t.Fatalf("setenv CLASH_SECRET: %v", err)
	}
	if err := os.Setenv("TRAFFIC_MONITOR_DB", "/tmp/override.db"); err != nil {
		t.Fatalf("setenv TRAFFIC_MONITOR_DB: %v", err)
	}
	if err := os.Setenv("TRAFFIC_MONITOR_RETENTION_DAYS", "90"); err != nil {
		t.Fatalf("setenv TRAFFIC_MONITOR_RETENTION_DAYS: %v", err)
	}
	if err := os.Setenv("TRAFFIC_MONITOR_AGG_RETENTION_DAYS", "120"); err != nil {
		t.Fatalf("setenv TRAFFIC_MONITOR_AGG_RETENTION_DAYS: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Fatalf("expected listen addr default to be :8080, got %q", cfg.ListenAddr)
	}
	if cfg.MihomoURL != "" {
		t.Fatalf("expected mihomo url default to be empty, got %q", cfg.MihomoURL)
	}
	if cfg.MihomoSecret != "" {
		t.Fatalf("expected mihomo secret default to be empty, got %q", cfg.MihomoSecret)
	}
	original := isContainerRuntime
	isContainerRuntime = func() bool { return false }
	t.Cleanup(func() {
		isContainerRuntime = original
	})
	if defaultDatabasePath() != "./data/traffic_monitor.db" {
		t.Fatalf("expected local default database path to be ./data/traffic_monitor.db, got %q", defaultDatabasePath())
	}
}

func TestResolveMihomoSettingsUsesEnvironmentAndPersists(t *testing.T) {
	db, err := openDatabase(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := saveMihomoSettings(db, mihomoSettings{
		URL:    "http://db.example:9090",
		Secret: "db-secret",
	}); err != nil {
		t.Fatalf("saveMihomoSettings: %v", err)
	}

	got, err := resolveMihomoSettings(db, "http://env.example:9090/", "env-secret")
	if err != nil {
		t.Fatalf("resolveMihomoSettings: %v", err)
	}

	if got.URL != "http://env.example:9090" {
		t.Fatalf("expected env url to win, got %q", got.URL)
	}
	if got.Secret != "env-secret" {
		t.Fatalf("expected env secret to win, got %q", got.Secret)
	}

	stored, err := loadMihomoSettings(db)
	if err != nil {
		t.Fatalf("loadMihomoSettings: %v", err)
	}
	if stored != got {
		t.Fatalf("expected stored settings to match resolved settings, got %+v want %+v", stored, got)
	}
}

func TestResolveMihomoSettingsFallsBackToStoredValues(t *testing.T) {
	db, err := openDatabase(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	want := mihomoSettings{
		URL:    "http://stored.example:9090",
		Secret: "stored-secret",
	}
	if err := saveMihomoSettings(db, want); err != nil {
		t.Fatalf("saveMihomoSettings: %v", err)
	}

	got, err := resolveMihomoSettings(db, "", "")
	if err != nil {
		t.Fatalf("resolveMihomoSettings: %v", err)
	}

	if got != want {
		t.Fatalf("expected stored settings fallback, got %+v want %+v", got, want)
	}
}

func TestAutoSwitchSettingsRoundTrip(t *testing.T) {
	svc := newTestService(t)

	want := autoSwitchSettings{
		Enabled:                 true,
		ThresholdBytesPerMinute: 512 * 1024 * 1024,
		CooldownSeconds:         900,
		GroupTargets: []autoSwitchGroupTarget{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			{GroupName: "🐟 漏网之鱼", TargetProxy: "DIRECT", Enabled: false},
		},
	}

	if err := saveAutoSwitchSettings(svc.db, want); err != nil {
		t.Fatalf("saveAutoSwitchSettings: %v", err)
	}

	got, err := loadAutoSwitchSettings(svc.db)
	if err != nil {
		t.Fatalf("loadAutoSwitchSettings: %v", err)
	}

	if got.Enabled != want.Enabled {
		t.Fatalf("expected enabled %v, got %v", want.Enabled, got.Enabled)
	}
	if got.ThresholdBytesPerMinute != want.ThresholdBytesPerMinute {
		t.Fatalf("expected threshold %d, got %d", want.ThresholdBytesPerMinute, got.ThresholdBytesPerMinute)
	}
	if got.CooldownSeconds != want.CooldownSeconds {
		t.Fatalf("expected cooldown %d, got %d", want.CooldownSeconds, got.CooldownSeconds)
	}
	if len(got.GroupTargets) != len(want.GroupTargets) {
		t.Fatalf("expected %d group targets, got %d", len(want.GroupTargets), len(got.GroupTargets))
	}
	for index, target := range want.GroupTargets {
		if got.GroupTargets[index] != target {
			t.Fatalf("unexpected group target at %d: got %+v want %+v", index, got.GroupTargets[index], target)
		}
	}
}

func TestLoadAutoSwitchSettingsDefaults(t *testing.T) {
	svc := newTestService(t)

	got, err := loadAutoSwitchSettings(svc.db)
	if err != nil {
		t.Fatalf("loadAutoSwitchSettings: %v", err)
	}

	if got.Enabled {
		t.Fatalf("expected auto switch to default disabled")
	}
	if got.ThresholdBytesPerMinute != 0 {
		t.Fatalf("expected zero threshold by default, got %d", got.ThresholdBytesPerMinute)
	}
	if got.CooldownSeconds != 0 {
		t.Fatalf("expected zero cooldown by default, got %d", got.CooldownSeconds)
	}
	if got.RestoreEnabled {
		t.Fatalf("expected auto restore to default disabled")
	}
	if got.RestoreQuietMinutes != 0 {
		t.Fatalf("expected zero restore quiet minutes by default, got %d", got.RestoreQuietMinutes)
	}
	if len(got.GroupTargets) != 0 {
		t.Fatalf("expected no group targets by default, got %d", len(got.GroupTargets))
	}
}

func TestAutoRestoreSettingsRoundTrip(t *testing.T) {
	svc := newTestService(t)

	want := autoSwitchSettings{
		Enabled:                 true,
		ThresholdBytesPerMinute: 512 * 1024 * 1024,
		CooldownSeconds:         900,
		RestoreEnabled:          true,
		RestoreQuietMinutes:     15,
		GroupTargets: []autoSwitchGroupTarget{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
		},
	}

	if err := saveAutoSwitchSettings(svc.db, want); err != nil {
		t.Fatalf("saveAutoSwitchSettings: %v", err)
	}

	got, err := loadAutoSwitchSettings(svc.db)
	if err != nil {
		t.Fatalf("loadAutoSwitchSettings: %v", err)
	}

	if got.RestoreEnabled != want.RestoreEnabled {
		t.Fatalf("expected restore enabled %v, got %v", want.RestoreEnabled, got.RestoreEnabled)
	}
	if got.RestoreQuietMinutes != want.RestoreQuietMinutes {
		t.Fatalf("expected restore quiet minutes %d, got %d", want.RestoreQuietMinutes, got.RestoreQuietMinutes)
	}
}

func TestRestoreSessionPersistenceRoundTrip(t *testing.T) {
	svc := newTestService(t)

	session := autoRestoreSession{
		GroupName:          "🌍 国外媒体",
		OriginalProxy:      "🚩 PROXY",
		CurrentProxy:       "🇸🇬 Singapore",
		LastTriggeredAt:    1_700_000_000_000,
		LastTriggeredHost:  "video.example",
		LastTriggeredBytes: 536_870_912,
	}

	if err := upsertAutoRestoreSession(svc.db, session); err != nil {
		t.Fatalf("upsertAutoRestoreSession insert: %v", err)
	}

	got, err := listAutoRestoreSessions(svc.db)
	if err != nil {
		t.Fatalf("listAutoRestoreSessions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 restore session, got %d", len(got))
	}
	if got[0] != session {
		t.Fatalf("unexpected restore session: got %+v want %+v", got[0], session)
	}

	session.CurrentProxy = "🇯🇵 Japan"
	session.LastTriggeredAt = 1_700_000_060_000
	session.LastTriggeredHost = "download.example"
	session.LastTriggeredBytes = 900_000_000
	if err := upsertAutoRestoreSession(svc.db, session); err != nil {
		t.Fatalf("upsertAutoRestoreSession update: %v", err)
	}

	got, err = listAutoRestoreSessions(svc.db)
	if err != nil {
		t.Fatalf("listAutoRestoreSessions after update: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 restore session after update, got %d", len(got))
	}
	if got[0] != session {
		t.Fatalf("unexpected updated restore session: got %+v want %+v", got[0], session)
	}

	if err := deleteAutoRestoreSession(svc.db, session.GroupName); err != nil {
		t.Fatalf("deleteAutoRestoreSession: %v", err)
	}

	got, err = listAutoRestoreSessions(svc.db)
	if err != nil {
		t.Fatalf("listAutoRestoreSessions after delete: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no restore sessions after delete, got %d", len(got))
	}
}

func TestRestoreSessionReloadAfterDatabaseReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "traffic.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase initial: %v", err)
	}

	session := autoRestoreSession{
		GroupName:          "🌍 国外媒体",
		OriginalProxy:      "🚩 PROXY",
		CurrentProxy:       "🇸🇬 Singapore",
		LastTriggeredAt:    1_700_000_000_000,
		LastTriggeredHost:  "video.example",
		LastTriggeredBytes: 536_870_912,
	}
	if err := upsertAutoRestoreSession(db, session); err != nil {
		t.Fatalf("upsertAutoRestoreSession: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close initial db: %v", err)
	}

	reopened, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase reopen: %v", err)
	}
	defer reopened.Close()

	got, err := listAutoRestoreSessions(reopened)
	if err != nil {
		t.Fatalf("listAutoRestoreSessions reopened: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 restore session after reopen, got %d", len(got))
	}
	if got[0] != session {
		t.Fatalf("unexpected reopened restore session: got %+v want %+v", got[0], session)
	}
}

func TestListAutoSwitchEventsNewestFirst(t *testing.T) {
	svc := newTestService(t)

	if err := insertAutoSwitchEvent(svc.db, autoSwitchEvent{
		TriggeredAt: 1000,
		Host:        "a.example",
		TotalBytes:  123,
		WindowStart: 0,
		WindowEnd:   60_000,
		Results: []autoSwitchExecutionResult{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Status: "switched"},
		},
	}); err != nil {
		t.Fatalf("insertAutoSwitchEvent first: %v", err)
	}

	if err := insertAutoSwitchEvent(svc.db, autoSwitchEvent{
		TriggeredAt: 2000,
		Host:        "b.example",
		TotalBytes:  456,
		WindowStart: 60_000,
		WindowEnd:   120_000,
		Results: []autoSwitchExecutionResult{
			{GroupName: "🐟 漏网之鱼", TargetProxy: "DIRECT", Status: "skipped"},
		},
		Error: "cooldown",
	}); err != nil {
		t.Fatalf("insertAutoSwitchEvent second: %v", err)
	}

	got, err := listAutoSwitchEvents(svc.db, 10)
	if err != nil {
		t.Fatalf("listAutoSwitchEvents: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	if got[0].TriggeredAt != 2000 || got[0].Host != "b.example" {
		t.Fatalf("expected newest event first, got %+v", got[0])
	}
	if got[0].Error != "cooldown" {
		t.Fatalf("expected persisted error, got %q", got[0].Error)
	}
	if len(got[0].Results) != 1 || got[0].Results[0].GroupName != "🐟 漏网之鱼" {
		t.Fatalf("unexpected first event results: %+v", got[0].Results)
	}
	if got[1].TriggeredAt != 1000 || got[1].Host != "a.example" {
		t.Fatalf("expected oldest event second, got %+v", got[1])
	}
}

func TestListControllableProxyGroupsFiltersToSelectAndFallback(t *testing.T) {
	svc := newTestService(t)
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/proxies" {
				t.Fatalf("unexpected request path: %s", req.URL.Path)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer test-secret" {
				t.Fatalf("expected bearer token, got %q", got)
			}

			body := `{
				"proxies": {
					"🌍 国外媒体": {"type":"Selector","all":["⏬ 大流量节点","🚩 PROXY"],"now":"🚩 PROXY"},
					"⏬ 大流量节点": {"type":"Fallback","all":["🇯🇵 Japan","🇸🇬 Singapore"],"now":"🇯🇵 Japan"},
					"♻️ 自动选择": {"type":"URLTest","all":["🇯🇵 Japan","🇸🇬 Singapore"],"now":"🇸🇬 Singapore"},
					"DIRECT": {"type":"Direct","all":[],"now":"DIRECT"}
				}
			}`

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	got, err := svc.listControllableProxyGroups(context.Background(), mihomoSettings{
		URL:    "http://127.0.0.1:9090",
		Secret: "test-secret",
	})
	if err != nil {
		t.Fatalf("listControllableProxyGroups: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 controllable groups, got %d", len(got))
	}
	if got[0].Name != "⏬ 大流量节点" || got[0].Type != "fallback" {
		t.Fatalf("unexpected first group: %+v", got[0])
	}
	if got[1].Name != "🌍 国外媒体" || got[1].Type != "select" {
		t.Fatalf("unexpected second group: %+v", got[1])
	}
	if got[1].Now != "🚩 PROXY" {
		t.Fatalf("expected current selection to be preserved, got %+v", got[1])
	}
	if len(got[1].All) != 2 || got[1].All[0] != "⏬ 大流量节点" {
		t.Fatalf("unexpected candidates: %+v", got[1].All)
	}
}

func TestSwitchProxyGroupRejectsTargetOutsideCandidates(t *testing.T) {
	svc := newTestService(t)

	err := svc.switchProxyGroup(context.Background(), mihomoSettings{URL: "http://127.0.0.1:9090"}, controllableProxyGroup{
		Name: "🌍 国外媒体",
		Type: "select",
		Now:  "🚩 PROXY",
		All:  []string{"⏬ 大流量节点", "🚩 PROXY"},
	}, "🇺🇸 USA")
	if err == nil {
		t.Fatalf("expected invalid target to be rejected")
	}
	if !strings.Contains(err.Error(), "target proxy") {
		t.Fatalf("expected target validation error, got %v", err)
	}
}

func TestSwitchProxyGroupSendsSelectionRequest(t *testing.T) {
	svc := newTestService(t)
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPut {
				t.Fatalf("expected PUT request, got %s", req.Method)
			}
			if req.URL.Path != "/proxies/🌍 国外媒体" {
				t.Fatalf("unexpected request path: %s", req.URL.Path)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer test-secret" {
				t.Fatalf("expected bearer token, got %q", got)
			}

			var payload map[string]string
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if payload["name"] != "🇸🇬 Singapore" {
				t.Fatalf("expected target proxy to be posted, got %+v", payload)
			}

			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := svc.switchProxyGroup(context.Background(), mihomoSettings{
		URL:    "http://127.0.0.1:9090",
		Secret: "test-secret",
	}, controllableProxyGroup{
		Name: "🌍 国外媒体",
		Type: "select",
		Now:  "🚩 PROXY",
		All:  []string{"⏬ 大流量节点", "🇸🇬 Singapore"},
	}, "🇸🇬 Singapore")
	if err != nil {
		t.Fatalf("switchProxyGroup: %v", err)
	}
}

func TestDefaultDatabasePathUsesContainerDataDir(t *testing.T) {
	original := isContainerRuntime
	isContainerRuntime = func() bool { return true }
	t.Cleanup(func() {
		isContainerRuntime = original
	})

	if defaultDatabasePath() != "/data/traffic_monitor.db" {
		t.Fatalf("expected container default database path to be /data/traffic_monitor.db, got %q", defaultDatabasePath())
	}
}

func TestOpenDatabaseCreatesParentDirectory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "traffic_monitor.db")

	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if _, err := os.Stat(filepath.Dir(dbPath)); err != nil {
		t.Fatalf("expected parent dir to exist: %v", err)
	}
}

func TestCleanupOldLogsKeepsThirtyDaysOfAggregates(t *testing.T) {
	svc := newTestService(t)

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.Local).UnixMilli()

	insertTestLogs(t, svc.db, []trafficLog{
		{Timestamp: now - int64(4*24*time.Hour/time.Millisecond), SourceIP: "old-raw", Host: "a.com", Process: "chrome", Outbound: "NodeA", Upload: 1, Download: 1},
		{Timestamp: now - int64(2*24*time.Hour/time.Millisecond), SourceIP: "keep-raw", Host: "a.com", Process: "chrome", Outbound: "NodeA", Upload: 2, Download: 2},
	})
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: now - int64(31*24*time.Hour/time.Millisecond), BucketEnd: now - int64(31*24*time.Hour/time.Millisecond) + 60000, SourceIP: "old-agg", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 3, Download: 3, Count: 1},
		{BucketStart: now - int64(20*24*time.Hour/time.Millisecond), BucketEnd: now - int64(20*24*time.Hour/time.Millisecond) + 60000, SourceIP: "keep-agg", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 4, Download: 4, Count: 1},
	})

	if err := svc.cleanupOldLogs(now); err != nil {
		t.Fatalf("cleanupOldLogs: %v", err)
	}

	var rawCount int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_logs`).Scan(&rawCount); err != nil {
		t.Fatalf("count traffic_logs: %v", err)
	}
	if rawCount != 0 {
		t.Fatalf("expected cleanup to remove persisted raw logs, got %d rows", rawCount)
	}

	var aggregateCount int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_aggregated`).Scan(&aggregateCount); err != nil {
		t.Fatalf("count traffic_aggregated: %v", err)
	}
	if aggregateCount != 1 {
		t.Fatalf("expected 1 aggregate row after cleanup, got %d", aggregateCount)
	}
}

func TestBackfillSummaryBuildsDailySummaryRows(t *testing.T) {
	svc := newTestService(t)

	day := int64(24 * time.Hour / time.Millisecond)
	now := time.Date(2026, 8, 6, 15, 0, 0, 0, time.Local).UnixMilli()
	dayStart := (now / day) * day
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{
			BucketStart: dayStart - 2*day,
			BucketEnd:   dayStart - 2*day + 60000,
			SourceIP:    "192.168.1.8",
			Host:        "old.example.com",
			Outbound:    "DIRECT",
			Chains:      `["DIRECT"]`,
			Upload:      10,
			Download:    20,
			Count:       1,
		},
		{
			BucketStart: dayStart - day,
			BucketEnd:   dayStart - day + 60000,
			SourceIP:    "192.168.1.8",
			Host:        "new.example.com",
			Outbound:    "ProxyA",
			Chains:      `["ProxyA"]`,
			Upload:      30,
			Download:    40,
			Count:       2,
		},
	})

	if err := backfillSummary(svc.db, now); err != nil {
		t.Fatalf("backfillSummary: %v", err)
	}

	var rowCount int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_summary`).Scan(&rowCount); err != nil {
		t.Fatalf("count traffic_summary: %v", err)
	}
	if rowCount != 8 {
		t.Fatalf("expected 2 days x source/outbound/rule/total summary rows, got %d", rowCount)
	}
}

func TestQuerySummaryAggregateSecondaryAndTrend(t *testing.T) {
	svc := newTestService(t)

	day := int64(24 * time.Hour / time.Millisecond)
	now := time.Date(2026, 8, 6, 15, 0, 0, 0, time.Local).UnixMilli()
	dayStart := (now / day) * day
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{
			BucketStart:   dayStart - day,
			BucketEnd:     dayStart - day + 60000,
			SourceIP:      "192.168.1.8",
			Host:          "api.example.com",
			DestinationIP: "1.1.1.1",
			Process:       "curl",
			Outbound:      "ProxyA",
			Chains:        `["ProxyA"]`,
			Upload:        15,
			Download:      25,
			Count:         1,
		},
	})
	if err := backfillSummary(svc.db, now); err != nil {
		t.Fatalf("backfillSummary: %v", err)
	}

	start := dayStart - day
	end := dayStart - 1
	sources, err := svc.querySummaryAggregate("sourceIP", start, end, false)
	if err != nil {
		t.Fatalf("querySummaryAggregate(sourceIP): %v", err)
	}
	if len(sources) != 1 || sources[0].Label != "192.168.1.8" || sources[0].Upload != 15 || sources[0].Download != 25 {
		t.Fatalf("unexpected source summary: %+v", sources)
	}

	hosts, err := svc.querySummarySecondary("sourceIP", "192.168.1.8", start, end)
	if err != nil {
		t.Fatalf("querySummarySecondary(sourceIP): %v", err)
	}
	if len(hosts) != 1 || hosts[0].Label != "api.example.com" {
		t.Fatalf("unexpected host secondary summary: %+v", hosts)
	}

	devices, err := svc.querySummarySecondary("host", "api.example.com", start, end)
	if err != nil {
		t.Fatalf("querySummarySecondary(host): %v", err)
	}
	if len(devices) != 1 || devices[0].Label != "192.168.1.8" {
		t.Fatalf("unexpected device secondary summary: %+v", devices)
	}

	trend, err := svc.queryTrendSummary(start, end, day)
	if err != nil {
		t.Fatalf("queryTrendSummary: %v", err)
	}
	if len(trend) != 1 || trend[0].Upload != 15 || trend[0].Download != 25 {
		t.Fatalf("unexpected trend summary: %+v", trend)
	}
}

func TestQuerySummaryIncludesCurrentDayDetailFallback(t *testing.T) {
	svc := newTestService(t)

	day := int64(24 * time.Hour / time.Millisecond)
	now := time.Date(2026, 8, 6, 15, 0, 0, 0, time.Local).UnixMilli()
	dayStart := (now / day) * day
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{
			BucketStart: dayStart - day,
			BucketEnd:   dayStart - day + 60000,
			SourceIP:    "192.168.1.8",
			Host:        "old.example.com",
			Outbound:    "ProxyA",
			Chains:      `["ProxyA"]`,
			Upload:      10,
			Download:    20,
			Count:       1,
		},
		{
			BucketStart: dayStart,
			BucketEnd:   dayStart + 60000,
			SourceIP:    "192.168.1.8",
			Host:        "today.example.com",
			Outbound:    "ProxyB",
			Chains:      `["ProxyB"]`,
			Upload:      30,
			Download:    40,
			Count:       1,
		},
	})
	if err := backfillSummary(svc.db, now); err != nil {
		t.Fatalf("backfillSummary: %v", err)
	}

	rows, err := svc.querySummaryAggregate("sourceIP", dayStart-day, now, false)
	if err != nil {
		t.Fatalf("querySummaryAggregate: %v", err)
	}
	if len(rows) != 1 || rows[0].Label != "192.168.1.8" || rows[0].Upload != 40 || rows[0].Download != 60 {
		t.Fatalf("expected summary plus current day fallback, got %+v", rows)
	}

	hosts, err := svc.querySummarySecondary("sourceIP", "192.168.1.8", dayStart-day, now)
	if err != nil {
		t.Fatalf("querySummarySecondary: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected both summary and current day hosts, got %+v", hosts)
	}

	trend, err := svc.queryTrendSummary(dayStart-day, now, day)
	if err != nil {
		t.Fatalf("queryTrendSummary: %v", err)
	}
	if len(trend) != 2 || trend[1].Upload != 30 || trend[1].Download != 40 {
		t.Fatalf("expected summary and current day trend, got %+v", trend)
	}
}

func TestCleanupOldLogsKeepsSummaryForFourTimesRetention(t *testing.T) {
	svc := newTestService(t)

	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.Local).UnixMilli()
	day := int64(24 * time.Hour / time.Millisecond)
	insertSummaryRows := func(bucketStart int64, label string) {
		t.Helper()
		_, err := svc.db.Exec(`
			INSERT INTO traffic_summary
			(bucket_start, bucket_end, dimension, label, secondary_label, upload, download, count)
			VALUES (?, ?, 'source_ip', ?, '', 1, 2, 3)
		`, bucketStart, bucketStart+day, label)
		if err != nil {
			t.Fatalf("insert traffic_summary: %v", err)
		}
	}

	cutoff := now - int64(svc.aggregateRetentionDays*4)*day
	insertSummaryRows(cutoff-2*day, "old")
	insertSummaryRows(cutoff+day, "keep")

	if err := svc.cleanupOldLogs(now); err != nil {
		t.Fatalf("cleanupOldLogs: %v", err)
	}

	var labels []string
	rows, err := svc.db.Query(`SELECT label FROM traffic_summary ORDER BY label`)
	if err != nil {
		t.Fatalf("query traffic_summary: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			t.Fatalf("scan traffic_summary: %v", err)
		}
		labels = append(labels, label)
	}
	if len(labels) != 1 || labels[0] != "keep" {
		t.Fatalf("expected only recent summary row, got %v", labels)
	}
}

func TestProcessConnectionsBuffersAggregatesWithoutPersistingRawLogs(t *testing.T) {
	svc := newTestService(t)

	payload := &connectionsResponse{
		Connections: []connection{
			{
				ID:       "conn-1",
				Upload:   128,
				Download: 256,
				Chains:   []string{"ProxyA", "RelayB"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{
					SourceIP:      "192.168.1.8",
					Host:          "api.example.com",
					DestinationIP: "1.1.1.1",
					Process:       "curl",
				},
			},
		},
	}

	if err := svc.processConnections(context.Background(), payload); err != nil {
		t.Fatalf("processConnections: %v", err)
	}

	var rawCount int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_logs`).Scan(&rawCount); err != nil {
		t.Fatalf("count traffic_logs: %v", err)
	}
	if rawCount != 0 {
		t.Fatalf("expected no raw logs to be persisted, got %d", rawCount)
	}

	if len(svc.aggregateBuffer) != 1 {
		t.Fatalf("expected 1 aggregate buffer entry, got %d", len(svc.aggregateBuffer))
	}
	for _, entry := range svc.aggregateBuffer {
		if entry.Host != "api.example.com" || entry.DestinationIP != "1.1.1.1" {
			t.Fatalf("unexpected aggregate entry: %+v", entry)
		}
		if entry.Outbound != "ProxyA" || entry.Process != "curl" {
			t.Fatalf("unexpected routing fields: %+v", entry)
		}
		if entry.Upload != 128 || entry.Download != 256 || entry.Count != 1 {
			t.Fatalf("unexpected aggregate totals: %+v", entry)
		}
	}
}

func TestProcessConnectionsSkipsDirectTrafficWhenFilterEnabled(t *testing.T) {
	svc := newTestService(t)
	svc.filterDirectTraffic = true

	payload := &connectionsResponse{
		Connections: []connection{
			testConnection("conn-direct", []string{"DIRECT"}, 9000, 9000),
			testConnection("conn-proxy", []string{"ProxyA", "RelayB"}, 128, 256),
		},
	}

	if err := svc.processConnections(context.Background(), payload); err != nil {
		t.Fatalf("processConnections: %v", err)
	}

	if len(svc.aggregateBuffer) != 1 {
		t.Fatalf("expected only the proxied connection to be buffered, got %d entries", len(svc.aggregateBuffer))
	}
	for _, entry := range svc.aggregateBuffer {
		if entry.Outbound != "ProxyA" {
			t.Fatalf("unexpected buffered outbound: %+v", entry)
		}
		if entry.Upload != 128 || entry.Download != 256 {
			t.Fatalf("unexpected buffered totals: %+v", entry)
		}
	}
}

func TestFilterDirectTrafficSettingDefaultsOffAndSurvivesRestart(t *testing.T) {
	svc := newTestService(t)

	if svc.currentFilterDirectTraffic() {
		t.Fatal("expected direct traffic filter to default to off")
	}

	if err := saveFilterDirectTraffic(svc.db, true); err != nil {
		t.Fatalf("saveFilterDirectTraffic: %v", err)
	}
	if !loadFilterDirectTraffic(svc.db) {
		t.Fatal("expected persisted filter flag to load as true")
	}

	restarted := newTestServiceOnDB(svc.db)
	if !restarted.currentFilterDirectTraffic() {
		t.Fatal("expected restarted service to pick up the persisted filter flag")
	}
}

func TestDirectTrafficFilterKeepsBaselineSoReplayDoesNotSpike(t *testing.T) {
	svc := newTestService(t)

	if err := svc.updateFilterDirectTraffic(true); err != nil {
		t.Fatalf("updateFilterDirectTraffic(true): %v", err)
	}

	first := &connectionsResponse{
		Connections: []connection{testConnection("conn-1", []string{"DIRECT"}, 100, 100)},
	}
	if err := svc.processConnections(context.Background(), first); err != nil {
		t.Fatalf("processConnections first: %v", err)
	}
	if len(svc.aggregateBuffer) != 0 {
		t.Fatalf("expected direct traffic to be dropped, got %d buffer entries", len(svc.aggregateBuffer))
	}

	if err := svc.updateFilterDirectTraffic(false); err != nil {
		t.Fatalf("updateFilterDirectTraffic(false): %v", err)
	}

	second := &connectionsResponse{
		Connections: []connection{testConnection("conn-1", []string{"DIRECT"}, 500, 500)},
	}
	if err := svc.processConnections(context.Background(), second); err != nil {
		t.Fatalf("processConnections second: %v", err)
	}

	if len(svc.aggregateBuffer) != 1 {
		t.Fatalf("expected 1 buffer entry after re-enabling tracking, got %d", len(svc.aggregateBuffer))
	}
	for _, entry := range svc.aggregateBuffer {
		if entry.Upload != 400 || entry.Download != 400 {
			t.Fatalf("expected only the 400 byte delta to be recorded, got %+v", entry)
		}
	}
}

func TestProcessConnectionsAutoSwitchTriggersOncePerMinute(t *testing.T) {
	svc := newTestService(t)

	if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
		Enabled:                 true,
		ThresholdBytesPerMinute: 300,
		CooldownSeconds:         600,
		GroupTargets: []autoSwitchGroupTarget{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
		},
	}); err != nil {
		t.Fatalf("saveAutoSwitchSettings: %v", err)
	}

	svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090", Secret: "test-secret"})
	currentTime := time.Date(2026, 4, 27, 12, 0, 10, 0, time.Local)
	svc.now = func() time.Time { return currentTime }

	var putCount int
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/proxies":
				body := `{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":"🚩 PROXY"}}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
				putCount++
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		}),
	}

	first := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   100,
			Download: 100,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}
	second := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   250,
			Download: 150,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}
	third := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   300,
			Download: 200,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}

	if err := svc.processConnections(context.Background(), first); err != nil {
		t.Fatalf("processConnections first: %v", err)
	}
	if err := svc.processConnections(context.Background(), second); err != nil {
		t.Fatalf("processConnections second: %v", err)
	}
	if err := svc.processConnections(context.Background(), third); err != nil {
		t.Fatalf("processConnections third: %v", err)
	}

	if putCount != 1 {
		t.Fatalf("expected exactly 1 switch request, got %d", putCount)
	}
	if got := svc.hostMinuteWindows["video.example\x00🌍 国外媒体"]; got == nil || got.TotalBytes != 500 {
		t.Fatalf("expected minute window total 500, got %+v", got)
	}

	events, err := listAutoSwitchEvents(svc.db, 10)
	if err != nil {
		t.Fatalf("listAutoSwitchEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 auto switch event, got %d", len(events))
	}
	if events[0].Host != "video.example" || events[0].TotalBytes != 400 {
		t.Fatalf("unexpected event payload: %+v", events[0])
	}
	if len(events[0].Results) != 1 || events[0].Results[0].Status != "switched" {
		t.Fatalf("unexpected event results: %+v", events[0].Results)
	}
}

func TestAutoSwitchOnlySwitchesTriggeredEnabledGroup(t *testing.T) {
	svc := newTestService(t)

	if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
		Enabled:                 true,
		ThresholdBytesPerMinute: 300,
		CooldownSeconds:         0,
		GroupTargets: []autoSwitchGroupTarget{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			{GroupName: "🐟 漏网之鱼", TargetProxy: "DIRECT", Enabled: true},
		},
	}); err != nil {
		t.Fatalf("saveAutoSwitchSettings: %v", err)
	}

	svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
	currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
	svc.now = func() time.Time { return currentTime }

	switches := make([]string, 0, 2)
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/proxies":
				body := `{"proxies":{
					"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":"🚩 PROXY"},
					"🐟 漏网之鱼":{"type":"Selector","all":["DIRECT","🚩 PROXY"],"now":"🚩 PROXY"}
				}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			case req.Method == http.MethodPut:
				switches = append(switches, req.URL.Path)
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		}),
	}

	first := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   100,
			Download: 100,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}
	second := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   250,
			Download: 150,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}

	if err := svc.processConnections(context.Background(), first); err != nil {
		t.Fatalf("processConnections first: %v", err)
	}
	if err := svc.processConnections(context.Background(), second); err != nil {
		t.Fatalf("processConnections second: %v", err)
	}

	if len(switches) != 1 {
		t.Fatalf("expected exactly 1 switch request, got %d (%v)", len(switches), switches)
	}
	if switches[0] != "/proxies/🌍 国外媒体" {
		t.Fatalf("expected only triggered group to switch, got %v", switches)
	}

	events, err := listAutoSwitchEvents(svc.db, 10)
	if err != nil {
		t.Fatalf("listAutoSwitchEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 auto switch event, got %d", len(events))
	}
	if len(events[0].Results) != 1 || events[0].Results[0].GroupName != "🌍 国外媒体" {
		t.Fatalf("expected event to contain only triggered group result, got %+v", events[0].Results)
	}
}

func TestAutoSwitchMatchesEnabledGroupWithinChains(t *testing.T) {
	svc := newTestService(t)

	if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
		Enabled:                 true,
		ThresholdBytesPerMinute: 300,
		CooldownSeconds:         0,
		GroupTargets: []autoSwitchGroupTarget{
			{GroupName: "🇺🇸 USA", TargetProxy: "z vps |美国 VPS-jbirgl3y", Enabled: true},
		},
	}); err != nil {
		t.Fatalf("saveAutoSwitchSettings: %v", err)
	}

	svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
	currentTime := time.Date(2026, 4, 30, 2, 49, 10, 0, time.Local)
	svc.now = func() time.Time { return currentTime }

	var switches []string
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/proxies":
				body := `{"proxies":{
					"🇺🇸 USA":{"type":"Selector","all":["z vps |美国 VPS-jbirgl3y","speedVPS |美国 VPS_Speed-nvji7ppb"],"now":"speedVPS |美国 VPS_Speed-nvji7ppb"}
				}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			case req.Method == http.MethodPut:
				switches = append(switches, req.URL.Path)
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		}),
	}

	first := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   100,
			Download: 100,
			Chains:   []string{"speedVPS |美国 VPS_Speed-nvji7ppb", "🇺🇸 USA", "🤖 人工智能"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "edgedl.me.gvt1.com", DestinationIP: "34.104.35.123", Process: "chrome"},
		}},
	}
	second := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   250,
			Download: 150,
			Chains:   []string{"speedVPS |美国 VPS_Speed-nvji7ppb", "🇺🇸 USA", "🤖 人工智能"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "edgedl.me.gvt1.com", DestinationIP: "34.104.35.123", Process: "chrome"},
		}},
	}

	if err := svc.processConnections(context.Background(), first); err != nil {
		t.Fatalf("processConnections first: %v", err)
	}
	if err := svc.processConnections(context.Background(), second); err != nil {
		t.Fatalf("processConnections second: %v", err)
	}

	if len(switches) != 1 || switches[0] != "/proxies/🇺🇸 USA" {
		t.Fatalf("expected switch for enabled group inside chains, got %v", switches)
	}

	events, err := listAutoSwitchEvents(svc.db, 10)
	if err != nil {
		t.Fatalf("listAutoSwitchEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 auto switch event, got %d", len(events))
	}
	if len(events[0].Results) != 1 || events[0].Results[0].GroupName != "🇺🇸 USA" {
		t.Fatalf("unexpected event results: %+v", events[0].Results)
	}
}

func TestAutoSwitchIgnoresTrafficForGroupsNotEnabledInSettings(t *testing.T) {
	svc := newTestService(t)

	if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
		Enabled:                 true,
		ThresholdBytesPerMinute: 300,
		CooldownSeconds:         0,
		GroupTargets: []autoSwitchGroupTarget{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: false},
			{GroupName: "🐟 漏网之鱼", TargetProxy: "DIRECT", Enabled: true},
		},
	}); err != nil {
		t.Fatalf("saveAutoSwitchSettings: %v", err)
	}

	svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
	currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
	svc.now = func() time.Time { return currentTime }

	var putCount int
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/proxies":
				body := `{"proxies":{
					"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":"🚩 PROXY"},
					"🐟 漏网之鱼":{"type":"Selector","all":["DIRECT","🚩 PROXY"],"now":"🚩 PROXY"}
				}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			case req.Method == http.MethodPut:
				putCount++
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		}),
	}

	first := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   100,
			Download: 100,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}
	second := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   250,
			Download: 150,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}

	if err := svc.processConnections(context.Background(), first); err != nil {
		t.Fatalf("processConnections first: %v", err)
	}
	if err := svc.processConnections(context.Background(), second); err != nil {
		t.Fatalf("processConnections second: %v", err)
	}

	if putCount != 0 {
		t.Fatalf("expected no switch request for disabled triggered group, got %d", putCount)
	}

	events, err := listAutoSwitchEvents(svc.db, 10)
	if err != nil {
		t.Fatalf("listAutoSwitchEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no auto switch events, got %+v", events)
	}
}

func TestAutoSwitchCooldownSkipsNextMinuteTrigger(t *testing.T) {
	svc := newTestService(t)

	if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
		Enabled:                 true,
		ThresholdBytesPerMinute: 300,
		CooldownSeconds:         600,
		GroupTargets: []autoSwitchGroupTarget{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
		},
	}); err != nil {
		t.Fatalf("saveAutoSwitchSettings: %v", err)
	}

	svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
	currentTime := time.Date(2026, 4, 27, 12, 0, 10, 0, time.Local)
	svc.now = func() time.Time { return currentTime }

	var putCount int
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/proxies":
				body := `{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":"🚩 PROXY"}}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
				putCount++
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		}),
	}

	firstMinute := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-1",
			Upload:   200,
			Download: 200,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
		}},
	}
	secondMinute := &connectionsResponse{
		Connections: []connection{{
			ID:       "conn-2",
			Upload:   500,
			Download: 0,
			Chains:   []string{"🌍 国外媒体"},
			Metadata: struct {
				SourceIP      string "json:\"sourceIP\""
				Host          string "json:\"host\""
				DestinationIP string "json:\"destinationIP\""
				Process       string "json:\"process\""
			}{SourceIP: "192.168.1.3", Host: "download.example", DestinationIP: "8.8.8.8", Process: "wget"},
		}},
	}

	if err := svc.processConnections(context.Background(), firstMinute); err != nil {
		t.Fatalf("processConnections firstMinute: %v", err)
	}

	currentTime = currentTime.Add(time.Minute)
	if err := svc.processConnections(context.Background(), secondMinute); err != nil {
		t.Fatalf("processConnections secondMinute: %v", err)
	}

	if putCount != 1 {
		t.Fatalf("expected cooldown to keep switch count at 1, got %d", putCount)
	}

	events, err := listAutoSwitchEvents(svc.db, 10)
	if err != nil {
		t.Fatalf("listAutoSwitchEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected cooldown to prevent second event, got %d", len(events))
	}
}

func TestAutoSwitchCreatesRestoreSession(t *testing.T) {
	t.Run("successful switch creates restore session", func(t *testing.T) {
		svc := newTestService(t)

		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     15,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		currentProxy := "🚩 PROXY"
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":%q}}}`, currentProxy)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					currentProxy = "🇸🇬 Singapore"
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   100,
				Download: 100,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}
		second := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   250,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}

		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), second); err != nil {
			t.Fatalf("processConnections second: %v", err)
		}

		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 restore session, got %d", len(sessions))
		}
		if sessions[0].GroupName != "🌍 国外媒体" || sessions[0].OriginalProxy != "🚩 PROXY" {
			t.Fatalf("unexpected restore session identity: %+v", sessions[0])
		}
		if sessions[0].CurrentProxy != "🇸🇬 Singapore" {
			t.Fatalf("expected current proxy to track switched target, got %+v", sessions[0])
		}
		if sessions[0].LastTriggeredAt != currentTime.UnixMilli() {
			t.Fatalf("expected trigger timestamp %d, got %d", currentTime.UnixMilli(), sessions[0].LastTriggeredAt)
		}
		if sessions[0].LastTriggeredHost != "video.example" || sessions[0].LastTriggeredBytes != 400 {
			t.Fatalf("unexpected trigger metadata: %+v", sessions[0])
		}
	})

	t.Run("recursive switch follows enabled nested groups", func(t *testing.T) {
		svc := newTestService(t)

		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     15,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "⏬ 大流量套餐", Enabled: true},
				{GroupName: "⏬ 大流量套餐", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		currentProxy := map[string]string{
			"🌍 国外媒体":  "🚩 PROXY",
			"⏬ 大流量套餐": "🇯🇵 Japan",
		}
		switches := make([]string, 0, 2)
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{
						"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","⏬ 大流量套餐"],"now":%q},
						"⏬ 大流量套餐":{"type":"Selector","all":["🇯🇵 Japan","🇸🇬 Singapore"],"now":%q}
					}}`, currentProxy["🌍 国外媒体"], currentProxy["⏬ 大流量套餐"])
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					currentProxy["🌍 国外媒体"] = "⏬ 大流量套餐"
					switches = append(switches, "🌍 国外媒体->⏬ 大流量套餐")
					return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/⏬ 大流量套餐":
					currentProxy["⏬ 大流量套餐"] = "🇸🇬 Singapore"
					switches = append(switches, "⏬ 大流量套餐->🇸🇬 Singapore")
					return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   100,
				Download: 100,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}
		second := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   250,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}

		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), second); err != nil {
			t.Fatalf("processConnections second: %v", err)
		}

		if len(switches) != 2 {
			t.Fatalf("expected two recursive switches, got %v", switches)
		}
		if switches[0] != "🌍 国外媒体->⏬ 大流量套餐" || switches[1] != "⏬ 大流量套餐->🇸🇬 Singapore" {
			t.Fatalf("unexpected recursive switch chain: %v", switches)
		}

		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 2 {
			t.Fatalf("expected restore sessions for both switched groups, got %+v", sessions)
		}
		if sessions[0].GroupName != "⏬ 大流量套餐" || sessions[0].OriginalProxy != "🇯🇵 Japan" || sessions[0].CurrentProxy != "🇸🇬 Singapore" {
			t.Fatalf("unexpected nested restore session: %+v", sessions[0])
		}
		if sessions[1].GroupName != "🌍 国外媒体" || sessions[1].OriginalProxy != "🚩 PROXY" || sessions[1].CurrentProxy != "⏬ 大流量套餐" {
			t.Fatalf("unexpected root restore session: %+v", sessions[1])
		}

		events, err := listAutoSwitchEvents(svc.db, 10)
		if err != nil {
			t.Fatalf("listAutoSwitchEvents: %v", err)
		}
		if len(events) != 1 || len(events[0].Results) != 2 {
			t.Fatalf("expected one event with full recursive chain, got %+v", events)
		}
	})

	t.Run("recursive switch stops at non enabled group target", func(t *testing.T) {
		svc := newTestService(t)

		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     15,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "⏬ 大流量套餐", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		var switches []string
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := `{"proxies":{
						"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","⏬ 大流量套餐"],"now":"🚩 PROXY"},
						"⏬ 大流量套餐":{"type":"Selector","all":["🇯🇵 Japan","🇸🇬 Singapore"],"now":"🇯🇵 Japan"}
					}}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					switches = append(switches, "🌍 国外媒体->⏬ 大流量套餐")
					return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/⏬ 大流量套餐":
					switches = append(switches, "⏬ 大流量套餐->🇸🇬 Singapore")
					return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   100,
				Download: 100,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}
		second := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   250,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}

		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), second); err != nil {
			t.Fatalf("processConnections second: %v", err)
		}

		if len(switches) != 1 || switches[0] != "🌍 国外媒体->⏬ 大流量套餐" {
			t.Fatalf("expected recursion to stop at non enabled group, got %v", switches)
		}

		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 1 || sessions[0].GroupName != "🌍 国外媒体" || sessions[0].CurrentProxy != "⏬ 大流量套餐" {
			t.Fatalf("expected only root restore session when recursion stops, got %+v", sessions)
		}
	})

	t.Run("recursive switch detects cycles", func(t *testing.T) {
		svc := newTestService(t)

		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     15,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "⏬ 大流量套餐", Enabled: true},
				{GroupName: "⏬ 大流量套餐", TargetProxy: "🌍 国外媒体", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		switches := make([]string, 0, 2)
		currentProxy := map[string]string{
			"🌍 国外媒体":  "🚩 PROXY",
			"⏬ 大流量套餐": "🇯🇵 Japan",
		}
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{
						"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","⏬ 大流量套餐"],"now":%q},
						"⏬ 大流量套餐":{"type":"Selector","all":["🇯🇵 Japan","🌍 国外媒体"],"now":%q}
					}}`, currentProxy["🌍 国外媒体"], currentProxy["⏬ 大流量套餐"])
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					currentProxy["🌍 国外媒体"] = "⏬ 大流量套餐"
					switches = append(switches, "🌍 国外媒体->⏬ 大流量套餐")
					return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/⏬ 大流量套餐":
					currentProxy["⏬ 大流量套餐"] = "🌍 国外媒体"
					switches = append(switches, "⏬ 大流量套餐->🌍 国外媒体")
					return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   100,
				Download: 100,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}
		second := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   250,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}

		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), second); err != nil {
			t.Fatalf("processConnections second: %v", err)
		}

		if len(switches) != 2 {
			t.Fatalf("expected cycle test to stop after two concrete switches, got %v", switches)
		}

		events, err := listAutoSwitchEvents(svc.db, 10)
		if err != nil {
			t.Fatalf("listAutoSwitchEvents: %v", err)
		}
		if len(events) != 1 || len(events[0].Results) != 3 {
			t.Fatalf("expected cycle event to record two switches plus cycle error, got %+v", events)
		}
		last := events[0].Results[2]
		if last.Status != "error" || last.Message != "cyclic auto switch target chain" {
			t.Fatalf("expected cycle detection result, got %+v", last)
		}
	})

	t.Run("skipped or failed switch does not create restore session", func(t *testing.T) {
		cases := []struct {
			name       string
			currentNow string
			putStatus  int
		}{
			{name: "skipped", currentNow: "🇸🇬 Singapore", putStatus: http.StatusNoContent},
			{name: "failed", currentNow: "🚩 PROXY", putStatus: http.StatusInternalServerError},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				svc := newTestService(t)

				if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
					Enabled:                 true,
					ThresholdBytesPerMinute: 300,
					CooldownSeconds:         0,
					RestoreEnabled:          true,
					RestoreQuietMinutes:     15,
					GroupTargets: []autoSwitchGroupTarget{
						{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
					},
				}); err != nil {
					t.Fatalf("saveAutoSwitchSettings: %v", err)
				}

				svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
				currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
				svc.now = func() time.Time { return currentTime }

				svc.client = &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						switch {
						case req.Method == http.MethodGet && req.URL.Path == "/proxies":
							body := fmt.Sprintf(`{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":%q}}}`, tc.currentNow)
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(strings.NewReader(body)),
								Header:     make(http.Header),
							}, nil
						case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
							return &http.Response{
								StatusCode: tc.putStatus,
								Body:       io.NopCloser(strings.NewReader("")),
								Header:     make(http.Header),
							}, nil
						default:
							t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
							return nil, nil
						}
					}),
				}

				first := &connectionsResponse{
					Connections: []connection{{
						ID:       "conn-1",
						Upload:   100,
						Download: 100,
						Chains:   []string{"🌍 国外媒体"},
						Metadata: struct {
							SourceIP      string "json:\"sourceIP\""
							Host          string "json:\"host\""
							DestinationIP string "json:\"destinationIP\""
							Process       string "json:\"process\""
						}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
					}},
				}
				second := &connectionsResponse{
					Connections: []connection{{
						ID:       "conn-1",
						Upload:   250,
						Download: 150,
						Chains:   []string{"🌍 国外媒体"},
						Metadata: struct {
							SourceIP      string "json:\"sourceIP\""
							Host          string "json:\"host\""
							DestinationIP string "json:\"destinationIP\""
							Process       string "json:\"process\""
						}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
					}},
				}

				if err := svc.processConnections(context.Background(), first); err != nil {
					t.Fatalf("processConnections first: %v", err)
				}
				if err := svc.processConnections(context.Background(), second); err != nil && tc.name != "failed" {
					t.Fatalf("processConnections second: %v", err)
				}

				sessions, err := listAutoRestoreSessions(svc.db)
				if err != nil {
					t.Fatalf("listAutoRestoreSessions: %v", err)
				}
				if len(sessions) != 0 {
					t.Fatalf("expected no restore sessions for %s path, got %+v", tc.name, sessions)
				}
			})
		}
	})

	t.Run("repeated trigger updates timing without losing original proxy", func(t *testing.T) {
		svc := newTestService(t)

		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     15,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		currentProxy := "🚩 PROXY"
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":%q}}}`, currentProxy)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					currentProxy = "🇸🇬 Singapore"
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		firstMinute := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   100,
				Download: 100,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}
		firstMinuteTrigger := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   250,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: "video.example", DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}
		secondMinuteTrigger := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-2",
				Upload:   350,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.3", Host: "download.example", DestinationIP: "8.8.8.8", Process: "wget"},
			}},
		}

		if err := svc.processConnections(context.Background(), firstMinute); err != nil {
			t.Fatalf("processConnections firstMinute: %v", err)
		}
		if err := svc.processConnections(context.Background(), firstMinuteTrigger); err != nil {
			t.Fatalf("processConnections firstMinuteTrigger: %v", err)
		}

		currentTime = currentTime.Add(time.Minute)
		if err := svc.processConnections(context.Background(), secondMinuteTrigger); err != nil {
			t.Fatalf("processConnections secondMinuteTrigger: %v", err)
		}

		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 restore session after repeated triggers, got %d", len(sessions))
		}
		if sessions[0].OriginalProxy != "🚩 PROXY" {
			t.Fatalf("expected original proxy to be preserved, got %+v", sessions[0])
		}
		if sessions[0].CurrentProxy != "🇸🇬 Singapore" {
			t.Fatalf("expected current proxy to remain target, got %+v", sessions[0])
		}
		if sessions[0].LastTriggeredAt != currentTime.UnixMilli() {
			t.Fatalf("expected timestamp to refresh to %d, got %d", currentTime.UnixMilli(), sessions[0].LastTriggeredAt)
		}
		if sessions[0].LastTriggeredHost != "download.example" || sessions[0].LastTriggeredBytes != 500 {
			t.Fatalf("expected repeated trigger metadata to refresh, got %+v", sessions[0])
		}
	})
}

func TestAutoRestore(t *testing.T) {
	newTriggerResponses := func(host string) (*connectionsResponse, *connectionsResponse) {
		return &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   100,
				Download: 100,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: host, DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}, &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-1",
				Upload:   250,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.2", Host: host, DestinationIP: "1.1.1.1", Process: "chrome"},
			}},
		}
	}

	t.Run("restore happens after quiet minutes with no new trigger", func(t *testing.T) {
		svc := newTestService(t)
		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     2,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		currentProxy := "🚩 PROXY"
		available := []string{"🚩 PROXY", "🇸🇬 Singapore"}
		restoreCount := 0
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["%s","%s"],"now":%q}}}`, available[0], available[1], currentProxy)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					payload, err := io.ReadAll(req.Body)
					if err != nil {
						t.Fatalf("read put body: %v", err)
					}
					if strings.Contains(string(payload), "🚩 PROXY") {
						restoreCount++
						currentProxy = "🚩 PROXY"
					} else {
						currentProxy = "🇸🇬 Singapore"
					}
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first, trigger := newTriggerResponses("video.example")
		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), trigger); err != nil {
			t.Fatalf("processConnections trigger: %v", err)
		}

		currentTime = currentTime.Add(2 * time.Minute)
		if err := svc.processConnections(context.Background(), &connectionsResponse{}); err != nil {
			t.Fatalf("processConnections restore tick: %v", err)
		}

		if restoreCount != 1 {
			t.Fatalf("expected one restore switch, got %d", restoreCount)
		}
		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 0 {
			t.Fatalf("expected restore session cleanup after restore, got %+v", sessions)
		}

		events, err := listAutoSwitchEvents(svc.db, 10)
		if err != nil {
			t.Fatalf("listAutoSwitchEvents: %v", err)
		}
		if len(events) < 2 {
			t.Fatalf("expected trigger event plus restore event, got %d", len(events))
		}
		if len(events[0].Results) != 1 || events[0].Results[0].Status != "restored" {
			t.Fatalf("expected latest event to record restored status, got %+v", events[0])
		}
	})

	t.Run("new heavy traffic trigger resets quiet waiting", func(t *testing.T) {
		svc := newTestService(t)
		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     2,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		currentProxy := "🚩 PROXY"
		restoreCount := 0
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore"],"now":%q}}}`, currentProxy)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					payload, err := io.ReadAll(req.Body)
					if err != nil {
						t.Fatalf("read put body: %v", err)
					}
					if strings.Contains(string(payload), "🚩 PROXY") {
						restoreCount++
					}
					currentProxy = "🇸🇬 Singapore"
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first, trigger := newTriggerResponses("video.example")
		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), trigger); err != nil {
			t.Fatalf("processConnections trigger: %v", err)
		}

		currentTime = currentTime.Add(time.Minute)
		nextMinute := &connectionsResponse{
			Connections: []connection{{
				ID:       "conn-2",
				Upload:   350,
				Download: 150,
				Chains:   []string{"🌍 国外媒体"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{SourceIP: "192.168.1.3", Host: "download.example", DestinationIP: "8.8.8.8", Process: "wget"},
			}},
		}
		if err := svc.processConnections(context.Background(), nextMinute); err != nil {
			t.Fatalf("processConnections nextMinute: %v", err)
		}

		currentTime = currentTime.Add(time.Minute)
		if err := svc.processConnections(context.Background(), &connectionsResponse{}); err != nil {
			t.Fatalf("processConnections quiet tick: %v", err)
		}

		if restoreCount != 0 {
			t.Fatalf("expected quiet waiting to reset after new trigger, got %d restores", restoreCount)
		}
		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected restore session to remain pending, got %+v", sessions)
		}
	})

	t.Run("manual proxy change cancels restore session", func(t *testing.T) {
		svc := newTestService(t)
		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     2,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		currentProxy := "🚩 PROXY"
		restorePutCount := 0
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["🚩 PROXY","🇸🇬 Singapore","🇯🇵 Japan"],"now":%q}}}`, currentProxy)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					payload, err := io.ReadAll(req.Body)
					if err != nil {
						t.Fatalf("read put body: %v", err)
					}
					if strings.Contains(string(payload), "🚩 PROXY") {
						restorePutCount++
					} else {
						currentProxy = "🇸🇬 Singapore"
					}
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first, trigger := newTriggerResponses("video.example")
		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), trigger); err != nil {
			t.Fatalf("processConnections trigger: %v", err)
		}

		currentProxy = "🇯🇵 Japan"
		currentTime = currentTime.Add(2 * time.Minute)
		if err := svc.processConnections(context.Background(), &connectionsResponse{}); err != nil {
			t.Fatalf("processConnections restore tick: %v", err)
		}

		if restorePutCount != 0 {
			t.Fatalf("expected no restore call after manual change, got %d", restorePutCount)
		}
		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 0 {
			t.Fatalf("expected manual change to cancel restore session, got %+v", sessions)
		}

		events, err := listAutoSwitchEvents(svc.db, 10)
		if err != nil {
			t.Fatalf("listAutoSwitchEvents: %v", err)
		}
		if len(events) < 2 || len(events[0].Results) != 1 || events[0].Results[0].Status != "restore_skipped" {
			t.Fatalf("expected latest event to record restore_skipped, got %+v", events)
		}
	})

	t.Run("missing original proxy records restore error", func(t *testing.T) {
		svc := newTestService(t)
		if err := saveAutoSwitchSettings(svc.db, autoSwitchSettings{
			Enabled:                 true,
			ThresholdBytesPerMinute: 300,
			CooldownSeconds:         0,
			RestoreEnabled:          true,
			RestoreQuietMinutes:     2,
			GroupTargets: []autoSwitchGroupTarget{
				{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("saveAutoSwitchSettings: %v", err)
		}

		svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
		currentTime := time.Date(2026, 4, 28, 12, 0, 10, 0, time.Local)
		svc.now = func() time.Time { return currentTime }

		currentProxy := "🚩 PROXY"
		allList := []string{"🚩 PROXY", "🇸🇬 Singapore"}
		restorePutCount := 0
		svc.client = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/proxies":
					body := fmt.Sprintf(`{"proxies":{"🌍 国外媒体":{"type":"Selector","all":["%s","%s"],"now":%q}}}`, allList[0], allList[1], currentProxy)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				case req.Method == http.MethodPut && req.URL.Path == "/proxies/🌍 国外媒体":
					payload, err := io.ReadAll(req.Body)
					if err != nil {
						t.Fatalf("read put body: %v", err)
					}
					if strings.Contains(string(payload), "🚩 PROXY") {
						restorePutCount++
					} else {
						currentProxy = "🇸🇬 Singapore"
					}
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
					return nil, nil
				}
			}),
		}

		first, trigger := newTriggerResponses("video.example")
		if err := svc.processConnections(context.Background(), first); err != nil {
			t.Fatalf("processConnections first: %v", err)
		}
		if err := svc.processConnections(context.Background(), trigger); err != nil {
			t.Fatalf("processConnections trigger: %v", err)
		}

		allList = []string{"🇸🇬 Singapore", "🇯🇵 Japan"}
		currentTime = currentTime.Add(2 * time.Minute)
		if err := svc.processConnections(context.Background(), &connectionsResponse{}); err != nil {
			t.Fatalf("processConnections restore tick: %v", err)
		}

		if restorePutCount != 0 {
			t.Fatalf("expected no restore call when original proxy disappeared, got %d", restorePutCount)
		}
		sessions, err := listAutoRestoreSessions(svc.db)
		if err != nil {
			t.Fatalf("listAutoRestoreSessions: %v", err)
		}
		if len(sessions) != 0 {
			t.Fatalf("expected restore session cleanup after restore error, got %+v", sessions)
		}

		events, err := listAutoSwitchEvents(svc.db, 10)
		if err != nil {
			t.Fatalf("listAutoSwitchEvents: %v", err)
		}
		if len(events) < 2 || len(events[0].Results) != 1 || events[0].Results[0].Status != "restore_error" {
			t.Fatalf("expected latest event to record restore_error, got %+v", events)
		}
	})
}

func TestCollectOnceSkipsPollingWhenMihomoURLIsUnset(t *testing.T) {
	svc := newTestService(t)
	svc.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatalf("unexpected outbound request when mihomo url is unset")
			return nil, nil
		}),
	}
	svc.setMihomoSettings(mihomoSettings{})

	svc.collectOnce(context.Background())
}

func TestHandleMihomoSettingsRoundTrip(t *testing.T) {
	svc := newTestService(t)

	req := httptest.NewRequest(http.MethodPut, "/api/settings/mihomo", bytes.NewBufferString(`{"url":"http://127.0.0.1:9090/","secret":"test-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected put status: %d body=%s", rec.Code, rec.Body.String())
	}

	var updated mihomoSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if updated.URL != "http://127.0.0.1:9090" {
		t.Fatalf("expected trailing slash to be trimmed, got %q", updated.URL)
	}
	if updated.Secret != "test-secret" {
		t.Fatalf("expected updated secret in response, got %q", updated.Secret)
	}

	stored, err := loadMihomoSettings(svc.db)
	if err != nil {
		t.Fatalf("loadMihomoSettings: %v", err)
	}
	if stored != updated {
		t.Fatalf("expected persisted settings to match response, got %+v want %+v", stored, updated)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/settings/mihomo", nil)
	getRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("unexpected get status: %d body=%s", getRec.Code, getRec.Body.String())
	}

	var fetched mihomoSettings
	if err := json.Unmarshal(getRec.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if fetched != updated {
		t.Fatalf("expected get response to match updated settings, got %+v want %+v", fetched, updated)
	}
}

func TestHandleMihomoSettingsRejectsEmptyURL(t *testing.T) {
	svc := newTestService(t)

	req := httptest.NewRequest(http.MethodPut, "/api/settings/mihomo", bytes.NewBufferString(`{"url":"   ","secret":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for empty mihomo url, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAutoSwitchSettingsRoundTrip(t *testing.T) {
	svc := newTestService(t)

	putReq := httptest.NewRequest(http.MethodPut, "/api/auto-switch/settings", bytes.NewBufferString(`{
		"enabled": true,
		"thresholdBytesPerMinute": 536870912,
		"cooldownSeconds": 900,
		"restoreEnabled": true,
		"restoreQuietMinutes": 15,
		"groupTargets": [
			{"groupName":"🌍 国外媒体","targetProxy":"🇸🇬 Singapore","enabled":true}
		]
	}`))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()

	svc.routes().ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("unexpected put status: %d body=%s", putRec.Code, putRec.Body.String())
	}

	var updated autoSwitchSettings
	if err := json.Unmarshal(putRec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if !updated.Enabled || updated.ThresholdBytesPerMinute != 536870912 || updated.CooldownSeconds != 900 {
		t.Fatalf("unexpected saved settings: %+v", updated)
	}
	if !updated.RestoreEnabled || updated.RestoreQuietMinutes != 15 {
		t.Fatalf("unexpected saved restore settings: %+v", updated)
	}
	if len(updated.GroupTargets) != 1 || updated.GroupTargets[0].GroupName != "🌍 国外媒体" {
		t.Fatalf("unexpected saved group targets: %+v", updated.GroupTargets)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/auto-switch/settings", nil)
	getRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("unexpected get status: %d body=%s", getRec.Code, getRec.Body.String())
	}

	var fetched autoSwitchSettings
	if err := json.Unmarshal(getRec.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if fetched.Enabled != updated.Enabled || fetched.ThresholdBytesPerMinute != updated.ThresholdBytesPerMinute {
		t.Fatalf("unexpected fetched settings: %+v want %+v", fetched, updated)
	}
	if fetched.RestoreEnabled != updated.RestoreEnabled || fetched.RestoreQuietMinutes != updated.RestoreQuietMinutes {
		t.Fatalf("unexpected fetched restore settings: %+v want %+v", fetched, updated)
	}
}

func TestHandleAutoSwitchSettingsRejectsInvalidThreshold(t *testing.T) {
	svc := newTestService(t)

	req := httptest.NewRequest(http.MethodPut, "/api/auto-switch/settings", bytes.NewBufferString(`{
		"enabled": true,
		"thresholdBytesPerMinute": 0,
		"cooldownSeconds": 60,
		"groupTargets": [{"groupName":"🌍 国外媒体","targetProxy":"🇸🇬 Singapore","enabled":true}]
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for invalid threshold, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAutoSwitchSettingsRejectsNegativeRestoreQuietMinutes(t *testing.T) {
	svc := newTestService(t)

	req := httptest.NewRequest(http.MethodPut, "/api/auto-switch/settings", bytes.NewBufferString(`{
		"enabled": true,
		"thresholdBytesPerMinute": 300,
		"cooldownSeconds": 60,
		"restoreEnabled": true,
		"restoreQuietMinutes": -1,
		"groupTargets": [{"groupName":"🌍 国外媒体","targetProxy":"🇸🇬 Singapore","enabled":true}]
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for negative restore quiet minutes, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAutoSwitchGroupsReturnsControllableGroups(t *testing.T) {
	svc := newTestService(t)
	svc.setMihomoSettings(mihomoSettings{URL: "http://127.0.0.1:9090"})
	svc.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := `{
				"proxies": {
					"🌍 国外媒体": {"type":"Selector","all":["⏬ 大流量节点","🚩 PROXY"],"now":"🚩 PROXY"},
					"♻️ 自动选择": {"type":"URLTest","all":["🇯🇵 Japan"],"now":"🇯🇵 Japan"}
				}
			}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auto-switch/groups", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var got []controllableProxyGroup
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 || got[0].Name != "🌍 国外媒体" {
		t.Fatalf("unexpected groups: %+v", got)
	}
}

func TestHandleAutoSwitchEventsReturnsRecentEvents(t *testing.T) {
	svc := newTestService(t)

	if err := insertAutoSwitchEvent(svc.db, autoSwitchEvent{
		TriggeredAt: 1234,
		Host:        "video.example",
		TotalBytes:  999,
		WindowStart: 0,
		WindowEnd:   60_000,
		Results: []autoSwitchExecutionResult{
			{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Status: "switched"},
		},
	}); err != nil {
		t.Fatalf("insertAutoSwitchEvent: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auto-switch/events", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var got []autoSwitchEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 || got[0].Host != "video.example" {
		t.Fatalf("unexpected events payload: %+v", got)
	}
}

func TestHandleAutoSwitchEventsLimitsToFifty(t *testing.T) {
	svc := newTestService(t)

	for i := 0; i < 55; i++ {
		if err := insertAutoSwitchEvent(svc.db, autoSwitchEvent{
			TriggeredAt: int64(1_000 + i),
			Host:        fmt.Sprintf("video-%02d.example", i),
			TotalBytes:  int64(1_000 + i),
			WindowStart: int64(i) * 60_000,
			WindowEnd:   int64(i+1) * 60_000,
			Results: []autoSwitchExecutionResult{
				{GroupName: "🌍 国外媒体", TargetProxy: "🇸🇬 Singapore", Status: "switched"},
			},
		}); err != nil {
			t.Fatalf("insertAutoSwitchEvent %d: %v", i, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auto-switch/events", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var got []autoSwitchEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 50 {
		t.Fatalf("expected 50 events, got %d", len(got))
	}
	if got[0].Host != "video-54.example" || got[len(got)-1].Host != "video-05.example" {
		t.Fatalf("unexpected event ordering: first=%q last=%q", got[0].Host, got[len(got)-1].Host)
	}
}

func TestHandleAutoSwitchEventsReturnsRestoreStatuses(t *testing.T) {
	svc := newTestService(t)

	if err := insertAutoSwitchEvent(svc.db, autoSwitchEvent{
		TriggeredAt: 5678,
		Host:        "",
		TotalBytes:  0,
		WindowStart: 120_000,
		WindowEnd:   180_000,
		Results: []autoSwitchExecutionResult{
			{GroupName: "🌍 国外媒体", TargetProxy: "🚩 PROXY", Status: "restored"},
			{GroupName: "🐟 漏网之鱼", TargetProxy: "DIRECT", Status: "restore_error", Message: "original proxy is no longer available"},
		},
		Error: "🐟 漏网之鱼: original proxy unavailable",
	}); err != nil {
		t.Fatalf("insertAutoSwitchEvent: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auto-switch/events", nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var got []autoSwitchEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one event payload, got %d", len(got))
	}
	if len(got[0].Results) != 2 {
		t.Fatalf("expected restore results to round-trip, got %+v", got[0].Results)
	}
	if got[0].Results[0].Status != "restored" || got[0].Results[1].Status != "restore_error" {
		t.Fatalf("expected restore statuses in payload, got %+v", got[0].Results)
	}
}

func TestQueryAggregateIncludesBufferedData(t *testing.T) {
	svc := newTestService(t)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{
			BucketStart: 60_000,
			BucketEnd:   120_000,
			SourceIP:    "192.168.1.2",
			Host:        "a.com",
			Process:     "chrome",
			Outbound:    "NodeA",
			Chains:      `["DIRECT"]`,
			Upload:      30,
			Download:    40,
			Count:       1,
		},
	})

	svc.aggregateBuffer["pending"] = &aggregatedEntry{
		BucketStart:   120_000,
		BucketEnd:     180_000,
		SourceIP:      "192.168.1.2",
		Host:          "a.com",
		DestinationIP: "1.1.1.1",
		Process:       "chrome",
		Outbound:      "NodeA",
		Chains:        `["DIRECT"]`,
		Upload:        50,
		Download:      60,
		Count:         1,
	}

	got, err := svc.queryAggregate("sourceIP", 60_000, 180_000, false)
	if err != nil {
		t.Fatalf("queryAggregate: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Upload != 80 || got[0].Download != 100 || got[0].Total != 180 || got[0].Count != 2 {
		t.Fatalf("unexpected aggregated result: %+v", got[0])
	}
}

func TestSummaryAPIEndpointsUseSummaryTable(t *testing.T) {
	svc := newTestService(t)

	day := int64(24 * time.Hour / time.Millisecond)
	now := time.Date(2026, 8, 6, 15, 0, 0, 0, time.Local).UnixMilli()
	dayStart := (now / day) * day
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{
			BucketStart: dayStart - day,
			BucketEnd:   dayStart - day + 60000,
			SourceIP:    "192.168.1.8",
			Host:        "api.example.com",
			Outbound:    "ProxyA",
			Chains:      `["ProxyA"]`,
			Upload:      15,
			Download:    25,
			Count:       1,
		},
	})
	if err := backfillSummary(svc.db, now); err != nil {
		t.Fatalf("backfillSummary: %v", err)
	}

	start := dayStart - day
	end := dayStart - 1
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/traffic/aggregate?dimension=sourceIP&start="+strconv.FormatInt(start, 10)+"&end="+strconv.FormatInt(end, 10)+"&summary=1",
		nil,
	)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("aggregate summary status: %d body=%s", rec.Code, rec.Body.String())
	}
	var rows []aggregatedData
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode aggregate summary: %v", err)
	}
	if len(rows) != 1 || rows[0].Label != "192.168.1.8" || rows[0].Upload != 15 {
		t.Fatalf("unexpected aggregate summary response: %+v", rows)
	}

	req = httptest.NewRequest(
		http.MethodGet,
		"/api/traffic/trend?start="+strconv.FormatInt(start, 10)+"&end="+strconv.FormatInt(end, 10)+"&bucket="+strconv.FormatInt(day, 10)+"&summary=1",
		nil,
	)
	rec = httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trend summary status: %d body=%s", rec.Code, rec.Body.String())
	}
	var points []trendPoint
	if err := json.Unmarshal(rec.Body.Bytes(), &points); err != nil {
		t.Fatalf("decode trend summary: %v", err)
	}
	if len(points) != 1 || points[0].Upload != 15 || points[0].Download != 25 {
		t.Fatalf("unexpected trend summary response: %+v", points)
	}

	req = httptest.NewRequest(
		http.MethodGet,
		"/api/traffic/details?dimension=sourceIP&primary=192.168.1.8&secondary=api.example.com&start="+strconv.FormatInt(start, 10)+"&end="+strconv.FormatInt(end, 10)+"&summary=1",
		nil,
	)
	rec = httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("details summary status: %d body=%s", rec.Code, rec.Body.String())
	}
	var details []connectionDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &details); err != nil {
		t.Fatalf("decode details summary: %v", err)
	}
	if len(details) != 0 {
		t.Fatalf("expected summary details to be empty, got %+v", details)
	}
}

func TestQueryTrendRebucketsAggregatedMinuteData(t *testing.T) {
	svc := newTestService(t)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 60_000, BucketEnd: 120_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 10, Download: 20, Count: 1},
		{BucketStart: 120_000, BucketEnd: 180_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 30, Download: 40, Count: 1},
		{BucketStart: 180_000, BucketEnd: 240_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 50, Download: 60, Count: 1},
		{BucketStart: 240_000, BucketEnd: 300_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 70, Download: 80, Count: 1},
	})

	got, err := svc.queryTrend(0, 600_000, 300_000)
	if err != nil {
		t.Fatalf("queryTrend: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(got))
	}
	if got[0].Timestamp != 0 || got[0].Upload != 160 || got[0].Download != 200 {
		t.Fatalf("unexpected first bucket: %+v", got[0])
	}
	if got[1].Timestamp != 300_000 || got[1].Upload != 0 || got[1].Download != 0 {
		t.Fatalf("unexpected second bucket: %+v", got[1])
	}
}

func TestQueryTrendIncludesBufferedData(t *testing.T) {
	svc := newTestService(t)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 10, Download: 20, Count: 1},
	})

	svc.aggregateBuffer["pending"] = &aggregatedEntry{
		BucketStart:   60_000,
		BucketEnd:     120_000,
		SourceIP:      "192.168.1.2",
		Host:          "a.com",
		DestinationIP: "1.1.1.1",
		Process:       "chrome",
		Outbound:      "NodeA",
		Chains:        `["DIRECT"]`,
		Upload:        30,
		Download:      40,
		Count:         1,
	}

	got, err := svc.queryTrend(0, 120_000, 60_000)
	if err != nil {
		t.Fatalf("queryTrend: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(got))
	}
	if got[0].Timestamp != 0 || got[0].Upload != 10 || got[0].Download != 20 {
		t.Fatalf("unexpected first bucket: %+v", got[0])
	}
	if got[1].Timestamp != 60_000 || got[1].Upload != 30 || got[1].Download != 40 {
		t.Fatalf("unexpected second bucket: %+v", got[1])
	}
}

func TestHandleLogsClearsAggregatesAndBuffer(t *testing.T) {
	svc := newTestService(t)

	insertTestLogs(t, svc.db, []trafficLog{
		{Timestamp: 1000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Upload: 100, Download: 200},
	})
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "a.com", Process: "chrome", Outbound: "NodeA", Chains: `["DIRECT"]`, Upload: 100, Download: 200, Count: 1},
	})
	svc.aggregateBuffer["pending"] = &aggregatedEntry{BucketStart: 60_000, BucketEnd: 120_000, SourceIP: "192.168.1.2"}
	if _, err := svc.db.Exec(`
		INSERT INTO traffic_summary
		(bucket_start, bucket_end, dimension, label, secondary_label, upload, download, count)
		VALUES (0, 60000, 'source_ip', '192.168.1.2', 'a.com', 100, 200, 1)
	`); err != nil {
		t.Fatalf("insert traffic_summary: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/traffic/logs", nil)
	rec := httptest.NewRecorder()

	svc.handleLogs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var rawCount int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_logs`).Scan(&rawCount); err != nil {
		t.Fatalf("count traffic_logs: %v", err)
	}
	if rawCount != 0 {
		t.Fatalf("expected traffic_logs to be empty, got %d rows", rawCount)
	}

	var aggregateCount int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_aggregated`).Scan(&aggregateCount); err != nil {
		t.Fatalf("count traffic_aggregated: %v", err)
	}
	if aggregateCount != 0 {
		t.Fatalf("expected traffic_aggregated to be empty, got %d rows", aggregateCount)
	}

	var summaryCount int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_summary`).Scan(&summaryCount); err != nil {
		t.Fatalf("count traffic_summary: %v", err)
	}
	if summaryCount != 0 {
		t.Fatalf("expected traffic_summary to be empty, got %d rows", summaryCount)
	}

	if len(svc.aggregateBuffer) != 0 {
		t.Fatalf("expected aggregate buffer to be empty, got %d entries", len(svc.aggregateBuffer))
	}
}

func TestHandleConnectionDetailsReturnsGroupedDetails(t *testing.T) {
	svc := newTestService(t)

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{
			BucketStart:   0,
			BucketEnd:     60_000,
			SourceIP:      "192.168.1.2",
			Host:          "a.com",
			DestinationIP: "1.1.1.1",
			Process:       "chrome",
			Outbound:      "NodeA",
			Chains:        `["NodeA","RelayA"]`,
			Upload:        100,
			Download:      200,
			Count:         1,
		},
		{
			BucketStart:   60_000,
			BucketEnd:     120_000,
			SourceIP:      "192.168.1.2",
			Host:          "a.com",
			DestinationIP: "1.1.1.1",
			Process:       "chrome",
			Outbound:      "NodeA",
			Chains:        `["NodeA","RelayA"]`,
			Upload:        10,
			Download:      20,
			Count:         1,
		},
		{
			BucketStart:   0,
			BucketEnd:     60_000,
			SourceIP:      "192.168.1.3",
			Host:          "a.com",
			DestinationIP: "8.8.8.8",
			Process:       "curl",
			Outbound:      "NodeB",
			Chains:        `["NodeB"]`,
			Upload:        30,
			Download:      40,
			Count:         1,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/details?dimension=host&primary=a.com&secondary=192.168.1.2&start=1&end=120000", nil)
	rec := httptest.NewRecorder()

	svc.handleConnectionDetails(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var got []connectionDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 grouped detail, got %d", len(got))
	}
	if got[0].DestinationIP != "1.1.1.1" {
		t.Fatalf("unexpected destination ip: %+v", got[0])
	}
	if got[0].SourceIP != "192.168.1.2" {
		t.Fatalf("unexpected source ip: %+v", got[0])
	}
	if got[0].Process != "chrome" || got[0].Outbound != "NodeA" {
		t.Fatalf("unexpected routing info: %+v", got[0])
	}
	if got[0].Upload != 110 || got[0].Download != 220 || got[0].Count != 2 {
		t.Fatalf("unexpected aggregates: %+v", got[0])
	}
	if len(got[0].Chains) != 2 || got[0].Chains[0] != "NodeA" {
		t.Fatalf("unexpected chains: %+v", got[0])
	}
}

func TestHandleConnectionDetailsIncludesBufferedData(t *testing.T) {
	svc := newTestService(t)

	svc.aggregateBuffer["pending"] = &aggregatedEntry{
		BucketStart:   120_000,
		BucketEnd:     180_000,
		SourceIP:      "192.168.1.2",
		Host:          "a.com",
		DestinationIP: "1.1.1.1",
		Process:       "chrome",
		Outbound:      "NodeA",
		Chains:        `["NodeA","RelayA"]`,
		Upload:        15,
		Download:      25,
		Count:         1,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/details?dimension=host&primary=a.com&secondary=192.168.1.2&start=1&end=180000", nil)
	rec := httptest.NewRecorder()

	svc.handleConnectionDetails(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var got []connectionDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 grouped detail, got %d", len(got))
	}
	if got[0].Upload != 15 || got[0].Download != 25 || got[0].Count != 1 {
		t.Fatalf("unexpected buffered detail aggregates: %+v", got[0])
	}
}

func TestEmbeddedIndexDisablesPeriodicAutoRefresh(t *testing.T) {
	content, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}

	html := string(content)
	if !strings.Contains(html, `href="/styles.css"`) {
		t.Fatalf("expected embedded index.html to load external stylesheet")
	}
	if !strings.Contains(html, `src="/app.js"`) {
		t.Fatalf("expected embedded index.html to load external app script")
	}
	if !strings.Contains(html, `id="statusBanner"`) || !strings.Contains(html, `id="dashboardShell"`) {
		t.Fatalf("expected embedded index.html to preserve dashboard shell regions")
	}

	scriptContent, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}

	script := string(scriptContent)
	if !strings.Contains(script, `elements.refreshBtn.addEventListener("click", loadData)`) {
		t.Fatalf("expected manual refresh handler to remain available")
	}
	if !strings.Contains(script, `elements.range.addEventListener("change", () => {`) {
		t.Fatalf("expected range change handler to exist")
	}
	if !strings.Contains(script, "if (Number(elements.range.value) !== -1) updateCustomInputs()") {
		t.Fatalf("expected preset range change to keep custom inputs in sync")
	}
	if !strings.Contains(script, `elements.start.addEventListener("change", () => {`) {
		t.Fatalf("expected custom start time change handler to exist")
	}
	if !strings.Contains(script, `elements.end.addEventListener("change", () => {`) {
		t.Fatalf("expected custom end time change handler to exist")
	}
	if !strings.Contains(script, `elements.range.value = "-1"`) {
		t.Fatalf("expected manual datetime edits to switch range into custom mode")
	}
	if !strings.Contains(script, `elements.start.addEventListener("change", () => {`) || !strings.Contains(script, `loadData()`) {
		t.Fatalf("expected manual time edits to request fresh data")
	}
	if strings.Contains(script, "setInterval(loadData, 30000)") {
		t.Fatalf("expected periodic auto refresh to be removed")
	}
	if !strings.Contains(script, "await loadSettings()") {
		t.Fatalf("expected initial page boot to load saved mihomo settings before fetching data")
	}
	if !strings.Contains(script, "if (state.settingsRequired)") || !strings.Contains(script, "await loadData()") {
		t.Fatalf("expected initial page boot to gate data loading on saved mihomo settings")
	}
	if !strings.Contains(html, `id="settingsPanel"`) || !strings.Contains(html, `id="settingsBtn"`) {
		t.Fatalf("expected embedded index.html to include mihomo settings entry points")
	}
	for _, want := range []string{
		`id="autoSwitchBtn"`,
		`id="autoSwitchModal"`,
		`class="modal-shell hidden"`,
		`id="autoSwitchPanel"`,
		`class="panel auto-switch-panel modal-panel"`,
		`id="autoSwitchCancelBtn"`,
		`id="autoRestoreEnabled"`,
		`id="autoRestoreQuietMinutes"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected embedded index.html to contain %q", want)
		}
	}
	if !strings.Contains(script, `sendJSON("/api/settings/mihomo", "PUT", mihomoPayload)`) {
		t.Fatalf("expected embedded index.html to save mihomo settings through the settings API")
	}
	for _, want := range []string{
		`elements.autoSwitchBtn.addEventListener("click", openAutoSwitchPanel)`,
		`elements.autoSwitchCancelBtn.addEventListener("click", closeAutoSwitchPanel)`,
		`state.autoSwitchOpen = false`,
		`autoRestoreEnabled: document.getElementById("autoRestoreEnabled")`,
		`autoRestoreQuietMinutes: document.getElementById("autoRestoreQuietMinutes")`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected embedded app.js to contain %q", want)
		}
	}
	for _, label := range []string{"1 天", "7 天", "15 天", "30 天", "自定义"} {
		if !strings.Contains(html, label) {
			t.Fatalf("expected range option %q to exist", label)
		}
	}
	for _, label := range []string{"最近 1 小时", "最近 24 小时"} {
		if strings.Contains(html, label) {
			t.Fatalf("expected old range option %q to be removed", label)
		}
	}
}

func TestEmbeddedIndexIncludesDirectTrafficFilterToggle(t *testing.T) {
	content, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}
	html := string(content)

	scriptContent, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	script := string(scriptContent)

	for _, want := range []string{
		`id="filterDirectTraffic"`,
		"过滤 DIRECT 直连流量",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected embedded index.html to contain %q", want)
		}
	}

	for _, want := range []string{
		`filterDirectTraffic: document.getElementById("filterDirectTraffic")`,
		`elements.filterDirectTraffic.checked = Boolean(state.filterDirectTraffic)`,
		`fetchJSON("/api/settings/direct-traffic-filter")`,
		`sendJSON("/api/settings/direct-traffic-filter", "PUT", directFilterPayload)`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected embedded app.js to contain %q", want)
		}
	}
}

func TestEmbeddedIndexIncludesGithubAndLicenseFooter(t *testing.T) {
	content, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}

	html := string(content)
	for _, unwanted := range []string{
		`id="primaryHint"`,
		`id="secondaryHint"`,
		`id="detailHint"`,
		`class="panel-subtitle"`,
	} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("expected embedded index.html to remove verbose helper text marker %q", unwanted)
		}
	}

	for _, want := range []string{
		`id="runtimeSummary"`,
		`id="selectionPath"`,
		`id="overviewSection"`,
		`id="drilldownSection"`,
		`class="panel card card-count"`,
		`class="panel card card-upload"`,
		`class="panel card card-download"`,
		`class="panel card card-total"`,
		`id="secondaryTitle"`,
		`id="detailTitle"`,
		`href="https://github.com/zhf883680/clash-traffic-monitor"`,
		`>GitHub<`,
		`href="/LICENSE"`,
		`>MIT License<`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected embedded index.html to contain %q", want)
		}
	}
}

func TestEmbeddedSummaryModeMarkers(t *testing.T) {
	indexContent, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}
	html := string(indexContent)

	scriptContent, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	script := string(scriptContent)

	styleContent, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatalf("read embedded styles.css: %v", err)
	}
	styles := string(styleContent)

	for _, want := range []string{
		`class="mode-switch"`,
		`data-mode="summary"`,
		`id="secondaryChart"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected embedded index.html to contain %q", want)
		}
	}
	for _, want := range []string{
		"MODE_STORAGE_KEY",
		"function renderSecondaryChart(",
		"function renderPrimaryChart(",
		`const summary = state.mode === "summary" ? "1" : ""`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected embedded app.js to contain %q", want)
		}
	}
	// Detail/summary mode switches rewrite the range select; the start/end
	// pickers must be refreshed so they match the range actually queried.
	syncRangeOptions := extractJSFunction(script, "syncRangeOptions")
	if !strings.Contains(syncRangeOptions, "updateCustomInputs()") {
		t.Fatalf("expected syncRangeOptions() to refresh custom time inputs after changing the range")
	}
	if !strings.Contains(styles, "body.summary-mode") {
		t.Fatalf("expected embedded styles.css to include summary mode layout rules")
	}
}

func extractJSFunction(script, name string) string {
	start := strings.Index(script, "function "+name+"(")
	if start < 0 {
		return ""
	}
	next := strings.Index(script[start:], "\nfunction ")
	if next < 0 {
		return script[start:]
	}
	return script[start : start+next]
}

func TestEmbeddedTrendChartIncludesAxisAndTooltip(t *testing.T) {
	indexContent, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}

	html := string(indexContent)
	for _, unwanted := range []string{
		`class="trend-legend"`,
		`class="trend-legend-item total"`,
		`class="trend-legend-item upload"`,
		`class="trend-legend-item download"`,
	} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("expected embedded index.html to remove %q", unwanted)
		}
	}

	for _, want := range []string{
		`id="trendTooltip"`,
		`id="trendAxis"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected embedded index.html to contain %q", want)
		}
	}
	if strings.Contains(html, `class="trend-axis-caption"`) {
		t.Fatalf("expected embedded index.html to remove the trend axis caption")
	}

	scriptContent, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}

	script := string(scriptContent)
	for _, want := range []string{
		`trendTooltip: document.getElementById("trendTooltip")`,
		`trendAxis: document.getElementById("trendAxis")`,
		"function formatTrendAxisTick(",
		"function getTrendTickIndexes(",
		"function updateTrendAxisLabels(points) {",
		"function showTrendTooltip(event) {",
		"function hideTrendTooltip() {",
		"elements.trendAxis.innerHTML =",
		"updateTrendAxisLabels(points)",
		`elements.trendCanvas.addEventListener("mousemove", showTrendTooltip)`,
		`elements.trendCanvas.addEventListener("mouseleave", hideTrendTooltip)`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected embedded app.js to contain %q", want)
		}
	}

	styleContent, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatalf("read embedded styles.css: %v", err)
	}

	styles := string(styleContent)
	for _, want := range []string{
		".trend-chart-shell",
		"grid-template-rows: minmax(0, 1fr) auto;",
		".trend-tooltip",
		"position: fixed;",
		".trend-tooltip-time",
		".trend-tooltip-metric",
		".trend-axis",
		".trend-axis span",
	} {
		if !strings.Contains(styles, want) {
			t.Fatalf("expected embedded styles.css to contain %q", want)
		}
	}
}

func TestEmbeddedAppScriptIncludesContextualDashboardLabels(t *testing.T) {
	content, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}

	script := string(content)
	for _, want := range []string{
		"function syncContextSummary()",
		"const autoSwitchStatusLabels = {",
		`restored: "已恢复原节点"`,
		`restore_skipped: "恢复已取消"`,
		`restore_error: "恢复失败"`,
		`${primary} 访问的主机`,
		`${primary} 的访问设备`,
		`${primary} 命中的目标主机`,
		`selectionPath: document.getElementById("selectionPath")`,
		`secondaryTitle: document.getElementById("secondaryTitle")`,
		`detailTitle: document.getElementById("detailTitle")`,
		`elements.selectionPath.textContent =`,
		`elements.secondaryTitle.textContent =`,
		`elements.secondaryTitle.title =`,
		`elements.detailTitle.textContent =`,
		`elements.detailTitle.title =`,
		"function applyAutoSwitchDefaults()",
		"function applyAutoRestoreDefaults()",
		"currentThreshold === 500",
		`elements.autoSwitchThreshold.value = "100"`,
		`elements.autoSwitchCooldown.value = "10"`,
		`elements.autoRestoreQuietMinutes.value = "5"`,
		`elements.autoSwitchEnabled.addEventListener("change", () => {`,
		`elements.autoRestoreEnabled.addEventListener("change", () => {`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected embedded app.js to contain %q", want)
		}
	}
}

func TestEmbeddedStylesConstrainDashboardHeight(t *testing.T) {
	content, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatalf("read embedded styles.css: %v", err)
	}

	styles := string(content)
	for _, want := range []string{
		"--overview-panel-height:",
		"clamp(228px, 29vh, 244px);",
		"height: var(--overview-panel-height);",
		"grid-template-areas:",
		`"count total"`,
		`"upload download"`,
		".card-upload",
		"grid-area: upload;",
		".card-download",
		"grid-area: download;",
		".dashboard .panel-title",
		".secondary-panel .panel-head",
		"grid-template-columns: minmax(0, 1fr) auto;",
		"overflow-wrap: anywhere;",
		"-webkit-line-clamp: 2;",
		"width: 180px;",
		".ranking-title .mono",
		"flex: 1 1 auto;",
		".ranking-total",
		"flex: 0 0 auto;",
		".ranking-list",
		".detail-table-wrap",
		".detail-cards-shell",
		"overflow: auto",
	} {
		if !strings.Contains(styles, want) {
			t.Fatalf("expected embedded styles.css to contain %q", want)
		}
	}
}

func TestRoutesServeLicense(t *testing.T) {
	svc := newTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/LICENSE", nil)
	rec := httptest.NewRecorder()

	svc.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/plain") {
		t.Fatalf("expected text/plain content type, got %q", contentType)
	}
	for _, want := range []string{
		"MIT License",
		"Permission is hereby granted, free of charge",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("expected license response to contain %q", want)
		}
	}
}

func TestRoutesServeEmbeddedStaticAssets(t *testing.T) {
	svc := newTestService(t)

	tests := []struct {
		path        string
		contentType string
		bodyNeedle  string
	}{
		{path: "/styles.css", contentType: "text/css", bodyNeedle: ":root"},
		{path: "/app.js", contentType: "javascript", bodyNeedle: "loadSettings"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()

			svc.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
			}
			if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, tc.contentType) {
				t.Fatalf("expected %s content type for %s, got %q", tc.contentType, tc.path, contentType)
			}
			if !strings.Contains(rec.Body.String(), tc.bodyNeedle) {
				t.Fatalf("expected %s response to contain %q", tc.path, tc.bodyNeedle)
			}
		})
	}
}

func newTestService(t *testing.T) *service {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "traffic.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	return newTestServiceOnDB(db)
}

func newTestServiceOnDB(db *sql.DB) *service {
	return &service{
		db:                     db,
		now:                    time.Now,
		domainGroupingEnabled:  loadDomainGroupingEnabled(db),
		filterDirectTraffic:    loadFilterDirectTraffic(db),
		aggregateRetentionDays: loadRetentionDays(db),
		lastConnections:        make(map[string]connection),
		aggregateBuffer:        make(map[string]*aggregatedEntry),
		hostMinuteWindows:      make(map[string]*hostTrafficWindow),
	}
}

func testConnection(id string, chains []string, upload, download int64) connection {
	conn := connection{
		ID:       id,
		Upload:   upload,
		Download: download,
		Chains:   chains,
	}
	conn.Metadata.SourceIP = "192.168.1.2"
	conn.Metadata.Host = "example.com"
	conn.Metadata.DestinationIP = "1.1.1.1"
	conn.Metadata.Process = "chrome"
	return conn
}

func insertTestLogs(t *testing.T, db *sql.DB, logs []trafficLog) {
	t.Helper()

	for _, entry := range logs {
		chainsRaw, err := json.Marshal(entry.Chains)
		if err != nil {
			t.Fatalf("marshal chains: %v", err)
		}

		ruleGroup := entry.RuleGroup
		if ruleGroup == "" {
			ruleGroup = unknownRuleGroup
		}

		_, err = db.Exec(
			`INSERT INTO traffic_logs (timestamp, source_ip, host, destination_ip, process, outbound, chains, rule_group, upload, download)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.Timestamp,
			entry.SourceIP,
			entry.Host,
			entry.DestinationIP,
			entry.Process,
			entry.Outbound,
			string(chainsRaw),
			ruleGroup,
			entry.Upload,
			entry.Download,
		)
		if err != nil {
			t.Fatalf("insert log: %v", err)
		}
	}
}

func insertTestAggregates(t *testing.T, db *sql.DB, entries []aggregatedEntry) {
	t.Helper()

	for _, entry := range entries {
		ruleGroup := entry.RuleGroup
		if ruleGroup == "" {
			ruleGroup = unknownRuleGroup
		}

		_, err := db.Exec(
			`INSERT INTO traffic_aggregated
			 (bucket_start, bucket_end, source_ip, host, destination_ip, process, outbound, chains, rule_group, upload, download, count)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.BucketStart,
			entry.BucketEnd,
			entry.SourceIP,
			entry.Host,
			entry.DestinationIP,
			entry.Process,
			entry.Outbound,
			entry.Chains,
			ruleGroup,
			entry.Upload,
			entry.Download,
			entry.Count,
		)
		if err != nil {
			t.Fatalf("insert aggregate: %v", err)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestDomainGroupingEnabled(t *testing.T) {
	svc := newTestService(t)

	// Default: no row in DB → returns true
	if got := loadDomainGroupingEnabled(svc.db); !got {
		t.Fatal("expected default to be true")
	}

	// Save false, reload
	if err := saveDomainGroupingEnabled(svc.db, false); err != nil {
		t.Fatalf("saveDomainGroupingEnabled(false): %v", err)
	}
	if got := loadDomainGroupingEnabled(svc.db); got {
		t.Fatal("expected false after saving false")
	}

	// Save true, reload
	if err := saveDomainGroupingEnabled(svc.db, true); err != nil {
		t.Fatalf("saveDomainGroupingEnabled(true): %v", err)
	}
	if got := loadDomainGroupingEnabled(svc.db); !got {
		t.Fatal("expected true after saving true")
	}
}

func TestHandleDomainGroupingSettings(t *testing.T) {
	svc := newTestService(t)

	t.Run("GET returns default true", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/settings/domain-grouping", nil)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET status %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["enabled"] != true {
			t.Fatalf("expected enabled=true, got %v", resp["enabled"])
		}
	})

	t.Run("PUT sets false", func(t *testing.T) {
		body := bytes.NewBufferString(`{"enabled":false}`)
		req := httptest.NewRequest(http.MethodPut, "/api/settings/domain-grouping", body)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["enabled"] != false {
			t.Fatalf("expected enabled=false, got %v", resp["enabled"])
		}
		if svc.currentDomainGroupingEnabled() {
			t.Fatal("expected in-memory state to be false")
		}
	})

	t.Run("PUT sets true", func(t *testing.T) {
		body := bytes.NewBufferString(`{"enabled":true}`)
		req := httptest.NewRequest(http.MethodPut, "/api/settings/domain-grouping", body)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status %d: %s", rec.Code, rec.Body.String())
		}
		if !svc.currentDomainGroupingEnabled() {
			t.Fatal("expected in-memory state to be true")
		}
	})

	t.Run("PUT bad JSON returns 400", func(t *testing.T) {
		body := bytes.NewBufferString(`not-json`)
		req := httptest.NewRequest(http.MethodPut, "/api/settings/domain-grouping", body)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("DELETE returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/settings/domain-grouping", nil)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}
	})
}

func TestHandleDirectTrafficFilterSettings(t *testing.T) {
	svc := newTestService(t)

	t.Run("GET returns default false", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/settings/direct-traffic-filter", nil)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET status %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["enabled"] != false {
			t.Fatalf("expected enabled=false, got %v", resp["enabled"])
		}
	})

	t.Run("PUT sets true", func(t *testing.T) {
		body := bytes.NewBufferString(`{"enabled":true}`)
		req := httptest.NewRequest(http.MethodPut, "/api/settings/direct-traffic-filter", body)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["enabled"] != true {
			t.Fatalf("expected enabled=true, got %v", resp["enabled"])
		}
		if !svc.currentFilterDirectTraffic() {
			t.Fatal("expected in-memory state to be true")
		}
		if !loadFilterDirectTraffic(svc.db) {
			t.Fatal("expected the setting to be persisted")
		}
	})

	t.Run("PUT bad JSON returns 400", func(t *testing.T) {
		body := bytes.NewBufferString(`not-json`)
		req := httptest.NewRequest(http.MethodPut, "/api/settings/direct-traffic-filter", body)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("DELETE returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/settings/direct-traffic-filter", nil)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}
	})
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"r1---sn-abc.googlevideo.com", "googlevideo.com"},
		{"www.youtube.com", "youtube.com"},
		{"91.108.56.111", "91.108.56.111"},
		{"2001:db8::1", "2001:db8::1"},
		{"youtube.com", "youtube.com"},
		{"localhost", "localhost"},
		{"example.com:443", "example.com"},
		{"sub.sub.example.com", "example.com"},
	}
	for _, c := range cases {
		got := normalizeHost(c.input)
		if got != c.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestGroupHostRows(t *testing.T) {
	rows := []aggregatedData{
		{Label: "r1---sn-abc.googlevideo.com", Upload: 100, Download: 200, Total: 300, Count: 1},
		{Label: "r4---sn-xyz.googlevideo.com", Upload: 50, Download: 80, Total: 130, Count: 2},
		{Label: "www.youtube.com", Upload: 10, Download: 20, Total: 30, Count: 1},
		{Label: "91.108.56.111", Upload: 5, Download: 5, Total: 10, Count: 1},
	}
	got := groupHostRows(rows)

	byLabel := make(map[string]aggregatedData, len(got))
	for _, r := range got {
		byLabel[r.Label] = r
	}

	gv, ok := byLabel["googlevideo.com"]
	if !ok {
		t.Fatal("expected googlevideo.com in result")
	}
	if gv.Upload != 150 || gv.Download != 280 || gv.Total != 430 || gv.Count != 3 {
		t.Errorf("googlevideo.com unexpected: %+v", gv)
	}

	yt, ok := byLabel["youtube.com"]
	if !ok {
		t.Fatal("expected youtube.com in result")
	}
	if yt.Upload != 10 || yt.Download != 20 || yt.Total != 30 {
		t.Errorf("youtube.com unexpected: %+v", yt)
	}

	ip, ok := byLabel["91.108.56.111"]
	if !ok {
		t.Fatal("expected bare IP in result")
	}
	if ip.Total != 10 {
		t.Errorf("bare IP unexpected: %+v", ip)
	}

	if len(got) != 3 {
		t.Errorf("expected 3 rows after grouping, got %d", len(got))
	}
}

func TestQueryAggregateHostGrouping(t *testing.T) {
	t.Run("groups subdomains when enabled", func(t *testing.T) {
		svc := newTestService(t)
		insertTestAggregates(t, svc.db, []aggregatedEntry{
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r1---sn-abc.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r4---sn-xyz.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 80, Count: 2},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "www.youtube.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 10, Download: 20, Count: 1},
		})

		rows, err := svc.queryAggregate("host", 0, 60_000, false)
		if err != nil {
			t.Fatalf("queryAggregate: %v", err)
		}

		byLabel := make(map[string]aggregatedData)
		for _, r := range rows {
			byLabel[r.Label] = r
		}

		gv, ok := byLabel["googlevideo.com"]
		if !ok {
			t.Fatal("expected googlevideo.com grouped row")
		}
		if gv.Upload != 150 || gv.Download != 280 || gv.Count != 3 {
			t.Errorf("googlevideo.com unexpected: %+v", gv)
		}
		if _, raw := byLabel["r1---sn-abc.googlevideo.com"]; raw {
			t.Error("raw subdomain r1---sn-abc.googlevideo.com should not appear when grouping enabled")
		}
		if len(rows) != 2 {
			t.Errorf("expected 2 rows (googlevideo.com + youtube.com), got %d: %v", len(rows), rows)
		}
	})

	t.Run("returns raw hosts when grouping disabled", func(t *testing.T) {
		svc := newTestService(t)
		if err := svc.updateDomainGroupingEnabled(false); err != nil {
			t.Fatalf("updateDomainGroupingEnabled: %v", err)
		}
		insertTestAggregates(t, svc.db, []aggregatedEntry{
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r1---sn-abc.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r4---sn-xyz.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 80, Count: 2},
		})

		rows, err := svc.queryAggregate("host", 0, 60_000, false)
		if err != nil {
			t.Fatalf("queryAggregate: %v", err)
		}
		if len(rows) != 2 {
			t.Errorf("expected 2 raw rows when grouping disabled, got %d", len(rows))
		}
	})

	t.Run("non-host dimensions are not grouped", func(t *testing.T) {
		svc := newTestService(t)
		insertTestAggregates(t, svc.db, []aggregatedEntry{
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r1---sn-abc.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.3", Host: "r4---sn-xyz.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 80, Count: 1},
		})

		rows, err := svc.queryAggregate("sourceIP", 0, 60_000, false)
		if err != nil {
			t.Fatalf("queryAggregate: %v", err)
		}
		if len(rows) != 2 {
			t.Errorf("expected 2 rows for sourceIP dimension, got %d", len(rows))
		}
	})
}

func TestQueryAggregateRawPassthrough(t *testing.T) {
	svc := newTestService(t)
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r1---sn-abc.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r4---sn-xyz.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 80, Count: 2},
	})

	t.Run("raw=false groups subdomains", func(t *testing.T) {
		rows, err := svc.queryAggregate("host", 0, 60_000, false)
		if err != nil {
			t.Fatalf("queryAggregate: %v", err)
		}
		if len(rows) != 1 {
			t.Errorf("expected 1 grouped row, got %d: %v", len(rows), rows)
		}
		if rows[0].Label != "googlevideo.com" {
			t.Errorf("expected label googlevideo.com, got %s", rows[0].Label)
		}
	})

	t.Run("raw=true bypasses grouping", func(t *testing.T) {
		rows, err := svc.queryAggregate("host", 0, 60_000, true)
		if err != nil {
			t.Fatalf("queryAggregate: %v", err)
		}
		if len(rows) != 2 {
			t.Errorf("expected 2 raw rows, got %d: %v", len(rows), rows)
		}
		labels := make(map[string]bool)
		for _, r := range rows {
			labels[r.Label] = true
		}
		if !labels["r1---sn-abc.googlevideo.com"] || !labels["r4---sn-xyz.googlevideo.com"] {
			t.Errorf("expected raw subdomain labels, got %v", labels)
		}
	})
}

func TestQuerySubstatsHostGrouping(t *testing.T) {
	t.Run("returns raw subdomains for normalized host when grouping enabled", func(t *testing.T) {
		svc := newTestService(t)
		insertTestAggregates(t, svc.db, []aggregatedEntry{
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r1---sn-abc.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r4---sn-xyz.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 80, Count: 2},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "www.youtube.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 10, Download: 20, Count: 1},
		})

		rows, err := svc.querySubstats("host", "googlevideo.com", 0, 60_000)
		if err != nil {
			t.Fatalf("querySubstats: %v", err)
		}
		if len(rows) != 2 {
			t.Errorf("expected 2 subdomain rows, got %d: %v", len(rows), rows)
		}
		byLabel := make(map[string]aggregatedData)
		for _, r := range rows {
			byLabel[r.Label] = r
		}
		if _, ok := byLabel["r1---sn-abc.googlevideo.com"]; !ok {
			t.Error("expected r1---sn-abc.googlevideo.com in results")
		}
		if _, ok := byLabel["r4---sn-xyz.googlevideo.com"]; !ok {
			t.Error("expected r4---sn-xyz.googlevideo.com in results")
		}
		if _, ok := byLabel["www.youtube.com"]; ok {
			t.Error("www.youtube.com should not appear in googlevideo.com substats")
		}
	})

	t.Run("returns error when grouping disabled", func(t *testing.T) {
		svc := newTestService(t)
		if err := svc.updateDomainGroupingEnabled(false); err != nil {
			t.Fatalf("updateDomainGroupingEnabled: %v", err)
		}
		_, err := svc.querySubstats("host", "googlevideo.com", 0, 60_000)
		if err == nil {
			t.Fatal("expected error for host substats when grouping disabled")
		}
	})

	t.Run("exact match passes through for bare IP label", func(t *testing.T) {
		svc := newTestService(t)
		insertTestAggregates(t, svc.db, []aggregatedEntry{
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "192.0.2.1", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
			{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "example.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 10, Download: 20, Count: 1},
		})

		rows, err := svc.querySubstats("host", "192.0.2.1", 0, 60_000)
		if err != nil {
			t.Fatalf("querySubstats: %v", err)
		}
		if len(rows) != 1 {
			t.Errorf("expected 1 row for bare IP, got %d: %v", len(rows), rows)
		}
		if rows[0].Label != "192.0.2.1" {
			t.Errorf("expected label 192.0.2.1, got %s", rows[0].Label)
		}
	})
}

func TestConnectionDetailsSubdomainSecondary(t *testing.T) {
	svc := newTestService(t)
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r1---sn-abc.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 100, Download: 200, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.3", Host: "r1---sn-abc.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 50, Download: 80, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "r4---sn-xyz.googlevideo.com", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 10, Download: 20, Count: 1},
	})

	// secondary is a raw subdomain — should return all source IPs for that host
	details, err := svc.queryConnectionDetails("host", "googlevideo.com", "r1---sn-abc.googlevideo.com", 0, 60_000)
	if err != nil {
		t.Fatalf("queryConnectionDetails: %v", err)
	}
	if len(details) != 2 {
		t.Errorf("expected 2 detail rows (one per source IP), got %d: %v", len(details), details)
	}
	sourceIPs := make(map[string]bool)
	for _, d := range details {
		sourceIPs[d.SourceIP] = true
	}
	if !sourceIPs["192.168.1.2"] || !sourceIPs["192.168.1.3"] {
		t.Errorf("expected both source IPs, got %v", sourceIPs)
	}

	// secondary is a source IP — existing behaviour unchanged
	details, err = svc.queryConnectionDetails("host", "googlevideo.com", "192.168.1.2", 0, 60_000)
	if err != nil {
		t.Fatalf("queryConnectionDetails (IP secondary): %v", err)
	}
	if len(details) == 0 {
		t.Error("expected results for source IP secondary")
	}
	for _, d := range details {
		if d.SourceIP != "192.168.1.2" {
			t.Errorf("expected only source IP 192.168.1.2, got %s", d.SourceIP)
		}
	}

	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.9", Host: "64.233.170.91", DestinationIP: "64.233.170.91", Process: "chrome", Outbound: "NodeA", Chains: `["NodeA"]`, Upload: 300, Download: 700, Count: 1},
	})

	details, err = svc.queryConnectionDetails("host", "64.233.170.91", "64.233.170.91", 0, 60_000)
	if err != nil {
		t.Fatalf("queryConnectionDetails (grouped IP host): %v", err)
	}
	if len(details) != 1 {
		t.Fatalf("expected 1 detail row for grouped IP host, got %d: %v", len(details), details)
	}
	if details[0].SourceIP != "192.168.1.9" || details[0].DestinationIP != "64.233.170.91" {
		t.Fatalf("unexpected grouped IP host detail row: %+v", details[0])
	}
}

func TestRuleGroupLabel(t *testing.T) {
	cases := []struct {
		name    string
		rule    string
		payload string
		want    string
	}{
		{name: "empty rule", want: "unknown"},
		{name: "real match rule shown", rule: "MATCH", payload: "", want: "match"},
		{name: "match rule no payload", rule: "MATCH", want: "match"},
		{name: "geosite", rule: "GeoSite", payload: "telegram", want: "geosite:telegram"},
		{name: "geoip keeps payload case", rule: "GeoIP", payload: "CN", want: "geoip:CN"},
		{name: "domain suffix", rule: "DOMAIN-SUFFIX", payload: "telegram.org", want: "domain-suffix:telegram.org"},
		{name: "rule type only", rule: "MATCH", payload: " ", want: "match"},
		{name: "whitespace trimmed", rule: "  GeoSite  ", payload: "  telegram  ", want: "geosite:telegram"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ruleGroupLabel(tc.rule, tc.payload); got != tc.want {
				t.Fatalf("ruleGroupLabel(%q, %q) = %q, want %q", tc.rule, tc.payload, got, tc.want)
			}
		})
	}
}

func TestProcessConnectionsCapturesRuleGroup(t *testing.T) {
	svc := newTestService(t)

	payload := &connectionsResponse{
		Connections: []connection{
			{
				ID:          "conn-tg",
				Upload:      128,
				Download:    256,
				Chains:      []string{"ProxyA"},
				Rule:        "GeoSite",
				RulePayload: "telegram",
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{
					SourceIP:      "192.168.1.8",
					Host:          "91.108.56.108",
					DestinationIP: "91.108.56.108",
					Process:       "Telegram",
				},
			},
			{
				ID:          "conn-ip",
				Upload:      10,
				Download:    20,
				Chains:      []string{"DIRECT"},
				Rule:        "GeoIP",
				RulePayload: "CN",
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{
					SourceIP:      "192.168.1.8",
					Host:          "223.5.5.5",
					DestinationIP: "223.5.5.5",
					Process:       "curl",
				},
			},
			{
				ID:       "conn-plain",
				Upload:   5,
				Download: 5,
				Chains:   []string{"DIRECT"},
				Metadata: struct {
					SourceIP      string "json:\"sourceIP\""
					Host          string "json:\"host\""
					DestinationIP string "json:\"destinationIP\""
					Process       string "json:\"process\""
				}{
					SourceIP: "192.168.1.8",
					Host:     "localhost.localdomain",
				},
			},
		},
	}

	if err := svc.processConnections(context.Background(), payload); err != nil {
		t.Fatalf("processConnections: %v", err)
	}

	want := map[string]int64{
		"geosite:telegram": 1,
		"geoip:CN":         1,
		unknownRuleGroup:   1,
	}
	got := make(map[string]int64)
	for _, entry := range svc.aggregateBuffer {
		got[entry.RuleGroup]++
	}
	if len(got) != len(want) {
		t.Fatalf("expected rule groups %v, got %v", want, got)
	}
	for rule, count := range want {
		if got[rule] != count {
			t.Errorf("rule group %q: expected %d entries, got %d", rule, count, got[rule])
		}
	}
}

func TestQueryAggregateRuleDimension(t *testing.T) {
	svc := newTestService(t)
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "91.108.56.108", DestinationIP: "91.108.56.108", Outbound: "NodeA", Chains: `["NodeA"]`, RuleGroup: "geosite:telegram", Upload: 100, Download: 200, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "t.me", Outbound: "NodeA", Chains: `["NodeA"]`, RuleGroup: "geosite:telegram", Upload: 50, Download: 80, Count: 2},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "223.5.5.5", Outbound: "DIRECT", Chains: `["DIRECT"]`, RuleGroup: "geoip:CN", Upload: 10, Download: 20, Count: 1},
	})
	svc.aggregateBuffer["pending"] = &aggregatedEntry{
		BucketStart: 60_000, BucketEnd: 120_000, SourceIP: "192.168.1.2", Host: "example.com", Outbound: "NodeA", Chains: `["NodeA"]`, RuleGroup: "geosite:telegram", Upload: 7, Download: 9, Count: 1,
	}

	rows, err := svc.queryAggregate("rule", 0, 120_000, false)
	if err != nil {
		t.Fatalf("queryAggregate(rule): %v", err)
	}

	byLabel := make(map[string]aggregatedData)
	for _, r := range rows {
		byLabel[r.Label] = r
	}

	tg, ok := byLabel["geosite:telegram"]
	if !ok {
		t.Fatalf("expected geosite:telegram row, got %v", rows)
	}
	if tg.Upload != 157 || tg.Download != 289 || tg.Total != 446 || tg.Count != 4 {
		t.Errorf("geosite:telegram unexpected totals: %+v", tg)
	}

	cn, ok := byLabel["geoip:CN"]
	if !ok {
		t.Fatalf("expected geoip:CN row, got %v", rows)
	}
	if cn.Upload != 10 || cn.Download != 20 {
		t.Errorf("geoip:CN unexpected totals: %+v", cn)
	}

	if len(rows) != 2 {
		t.Errorf("expected 2 rule rows, got %d: %v", len(rows), rows)
	}

	// Secondary drilldown: hosts matching one rule group.
	hosts, err := svc.querySubstats("rule", "geosite:telegram", 0, 120_000)
	if err != nil {
		t.Fatalf("querySubstats(rule): %v", err)
	}
	hostLabels := make(map[string]bool)
	for _, h := range hosts {
		hostLabels[h.Label] = true
	}
	if !hostLabels["91.108.56.108"] || !hostLabels["t.me"] || !hostLabels["example.com"] {
		t.Errorf("expected telegram hosts, got %v", hostLabels)
	}

	// Detail drilldown: one host under one rule group.
	details, err := svc.queryConnectionDetails("rule", "geosite:telegram", "91.108.56.108", 0, 120_000)
	if err != nil {
		t.Fatalf("queryConnectionDetails(rule): %v", err)
	}
	if len(details) != 1 || details[0].DestinationIP != "91.108.56.108" {
		t.Errorf("unexpected rule detail rows: %+v", details)
	}
}

func TestQuerySummaryRuleDimension(t *testing.T) {
	svc := newTestService(t)

	day := int64(24 * time.Hour / time.Millisecond)
	now := time.Date(2026, 8, 6, 15, 0, 0, 0, time.Local).UnixMilli()
	dayStart := (now / day) * day
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{
			BucketStart: dayStart - day,
			BucketEnd:   dayStart - day + 60000,
			SourceIP:    "192.168.1.8",
			Host:        "91.108.56.108",
			Outbound:    "ProxyA",
			Chains:      `["ProxyA"]`,
			RuleGroup:   "geosite:telegram",
			Upload:      15,
			Download:    25,
			Count:       1,
		},
	})
	if err := backfillSummary(svc.db, now); err != nil {
		t.Fatalf("backfillSummary: %v", err)
	}

	start := dayStart - day
	end := dayStart - 1

	rows, err := svc.querySummaryAggregate("rule", start, end, false)
	if err != nil {
		t.Fatalf("querySummaryAggregate(rule): %v", err)
	}
	if len(rows) != 1 || rows[0].Label != "geosite:telegram" || rows[0].Upload != 15 || rows[0].Download != 25 {
		t.Fatalf("unexpected rule summary: %+v", rows)
	}

	hosts, err := svc.querySummarySecondary("rule", "geosite:telegram", start, end)
	if err != nil {
		t.Fatalf("querySummarySecondary(rule): %v", err)
	}
	if len(hosts) != 1 || hosts[0].Label != "91.108.56.108" {
		t.Fatalf("unexpected rule secondary summary: %+v", hosts)
	}
}

func TestOpenDatabaseUpgradesLegacySchemaWithoutRuleGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE traffic_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			source_ip TEXT NOT NULL,
			host TEXT NOT NULL,
			destination_ip TEXT NOT NULL DEFAULT '',
			process TEXT NOT NULL,
			outbound TEXT NOT NULL,
			chains TEXT NOT NULL DEFAULT '[]',
			upload INTEGER NOT NULL,
			download INTEGER NOT NULL
		);
		CREATE TABLE traffic_aggregated (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			bucket_start INTEGER NOT NULL,
			bucket_end INTEGER NOT NULL,
			source_ip TEXT NOT NULL,
			host TEXT NOT NULL,
			destination_ip TEXT NOT NULL DEFAULT '',
			process TEXT NOT NULL,
			outbound TEXT NOT NULL,
			chains TEXT NOT NULL DEFAULT '[]',
			upload INTEGER NOT NULL,
			download INTEGER NOT NULL,
			count INTEGER NOT NULL,
			UNIQUE(bucket_start, bucket_end, source_ip, host, destination_ip, process, outbound, chains)
		);
	`)
	if err != nil {
		db.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	opened, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase on legacy db: %v", err)
	}
	defer opened.Close()

	for _, table := range []string{"traffic_logs", "traffic_aggregated"} {
		var count int
		if err := opened.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('` + table + `') WHERE name = 'rule_group'`).Scan(&count); err != nil {
			t.Fatalf("check rule_group in %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("expected rule_group column in %s after upgrade, got %d", table, count)
		}
	}
}

func TestOpenDatabaseDropsLegacyTrafficLogsPerColumnIndexes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE traffic_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			source_ip TEXT NOT NULL,
			host TEXT NOT NULL,
			destination_ip TEXT NOT NULL DEFAULT '',
			process TEXT NOT NULL,
			outbound TEXT NOT NULL,
			chains TEXT NOT NULL DEFAULT '[]',
			rule_group TEXT NOT NULL DEFAULT 'unknown',
			upload INTEGER NOT NULL,
			download INTEGER NOT NULL
		);
		CREATE INDEX idx_traffic_logs_timestamp ON traffic_logs(timestamp);
		CREATE INDEX idx_traffic_logs_source_ip ON traffic_logs(source_ip);
		CREATE INDEX idx_traffic_logs_host ON traffic_logs(host);
		CREATE INDEX idx_traffic_logs_process ON traffic_logs(process);
		CREATE INDEX idx_traffic_logs_outbound ON traffic_logs(outbound);
		CREATE INDEX idx_traffic_logs_rule_group ON traffic_logs(rule_group);
	`)
	if err != nil {
		db.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	opened, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase on legacy db: %v", err)
	}
	defer opened.Close()

	rows, err := opened.Query(`PRAGMA index_list(traffic_logs)`)
	if err != nil {
		t.Fatalf("index_list: %v", err)
	}
	defer rows.Close()

	indexes := map[string]bool{}
	for rows.Next() {
		var (
			seq     int
			name    string
			unique  int
			origin  string
			partial int
		)
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index_list: %v", err)
		}
		indexes[name] = true
	}

	for _, dropped := range []string{
		"idx_traffic_logs_source_ip",
		"idx_traffic_logs_host",
		"idx_traffic_logs_process",
		"idx_traffic_logs_outbound",
		"idx_traffic_logs_rule_group",
	} {
		if indexes[dropped] {
			t.Errorf("expected legacy index %q to be dropped", dropped)
		}
	}
	if !indexes["idx_traffic_logs_timestamp"] {
		t.Errorf("expected idx_traffic_logs_timestamp to be kept")
	}
}

func TestRuleDimensionHidesUnknownButShowsMatch(t *testing.T) {
	svc := newTestService(t)
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "91.108.56.108", Outbound: "NodeA", Chains: `["NodeA"]`, RuleGroup: "geosite:telegram", Upload: 100, Download: 200, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "catchall.example.com", Outbound: "NodeB", Chains: `["NodeB"]`, RuleGroup: "match", Upload: 50, Download: 60, Count: 1},
		{BucketStart: 0, BucketEnd: 60_000, SourceIP: "192.168.1.2", Host: "old.example.com", Outbound: "DIRECT", Chains: `["DIRECT"]`, RuleGroup: "unknown", Upload: 500, Download: 700, Count: 1},
	})

	// Detail mode: legacy "unknown" is hidden; real catch-all "match" stays.
	rows, err := svc.queryAggregate("rule", 0, 60_000, false)
	if err != nil {
		t.Fatalf("queryAggregate(rule): %v", err)
	}
	byLabel := make(map[string]aggregatedData)
	for _, r := range rows {
		byLabel[r.Label] = r
	}
	if len(rows) != 2 {
		t.Fatalf("expected geosite:telegram + match, got %+v", rows)
	}
	if _, ok := byLabel[unknownRuleGroup]; ok {
		t.Fatalf("legacy unknown group should be hidden, got %+v", rows)
	}
	if m, ok := byLabel["match"]; !ok || m.Upload != 50 {
		t.Fatalf("real match group should be shown, got %+v", rows)
	}

	// Summary mode: same behavior after backfill.
	day := int64(24 * time.Hour / time.Millisecond)
	now := time.Date(2026, 8, 6, 15, 0, 0, 0, time.Local).UnixMilli()
	dayStart := (now / day) * day
	insertTestAggregates(t, svc.db, []aggregatedEntry{
		{BucketStart: dayStart - day, BucketEnd: dayStart - day + 60000, SourceIP: "192.168.1.2", Host: "new.example.com", Outbound: "NodeA", Chains: `["NodeA"]`, RuleGroup: "geoip:CN", Upload: 10, Download: 20, Count: 1},
		{BucketStart: dayStart - day, BucketEnd: dayStart - day + 60000, SourceIP: "192.168.1.2", Host: "catchall2.example.com", Outbound: "NodeB", Chains: `["NodeB"]`, RuleGroup: "match", Upload: 7, Download: 8, Count: 1},
		{BucketStart: dayStart - day, BucketEnd: dayStart - day + 60000, SourceIP: "192.168.1.2", Host: "old2.example.com", Outbound: "DIRECT", Chains: `["DIRECT"]`, RuleGroup: "unknown", Upload: 99, Download: 99, Count: 1},
	})
	if err := backfillSummary(svc.db, now); err != nil {
		t.Fatalf("backfillSummary: %v", err)
	}
	summaryRows, err := svc.querySummaryAggregate("rule", dayStart-day, dayStart-1, false)
	if err != nil {
		t.Fatalf("querySummaryAggregate(rule): %v", err)
	}
	summaryByLabel := make(map[string]aggregatedData)
	for _, r := range summaryRows {
		summaryByLabel[r.Label] = r
	}
	if len(summaryRows) != 2 {
		t.Fatalf("expected geoip:CN + match in summary, got %+v", summaryRows)
	}
	if _, ok := summaryByLabel[unknownRuleGroup]; ok {
		t.Fatalf("legacy unknown group should be hidden in summary, got %+v", summaryRows)
	}
	if m, ok := summaryByLabel["match"]; !ok || m.Upload != 7 {
		t.Fatalf("real match group should be shown in summary, got %+v", summaryRows)
	}
}

func TestLegacyMatchRowsRelabeledOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upgrade.db")

	// Simulate a database already migrated by the first rule_group build:
	// openDatabase creates the full schema, then we force user_version back to
	// 0 and insert rows labelled "match" (the old default for legacy data).
	opened, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if _, err := opened.Exec(`PRAGMA user_version = 0`); err != nil {
		opened.Close()
		t.Fatalf("reset user_version: %v", err)
	}
	if _, err := opened.Exec(`
		INSERT INTO traffic_aggregated (bucket_start, bucket_end, source_ip, host, destination_ip, process, outbound, chains, rule_group, upload, download, count)
		VALUES (0, 60000, '192.168.1.2', 'old.example.com', '', 'curl', 'DIRECT', '["DIRECT"]', 'match', 10, 20, 1);
		INSERT INTO traffic_logs (timestamp, source_ip, host, destination_ip, process, outbound, chains, rule_group, upload, download)
		VALUES (1000, '192.168.1.2', 'old.example.com', '', 'curl', 'DIRECT', '["DIRECT"]', 'match', 10, 20);
		INSERT INTO traffic_summary (bucket_start, bucket_end, dimension, label, secondary_label, upload, download, count)
		VALUES (0, 60000, 'rule', 'match', 'old.example.com', 10, 20, 1);
	`); err != nil {
		opened.Close()
		t.Fatalf("insert legacy match rows: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	// Reopen: the one-time re-label should convert legacy "match" rows to
	// "unknown" (hidden) and bump user_version so a real MATCH rule is never
	// relabelled on subsequent starts.
	reopened, err := openDatabase(path)
	if err != nil {
		t.Fatalf("reopenDatabase: %v", err)
	}
	defer reopened.Close()

	var version int
	if err := reopened.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected user_version 1 after migration, got %d", version)
	}

	for _, stmt := range []string{
		`SELECT COUNT(*) FROM traffic_aggregated WHERE rule_group = 'match'`,
		`SELECT COUNT(*) FROM traffic_logs WHERE rule_group = 'match'`,
		`SELECT COUNT(*) FROM traffic_summary WHERE dimension = 'rule' AND label = 'match'`,
	} {
		var count int
		if err := reopened.QueryRow(stmt).Scan(&count); err != nil {
			t.Fatalf("count match rows: %v", err)
		}
		if count != 0 {
			t.Errorf("expected no 'match' rows left, got %d for %q", count, stmt)
		}
	}

	var unknown int
	if err := reopened.QueryRow(`SELECT COUNT(*) FROM traffic_aggregated WHERE rule_group = 'unknown'`).Scan(&unknown); err != nil {
		t.Fatalf("count unknown rows: %v", err)
	}
	if unknown != 1 {
		t.Errorf("expected 1 unknown aggregate row after relabel, got %d", unknown)
	}
}

func TestApplicationServesAndShutsDownIdempotently(t *testing.T) {
	app, err := newApplication(config{ListenAddr: "127.0.0.1:0"}, filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("newApplication: %v", err)
	}

	app.start()

	resp, err := http.Get(fmt.Sprintf("http://%s/health", app.listener.Addr()))
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ok") {
		t.Fatalf("unexpected health response: %d %s", resp.StatusCode, body)
	}

	if err := app.shutdown(); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := app.shutdown(); err != nil {
		t.Fatalf("second shutdown must be idempotent: %v", err)
	}

	if _, err := http.Get(fmt.Sprintf("http://%s/health", app.listener.Addr())); err == nil {
		t.Fatal("expected server to refuse connections after shutdown")
	}
}

func TestApplicationPortConflictFailsSynchronously(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blocker listen: %v", err)
	}
	defer blocker.Close()

	app, err := newApplication(config{ListenAddr: blocker.Addr().String()}, filepath.Join(t.TempDir(), "traffic.db"))
	if err == nil {
		app.shutdown()
		t.Fatal("expected newApplication to fail while the port is occupied")
	}
	if app != nil {
		t.Fatal("expected nil application on listen failure")
	}
}

func TestApplicationServerErrorReachesErrorsChannel(t *testing.T) {
	app, err := newApplication(config{ListenAddr: "127.0.0.1:0"}, filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("newApplication: %v", err)
	}

	app.start()
	if err := app.listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	select {
	case err := <-app.errors():
		if err == nil {
			t.Fatal("expected non-nil server error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server error")
	}

	if err := app.shutdown(); err != nil {
		t.Fatalf("shutdown after server error: %v", err)
	}
}

func TestApplicationShutdownSkipsFlushWhenCollectorStuck(t *testing.T) {
	svc := newTestService(t)

	previousTimeout := collectorShutdownTimeout
	collectorShutdownTimeout = 200 * time.Millisecond
	t.Cleanup(func() { collectorShutdownTimeout = previousTimeout })

	bucketStart := (time.Now().UnixMilli() / 60000) * 60000
	svc.aggregateBuffer["stuck"] = &aggregatedEntry{
		BucketStart: bucketStart,
		BucketEnd:   bucketStart + 60000,
		SourceIP:    "192.168.1.2",
		Host:        "stuck.example",
		Process:     "chrome",
		Outbound:    "DIRECT",
		Chains:      `["DIRECT"]`,
		RuleGroup:   unknownRuleGroup,
		Upload:      10,
		Download:    5,
		Count:       1,
	}

	app := &application{
		cfg:           config{ListenAddr: "127.0.0.1:0"},
		db:            svc.db,
		svc:           svc,
		server:        &http.Server{Handler: svc.routes(), ReadHeaderTimeout: 5 * time.Second},
		ctx:           context.Background(),
		cancel:        func() {},
		collectorDone: make(chan struct{}),
		serverErr:     make(chan error, 1),
	}

	err := app.shutdown()
	if err == nil {
		t.Fatal("expected shutdown error while the collector is stuck")
	}
	if !strings.Contains(err.Error(), "skipping final flush") {
		t.Fatalf("expected skip-final-flush error, got %v", err)
	}

	var flushed int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM traffic_aggregated`).Scan(&flushed); err != nil {
		t.Fatalf("query aggregated after skipped flush: %v", err)
	}
	if flushed != 0 {
		t.Fatalf("expected no aggregates flushed during timed-out shutdown, got %d", flushed)
	}
}

func TestExecuteAutoSwitchRespectsContextCancellation(t *testing.T) {
	svc := newTestService(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer ts.Close()

	svc.setMihomoSettings(mihomoSettings{URL: ts.URL})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	target := autoSwitchGroupTarget{GroupName: "G", TargetProxy: "P", Enabled: true}
	_, err := svc.executeAutoSwitch(ctx, autoSwitchSettings{Enabled: true, GroupTargets: []autoSwitchGroupTarget{target}}, target, time.Now().UnixMilli(), "example.com", 100)
	if err == nil {
		t.Fatal("expected context cancellation error from blocked auto switch request")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
