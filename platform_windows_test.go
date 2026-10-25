//go:build windows

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func overrideExecutable(t *testing.T, exePath string) {
	t.Helper()
	previous := osExecutable
	osExecutable = func() (string, error) { return exePath, nil }
	t.Cleanup(func() { osExecutable = previous })
}

func overrideExecutableError(t *testing.T) {
	t.Helper()
	previous := osExecutable
	osExecutable = func() (string, error) { return "", errors.New("injected executable failure") }
	t.Cleanup(func() { osExecutable = previous })
}

func createLegacySQLiteDatabase(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create legacy directory: %v", err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO items (value) VALUES ('legacy-row')`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
}

func openSQLiteDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func countItemsRows(t *testing.T, path string, wantValue string) int {
	t.Helper()
	db := openSQLiteDatabase(t, path)
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM items WHERE value = ?`, wantValue).Scan(&count); err != nil {
		t.Fatalf("count rows in %s: %v", path, err)
	}
	return count
}

func TestWindowsDataDirAnchorsToExecutable(t *testing.T) {
	exeDir := t.TempDir()
	overrideExecutable(t, filepath.Join(exeDir, "sub", "traffic-monitor.exe"))

	got, err := windowsDataDir()
	if err != nil {
		t.Fatalf("windowsDataDir: %v", err)
	}
	want := filepath.Join(exeDir, "sub", "data")
	if got != want {
		t.Fatalf("expected data dir %q, got %q", want, got)
	}
}

func TestWindowsDataDirFailsWithoutExecutable(t *testing.T) {
	overrideExecutableError(t)
	if _, err := windowsDataDir(); err == nil {
		t.Fatal("expected error when the executable path cannot be resolved")
	}
}

func TestWindowsDatabasePathPrefersExistingCanonical(t *testing.T) {
	root := t.TempDir()
	overrideExecutable(t, filepath.Join(root, "app", "traffic-monitor.exe"))
	chdirForTest(t, root)

	canonicalDir := filepath.Join(root, "app", "data")
	if err := os.MkdirAll(canonicalDir, 0o755); err != nil {
		t.Fatalf("create canonical dir: %v", err)
	}
	canonical := filepath.Join(canonicalDir, windowsDatabaseName)
	createLegacySQLiteDatabase(t, canonical)

	legacyPath := filepath.Join(root, "data", windowsDatabaseName)
	createLegacySQLiteDatabase(t, legacyPath)
	legacyInfo, err := os.Stat(legacyPath)
	if err != nil {
		t.Fatalf("stat legacy: %v", err)
	}

	got, err := windowsDatabasePath()
	if err != nil {
		t.Fatalf("windowsDatabasePath: %v", err)
	}
	if got != canonical {
		t.Fatalf("expected canonical path %q, got %q", canonical, got)
	}
	if _, err := os.Stat(filepath.Join(root, "app", "data", windowsDatabaseName+windowsMigratingSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no migrating temp file, got %v", err)
	}
	stillThere, err := os.Stat(legacyPath)
	if err != nil || !stillThere.ModTime().Equal(legacyInfo.ModTime()) {
		t.Fatalf("legacy database must remain untouched: %v", err)
	}
}

func TestWindowsDatabasePathMigratesLegacyDatabase(t *testing.T) {
	root := t.TempDir()
	overrideExecutable(t, filepath.Join(root, "app", "traffic-monitor.exe"))
	chdirForTest(t, root)

	legacyPath := filepath.Join(root, "data", windowsDatabaseName)
	createLegacySQLiteDatabase(t, legacyPath)

	got, err := windowsDatabasePath()
	if err != nil {
		t.Fatalf("windowsDatabasePath: %v", err)
	}
	canonical := filepath.Join(root, "app", "data", windowsDatabaseName)
	if got != canonical {
		t.Fatalf("expected canonical path %q, got %q", canonical, got)
	}
	if countItemsRows(t, canonical, "legacy-row") != 1 {
		t.Fatal("migrated database must contain the legacy rows")
	}
	if countItemsRows(t, legacyPath, "legacy-row") != 1 {
		t.Fatal("legacy database must be preserved as backup")
	}
	if _, err := os.Stat(canonical + windowsMigratingSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected migrating temp file to be gone, got %v", err)
	}
}

func TestWindowsDatabasePathWithoutAnyDatabase(t *testing.T) {
	root := t.TempDir()
	overrideExecutable(t, filepath.Join(root, "app", "traffic-monitor.exe"))
	chdirForTest(t, root)

	got, err := windowsDatabasePath()
	if err != nil {
		t.Fatalf("windowsDatabasePath: %v", err)
	}
	canonical := filepath.Join(root, "app", "data", windowsDatabaseName)
	if got != canonical {
		t.Fatalf("expected canonical path %q, got %q", canonical, got)
	}
	if _, err := os.Stat(canonical); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolver must not create the database, got %v", err)
	}
}

func TestWindowsDatabasePathExecutableFailure(t *testing.T) {
	overrideExecutableError(t)
	if _, err := windowsDatabasePath(); err == nil {
		t.Fatal("expected error when executable cannot be resolved")
	}
}

func TestMigrateLegacyWindowsDatabaseKeepsUncheckpointedWAL(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "legacy.db")
	dst := filepath.Join(root, "canonical", windowsDatabaseName)

	srcDB := openSQLiteDatabase(t, src)
	if _, err := srcDB.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatalf("enable WAL: %v", err)
	}
	if _, err := srcDB.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := srcDB.Exec(`INSERT INTO items (value) VALUES ('wal-row')`); err != nil {
		t.Fatalf("insert row: %v", err)
	}
	// srcDB stays open: the committed row lives in the -wal file only.

	if err := migrateLegacyWindowsDatabase(src, dst); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if countItemsRows(t, dst, "wal-row") != 1 {
		t.Fatal("migrated database must include uncheckpointed WAL content")
	}
	var stillThere int
	if err := srcDB.QueryRow(`SELECT COUNT(*) FROM items`).Scan(&stillThere); err != nil || stillThere != 1 {
		t.Fatalf("source database must remain readable: %v (rows=%d)", err, stillThere)
	}
}

func TestMigrateLegacyWindowsDatabaseWithConcurrentWriter(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "legacy.db")
	dst := filepath.Join(root, "canonical", windowsDatabaseName)

	srcDB := openSQLiteDatabase(t, src)
	if _, err := srcDB.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := srcDB.Exec(`INSERT INTO items (value) VALUES ('first')`); err != nil {
		t.Fatalf("insert first row: %v", err)
	}

	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := srcDB.Exec(fmt.Sprintf(`INSERT INTO items (value) VALUES ('writer-%d')`, i)); err != nil {
				t.Logf("background writer stopped: %v", err)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	err := migrateLegacyWindowsDatabase(src, dst)
	close(stop)
	<-writerDone
	if err != nil {
		t.Fatalf("migrate with concurrent writer: %v", err)
	}
	if countItemsRows(t, dst, "first") != 1 {
		t.Fatal("migrated database must contain data committed before the backup")
	}
}

func TestMigrateLegacyWindowsDatabaseBusyTimesOutWithoutCreatingTarget(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "legacy.db")
	dst := filepath.Join(root, "canonical", windowsDatabaseName)

	srcDB := openSQLiteDatabase(t, src)
	if _, err := srcDB.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := srcDB.Exec(`INSERT INTO items (value) VALUES ('locked')`); err != nil {
		t.Fatalf("insert row: %v", err)
	}

	// Hold an exclusive lock on a dedicated connection for the whole attempt.
	lockConn, err := srcDB.Conn(context.Background())
	if err != nil {
		t.Fatalf("acquire lock connection: %v", err)
	}
	if _, err := lockConn.ExecContext(context.Background(), `BEGIN EXCLUSIVE`); err != nil {
		lockConn.Close()
		t.Fatalf("acquire exclusive lock: %v", err)
	}
	defer func() {
		_, _ = lockConn.ExecContext(context.Background(), `ROLLBACK`)
		_ = lockConn.Close()
	}()

	previousTimeout := databaseBackupTimeout
	databaseBackupTimeout = 400 * time.Millisecond
	t.Cleanup(func() { databaseBackupTimeout = previousTimeout })

	if err := migrateLegacyWindowsDatabase(src, dst); err == nil {
		t.Fatal("expected migration to fail while the source stays locked")
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target database must not be created on failure, got %v", err)
	}
	if _, err := os.Stat(dst + windowsMigratingSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("migrating temp file must be cleaned up, got %v", err)
	}
}

func TestRotatingLogWriterAppendsWithoutRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-monitor.log")
	w, err := newRotatingLogWriter(path)
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}

	if _, err := w.Write([]byte("line-one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := w.Write([]byte("line-two\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(content) != "line-one\nline-two\n" {
		t.Fatalf("unexpected log content: %q", content)
	}
	if _, err := os.Stat(path + rotatingLogBackupSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no backup expected below the size limit, got %v", err)
	}
}

func TestRotatingLogWriterRotatesAcrossThreshold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-monitor.log")
	w, err := newRotatingLogWriter(path)
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}

	// First write lands just below the limit; the second crosses it and must
	// move the first chunk to .1 before being written to the fresh file.
	oldContent := strings.Repeat("a", rotatingLogMaxSize-4) + "\n"
	if _, err := w.Write([]byte(oldContent)); err != nil {
		t.Fatalf("write old content: %v", err)
	}
	if _, err := w.Write([]byte("fresh\n")); err != nil {
		t.Fatalf("write fresh content: %v", err)
	}
	w.Close()

	backup, err := os.ReadFile(path + rotatingLogBackupSuffix)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != oldContent {
		t.Fatalf("backup must contain the rotated content (%d bytes), got %d bytes", len(oldContent), len(backup))
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(current) != "fresh\n" {
		t.Fatalf("current must only contain the fresh content, got %q", current)
	}
}

func TestRotatingLogWriterWritesOversizedMessageFully(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-monitor.log")
	w, err := newRotatingLogWriter(path)
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}

	huge := strings.Repeat("z", rotatingLogMaxSize+1024) + "\n"
	if _, err := w.Write([]byte(huge)); err != nil {
		t.Fatalf("write oversized message: %v", err)
	}
	w.Close()

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if len(current) != len(huge) {
		t.Fatalf("oversized message must be written fully: got %d bytes, want %d", len(current), len(huge))
	}
	// Rotation runs before the message is written, so the empty first
	// generation becomes the .1 backup.
	backupInfo, err := os.Stat(path + rotatingLogBackupSuffix)
	if err != nil {
		t.Fatalf("first generation must be moved to backup: %v", err)
	}
	if backupInfo.Size() != 0 {
		t.Fatalf("expected empty backup of the first generation, got %d bytes", backupInfo.Size())
	}
}

func TestRotatingLogWriterKeepsSingleBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic-monitor.log")
	w, err := newRotatingLogWriter(path)
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}

	generations := []string{"gen-0\n", "gen-1\n", "gen-2\n"}
	for _, gen := range generations {
		if _, err := w.Write([]byte(strings.Repeat("g", rotatingLogMaxSize/2+5) + gen)); err != nil {
			t.Fatalf("write %s: %v", gen, err)
		}
	}
	w.Close()

	backup, err := os.ReadFile(path + rotatingLogBackupSuffix)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !strings.HasSuffix(string(backup), "gen-1\n") {
		t.Fatal("backup must hold the previous generation")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if !strings.HasSuffix(string(current), "gen-2\n") {
		t.Fatal("current must hold the newest generation")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected exactly two log files, got %v", names)
	}
}

func TestRotatingLogWriterConcurrentWritesStayComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-monitor.log")
	w, err := newRotatingLogWriter(path)
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}

	const writers = 8
	const perWriter = 64
	message := strings.Repeat("m", 2048) + "\n"

	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if _, err := w.Write([]byte(message)); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}
	w.Close()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if len(content) != writers*perWriter*len(message) {
		t.Fatalf("expected %d written bytes, got %d", writers*perWriter*len(message), len(content))
	}
}

func TestRotatingLogWriterNotifiesOnRotationFailureAndKeepsWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-monitor.log")
	w, err := newRotatingLogWriter(path)
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}

	if _, err := w.Write([]byte("first\n")); err != nil {
		t.Fatalf("write first: %v", err)
	}
	// A non-empty directory at the backup path blocks remove and rename.
	if err := os.MkdirAll(path+rotatingLogBackupSuffix, 0o755); err != nil {
		t.Fatalf("create blocking dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path+rotatingLogBackupSuffix, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatalf("populate blocking dir: %v", err)
	}

	if _, err := w.Write([]byte(strings.Repeat("x", rotatingLogMaxSize+16) + "\nafter-failure\n")); err != nil {
		t.Fatalf("write across threshold: %v", err)
	}

	select {
	case rotateErr := <-w.Errors():
		if rotateErr == nil {
			t.Fatal("expected a rotation failure notification")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for rotation failure notification")
	}
	if err := w.stickyError(); err != nil {
		t.Fatalf("writer must keep writing after a failed rotation: %v", err)
	}

	if _, err := w.Write([]byte("still-alive\n")); err != nil {
		t.Fatalf("write after failure: %v", err)
	}
	w.Close()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if !strings.HasPrefix(string(content), "first\n") || !strings.Contains(string(content), "after-failure\n") || !strings.HasSuffix(string(content), "still-alive\n") {
		t.Fatal("log content must be preserved and appended after the failed rotation")
	}
}

// chdirForTest changes the process working directory for the duration of the
// test. testing.T.Chdir needs go1.24, but the module targets go1.21.
func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
}

type fakeAddr struct {
	network string
	str     string
}

func (f fakeAddr) Network() string { return f.network }
func (f fakeAddr) String() string  { return f.str }

func TestDashboardURLFromListenerAddr(t *testing.T) {
	cases := []struct {
		addr    string
		want    string
		wantErr bool
	}{
		{addr: ":8080", want: "http://127.0.0.1:8080/"},
		{addr: "0.0.0.0:8080", want: "http://127.0.0.1:8080/"},
		{addr: "[::]:8080", want: "http://127.0.0.1:8080/"},
		{addr: "127.0.0.1:9000", want: "http://127.0.0.1:9000/"},
		{addr: "localhost:9000", want: "http://localhost:9000/"},
		{addr: "[::1]:9000", want: "http://[::1]:9000/"},
		{addr: "no-port", wantErr: true},
		{addr: "127.0.0.1:0", wantErr: true},
		{addr: "127.0.0.1:notaport", wantErr: true},
	}
	for _, tc := range cases {
		got, err := dashboardURLFromAddr(fakeAddr{network: "tcp", str: tc.addr})
		if tc.wantErr {
			if err == nil {
				t.Fatalf("dashboardURLFromAddr(%q) expected error, got %q", tc.addr, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("dashboardURLFromAddr(%q): %v", tc.addr, err)
		}
		if got != tc.want {
			t.Fatalf("dashboardURLFromAddr(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	got, err := dashboardURLFromAddr(listener.Addr())
	if err != nil {
		t.Fatalf("dashboardURLFromAddr(actual listener): %v", err)
	}
	if !strings.HasSuffix(got, fmt.Sprintf(":%d/", listener.Addr().(*net.TCPAddr).Port)) {
		t.Fatalf("expected actual port in url %q", got)
	}
}

func TestValidateMetadataURL(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:8080/",
		"https://localhost:9000/",
		"http://[::1]:9000/",
	}
	for _, raw := range valid {
		if err := validateMetadataURL(raw); err != nil {
			t.Fatalf("validateMetadataURL(%q) should accept: %v", raw, err)
		}
	}
	invalid := []string{
		"",
		"file:///C:/Windows/System32/calc.exe",
		"ftp://127.0.0.1:8080/",
		"http://user:pass@127.0.0.1:8080/",
		"http://127.0.0.1:8080/path?x=1",
		"http://127.0.0.1:8080/#frag",
		"http://127.0.0.1/",
		"http://127.0.0.1:0/",
	}
	for _, raw := range invalid {
		if err := validateMetadataURL(raw); err == nil {
			t.Fatalf("validateMetadataURL(%q) should reject", raw)
		}
	}
}

func TestRuntimeMetadataPublishReadDeleteIfOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-7.json")

	meta := runtimeMetadata{PID: os.Getpid(), SessionID: 7, URL: "http://127.0.0.1:8080/", StartedAt: 42}
	if err := publishRuntimeMetadata(path, meta); err != nil {
		t.Fatalf("publishRuntimeMetadata: %v", err)
	}
	got, err := readRuntimeMetadata(path)
	if err != nil {
		t.Fatalf("readRuntimeMetadata: %v", err)
	}
	if got != meta {
		t.Fatalf("metadata roundtrip mismatch: %+v vs %+v", got, meta)
	}

	deleteRuntimeMetadataIfOwner(path, meta.PID+1, meta.SessionID)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("metadata must survive a non-owner delete: %v", err)
	}

	deleteRuntimeMetadataIfOwner(path, meta.PID, meta.SessionID)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner delete must remove metadata, got %v", err)
	}
}

func TestAutostartCommandQuotesSpaces(t *testing.T) {
	exe := `C:\Program Files\Traffic Monitor\traffic-monitor.exe`
	if got := autostartCommand(exe); got != `"`+exe+`"` {
		t.Fatalf("autostart command must quote the path: %q", got)
	}
}

func TestRegistryAutoStartStoreOnTempKey(t *testing.T) {
	base := fmt.Sprintf(`Software\TrafficMonitorTest\%d`, time.Now().UnixNano())
	store := registryAutoStartStore{runKeyPath: base}
	t.Cleanup(func() {
		_ = store.Disable()
		_ = registry.DeleteKey(registry.CURRENT_USER, base)
	})

	exe := `C:\Program Files\Traffic Monitor\traffic-monitor.exe`

	enabled, err := store.Enabled(exe)
	if err != nil || enabled {
		t.Fatalf("fresh store must be disabled: enabled=%v err=%v", enabled, err)
	}

	if err := store.Enable(exe); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	enabled, err = store.Enabled(exe)
	if err != nil || !enabled {
		t.Fatalf("Enabled after Enable: enabled=%v err=%v", enabled, err)
	}
	if other, err := store.Enabled(`C:\Other\Path\app.exe`); err != nil || other {
		t.Fatalf("Enabled must compare the exact command: enabled=%v err=%v", other, err)
	}

	if err := store.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if enabled, err := store.Enabled(exe); err != nil || enabled {
		t.Fatalf("Enabled after Disable: enabled=%v err=%v", enabled, err)
	}
	if err := store.Disable(); err != nil {
		t.Fatalf("Disable on missing value must succeed: %v", err)
	}
}

func TestOpenDashboardFromMetadataOpensLiveInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-1.json")
	var opened []string
	opener := func(raw string) error {
		opened = append(opened, raw)
		return nil
	}

	meta := runtimeMetadata{PID: os.Getpid(), SessionID: 1, URL: "http://127.0.0.1:8080/", StartedAt: 1}
	if err := publishRuntimeMetadata(path, meta); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := openDashboardFromMetadata(path, 2*time.Second, opener); err != nil {
		t.Fatalf("openDashboardFromMetadata: %v", err)
	}
	if len(opened) != 1 || opened[0] != meta.URL {
		t.Fatalf("expected opener for %q, got %v", meta.URL, opened)
	}

	dead := runtimeMetadata{PID: 0, SessionID: 1, URL: meta.URL}
	if err := publishRuntimeMetadata(path, dead); err != nil {
		t.Fatalf("publish dead: %v", err)
	}
	if err := openDashboardFromMetadata(path, 300*time.Millisecond, opener); err == nil {
		t.Fatal("expected failure while no live instance is published")
	}
	if len(opened) != 1 {
		t.Fatalf("opener must not run for dead instances: %v", opened)
	}

	bogus := runtimeMetadata{PID: os.Getpid(), SessionID: 1, URL: "file:///C:/Windows/System32/calc.exe"}
	if err := publishRuntimeMetadata(path, bogus); err != nil {
		t.Fatalf("publish bogus: %v", err)
	}
	if err := openDashboardFromMetadata(path, 300*time.Millisecond, opener); err == nil {
		t.Fatal("expected failure for an invalid metadata url")
	}
	if len(opened) != 1 {
		t.Fatalf("opener must not run for invalid urls: %v", opened)
	}
}

type fakeTrayRunner struct {
	mu        sync.Mutex
	quitCalls int
	quit      chan struct{}
}

func newFakeTrayRunner() *fakeTrayRunner {
	return &fakeTrayRunner{quit: make(chan struct{})}
}

func (f *fakeTrayRunner) Run(onReady, onExit func()) {
	<-f.quit
	if onExit != nil {
		onExit()
	}
}

func (f *fakeTrayRunner) Quit() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quitCalls++
	select {
	case <-f.quit:
	default:
		close(f.quit)
	}
}

func (f *fakeTrayRunner) quitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.quitCalls
}

type fakeAutoStartStore struct {
	mu      sync.Mutex
	enabled bool
	failOn  string
	exeSeen string
}

func (f *fakeAutoStartStore) Enabled(exePath string) (bool, error) {
	if f.failOn == "enabled" {
		return false, errors.New("injected enabled failure")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled, nil
}

func (f *fakeAutoStartStore) Enable(exePath string) error {
	if f.failOn == "enable" {
		return errors.New("injected enable failure")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = true
	f.exeSeen = exePath
	return nil
}

func (f *fakeAutoStartStore) Disable() error {
	if f.failOn == "disable" {
		return errors.New("injected disable failure")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = false
	return nil
}

func (f *fakeAutoStartStore) isEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled
}

// newSupervisorTestApplication builds an application whose collector is
// already quiet so shutdown completes immediately.
func newSupervisorTestApplication(t *testing.T) (*application, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	svc := newTestServiceOnDB(db)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	quiet := make(chan struct{})
	close(quiet)
	return &application{
		cfg:           config{ListenAddr: "127.0.0.1:0"},
		db:            db,
		svc:           svc,
		server:        &http.Server{Handler: svc.routes(), ReadHeaderTimeout: 5 * time.Second},
		ctx:           ctx,
		cancel:        cancel,
		collectorDone: quiet,
		serverErr:     make(chan error, 1),
	}, dbPath
}

type supervisorHarness struct {
	app        *application
	dbPath     string
	runner     *fakeTrayRunner
	store      *fakeAutoStartStore
	logWriter  *rotatingLogWriter
	menuCh     chan trayMenu
	quitReq    atomic.Bool
	outcome    chan error
	stop       chan struct{}
	done       chan struct{}
	messageBox []string

	openCh  chan struct{}
	autoCh  chan struct{}
	quitCh  chan struct{}
	setCh   chan bool
	exePath string
	mu      sync.Mutex
}

func newSupervisorHarness(t *testing.T, exePath string, initialAutoStart bool) *supervisorHarness {
	t.Helper()

	logWriter, err := newRotatingLogWriter(filepath.Join(t.TempDir(), "supervisor-test.log"))
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}

	app, dbPath := newSupervisorTestApplication(t)
	h := &supervisorHarness{
		app:       app,
		dbPath:    dbPath,
		runner:    newFakeTrayRunner(),
		store:     &fakeAutoStartStore{},
		logWriter: logWriter,
		menuCh:    make(chan trayMenu, 1),
		outcome:   make(chan error, 1),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		openCh:    make(chan struct{}, 4),
		autoCh:    make(chan struct{}, 4),
		quitCh:    make(chan struct{}, 4),
		setCh:     make(chan bool, 8),
		exePath:   exePath,
	}

	previous := showMessageBox
	showMessageBox = func(text string) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.messageBox = append(h.messageBox, text)
	}
	t.Cleanup(func() {
		close(h.stop)
		<-h.done
		showMessageBox = previous
		_ = logWriter.Close()
	})

	h.menuCh <- trayMenu{
		openPageClicks:  h.openCh,
		autoStartClicks: h.autoCh,
		quitClicks:      h.quitCh,
		setAutoStart: func(checked bool) {
			h.setCh <- checked
		},
	}

	supervisor := &traySupervisor{
		app:              h.app,
		runner:           h.runner,
		store:            h.store,
		exePath:          h.exePath,
		dashboardURL:     "http://127.0.0.1:8080/",
		openURL:          func(string) error { return nil },
		logWriter:        logWriter,
		interruptCh:      make(chan os.Signal, 1),
		menuCh:           h.menuCh,
		initialAutoStart: initialAutoStart,
		quitRequested:    &h.quitReq,
		outcome:          h.outcome,
	}
	go func() {
		supervisor.run(h.stop)
		close(h.done)
	}()
	return h
}

func (h *supervisorHarness) waitSetState(t *testing.T, want bool) {
	t.Helper()
	select {
	case got := <-h.setCh:
		if got != want {
			t.Fatalf("expected setAutoStart(%v), got %v", want, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for setAutoStart(%v)", want)
	}
}

func (h *supervisorHarness) messageBoxCount(t *testing.T) int {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.messageBox)
}

func TestTraySupervisorQuitShutsDownApplication(t *testing.T) {
	h := newSupervisorHarness(t, `C:\Program Files\Traffic Monitor\app.exe`, false)

	// Buffer an aggregate that only a graceful shutdown flush will persist.
	bucketStart := (time.Now().UnixMilli() / 60000) * 60000
	h.app.svc.mu.Lock()
	h.app.svc.aggregateBuffer["qa-flush"] = &aggregatedEntry{
		BucketStart: bucketStart,
		BucketEnd:   bucketStart + 60000,
		SourceIP:    "192.168.1.2",
		Host:        "flush.example",
		Process:     "chrome",
		Outbound:    "DIRECT",
		Chains:      `["DIRECT"]`,
		RuleGroup:   unknownRuleGroup,
		Upload:      21,
		Download:    14,
		Count:       1,
	}
	h.app.svc.mu.Unlock()

	h.quitCh <- struct{}{}

	select {
	case err := <-h.outcome:
		if err != nil {
			t.Fatalf("clean quit must report nil outcome, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for quit outcome")
	}
	if !h.quitReq.Load() {
		t.Fatal("quit request flag must be set")
	}
	if h.runner.quitCount() != 1 {
		t.Fatalf("expected exactly one runner.Quit call, got %d", h.runner.quitCount())
	}
	if err := h.app.db.Ping(); err == nil {
		t.Fatal("application database must be closed after quit")
	}

	reopened, err := sql.Open("sqlite3", h.dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer reopened.Close()
	var flushed int
	if err := reopened.QueryRow(`SELECT upload + download FROM traffic_aggregated WHERE host = 'flush.example'`).Scan(&flushed); err != nil {
		t.Fatalf("flushed aggregate missing after shutdown: %v", err)
	}
	if flushed != 35 {
		t.Fatalf("expected flushed total 35, got %d", flushed)
	}
}

func TestTraySupervisorServerErrorMessage(t *testing.T) {
	h := newSupervisorHarness(t, `C:\Program Files\Traffic Monitor\app.exe`, false)

	h.app.serverErr <- errors.New("listener failed")

	select {
	case err := <-h.outcome:
		if err == nil || !strings.Contains(err.Error(), "listener failed") {
			t.Fatalf("server error must reach the outcome, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server error outcome")
	}
	if !h.quitReq.Load() || h.runner.quitCount() != 1 {
		t.Fatal("server error must request quit")
	}
	if err := h.app.db.Ping(); err == nil {
		t.Fatal("application database must be closed after a server error")
	}
}

func TestTraySupervisorAutostartToggle(t *testing.T) {
	h := newSupervisorHarness(t, `C:\Program Files\Traffic Monitor\app.exe`, false)

	h.autoCh <- struct{}{}
	h.waitSetState(t, true)
	if !h.store.isEnabled() || h.store.exeSeen != h.exePath {
		t.Fatalf("store must be enabled with the exe path: enabled=%v exe=%q", h.store.isEnabled(), h.store.exeSeen)
	}

	h.autoCh <- struct{}{}
	h.waitSetState(t, false)
	if h.store.isEnabled() {
		t.Fatal("store must be disabled after the second click")
	}

	h.store.mu.Lock()
	h.store.failOn = "enable"
	h.store.mu.Unlock()
	h.autoCh <- struct{}{}
	select {
	case state := <-h.setCh:
		t.Fatalf("failed enable must not change the checkbox state, got %v", state)
	case <-time.After(200 * time.Millisecond):
	}
	if h.store.isEnabled() {
		t.Fatal("failed enable must not flip the store state")
	}
	if h.messageBoxCount(t) == 0 {
		t.Fatal("failed enable must report a message box")
	}
}

func TestTraySupervisorLogFaultReportsOnce(t *testing.T) {
	h := newSupervisorHarness(t, `C:\Program Files\Traffic Monitor\app.exe`, false)

	h.logWriter.errCh <- errors.New("disk full")
	h.logWriter.errCh <- errors.New("disk still full")

	deadline := time.After(2 * time.Second)
	for h.messageBoxCount(t) < 1 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for log fault message box")
		case <-time.After(20 * time.Millisecond):
		}
	}
	time.Sleep(100 * time.Millisecond)
	if got := h.messageBoxCount(t); got != 1 {
		t.Fatalf("log fault must be reported exactly once, got %d", got)
	}
	if h.runner.quitCount() != 0 {
		t.Fatal("log fault must not quit the application")
	}
}

func TestTrayIconBytesLoadAsWindowsIcon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tray.ico")
	if err := os.WriteFile(path, trayIconBytes, 0o644); err != nil {
		t.Fatalf("write icon: %v", err)
	}

	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("utf16: %v", err)
	}
	const (
		imageIcon      = 1
		lrLoadFromFile = 0x00000010
		lrDefaultSize  = 0x00000040
	)
	loadImage := windows.NewLazySystemDLL("user32.dll").NewProc("LoadImageW")
	res, _, callErr := loadImage.Call(0, uintptr(unsafe.Pointer(ptr)), imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
	if res == 0 {
		t.Fatalf("embedded tray.ico must load as a Windows icon: %v", callErr)
	}
}
