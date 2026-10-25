//go:build windows

package main

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/systray"
	sqlite3 "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed assets/tray.ico
var trayIconBytes []byte

var osExecutable = os.Executable

const (
	windowsDataDirName     = "data"
	windowsDatabaseName    = "traffic_monitor.db"
	windowsLogName         = "traffic-monitor.log"
	windowsMigratingSuffix = ".migrating"

	singletonMutexName  = `Local\TrafficMonitor.Singleton`
	autostartRunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	autostartValueName  = "TrafficMonitor"
	runtimeMetadataDir  = "TrafficMonitor"
)

var (
	secondInstanceWait = 5 * time.Second
	trayReadyTimeout   = 5 * time.Second
)

// windowsDataDir returns the directory next to the executable that holds the
// database and log. Autostart via HKCU Run gives no working directory, so all
// local state must be anchored to the executable location instead of the cwd.
func windowsDataDir() (string, error) {
	exePath, err := resolveExecutablePath()
	if err != nil {
		return "", err
	}
	exeDir := filepath.Dir(exePath)
	if strings.TrimSpace(exeDir) == "" {
		return "", errors.New("executable path has no directory")
	}
	return filepath.Join(exeDir, windowsDataDirName), nil
}

func resolveExecutablePath() (string, error) {
	exePath, err := osExecutable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	abs, err := filepath.Abs(exePath)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return abs, nil
}

// windowsDatabasePath returns the canonical database path next to the
// executable and, on first run of the new layout, migrates a legacy database
// found in the working directory without ever deleting it.
func windowsDatabasePath() (string, error) {
	dataDir, err := windowsDataDir()
	if err != nil {
		return "", err
	}
	canonical := filepath.Join(dataDir, windowsDatabaseName)

	if _, err := os.Stat(canonical); err == nil {
		return canonical, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat canonical database: %w", err)
	}

	legacy, err := filepath.Abs(filepath.Join(windowsDataDirName, windowsDatabaseName))
	if err != nil {
		return "", fmt.Errorf("resolve legacy database path: %w", err)
	}
	if sameWindowsPath(legacy, canonical) {
		return canonical, nil
	}

	if _, err := os.Stat(legacy); err == nil {
		if err := migrateLegacyWindowsDatabase(legacy, canonical); err != nil {
			return "", err
		}
		return canonical, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat legacy database: %w", err)
	}

	return canonical, nil
}

func sameWindowsPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// dashboardURLFromAddr builds the URL a local browser can open from the
// actual listener address, replacing wildcard hosts with the loopback address.
func dashboardURLFromAddr(addr net.Addr) (string, error) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", fmt.Errorf("parse listen address %q: %w", addr.String(), err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber <= 0 || portNumber > 65535 {
		return "", fmt.Errorf("listen address %q has no usable port", addr.String())
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	dashboard := url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: "/"}
	return dashboard.String(), nil
}

type runtimeMetadata struct {
	PID       int    `json:"pid"`
	SessionID uint32 `json:"sessionId"`
	URL       string `json:"url"`
	StartedAt int64  `json:"startedAt"`
}

func runtimeMetadataPath(sessionID uint32) (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("resolve LocalAppData: %w", err)
	}
	return filepath.Join(base, runtimeMetadataDir, fmt.Sprintf("runtime-%d.json", sessionID)), nil
}

func publishRuntimeMetadata(path string, meta runtimeMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create runtime metadata directory: %w", err)
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encode runtime metadata: %w", err)
	}
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o644); err != nil {
		return fmt.Errorf("write runtime metadata: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("publish runtime metadata: %w", err)
	}
	return nil
}

func readRuntimeMetadata(path string) (runtimeMetadata, error) {
	var meta runtimeMetadata
	data, err := os.ReadFile(path)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return meta, fmt.Errorf("decode runtime metadata %s: %w", path, err)
	}
	return meta, nil
}

// validateMetadataURL only accepts plain http(s) origin URLs, so a tampered
// metadata file cannot turn the second-instance path into an arbitrary
// protocol launcher.
func validateMetadataURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse dashboard url: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("unacceptable dashboard url %q", raw)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("dashboard url %q has no host", raw)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("dashboard url %q has no usable port", raw)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("dashboard url %q has an unexpected path", raw)
	}
	return nil
}

func deleteRuntimeMetadataIfOwner(path string, pid int, sessionID uint32) {
	meta, err := readRuntimeMetadata(path)
	if err != nil || meta.PID != pid || meta.SessionID != sessionID {
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("remove runtime metadata %s: %v", path, err)
	}
}

// autostartCommand is the HKCU Run value: the quoted absolute executable path
// without any shell, so spaces are safe and the cwd does not matter.
func autostartCommand(exePath string) string {
	return `"` + exePath + `"`
}

type autoStartStore interface {
	Enabled(exePath string) (bool, error)
	Enable(exePath string) error
	Disable() error
}

// registryAutoStartStore toggles one HKCU Run value for the current user; no
// administrator rights are involved. runKeyPath is overridable so tests can
// exercise the adapter on an isolated key.
type registryAutoStartStore struct {
	runKeyPath string
}

func (s registryAutoStartStore) Enabled(exePath string) (bool, error) {
	value, err := s.readValue()
	if err != nil {
		return false, err
	}
	return value == autostartCommand(exePath), nil
}

func (s registryAutoStartStore) readValue() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, s.runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(autostartValueName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

func (s registryAutoStartStore) Enable(exePath string) error {
	key, openedExisting, err := registry.CreateKey(registry.CURRENT_USER, s.runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	_ = openedExisting
	return key.SetStringValue(autostartValueName, autostartCommand(exePath))
}

func (s registryAutoStartStore) Disable() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, s.runKeyPath, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer key.Close()
	if err := key.DeleteValue(autostartValueName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// acquireSingletonMutex creates the per-session single instance mutex. A valid
// handle together with ERROR_ALREADY_EXISTS means another instance owns it.
func acquireSingletonMutex(name string) (windows.Handle, bool, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, fmt.Errorf("invalid mutex name %q: %w", name, err)
	}
	handle, err := windows.CreateMutex(nil, false, namePtr)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return handle, true, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("create singleton mutex: %w", err)
	}
	return handle, false, nil
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil || handle == 0 {
		return false
	}
	windows.CloseHandle(handle)
	return true
}

func shellOpenURL(target string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// openDashboardFromMetadata waits up to `within` for the first instance to
// publish a valid, live dashboard URL and opens it with the given opener.
func openDashboardFromMetadata(path string, within time.Duration, opener func(string) error) error {
	deadline := time.Now().Add(within)
	for {
		meta, err := readRuntimeMetadata(path)
		if err == nil {
			if validateErr := validateMetadataURL(meta.URL); validateErr != nil {
				log.Printf("ignoring invalid runtime metadata url: %v", validateErr)
			} else if processAlive(meta.PID) {
				return opener(meta.URL)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Printf("read runtime metadata %s: %v", path, err)
		}
		if !time.Now().Before(deadline) {
			return errors.New("no running instance published a valid dashboard url")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// databaseBackupTimeout bounds the SQLite Online Backup used by the legacy
// database migration. It is a variable so tests can shorten it.
var databaseBackupTimeout = 10 * time.Second

// migrateLegacyWindowsDatabase snapshots the legacy database into dstPath via
// the SQLite Online Backup API, so uncheckpointed WAL content is included and
// concurrent writers observe a consistent snapshot. The legacy file is kept as
// a manually recoverable backup; this function never deletes it.
func migrateLegacyWindowsDatabase(srcPath, dstPath string) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	migratingPath := dstPath + windowsMigratingSuffix
	cleanupMigrating := func(cause error) error {
		if err := os.Remove(migratingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("remove failed migration temp file %s: %v", migratingPath, err)
		}
		return cause
	}

	if err := backupSQLiteDatabase(srcPath, migratingPath, databaseBackupTimeout); err != nil {
		return cleanupMigrating(fmt.Errorf("back up legacy database %s: %w", srcPath, err))
	}
	if err := quickCheckSQLiteDatabase(migratingPath); err != nil {
		return cleanupMigrating(err)
	}
	if err := syncFile(migratingPath); err != nil {
		return cleanupMigrating(fmt.Errorf("sync migrated database: %w", err))
	}
	if err := os.Rename(migratingPath, dstPath); err != nil {
		return cleanupMigrating(fmt.Errorf("move migrated database into place: %w", err))
	}

	log.Printf("migrated legacy database %s to %s; original file kept as backup", srcPath, dstPath)
	return nil
}

// backupSQLiteDatabase copies srcPath into dstPath with the Online Backup API.
// Both databases are private one-shot handles used only during startup, so the
// raw driver connections are held for the duration of the copy.
func backupSQLiteDatabase(srcPath, dstPath string, timeout time.Duration) error {
	srcDB, err := sql.Open("sqlite3", srcPath+"?_busy_timeout=1000")
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}
	defer srcDB.Close()

	dstDB, err := sql.Open("sqlite3", dstPath)
	if err != nil {
		return fmt.Errorf("open target database: %w", err)
	}
	defer dstDB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	srcConn, err := srcDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire source connection: %w", err)
	}
	defer srcConn.Close()

	dstConn, err := dstDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire target connection: %w", err)
	}
	defer dstConn.Close()

	var srcRaw, dstRaw *sqlite3.SQLiteConn
	if err := srcConn.Raw(func(driverConn any) error {
		conn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("source driver connection is not a sqlite connection")
		}
		srcRaw = conn
		return nil
	}); err != nil {
		return fmt.Errorf("access source connection: %w", err)
	}
	if err := dstConn.Raw(func(driverConn any) error {
		conn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("target driver connection is not a sqlite connection")
		}
		dstRaw = conn
		return nil
	}); err != nil {
		return fmt.Errorf("access target connection: %w", err)
	}

	backup, err := dstRaw.Backup("main", srcRaw, "main")
	if err != nil {
		return fmt.Errorf("start sqlite backup: %w", err)
	}

	deadline := time.Now().Add(timeout)
	var backupErr error
	for {
		done, stepErr := backup.Step(-1)
		if stepErr != nil {
			backupErr = stepErr
			if !isSQLiteBusyOrLocked(stepErr) {
				break
			}
			if !time.Now().Before(deadline) {
				backupErr = errors.New("sqlite backup timed out waiting for the source database")
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if done {
			backupErr = nil
			break
		}
		// Step returned without finishing: the backup restarted because the
		// source changed, or pages remain. Keep stepping until it completes.
		if !time.Now().Before(deadline) {
			backupErr = errors.New("sqlite backup timed out before completing")
			break
		}
	}
	if finishErr := backup.Finish(); backupErr == nil {
		backupErr = finishErr
	}
	if backupErr != nil {
		return fmt.Errorf("copy database: %w", backupErr)
	}
	return nil
}

func isSQLiteBusyOrLocked(err error) bool {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked
	}
	return false
}

func quickCheckSQLiteDatabase(path string) error {
	db, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open migrated database for verification: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`PRAGMA quick_check`)
	if err != nil {
		return fmt.Errorf("quick_check migrated database: %w", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("read quick_check result: %w", err)
		}
		results = append(results, line)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read quick_check result: %w", err)
	}
	if len(results) != 1 || results[0] != "ok" {
		return fmt.Errorf("quick_check reported: %s", strings.Join(results, "; "))
	}
	return nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

const (
	rotatingLogMaxSize      = 5 * 1024 * 1024
	rotatingLogBackupSuffix = ".1"
)

// rotatingLogWriter is a mutex-protected io.Writer for the standard log
// package that rotates the current file once it exceeds rotatingLogMaxSize and
// keeps a single ".1" backup. Rotation failures are reported on a non-blocking
// channel; writing continues by reopening the current file.
type rotatingLogWriter struct {
	mu         sync.Mutex
	path       string
	backupPath string
	file       *os.File
	size       int64
	errCh      chan error
	stickyErr  error
}

func newRotatingLogWriter(path string) (*rotatingLogWriter, error) {
	w := &rotatingLogWriter{
		path:       path,
		backupPath: path + rotatingLogBackupSuffix,
		errCh:      make(chan error, 1),
	}
	if err := w.openCurrentLocked(); err != nil {
		w.stickyErr = err
		return w, fmt.Errorf("open log file %s: %w", path, err)
	}
	return w, nil
}

func (w *rotatingLogWriter) Errors() <-chan error {
	return w.errCh
}

// stickyError reports an unrecoverable writer failure: logging cannot
// continue until the process restarts.
func (w *rotatingLogWriter) stickyError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stickyErr
}

func (w *rotatingLogWriter) notify(err error) {
	select {
	case w.errCh <- err:
	default:
	}
}

func (w *rotatingLogWriter) openCurrentLocked() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = info.Size()
	return nil
}

func (w *rotatingLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		if err := w.openCurrentLocked(); err != nil {
			w.stickyErr = err
			return 0, fmt.Errorf("reopen log file %s: %w", w.path, err)
		}
	}

	// Rotation happens before the oversized message is written so the message
	// itself always lands complete in the fresh file.
	if w.size+int64(len(p)) > rotatingLogMaxSize {
		if err := w.rotateLocked(); err != nil {
			w.notify(fmt.Errorf("rotate log: %w", err))
			if w.file == nil {
				return 0, err
			}
		}
	}

	n, err := w.file.Write(p)
	if n > 0 {
		w.size += int64(n)
	}
	if err != nil {
		w.notify(fmt.Errorf("write log: %w", err))
		return n, err
	}
	return n, nil
}

// rotateLocked moves the current file to the ".1" backup and opens a fresh
// one. Whatever fails, it reopens the current path afterwards so logging
// continues; callers report the returned error to the supervisor.
func (w *rotatingLogWriter) rotateLocked() error {
	var errs []error
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close current log: %w", err))
		}
		w.file = nil
		w.size = 0
	}

	if err := os.Remove(w.backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove old log backup: %w", err))
	}
	if err := os.Rename(w.path, w.backupPath); err != nil {
		errs = append(errs, fmt.Errorf("rename log to backup: %w", err))
	}

	if err := w.openCurrentLocked(); err != nil {
		w.stickyErr = err
		errs = append(errs, fmt.Errorf("reopen current log: %w", err))
		return errors.Join(errs...)
	}
	return errors.Join(errs...)
}

func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

var windowsLog *rotatingLogWriter

// showMessageBox is indirected so tests can observe fault reporting without
// opening real dialogs.
var showMessageBox = showErrorMessageBox

type trayRunner interface {
	Run(onReady, onExit func())
	Quit()
}

type systrayRunner struct{}

func (systrayRunner) Run(onReady, onExit func()) {
	systray.Run(onReady, onExit)
}

func (systrayRunner) Quit() {
	systray.Quit()
}

// trayMenu carries the tray interactions so the supervision loop can run
// against fakes in tests. Nil channels simply never fire before onReady
// delivers the real menu.
type trayMenu struct {
	openPageClicks  <-chan struct{}
	autoStartClicks <-chan struct{}
	quitClicks      <-chan struct{}
	setAutoStart    func(bool)
}

type traySupervisor struct {
	app              *application
	runner           trayRunner
	store            autoStartStore
	exePath          string
	dashboardURL     string
	openURL          func(string) error
	logWriter        *rotatingLogWriter
	interruptCh      <-chan os.Signal
	menuCh           <-chan trayMenu
	initialAutoStart bool
	quitRequested    *atomic.Bool
	outcome          chan<- error
}

func sendOutcome(outcome chan<- error, err error) {
	select {
	case outcome <- err:
	default:
	}
}

// run supervises menu clicks, server errors, log faults and interrupts until a
// quit is requested or stop is closed. A quit always shuts the application
// down before asking the tray loop to exit.
func (s *traySupervisor) run(stop <-chan struct{}) {
	var menu trayMenu
	autoStartEnabled := s.initialAutoStart
	logFaultReported := false

	for {
		select {
		case m, ok := <-s.menuCh:
			if ok {
				menu = m
			}
		case err := <-s.app.errors():
			log.Printf("server error: %v", err)
			shutdownErr := s.app.shutdown()
			s.quitRequested.Store(true)
			sendOutcome(s.outcome, errors.Join(err, shutdownErr))
			s.runner.Quit()
			return
		case err := <-s.logWriter.Errors():
			log.Printf("log writer failure: %v", err)
			if !logFaultReported {
				logFaultReported = true
				showMessageBox("Traffic Monitor 日志写入遇到磁盘故障，最近的日志可能丢失。")
			}
		case <-s.interruptCh:
			s.quitRequested.Store(true)
			sendOutcome(s.outcome, s.app.shutdown())
			s.runner.Quit()
			return
		case <-stop:
			return
		case <-menu.quitClicks:
			s.quitRequested.Store(true)
			sendOutcome(s.outcome, s.app.shutdown())
			s.runner.Quit()
			return
		case <-menu.openPageClicks:
			if err := s.openURL(s.dashboardURL); err != nil {
				log.Printf("open dashboard %s: %v", s.dashboardURL, err)
				showMessageBox(fmt.Sprintf("打开统计页失败：\n\n%v", err))
			}
		case <-menu.autoStartClicks:
			if autoStartEnabled {
				if err := s.store.Disable(); err != nil {
					log.Printf("disable autostart: %v", err)
					showMessageBox(fmt.Sprintf("关闭开机自动启动失败：\n\n%v", err))
					continue
				}
				autoStartEnabled = false
				menu.setAutoStart(false)
			} else {
				if err := s.store.Enable(s.exePath); err != nil {
					log.Printf("enable autostart: %v", err)
					showMessageBox(fmt.Sprintf("设置开机自动启动失败：\n\n%v", err))
					continue
				}
				autoStartEnabled = true
				menu.setAutoStart(true)
			}
		}
	}
}

const wmQuit = 0x0012

var procPostThreadMessageW = windows.NewLazySystemDLL("user32.dll").NewProc("PostThreadMessageW")

// postThreadQuitMessage wakes the tray message loop from another goroutine;
// this is the only reliable exit when the loop never reported ready and
// systray.Quit cannot be trusted.
func postThreadQuitMessage(threadID uint32) {
	_, _, _ = procPostThreadMessageW.Call(uintptr(threadID), wmQuit, 0, 0)
}

// runPlatform anchors all state next to the executable, enforces a single
// instance per login session and then serves the traffic monitor behind a
// tray icon until the user quits.
func runPlatform() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	exePath, err := resolveExecutablePath()
	if err != nil {
		return err
	}

	var sessionID uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil {
		return fmt.Errorf("resolve session id: %w", err)
	}
	metaPath, err := runtimeMetadataPath(sessionID)
	if err != nil {
		return err
	}

	mutexHandle, alreadyRunning, err := acquireSingletonMutex(singletonMutexName)
	if err != nil {
		return err
	}
	if alreadyRunning {
		windows.CloseHandle(mutexHandle)
		log.Printf("another instance is running in this session; opening its dashboard")
		if openErr := openDashboardFromMetadata(metaPath, secondInstanceWait, shellOpenURL); openErr != nil {
			showErrorMessageBox(fmt.Sprintf("Traffic Monitor 已经在运行，但打开统计页失败：\n\n%v", openErr))
			return openErr
		}
		return nil
	}
	defer windows.CloseHandle(mutexHandle)

	dataDir, err := windowsDataDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	logWriter, err := newRotatingLogWriter(filepath.Join(dataDir, windowsLogName))
	if err != nil {
		return err
	}
	windowsLog = logWriter
	log.SetOutput(logWriter)
	log.Printf("traffic monitor starting (pid %d, session %d)", os.Getpid(), sessionID)

	dbPath, err := windowsDatabasePath()
	if err != nil {
		return err
	}

	app, err := newApplication(cfg, dbPath)
	if err != nil {
		return err
	}

	dashboardURL, err := dashboardURLFromAddr(app.listener.Addr())
	if err != nil {
		app.shutdown()
		return err
	}

	app.start()
	if err := logWriter.stickyError(); err != nil {
		app.shutdown()
		return fmt.Errorf("log writer: %w", err)
	}

	meta := runtimeMetadata{
		PID:       os.Getpid(),
		SessionID: sessionID,
		URL:       dashboardURL,
		StartedAt: time.Now().UnixMilli(),
	}
	if err := publishRuntimeMetadata(metaPath, meta); err != nil {
		app.shutdown()
		return fmt.Errorf("publish runtime metadata: %w", err)
	}
	log.Printf("dashboard url: %s", dashboardURL)

	store := registryAutoStartStore{runKeyPath: autostartRunKeyPath}
	initialAutoStart := false
	if enabled, err := store.Enabled(exePath); err != nil {
		log.Printf("read autostart state: %v", err)
	} else {
		initialAutoStart = enabled
	}

	readyCh := make(chan struct{})
	menuCh := make(chan trayMenu, 1)
	stopCh := make(chan struct{})
	outcomeCh := make(chan error, 1)
	var quitRequested atomic.Bool
	var readyTimedOut atomic.Bool

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	runner := systrayRunner{}
	supervisor := &traySupervisor{
		app:              app,
		runner:           runner,
		store:            store,
		exePath:          exePath,
		dashboardURL:     dashboardURL,
		openURL:          shellOpenURL,
		logWriter:        logWriter,
		interruptCh:      sigCh,
		menuCh:           menuCh,
		initialAutoStart: initialAutoStart,
		quitRequested:    &quitRequested,
		outcome:          outcomeCh,
	}
	go supervisor.run(stopCh)

	// The systray package locks the main OS thread in its package init, so the
	// thread id captured here is the one running the event loop below.
	mainThreadID := windows.GetCurrentThreadId()
	wake := func() { postThreadQuitMessage(mainThreadID) }

	go func() {
		select {
		case <-readyCh:
		case <-stopCh:
		case <-time.After(trayReadyTimeout):
			readyTimedOut.Store(true)
			log.Printf("tray did not become ready within %s; waking event loop", trayReadyTimeout)
			wake()
		}
	}()

	onReady := func() {
		systray.SetIcon(trayIconBytes)
		systray.SetTitle("")
		systray.SetTooltip("Traffic Monitor")
		openItem := systray.AddMenuItem("打开统计页", "在默认浏览器中打开统计页")
		autoStartItem := systray.AddMenuItemCheckbox("开机自动启动", "登录 Windows 时自动启动 Traffic Monitor", initialAutoStart)
		systray.AddSeparator()
		quitItem := systray.AddMenuItem("退出", "停止采集并将数据落盘后退出")
		menuCh <- trayMenu{
			openPageClicks:  openItem.ClickedCh,
			autoStartClicks: autoStartItem.ClickedCh,
			quitClicks:      quitItem.ClickedCh,
			setAutoStart: func(checked bool) {
				if checked {
					autoStartItem.Check()
				} else {
					autoStartItem.Uncheck()
				}
			},
		}
		close(readyCh)
	}
	onExit := func() {
		if err := app.shutdown(); err != nil {
			log.Printf("shutdown on tray exit: %v", err)
		}
	}

	runner.Run(onReady, onExit)
	close(stopCh)

	var runErr error
	select {
	case err := <-outcomeCh:
		runErr = err
	default:
	}
	if !quitRequested.Load() {
		if readyTimedOut.Load() {
			runErr = fmt.Errorf("tray initialization did not complete within %s", trayReadyTimeout)
		} else {
			runErr = errors.New("tray event loop returned without an explicit quit")
		}
		if err := app.shutdown(); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}

	deleteRuntimeMetadataIfOwner(metaPath, os.Getpid(), sessionID)
	if err := logWriter.stickyError(); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("log writer: %w", err))
	}
	log.Printf("traffic monitor exiting")
	windowsLog.Close()
	return runErr
}

func reportPlatformFatal(err error) {
	log.Printf("fatal: %v", err)
	showErrorMessageBox(fmt.Sprintf("Traffic Monitor failed to start:\n\n%v\n\nSee traffic-monitor.log in the data folder next to the program for details.", err))
	if windowsLog != nil {
		windowsLog.Close()
	}
}

func showErrorMessageBox(text string) {
	title, err := windows.UTF16PtrFromString("Traffic Monitor")
	if err != nil {
		return
	}
	message, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	_, _ = windows.MessageBox(0, message, title, windows.MB_OK|windows.MB_ICONERROR)
}
