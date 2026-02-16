package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

//go:embed bpf/php.bpf.o
var bpfObject []byte

// otelLogger is the OpenTelemetry logger for emitting logs via OTLP
var otelLogger log.Logger

// initOTLPLogger initializes the OTLP log exporter and logger
// Configure endpoint via OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_LOGS_ENDPOINT
func initOTLPLogger(ctx context.Context) (func(context.Context) error, error) {
	// Create OTLP HTTP log exporter
	exporter, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	// Create resource with service info
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("php-dcr"),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create log provider with batch processor
	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	// Get logger instance
	otelLogger = loggerProvider.Logger("php-dcr")

	return loggerProvider.Shutdown, nil
}

// emitCompileLog emits a log record via OTLP with filename and compiletime
func emitCompileLog(ctx context.Context, filename string, compiletime int64) {
	if otelLogger == nil {
		return
	}

	record := log.Record{}
	record.SetTimestamp(time.Now())
	record.SetSeverity(log.SeverityInfo)
	record.SetBody(log.StringValue("PHP file compiled"))
	record.AddAttributes(
		log.String("php.filename", filename),
		log.Int64("php.compile_time_unix", compiletime),
		log.String("php.compile_time_rfc3339", time.Unix(compiletime, 0).Local().Format(time.RFC3339)),
	)

	otelLogger.Emit(ctx, record)
}

// searchDirs defines the directories to search for PHP binaries
var searchDirs = []string{
	"/usr/lib/apache2/modules",
	"/usr/bin",
}

// findPHPBinaries searches for files containing "php" in their names
// and returns unique files based on inode to avoid duplicate attachments
func findPHPBinaries() ([]string, error) {
	seenInodes := make(map[uint64]string) // inode -> first found path
	var result []string

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			slog.Warn("Failed to read directory", "dir", dir, "error", err)
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			// Match files containing "libphp" or named exactly "php" or "php-fpm"
			if !strings.Contains(name, "libphp") && name != "php" && name != "php-fpm" {
				continue
			}

			fullPath := filepath.Join(dir, name)

			// Get file info to check inode
			info, err := os.Stat(fullPath)
			if err != nil {
				slog.Warn("Failed to stat file", "path", fullPath, "error", err)
				continue
			}

			// Get inode from syscall.Stat_t
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				slog.Warn("Failed to get stat_t", "path", fullPath)
				continue
			}

			inode := stat.Ino
			if existingPath, exists := seenInodes[inode]; exists {
				slog.Info("Skipping duplicate inode", "path", fullPath, "sameAs", existingPath, "inode", inode)
				continue
			}

			seenInodes[inode] = fullPath
			result = append(result, fullPath)
			slog.Info("Found PHP binary", "path", fullPath, "inode", inode)
		}
	}

	return result, nil
}

const (
	MapKeyStrLen = 512
)

var targetDir string
var emitLogEvents bool
var rewriteRuleFlags []string
var rewriteRules []RewriteRule

// RewriteRule holds a compiled regex and its replacement string
type RewriteRule struct {
	Regex       *regexp.Regexp
	Replacement string
}

// targetFileList stores absolute paths of PHP files in targetDir (atomic for concurrent access)
var targetFileList atomic.Value // stores []string

// phpCompiled stores filepath -> compiled_time_unix mapping
var phpCompiled = make(map[string]int64)

// scriptStartTime stores the time when this process started
var scriptStartTime time.Time

// Report response structs
type ScriptInfo struct {
	StartTimeUnix    int64  `json:"start_time_unix"`
	StartTimeRFC3339 string `json:"start_time_rfc3339"`
}

type FileReport struct {
	Filepath            string `json:"filepath"`
	CompiledTimeUnix    int64  `json:"compiled_time_unix"`
	CompiledTimeRFC3339 string `json:"compiled_time_rfc3339"`
}

type ReportResponse struct {
	Script ScriptInfo   `json:"script"`
	Report []FileReport `json:"report"`
}

// StatsResponse represents the stats endpoint response
type StatsResponse struct {
	UptimeSeconds    float64 `json:"uptime_seconds"`
	TotalFiles       int     `json:"total_files"`
	CompiledFiles    int     `json:"compiled_files"`
	CodeCoverageRate float64 `json:"code_coverage_rate"`
}

// findPHPFiles recursively searches for PHP files in the given directory
// and returns their absolute paths
func findPHPFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			slog.Warn("Failed to access path", "path", path, "error", err)
			return nil // continue walking
		}

		if d.IsDir() {
			return nil
		}

		if strings.HasSuffix(strings.ToLower(d.Name()), ".php") {
			absPath, err := filepath.Abs(path)
			if err != nil {
				slog.Warn("Failed to get absolute path", "path", path, "error", err)
				return nil
			}
			files = append(files, absPath)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// updateTargetFileList updates the targetFileList atomically
func updateTargetFileList() {
	files, err := findPHPFiles(targetDir)
	if err != nil {
		slog.Error("Failed to update target file list", "error", err)
		return
	}

	targetFileList.Store(files)
	slog.Info("Updated target file list", "count", len(files))
}

// startFileListUpdater starts a goroutine that updates targetFileList every 5 minutes
func startFileListUpdater(stopCh <-chan struct{}) {
	// Initial update
	updateTargetFileList()

	ticker := time.NewTicker(5 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				slog.Info("Stopping file list updater")
				return
			case <-ticker.C:
				updateTargetFileList()
			}
		}
	}()
}

// getTargetFileList returns the current target file list
func getTargetFileList() []string {
	if v := targetFileList.Load(); v != nil {
		return v.([]string)
	}
	return nil
}

// handlePhpCompiledInfo returns phpCompiled as JSON
func handlePhpCompiledInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(phpCompiled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// handlePhpFileList returns targetFileList as JSON
func handlePhpFileList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	files := getTargetFileList()
	if err := json.NewEncoder(w).Encode(files); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// handleReport returns the report with script info and file compilation status
func handleReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	files := getTargetFileList()
	reports := make([]FileReport, 0, len(files))

	for _, filepath := range files {
		var compiledTimeUnix int64 = -1
		var compiledTimeRFC3339 string = ""

		if t, ok := phpCompiled[filepath]; ok {
			compiledTimeUnix = t
			compiledTimeRFC3339 = time.Unix(t, 0).Local().Format(time.RFC3339)
		}

		reports = append(reports, FileReport{
			Filepath:            filepath,
			CompiledTimeUnix:    compiledTimeUnix,
			CompiledTimeRFC3339: compiledTimeRFC3339,
		})
	}

	response := ReportResponse{
		Script: ScriptInfo{
			StartTimeUnix:    scriptStartTime.Unix(),
			StartTimeRFC3339: scriptStartTime.Format(time.RFC3339),
		},
		Report: reports,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// handleStats returns stats about the application
func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	totalFiles := len(getTargetFileList())
	compiledFiles := len(phpCompiled)

	var coverageRate float64
	if totalFiles > 0 {
		coverageRate = float64(compiledFiles) / float64(totalFiles) * 100
	}

	response := StatsResponse{
		UptimeSeconds:    time.Since(scriptStartTime).Seconds(),
		TotalFiles:       totalFiles,
		CompiledFiles:    compiledFiles,
		CodeCoverageRate: coverageRate,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

var rootCmd = &cobra.Command{
	Use:   "php-dcr",
	Short: "PHP Dead Code Reporter - Monitor PHP compile events using eBPF",
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVar(&targetDir, "target-dir", "", "Target directory to monitor")
	rootCmd.MarkFlagRequired("target-dir")
	rootCmd.Flags().BoolVar(&emitLogEvents, "emit-log-events", false, "Enable emitting log events via OTLP")
	rootCmd.Flags().StringArrayVar(&rewriteRuleFlags, "compiled-path-rewrite-rule", nil,
		"Rewrite rule for compiled file paths (format: regex::replacement, can be specified multiple times)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Record script start time
	scriptStartTime = time.Now()

	ctx := context.Background()

	// Initialize OTLP logger only if --emit-log-events is enabled
	if emitLogEvents {
		shutdownLogger, err := initOTLPLogger(ctx)
		if err != nil {
			slog.Warn("Failed to initialize OTLP logger, continuing without OTLP logging", "error", err)
		} else {
			defer func() {
				if err := shutdownLogger(ctx); err != nil {
					slog.Error("Failed to shutdown OTLP logger", "error", err)
				}
			}()
			slog.Info("OTLP logger initialized")
		}
	}

	// Validate targetDir is not empty
	if targetDir == "" {
		return fmt.Errorf("--target-dir must not be empty")
	}

	// Validate targetDir exists and is a directory
	info, err := os.Stat(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("--target-dir does not exist: %s", targetDir)
		}
		return fmt.Errorf("failed to access --target-dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--target-dir is not a directory: %s", targetDir)
	}

	// Parse rewrite rules
	if len(rewriteRuleFlags) > 0 {
		var err error
		rewriteRules, err = parseRewriteRules(rewriteRuleFlags)
		if err != nil {
			return fmt.Errorf("failed to parse rewrite rules: %w", err)
		}
		slog.Info("Loaded path rewrite rules", "count", len(rewriteRules))
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this program must be run as root (sudo)")
	}

	// Load the eBPF object file
	// bpfModule, err := bpf.NewModuleFromFile("bpf/php.bpf.o")
	// if err != nil {
	// 	slog.Error("Failed to load eBPF module", "error", err)
	// 	os.Exit(1)
	// }
	// defer bpfModule.Close()
	// バイトスライスから直接ロード
	bpfModule, err := libbpfgo.NewModuleFromBuffer(bpfObject, "program")
	if err != nil {
		return fmt.Errorf("failed to load eBPF module: %w", err)
	}
	defer bpfModule.Close()

	// Load the eBPF program into the kernel
	if err := bpfModule.BPFLoadObject(); err != nil {
		return fmt.Errorf("failed to load eBPF object: %w", err)
	}

	// Get the USDT program
	prog, err := bpfModule.GetProgram("compile_file_return")
	if err != nil {
		return fmt.Errorf("failed to get eBPF program: %w", err)
	}

	slog.Info("prog", "name", prog.Name())
	slog.Info("pin path", "path", prog.PinPath())
	slog.Info("section name", "name", prog.SectionName())

	// Find PHP binaries to attach to
	phpBinaries, err := findPHPBinaries()
	if err != nil {
		return fmt.Errorf("failed to find PHP binaries: %w", err)
	}

	if len(phpBinaries) == 0 {
		return fmt.Errorf("no PHP binaries found in search directories: %v", searchDirs)
	}

	// Attach USDT probe to each found PHP binary
	attachedCount := 0
	for _, binaryPath := range phpBinaries {
		_, err = prog.AttachUSDT(-1, binaryPath, "php", "compile__file__return")
		if err != nil {
			slog.Warn("Failed to attach USDT probe", "path", binaryPath, "error", err)
			continue
		}
		slog.Info("Attached USDT probe", "path", binaryPath)
		attachedCount++
	}

	if attachedCount == 0 {
		return fmt.Errorf("failed to attach to any PHP binary")
	}

	slog.Info("eBPF program loaded and attached successfully", "attachedCount", attachedCount)
	slog.Info("Monitoring PHP compile events... (Press Ctrl+C to exit)")

	// Get the BPF map
	bpfMap, err := bpfModule.GetMap("php_compile_file")
	if err != nil {
		return fmt.Errorf("failed to get BPF map: %w", err)
	}

	// Setup signal handler for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Start file list updater (updates every 5 minutes)
	stopFileListUpdater := make(chan struct{})
	startFileListUpdater(stopFileListUpdater)

	// Start HTTP server
	http.HandleFunc("/v1/php_compiled_info", handlePhpCompiledInfo)
	http.HandleFunc("/v1/php_file_list", handlePhpFileList)
	http.HandleFunc("/v1/report", handleReport)
	http.HandleFunc("/v1/stats", handleStats)
	go func() {
		slog.Info("Starting HTTP server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			slog.Error("HTTP server error", "error", err)
		}
	}()

	// Ticker for periodic map reading (every 5 seconds)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Main loop
	for {
		select {
		case <-sig:
			slog.Info("Shutting down...")
			close(stopFileListUpdater)
			return nil
		case <-ticker.C:
			// Read and display map contents
			displayMapContents(ctx, bpfMap)
		}
	}
}

// displayMapContents reads and displays the contents of the BPF map
func displayMapContents(ctx context.Context, bpfMap *bpf.BPFMap) {
	slog.Info("target directory", "target-dir", targetDir)
	fmt.Println("\n=== PHP Compile File Statistics ===")
	fmt.Printf("%-60s %s\n", "Filename", "Count")
	fmt.Println("-----------------------------------------------------------")

	iter := bpfMap.Iterator()
	count := 0

	for iter.Next() {
		keyBytes := iter.Key()

		v, _ := bpfMap.GetValue(unsafe.Pointer(&keyBytes[0]))

		filename := cstring(keyBytes)
		slog.Info(filename)

		// Apply rewrite rules to filename
		if len(rewriteRules) > 0 {
			rewritten := applyRewriteRules(filename, rewriteRules)
			if rewritten != filename {
				slog.Info("Rewrote path", "original", filename, "rewritten", rewritten)
				filename = rewritten
			}
		}

		var n int64

		buf := bytes.NewReader(v)
		err := binary.Read(buf, binary.LittleEndian, &n)
		if err != nil {
			panic(err)
		}

		boottime, _ := getBootTimeUnix()
		compiletime := boottime + n/1000/1000/1000

		// Store filepath and compiled_time_unix in global map only if it matches targetDir
		if strings.HasPrefix(filename, targetDir) {
			phpCompiled[filename] = compiletime
		}

		// Emit OTLP log with filename and compiletime
		emitCompileLog(ctx, filename, compiletime)

		t := time.Unix(compiletime, 0)
		// ローカルタイムゾーンに変換
		tLocal := t.Local()
		slog.Info(tLocal.Format(time.RFC3339))

		bpfMap.DeleteKey(unsafe.Pointer(&keyBytes[0]))
		slog.Info(filename + " deleted")
		count++

	}

	if count == 0 {
		fmt.Println("No data yet...")
	} else {
		fmt.Printf("\nTotal unique files: %d\n", count)
	}

}
func cstring(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// parseRewriteRules parses raw rule strings (format: "regex::replacement") into compiled RewriteRules
func parseRewriteRules(rawRules []string) ([]RewriteRule, error) {
	var rules []RewriteRule
	for _, raw := range rawRules {
		parts := strings.SplitN(raw, "::", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid rewrite rule (must contain '::'): %s", raw)
		}
		re, err := regexp.Compile(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid regex in rewrite rule %q: %w", raw, err)
		}
		rules = append(rules, RewriteRule{Regex: re, Replacement: parts[1]})
	}
	return rules, nil
}

// applyRewriteRules applies rewrite rules sequentially to the filename
func applyRewriteRules(filename string, rules []RewriteRule) string {
	for _, rule := range rules {
		filename = rule.Regex.ReplaceAllString(filename, rule.Replacement)
	}
	return filename
}

func getBootTimeUnix() (int64, error) {
	// /proc/uptimeを読み取る
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}

	// uptimeの秒数を取得（最初の値）
	fields := strings.Fields(string(data))
	uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	// 現在時刻からuptimeを引いてブート時刻を計算
	bootTime := time.Now().Add(-time.Duration(uptimeSeconds) * time.Second)
	return bootTime.Unix(), nil
}
