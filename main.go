package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/spf13/cobra"
)

//go:embed bpf/php.bpf.o
var bpfObject []byte

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

// targetFileList stores absolute paths of PHP files in targetDir (atomic for concurrent access)
var targetFileList atomic.Value // stores []string

// phpCompiled stores filepath -> compiled_time_unix mapping
var phpCompiled = make(map[string]int64)

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

var rootCmd = &cobra.Command{
	Use:   "php-dcr",
	Short: "PHP Dead Code Reporter - Monitor PHP compile events using eBPF",
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVar(&targetDir, "target-dir", "", "Target directory to monitor")
	rootCmd.MarkFlagRequired("target-dir")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Validate targetDir is not empty
	if targetDir == "" {
		return fmt.Errorf("--target-dir must not be empty")
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

	slog.Info("prog", prog.Name())
	slog.Info("pin path", prog.PinPath())
	slog.Info("section name", prog.SectionName())

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
			displayMapContents(bpfMap)
		}
	}
}

// displayMapContents reads and displays the contents of the BPF map
func displayMapContents(bpfMap *bpf.BPFMap) {
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
			// slog.Info("matched", "filaname", filename)
			phpCompiled[filename] = compiletime
		}

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
