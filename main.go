package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	maxStrLen = 256
)

// CallT represents the key structure in the BPF map
type CallT struct {
	Filename [maxStrLen]byte
}

func main() {
	// Check if running as root
	if os.Geteuid() != 0 {
		slog.Error("This program must be run as root (sudo)")
		os.Exit(1)
	}

	// Load the eBPF object file
	bpfModule, err := bpf.NewModuleFromFile("bpf/php.bpf.o")
	if err != nil {
		slog.Error("Failed to load eBPF module", "error", err)
		os.Exit(1)
	}
	defer bpfModule.Close()

	// Load the eBPF program into the kernel
	if err := bpfModule.BPFLoadObject(); err != nil {
		slog.Error("Failed to load eBPF object", "error", err)
		os.Exit(1)
	}

	// Get the USDT program
	prog, err := bpfModule.GetProgram("do_count")
	if err != nil {
		slog.Error("Failed to get eBPF program", "error", err)
		os.Exit(1)
	}

	slog.Info("prog", prog.GetName())
	slog.Info("pin path", prog.GetPinPath())
	slog.Info("section name", prog.GetSectionName())

	// _, err = prog.AttachGeneric()
	// if err != nil {
	// 	slog.Error("Failed to attach USDT probe", "error", err)
	// 	os.Exit(1)
	// }
	// Attach USDT probe
	// Adjust the path to your PHP library if different
	// _, err = prog.AttachUSDT(-1, "/usr/lib/apache2/modules/libphp8.1.so", "php", "compile__file__entry")
	_, err = prog.AttachUSDT(-1, "/usr/local/lib/libphp.so", "php", "compile__file__entry")
	if err != nil {
		slog.Error("Failed to attach USDT probe", "error", err)
		os.Exit(1)
	}

	slog.Info("eBPF program loaded and attached successfully")
	slog.Info("Monitoring PHP compile events... (Press Ctrl+C to exit)")

	// Get the BPF map
	bpfMap, err := bpfModule.GetMap("php_compile_file")
	if err != nil {
		slog.Error("Failed to get BPF map", "error", err)
		os.Exit(1)
	}

	// Setup signal handler for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Ticker for periodic map reading (every 5 seconds)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Main loop
	for {
		select {
		case <-sig:
			slog.Info("Shutting down...")
			return
		case <-ticker.C:
			// Read and display map contents
			displayMapContents(bpfMap)
		}
	}
}

// displayMapContents reads and displays the contents of the BPF map
func displayMapContents(bpfMap *bpf.BPFMap) {
	fmt.Println("\n=== PHP Compile File Statistics ===")
	fmt.Printf("%-60s %s\n", "Filename", "Count")
	fmt.Println("-----------------------------------------------------------")

	iter := bpfMap.Iterator()
	count := 0

	for iter.Next() {
		keyBytes := iter.Key()

		v, _ := bpfMap.GetValue(unsafe.Pointer(&keyBytes[0]))

		// Parse the key (CallT structure)
		var call CallT
		reader := bytes.NewReader(keyBytes)
		if err := binary.Read(reader, binary.LittleEndian, &call); err != nil {
			slog.Error("Failed to parse key", "error", err)
			continue
		}

		fmt.Printf(byteArrayToString(call.Filename))

		var n int64

		buf := bytes.NewReader(v)
		err := binary.Read(buf, binary.LittleEndian, &n)
		if err != nil {
			panic(err)
		}

		// fmt.Println(n)
		boottime, _ := getBootTimeUnix()
		compiletime := boottime + n/1000/1000

		t := time.Unix(compiletime, 0)
		// ローカルタイムゾーンに変換
		tLocal := t.Local()
		fmt.Println(tLocal)

		// Convert filename from byte array to string
		// filename := bytesToString(call.Filename[:])

		// if filename != "" {
		// 	fmt.Printf("%-60s %d\n", filename, value)
		// 	count++
		// }
	}

	if count == 0 {
		fmt.Println("No data yet...")
	} else {
		fmt.Printf("\nTotal unique files: %d\n", count)
	}

}
func byteArrayToString(b [256]byte) string {
	// null文字までを取得
	if n := bytes.IndexByte(b[:], 0); n != -1 {
		return string(b[:n])
	}
	return string(b[:])
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
