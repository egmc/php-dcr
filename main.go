package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
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
		log.Fatal("This program must be run as root (sudo)")
	}

	// Load the eBPF object file
	bpfModule, err := bpf.NewModuleFromFile("bpf/php.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF module: %v", err)
	}
	defer bpfModule.Close()

	// Load the eBPF program into the kernel
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}

	// Get the USDT program
	prog, err := bpfModule.GetProgram("do_count")
	if err != nil {
		log.Fatalf("Failed to get eBPF program: %v", err)
	}

	// Attach USDT probe
	// Adjust the path to your PHP library if different
	// _, err = prog.AttachUSDT(-1, "/usr/lib/apache2/modules/libphp8.1.so", "php", "compile__file__entry")
	// if err != nil {
	// 	log.Fatalf("Failed to attach USDT probe: %v", err)
	// }
	_, err = prog.AttachGeneric()
	if err != nil {
		log.Fatalf("Failed to attach USDT probe: %v", err)
	}

	log.Println("eBPF program loaded and attached successfully")
	log.Println("Monitoring PHP compile events... (Press Ctrl+C to exit)")

	// Get the BPF map
	bpfMap, err := bpfModule.GetMap("php_compile_file")
	if err != nil {
		log.Fatalf("Failed to get BPF map: %v", err)
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
			log.Println("\nShutting down...")
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
			log.Printf("Failed to parse key: %v", err)
			continue
		}

		fmt.Printf("%d\n", v)
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
