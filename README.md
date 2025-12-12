PHP Dead Code Reporter
=====================

A tool that uses eBPF to monitor PHP compile events and track file execution within a specified directory. Useful for detecting dead code (unused PHP files).

## Overview

This project uses USDT (User-level Statically Defined Tracing) probes to track PHP `compile__file__return` events. An eBPF program runs in kernel space and stores compiled PHP file paths with timestamps in a BPF MAP. The Go application periodically reads this map and provides reports via HTTP API.

## Requirements

### System Requirements
- Linux kernel 5.4 or later (eBPF CO-RE support)
- Root privileges

### Software Requirements
- Go 1.24 or later
- clang 10 or later
- libbpf
- bpftool
- Linux headers

### Ubuntu/Debian Installation
```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool
```

## Building

1. Clone the repository:
```bash
git clone <repository-url>
cd php-dcr
```

2. Download dependencies:
```bash
go mod download
```

3. Build:
```bash
make build
```

This will:
- Generate `vmlinux.h` from kernel BTF
- Compile the eBPF program (`bpf/php.bpf.o`)
- Build the Go binary (`php-dcr`)

## Usage

### Basic Usage

Run the program (requires root, `--target-dir` is required):
```bash
sudo ./php-dcr --target-dir /var/www/html
```

Only PHP files within the `--target-dir` directory will be tracked.

### HTTP API

After starting, an HTTP server runs on port 8080 with the following endpoints:

#### GET /v1/report
Returns a report of PHP files in the target directory and their compilation status.
```json
{
  "script": {
    "start_time_unix": 1733500000,
    "start_time_rfc3339": "2024-12-06T12:00:00+09:00"
  },
  "report": [
    {
      "filepath": "/var/www/html/index.php",
      "compiled_time_unix": 1733500100,
      "compiled_time_rfc3339": "2024-12-06T12:01:40+09:00"
    },
    {
      "filepath": "/var/www/html/unused.php",
      "compiled_time_unix": -1,
      "compiled_time_rfc3339": ""
    }
  ]
}
```
- `compiled_time_unix: -1` indicates the file was never compiled (potential dead code)

#### GET /v1/php_compiled_info
Returns a mapping of compiled PHP file paths to their compilation timestamps.
```json
{
  "/var/www/html/index.php": 1733500100,
  "/var/www/html/config.php": 1733500105
}
```

#### GET /v1/php_file_list
Returns a list of all PHP files in the target directory.
```json
[
  "/var/www/html/index.php",
  "/var/www/html/config.php",
  "/var/www/html/unused.php"
]
```

### Stopping

Press `Ctrl+C` to exit.

## How It Works

1. **eBPF Program** (`bpf/php.bpf.c`):
   - Attaches to PHP's `compile__file__return` USDT probe
   - Captures compiled file names and timestamps
   - Stores data in LRU HASH map `php_compile_file`

2. **Go Program** (`main.go`):
   - Loads embedded eBPF object file
   - Auto-discovers PHP binaries and attaches USDT probes
   - Reads BPF MAP every 5 seconds and records compilation info
   - Periodically updates the PHP file list in the target directory
   - Provides reports via HTTP API

3. **PHP Binary Auto-Discovery**:
   Automatically searches for PHP binaries in:
   - `/usr/lib/apache2/modules` (`libphp*`)
   - `/usr/bin` (`php`, `php-fpm`)

## Troubleshooting

### Failed to load eBPF program
- Ensure running with root privileges
- Verify kernel supports eBPF CO-RE (5.4+)
- Check BTF is enabled: `ls /sys/kernel/btf/vmlinux`

### Failed to attach USDT probe
- Ensure PHP was built with USDT support
- Check available probes: `sudo bpftool probe | grep php`

### No data displayed
- Verify PHP application is actually running
- Check that PHP is compiling files (opcache may be caching)
- Ensure `--target-dir` points to the correct path

## Cleanup

Remove build artifacts:
```bash
make clean
```

## License

Apache License 2.0

Note: The eBPF program (`bpf/*`) declares "GPL" license for kernel compatibility.