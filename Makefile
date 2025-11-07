.PHONY: all clean build ebpf go-build vmlinux

# Default target
all: vmlinux ebpf go-build

# Generate vmlinux.h from kernel BTF
vmlinux:
	@if [ ! -f bpf/vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; \
	fi

# eBPF compilation
ebpf: vmlinux
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I./bpf -c bpf/php.bpf.c -o bpf/php.bpf.o

# Go build
go-build:
	go build -o php-dcr main.go

# Build everything
build: ebpf go-build

# Clean build artifacts
clean:
	rm -f bpf/*.o
	rm -f bpf/vmlinux.h
	rm -f php-dcr

# Run the program (requires root)
run: build
	sudo ./php-dcr

# Help target
help:
	@echo "Available targets:"
	@echo "  vmlinux   - Generate vmlinux.h from kernel BTF"
	@echo "  ebpf      - Compile eBPF program"
	@echo "  go-build  - Build Go binary"
	@echo "  build     - Build everything"
	@echo "  all       - Build everything (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Build and run the program (requires root)"
