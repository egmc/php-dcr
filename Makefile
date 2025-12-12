.PHONY: all clean build ebpf go-build vmlinux build-libbpf

# Default target
all: vmlinux ebpf go-build

build-libbpf:
	make -C ./libbpf/src LIBSUBDIR=lib DESTDIR=../../dest/libbpf install install_uapi_headers

# Generate vmlinux.h from kernel BTF
vmlinux:
	@if [ ! -f bpf/vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; \
	fi

# eBPF compilation
ebpf: vmlinux
	clang -g -O2 -D__TARGET_ARCH_x86 -I./bpf  -I./dest/libbpf/usr/include -idirafter /usr/include/x86_64-linux-gnu -c bpf/php.bpf.c -target bpf -o bpf/php.bpf.o

# Go build
go-build:
	CGO_CFLAGS="-I$(CURDIR)/dest/libbpf/usr/include" \
	CGO_LDFLAGS="-L$(CURDIR)/dest/libbpf/usr/lib -lbpf -lelf" \
	go build -ldflags='-extldflags "-static"'

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
	@echo "  build-libbpf - Build and install libbpf to dest/libbpf"
	@echo "  vmlinux   - Generate vmlinux.h from kernel BTF"
	@echo "  ebpf      - Compile eBPF program"
	@echo "  go-build  - Build Go binary"
	@echo "  build     - Build everything"
	@echo "  all       - Build everything (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Build and run the program (requires root)"
