#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

#define MAX_STR_LEN 512

char filename[MAX_STR_LEN];


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, char[MAX_STR_LEN]);
    __type(value, u64);
} php_compile_file SEC(".maps");

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:compile__file__return")
int BPF_USDT(compile_file_return, char *arg0, char *arg1) 
{
    u64 ts = bpf_ktime_get_ns();

    static const char fmtstr[] = "compile file return: %s, %s\n"; 
    bpf_trace_printk(fmtstr, sizeof(fmtstr), arg0, arg1);


    bpf_probe_read_user_str(&filename, sizeof(filename), arg0);

    bpf_map_update_elem(&php_compile_file, &filename, &ts, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
