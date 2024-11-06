#include "bpf_helpers.h"
#include "bpf_endian.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct connection_info {
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u64 start_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct connection_info);
} connections SEC(".maps");

SEC("kprobe/tcp_connect")
int bpf_tcp_connect(struct pt_regs *ctx) {
    struct connection_info conn = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Get process info
    conn.pid = pid;
    conn.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));
    conn.start_time = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&connections, &pid_tgid, &conn, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_close")
int bpf_tcp_close(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&connections, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
