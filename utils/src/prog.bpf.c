#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define __sink(expr) asm volatile("" : "+g"(expr))

struct addr_key {
    u32 ip4;
    u32 port;
};

struct sock_key {
    struct addr_key local;
    struct addr_key remote;
};

struct hdr_str {
    u32 len;
    u8* ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, int);
} upgraded_conns SEC(".maps");
u32 num_upgraded_conns = 0;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map SEC(".maps");

volatile const u32 ip4;
volatile const u32 port;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, char[128]);
} matches SEC(".maps");

__noinline int extract_match(const struct sk_msg_md *msg, u8 idx, struct hdr_str* str __arg_nonnull) {
    int ret = -1;

	__sink(msg);
	__sink(idx);
	__sink(str);
	__sink(ret);

	return ret;
}

__noinline int parse_h1(struct sk_msg_md *msg) {
   	int ret = -1;

	__sink(msg);
	__sink(ret);

	bpf_msg_pull_data(msg, 0, msg->size, 0);

	return ret;
}

__noinline int parse_h2(struct sk_msg_md *msg) {
    int ret = -1;

	__sink(msg);
	__sink(ret);

	bpf_msg_pull_data(msg, 0, msg->size, 0);

	return ret;
}

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // socket identifeir of the ingress connection
    struct sock_key ikey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    bool is_downstream = (ikey.remote.ip4 == ip4 && ikey.remote.port == port);
    bpf_printk("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    bool is_h2 = (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL);
    if (is_h2) {
        int done_idx = parse_h2(msg);
        if (done_idx < 0) {
            bpf_printk("ERROR: Failed to parse h2 message: %s", msg->data);
            return SK_PASS;
        }

        // only store matches if we parsed a HEADER frame
        if (done_idx > 9) {
            u32 i = 0;
            bpf_for(i, 0, 32) {
                struct hdr_str str = { 0 };
                if (extract_match(msg, i, &str) == 0) {
                    u16 len = str.len;
                    if (len > 128) len = 128;

                    char tmp[128] = {0};
                    bpf_probe_read_kernel(tmp, len, str.ptr);
                    bpf_map_update_elem(&matches, &i, tmp, BPF_ANY);
                }
                else {
                    bpf_map_delete_elem(&matches, &i);
                }
            }
        }
    }
    else {
        int done_idx = parse_h1(msg);
        // if (done_idx < 0) {
        //     bpf_printk("ERROR: Failed to parse h1 message: %s", msg->data);
        //     return SK_PASS;
        // }

        // if (ms[0].idx == 0 && ms[0].len == 19) {
            int flag = 1;
            bpf_map_update_elem(&upgraded_conns, &ikey, &flag, BPF_ANY);
            num_upgraded_conns += 1;
        // }
    }

    return SK_PASS;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        // we don't want to get called anymore for this connection
        bpf_sock_ops_cb_flags_set(ops, 0);

        struct sock_key skey = {
            .local = {
                .ip4 = ops->local_ip4,
                .port = ops->local_port
            },
            .remote = {
                .ip4 = ops->remote_ip4,
                .port = bpf_ntohl(ops->remote_port)
            }
        };

        bpf_printk("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

        if (skey.remote.ip4 == ip4 && skey.remote.port == port) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_printk("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_printk("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}

SEC("syscall")
int get_num_upgraded_conns() {
    return num_upgraded_conns;
}
