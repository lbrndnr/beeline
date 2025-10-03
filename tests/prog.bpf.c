#include "beeline.h"

char LICENSE[] SEC("license") = "GPL";

struct addr_key {
    u32 ip4;
    u32 port;
};

struct sock_key {
    struct addr_key local;
    struct addr_key remote;
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

    enum sk_action res = SK_PASS;
    struct prange pranges[MAX_MATCHES] = { 0 };

    bool is_h2 = (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL);
    if (is_h2) {
        int done_idx = parse_h2(msg, pranges);
        if (done_idx < 0) {
            bpf_printk("ERROR: Failed to parse message: %s", msg->data);
            return SK_PASS;
        }
    }
    else {
        int done_idx = parse_h1(msg, pranges);
        if (done_idx < 0) {
            bpf_printk("ERROR: Failed to parse message: %s", msg->data);
            return SK_PASS;
        }

        if (pranges[0].idx == 0 && pranges[0].len == 19) {
            int flag = 1;
            bpf_map_update_elem(&upgraded_conns, &ikey, &flag, BPF_ANY);
            num_upgraded_conns += 1;
        }
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
