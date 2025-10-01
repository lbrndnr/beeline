#include "vmlinux.h"
#include "beeline.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct prange {
    u16 idx;
    u16 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, int);
} upgraded_conns SEC(".maps");

const u16 a_done = 1 << 14;
const u16 a_start_capture = 1 << 13;
const u16 a_end_capture = 1 << 12;
// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const u16 a_id_mask = 0x0FFF;
const u16 a_id_1_mask = 0x0FC0;
const u16 a_id_2_mask = 0x003F;

const u16 s_init = 0;
const u16 s_any = 1;

struct trans {
    u16 state;
    u16 action;
};

volatile const u32 ip4;
volatile const u32 port;

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0xFFFE
#define MAX_MATCHES 32
#define MAX_MATCH_MASK 31
#define MAX_STATES 512
#define MAX_TRANS 128

volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];

static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= 0x1FF;
    input &= 0x7F;

    struct trans t = s2ts[state][input];
    if (t.state == 0 && t.action == 0) {
        t = s2ts[state]['*'];
        if (t.state == 0 && t.action == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = t.state;
    *action = t.action;
}

static __always_inline int _parse_h1_from(const struct sk_msg_md *msg, u16 start, struct prange *pranges, u32* cidx, u16* s) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        char c = data[i];

        u16 a = 0;
        _next(*s, c, s, &a);

        if (*s == s_any) {
            _next(s_any, c, s, &a);
        }

        // it should never happen that any of these cases are true simultaneously
        // but it makes the verifier happy when we don't use else if here
        if ((a & a_start_capture) != 0) {
            u16 cid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_log("Start capture range (%d, ?) in [%d, ...]", cid, i);
            cidx[cid] = i;
        }
        if ((a & a_end_capture) != 0) {
            u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
            u16 rid = a & a_id_2_mask & MAX_MATCH_MASK;
            bpf_log("End capture range (%d, %d) in [%d, %d]", cid, rid, cidx[cid], i - cidx[cid]);

            pranges[rid] = (struct prange) {
                .idx = cidx[cid],
                .len = i - cidx[cid]
            };

            cidx[cid] = i;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return i-1;
        }
    }

    return -len;
}

static __always_inline int _parse_h1(struct sk_msg_md *msg, struct prange *pranges) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    int res = _parse_h1_from(msg, 0, pranges, cidx, &s);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h1_from(msg, -res, pranges, cidx, &s);
    }

    return res;
}

static __always_inline int _parse_h2_from(const struct sk_msg_md *msg, u16 start, struct prange *pranges, u32* cidx, u16* s) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        char c = data[i];

        u16 a = 0;
        _next(*s, c, s, &a);

        if (*s == s_any) {
            _next(s_any, c, s, &a);
        }

        // it should never happen that any of these cases are true simultaneously
        // but it makes the verifier happy when we don't use else if here
        if ((a & a_start_capture) != 0) {
            u16 cid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_log("Start capture range (%d, ?) in [%d, ...]", cid, i);
            cidx[cid] = i;
        }
        if ((a & a_end_capture) != 0) {
            u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
            u16 rid = a & a_id_2_mask & MAX_MATCH_MASK;
            bpf_log("End capture range (%d, %d) in [%d, %d]", cid, rid, cidx[cid], i - cidx[cid]);

            pranges[rid] = (struct prange) {
                .idx = cidx[cid],
                .len = i - cidx[cid]
            };

            cidx[cid] = i;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return i-1;
        }
    }

    return -len;
}

static __always_inline int _parse_h2(struct sk_msg_md *msg, struct prange *pranges) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    int res = _parse_h2_from(msg, 0, pranges, cidx, &s);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h2_from(msg, -res, pranges, cidx, &s);
    }

    return res;
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
    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    enum sk_action res = SK_PASS;
    struct prange pranges[MAX_MATCHES] = { 0 };

    bool is_h2 = (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL);
    if (is_h2) {
        int done_idx = _parse_h2(msg, pranges);
        if (done_idx < 0) {
            bpf_err("ERROR: Failed to parse message: %s", msg->data);
            return SK_PASS;
        }
    }
    else {
        int done_idx = _parse_h1(msg, pranges);
        if (done_idx < 0) {
            bpf_err("ERROR: Failed to parse message: %s", msg->data);
            return SK_PASS;
        }

        if (pranges[0].idx == 0 && pranges[0].len == 19) {
            int flag = 1;
            bpf_map_update_elem(&upgraded_conns, &ikey, &flag, BPF_ANY);
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

        bpf_log("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

        if (skey.remote.ip4 == ip4 && skey.remote.port == port) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_log("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}
