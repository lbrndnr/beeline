#include "vmlinux.h"
#include "beeline.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0xFFFE
#define MAX_MATCHES 16
#define MAX_MATCH_MASK 15

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

const u32 a_mask = 0xFFFF0000;
const u16 a_match = 1 << 15;
const u16 a_done = 1 << 14;
const u16 a_start_capture = 1 << 13;
const u16 a_end_capture = 1 << 12;
// if a_match -> then this represents the fid
// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const u16 a_id_mask = 0x0FFF;
const u16 a_id_1_mask = 0x0FC0;
const u16 a_id_2_mask = 0x003F;

const u32 s_mask = 0x0000FFFF;
const u16 s_init = 0;
const u16 s_any = 1;

volatile const u32 ip4;
volatile const u32 port;
volatile const u32 s2ts[128][256];

static __always_inline int _modify(struct sk_msg_md *msg, struct prange r, char *str, u16 str_len) {
    u16 len = r.len;
    u16 idx = r.idx;

    if (len > MAX_BYTES) return -1;
    len &= 0xFF;

    if (idx > MAX_BYTES) return -1;
    idx &= 0xFFF;

    s16 delta = str_len - len;

    bpf_log("Increasing msg size by %d (%d-%d) at %d", delta, str_len, len, idx);

    // we first have to linearize the data
    // TODO: figure out if we have to pull the data for every single modification
    if (bpf_msg_pull_data(msg, 0, idx+str_len, 0) < 0) return -1;

    if (delta > 0) {
        if (bpf_msg_push_data(msg, idx, delta, 0) < 0) return -1;
    }
    else if (delta < 0) {
        if (bpf_msg_pop_data(msg, idx, -delta, 0) < 0) return -1;
    }

    // we're done if we don't have to write anything
    if (str_len == 0) return 0;

    bpf_log("Rewriting payload (%dB) in range [%d, %d]", msg->size, idx, len);

    // at this point we have to pull the data again to get valid data pointers
    if (bpf_msg_pull_data(msg, idx, idx+str_len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    u32 i;
    bpf_for(i, 0, str_len+1) {
        if (data + i + 1 > data_end) return -1;
        data[i] = str[i];
    }

    return 0;
}

static __always_inline void _next(u16 state, u32 input, u16 *next_state, u16 *action) {
    state &= 0x7F;
    input &= 0xFF;

    u32 sa = s2ts[state][input];
    if (sa == 0) {
        sa = s2ts[state]['*'];
        bpf_clamp_uminmax(sa, 0, 0xFFFFFFFF);
        if (sa == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = sa & s_mask;
    *action = (sa & a_mask) >> 16;
}

static __always_inline int _parse_from(const struct sk_msg_md *msg, u32 start, struct prange *pranges, bool *pmatches, u32* cidx) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = ((u32)(data_end - data) - start) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }

    u16 s = s_init;
    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) return -1;
        char c = data[i];

        u16 a = 0;
        _next(s, c, &s, &a);

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

            // TODO: this is a hack, for now
            cidx[cid] = i;
        }
        if ((a & a_match) != 0) {
            u16 mid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_err("Match %d at %d", mid, i);
            pmatches[mid] = true;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return i-1;
        }

        // this means that we failed to match the current pattern
        // but maybe a new one starts now?
        if (s == s_any) {
            _next(s_any, c, &s, &a);
        }
    }

    return -1;
}

static __always_inline int _parse(struct sk_msg_md *msg, struct prange *pranges, bool *pmatches) {
    u32 cidx[MAX_MATCHES] = { 0 };
    int res = _parse_from(msg, 0, pranges, pmatches, cidx);

    // TODO: Ideally, we would do this in a loop until we have consumed the whole header
    if (res < 0) {
        u32 old_end = (long)msg->data_end - (long)msg->data;
        u32 new_end = 4096 > msg->size ? msg->size : 4096;

        bpf_msg_pull_data(msg, 0, new_end, 0);
        res = _parse_from(msg, 0, pranges, pmatches, cidx);
    }

    return res;
}

static __always_inline int _log_msg_range(struct sk_msg_md *msg, u16 idx, u16 len) {
    if (bpf_msg_pull_data(msg, idx, idx+len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    u16 j;
    bpf_for(j, 0, len+1) {
        if (data + j + 1 > data_end) return -1;
        bpf_log("data[%d]=%c", idx+j, data[j]);
    }

    return 0;
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
    bool pmatches[MAX_MATCHES] = { 0 };

    int done_idx = _parse(msg, pranges, pmatches);
    if (done_idx < 0) {
        bpf_err("ERROR: Failed to parse message: %s", msg->data);
        return SK_PASS;
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
