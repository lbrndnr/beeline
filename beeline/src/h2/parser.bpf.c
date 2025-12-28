#include "beeline.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum h2_parse_state {
    // integers
    H2_IDX = 0,
    H2_KEY_LEN = 1,
    H2_VAL_LEN = 2,

    // strings
    H2_KEY = 3,
    H2_VAL = 4,
};

#define H2_IS_STR(ps) (ps > H2_VAL_LEN)

struct header_field {
    u8 key[32];
    u8 val[32];
};

#define STATIC_TABLE_SIZE 61

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STATIC_TABLE_SIZE+1);
    __type(key, u32);
    __type(value, struct header_field);
} static_table SEC(".maps");

struct dynamic_table_key {
    struct ip4_conn conn;
    u32 idx;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct dynamic_table_key);
	__type(value, struct header_field);
} dynamic_table SEC(".maps");

struct dynamic_table_info {
    u16 size;
    u16 max_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
	__type(value, struct dynamic_table_info);
} dynamic_table_info SEC(".maps");

const u16 a_done = 1 << 14;
const u16 a_start_capture = 1 << 13;
const u16 a_end_capture = 1 << 12;

const u16 a_h2_read_st = 1 << 11;
const u16 a_h2_read_dt = 1 << 10;

// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const u16 a_id_mask = 0x0FFF;
const u16 a_id_1_mask = 0x0FC0;
const u16 a_id_2_mask = 0x003F;

const u16 s_init = 0;
const u16 s_any = 1;

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0xFFFE
#define MAX_MATCH_MASK 31
#define MAX_STATES 256
#define MAX_TRANS 256
#define MAX_MATCHES 32

volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];

struct parse_res {
    struct hdr_match ms[MAX_MATCHES];
};

struct msg_ctx {
    u8 *data;
    u8 *data_end;
    struct ip4_conn conn;
};

struct parse_res parse_res = { 0 };

static __always_inline struct msg_ctx _new_msg_ctx(const struct sk_msg_md *msg) {
    return (struct msg_ctx) {
        .data = msg->data,
        .data_end = msg->data_end,
        .conn = {
            .local = {
                .ip4 = msg->local_ip4,
                .port = msg->local_port
            },
            .remote = {
                .ip4 = msg->remote_ip4,
                .port = bpf_ntohl(msg->remote_port)
            }
        }
    };
}

static __always_inline struct dynamic_table_key _new_table_key(const struct ip4_conn *conn, u32 idx) {
    return (struct dynamic_table_key) {
        .conn = *conn,
        .idx = idx
    };
}

static __always_inline const u8* _extract_match(const struct msg_ctx *ctx, const struct hdr_match *m, bool is_key) {
    if (m->in_msg) {
        if (ctx->data + m->idx + m->len > ctx->data_end) return NULL;
        return ctx->data + m->idx;
    }

    struct header_field *hf = NULL;
    if (m->idx > STATIC_TABLE_SIZE) {
        struct dynamic_table_key key = _new_table_key(&ctx->conn, m->idx);

        // struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &key.conn);
        // if (dt_info == NULL) return NULL;
        // key.idx = dt_info->size - m->idx;
        hf = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        u32 key = m->idx;
        hf = bpf_map_lookup_elem(&static_table, &key);
    }

    if (hf == NULL) return NULL;
    barrier(); // this is needed so that clang doesn't reorder the null check
    return (is_key) ? hf->key : hf->val;
}

SEC("freplace")
bool matched(const struct sk_msg_md *msg, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct hdr_match m = parse_res.ms[idx & MAX_MATCH_MASK];
    return (m.len > 0);
}

SEC("freplace")
int extract_match(const struct sk_msg_md *msg, u8 idx, struct hdr_str* str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -1;

    struct hdr_match m = parse_res.ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    struct msg_ctx ctx = _new_msg_ctx(msg);
    const u8 *ptr = _extract_match(&ctx, &m, false);
    if (ptr == NULL) return -1;

    *str = (struct hdr_str) {
        .len = m.len,
        .ptr = ptr
    };
    return 0;
}

static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= 0xFF;
    input &= 0xFF;

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

__noinline __weak int _next_hpack(u8 c, enum h2_parse_state *ps __arg_nonnull, u32 *n __arg_nonnull, u32 *k __arg_nonnull, u8 *j __arg_nonnull) {
    if (*ps == H2_KEY_LEN) {
        *ps = H2_KEY;
        *j = *k-1;
        *k = 0;
        *n = 0;
    }
    else if (*ps == H2_VAL_LEN) {
        *ps = H2_VAL;
        *j = *k-1;
        *k = 0;
        *n = 0;
    }
    else if (*ps == H2_IDX && (*n == 6 || *n == 4) && (*k == 64 || *k == 0)) {
        *ps = H2_KEY_LEN;
        *j = 0;
        *k = 0;
        *n = 7;
    }
    else if (*ps == H2_IDX && (*n == 6 || *n == 4)) {
        *ps = H2_VAL_LEN;
        *j = 0;
        *k = 0;
        *n = 7;
    }
    else {
        *ps = H2_IDX;
        *j = 0;
        *k = 0;
        *n = 4;

        if ((c & 128) == 128) {
            *n = 7;
        }
        else if ((c & 192) == 64) {
            *n = 6;
        }
    }

    return 0;
}

static __always_inline void _parse_hpack(u8 c, enum h2_parse_state *ps, u32 *n, u32 *m, u32 *k, u8 *j) {
    // bpf_log("parse_hpack: c=%d, ps=%d, n=%d, m=%d, k=%d, j=%d", c, *ps, *n, *m, *k, *j);

    if (*j > 0) {
        if (H2_IS_STR(*ps)) {
            *j -= 1;
        }
        else {
            *k += (c & 127) * (1 << *m);
            *m += 7;
            *j = ((c & 128) == 128);
        }

        return;
    }

    _next_hpack(c, ps, n, k, j);
    *m = 0;
    // bpf_log("next: c=%d, ps=%d, n=%d, m=%d, k=%d, j=%d", c, *ps, *n, *m, *k, *j);

    if (!H2_IS_STR(*ps)) {
        u8 mask = (1 << *n) - 1;
        *k = c & mask;
        *j = (*k == mask);
    }
}

__noinline __weak s8 _parse_table_entry(const struct ip4_conn *conn __arg_nonnull, u16 *s __arg_nonnull, u32 idx, u16 dt_size, struct parse_res *pres __arg_nonnull) {
    struct header_field *hf = NULL;
    if (idx > STATIC_TABLE_SIZE) {
        idx = STATIC_TABLE_SIZE + dt_size - (idx - STATIC_TABLE_SIZE);

        struct dynamic_table_key key = _new_table_key(conn, idx);
        bpf_log("lookup dt: %d", idx);
        hf = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        hf = bpf_map_lookup_elem(&static_table, &idx);
    }

    if (!hf) return -1;

    u8 j = 0;
    u16 a = 0;
    bpf_for(j, 0, 32) {
        u8 c = hf->key[j & 0x1F];
        if (c == 0) return -1;

        _next(*s, c, s, &a);

        if ((a & a_start_capture) != 0) {
            u8 cid = a & a_id_mask & MAX_MATCH_MASK;

            if (hf->val[0] != 0) {
                bpf_log("capture: %d {%d}", cid, idx);
                pres->ms[cid] = (struct hdr_match) {
                    .idx = idx,
                    .len = 31,
                    .in_msg = false,
                };
                a = 0;
                return -1;
            }
            else {
                return cid;
            }
        }
    }

    return -1;
}

__noinline __weak int _add_table_entry(const struct msg_ctx *ctx __arg_nonnull, u32 idx, const struct hdr_match *key __arg_nonnull, const struct hdr_match *val __arg_nonnull) {
    const u8 *key_ptr = _extract_match(ctx, key, true);
    const u8 *val_ptr = _extract_match(ctx, val, false);
    if (!key_ptr || !val_ptr) return 0;

    struct dynamic_table_key dt_key = _new_table_key(&ctx->conn, idx);

    struct header_field dt_val = { 0 };
    u16 key_len = (key->in_msg) ? key->len & 0x1F : 0x1F;
    bpf_probe_read_kernel(dt_val.key, key_len, key_ptr);
    bpf_probe_read_kernel(dt_val.val, val->len & 0x1F, val_ptr);

    bpf_map_update_elem(&dynamic_table, &dt_key, &dt_val, BPF_ANY);
    bpf_log("add to dynamic table: %d", idx);
    bpf_log("key { %d %d %d}", key->idx, key->len, key->in_msg);
    bpf_log("val { %d %d %d}", val->idx, val->len, val->in_msg);

    return 1;
}

static __always_inline int _parse_from(const struct msg_ctx *ctx, u16 start, u16* s, struct parse_res *pres) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    if (data + 9 > data_end) return -1;

    // u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &ctx->conn);
    if (!dt_info) {
        struct dynamic_table_info new_info = {
            .size = 0,
            .max_size = 100,
        };
        bpf_map_update_elem(&dynamic_table_info, &ctx->conn, &new_info, BPF_ANY);

        dt_info = bpf_map_lookup_elem(&dynamic_table_info, &ctx->conn);
        if (!dt_info) return -1;
    }

    u32 n = 0, m = 0;
    u32 i = 0, k = 0;
    u8 j = 0;
    s8 cid = -1;
    enum h2_parse_state ps = H2_IDX;
    struct hdr_match key = {
        .idx = 0,
        .len = 0,
        .in_msg = true,
    };

    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        _parse_hpack(c, &ps, &n, &m, &k, &j);
        if (j != 0) continue;

        if (ps == H2_IDX) {
            bpf_log("parsed idx: %d, dt_size: %d", k, dt_info->size);

            *s = s_any;
            cid = _parse_table_entry(&ctx->conn, s, k, dt_info->size, pres);
            key.idx = k;
            key.in_msg = false;
        }
        else if (ps == H2_KEY_LEN) {
            key.len = k;
            key.in_msg = true;
        }
        else if (ps == H2_VAL_LEN) {
            if (cid >= 0) {
                struct hdr_match val = (struct hdr_match) {
                    .idx = i + 1,
                    .len = k,
                    .in_msg = true,
                };

                _add_table_entry(ctx, dt_info->size + STATIC_TABLE_SIZE, &key, &val);

                bpf_log("capture: %d {%d, %d}", cid, i, k);
                pres->ms[cid & MAX_MATCH_MASK] = val;
                cid = -1;
            }

            dt_info->size +=1;
        }
    }

    return i;
}

static __always_inline int _parse_msg_from(const struct sk_msg_md *msg, u16 start, u16* s, struct parse_res *pres) {
    struct msg_ctx ctx = _new_msg_ctx(msg);
    return _parse_from(&ctx, start, s, pres);
}

SEC("freplace")
int parse(struct sk_msg_md *msg) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + 9 > data_end) return -1;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];

    bpf_log("Parsing HTTP/2 message with length %d, type %d", len, type);

    if (type != 0x01) {
        return len + 9;
    }

    parse_res = (struct parse_res) { 0 };

    u16 s = s_any;
    int res = _parse_msg_from(msg, 9, &s, &parse_res);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_msg_from(msg, -res, &s, &parse_res);
    }

    return res + 9;
}
