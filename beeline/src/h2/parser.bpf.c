#include "vmlinux.h"
#include "beeline.h"
#include "bpf_tracing.h"
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

#define PS_IS_STR(ps) (ps > H2_VAL_LEN)
#define PS_LEN_TO_STR(ps) (ps + 2)

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
    u16 count;
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
const u16 a_id_mask = 0x0FFF;

const u16 s_any = 0;

// these restrictions are needed to make the verifier happy
#define MAX_STATES 256
#define MAX_TRANS 256

volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];

struct msg_ctx {
    u8 *data;
    u8 *data_end;
    struct ip4_conn conn;
};

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

static __always_inline struct msg_ctx _new_skb_ctx(const struct __sk_buff *skb) {
    return (struct msg_ctx) {
        .data = (u8 *)(long)skb->data,
        .data_end = (u8 *)(long)skb->data_end,
        .conn = {
            .local = {
                .ip4 = skb->local_ip4,
                .port = skb->local_port
            },
            .remote = {
                .ip4 = skb->remote_ip4,
                .port = bpf_ntohl(skb->remote_port)
            }
        }
    };
}

#define HPACK_HUFF_EOS    256
#define HPACK_HUFF_MAXLEN 30

/* Number of symbols whose canonical code has length L, for L = 0..30.
 * Derived from the code lengths in RFC 7541 Appendix B. */
static const u8 huff_count[HPACK_HUFF_MAXLEN + 1] = {
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3,
    0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4
};

/* First canonical code value at each length L. */
static const u32 huff_first_code[HPACK_HUFF_MAXLEN + 1] = {
    0, 0, 0, 0, 0, 0, 20, 92, 248, 508, 1016, 2042, 4090, 8184, 16380, 32764,
    65534, 131068, 262136, 524272, 1048550, 2097116, 4194258, 8388568, 16777194,
    33554412, 67108832, 134217694, 268435426, 536870910, 1073741820
};

/* Index into huff_symbols[] of the first symbol having length L. */
static const u16 huff_first_symbol[HPACK_HUFF_MAXLEN + 1] = {
    0, 0, 0, 0, 0, 0, 10, 36, 68, 74, 74, 79, 82, 84, 90, 92,
    95, 95, 95, 95, 98, 106, 119, 145, 174, 186, 190, 205, 224, 253, 253
};

/* Symbol values (0-255 = byte, 256 = EOS), grouped by ascending code
 * length and, within a length, by ascending symbol value -- this is the
 * order canonical Huffman assigns codes in, and matches the order the
 * symbols appear in RFC 7541 Appendix B. */
static const u16 huff_symbols[256] = {
     48,  49,  50,  97,  99, 101, 105, 111, 115, 116,  32,  37,  45,  46,  47,  51,
     52,  53,  54,  55,  56,  57,  61,  65,  95,  98, 100, 102, 103, 104, 108, 109,
    110, 112, 114, 117,  58,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,
     77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  89, 106, 107, 113, 118,
    119, 120, 121, 122,  38,  42,  44,  59,  88,  90,  33,  34,  40,  41,  63,  39,
     43, 124,  35,  62,   0,  36,  64,  91,  93, 126,  94, 125,  60,  96, 123,  92,
    195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161, 167, 172, 176, 177,
    179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156, 160,
    163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232,
    233,   1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157,
    158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191, 197, 231, 239,   9, 142,
    144, 145, 148, 159, 171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193,
    200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242, 243, 255, 203, 204, 211,
    212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252, 253, 254,
      2,   3,   4,   5,   6,   7,   8,  11,  12,  14,  15,  16,  17,  18,  19,  20,
     21,  23,  24,  25,  26,  27,  28,  29,  30,  31, 127, 220, 249,  10,  13,  22
};

static __always_inline struct dynamic_table_key _new_dynamic_table_key(const struct ip4_conn *conn, u32 idx) {
    return (struct dynamic_table_key) {
        .conn = *conn,
        .idx = idx
    };
}

static __always_inline u32 _get_dynamic_table_index(u32 idx, u32 dt_size) {
    u32 end_idx = STATIC_TABLE_SIZE + dt_size - 1;
    return (end_idx - idx) + STATIC_TABLE_SIZE + 1;
}

static __always_inline const u8* _extract_match(const struct msg_ctx *ctx, const struct hdr_match *m, bool is_key) {
    if (m->in_msg) {
        if (ctx->data + m->idx + m->len > ctx->data_end) return NULL;
        return ctx->data + m->idx;
    }

    struct header_field *hf = NULL;
    if (m->idx > STATIC_TABLE_SIZE) {
        struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &ctx->conn);
        if (dt_info == NULL) return NULL;

        u32 idx = _get_dynamic_table_index(m->idx, dt_info->size);
        struct dynamic_table_key key = _new_dynamic_table_key(&ctx->conn, idx);
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

static __always_inline int _next_hpack(u8 c, enum h2_parse_state *ps __arg_nonnull, u32 *n __arg_nonnull, u32 *k __arg_nonnull, u8 *j __arg_nonnull) {
    if (*ps == H2_KEY_LEN || *ps == H2_VAL_LEN) {
        *ps = PS_LEN_TO_STR(*ps);
        *j = *k-1;
        *n = 0;
    }
    else if (*ps == H2_IDX && ((*n == 6 && *k == 64) || (*n == 4 && *k == 0))) {
        *ps = H2_KEY_LEN;
        *j = 0;
        *n = 7;
    }
    else if ((*ps == H2_IDX && (*n == 6 || *n == 4)) || *ps == H2_KEY) {
        *ps = H2_VAL_LEN;
        *j = 0;
        *n = 7;
    }
    else {
        *ps = H2_IDX;
        *j = 0;
        *n = 4;

        if ((c & 128) == 128) {
            *n = 7;
        }
        else if ((c & 192) == 64) {
            *n = 6;
        }
    }

    *k = 0;

    return 0;
}

static __always_inline void _parse_hpack(u8 c, enum h2_parse_state *ps, u32 *n, u32 *m, u32 *k, u8 *j) {
    // bpf_debug("parse_hpack: c=%d, ps=%d, n=%d, m=%d, k=%d, j=%d", c, *ps, *n, *m, *k, *j);

    if (*j > 0) {
        if (PS_IS_STR(*ps)) {
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
    // bpf_debug("next: c=%d, ps=%d, n=%d, m=%d, k=%d, j=%d", c, *ps, *n, *m, *k, *j);

    if (!PS_IS_STR(*ps)) {
        u8 mask = (1 << *n) - 1;
        *k = c & mask;
        *j = (*k == mask);
    }
}

static __always_inline int _get_table_entry(const struct ip4_conn *conn __arg_nonnull, u32 idx, u16 dt_size, struct header_field **hf) {
    if (idx > STATIC_TABLE_SIZE) {
        u32 nidx = _get_dynamic_table_index(idx, dt_size);

        struct dynamic_table_key key = _new_dynamic_table_key(conn, nidx);
        bpf_debug("lookup dt: %d -> %d", idx, nidx);
        *hf = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        *hf = bpf_map_lookup_elem(&static_table, &idx);
    }

    return (hf == NULL) ? -1 : idx;
}

static __always_inline s8 _match_header_key(const u8 *key __arg_nonnull, u16 key__sz, u16 *s __arg_nonnull) {
    u8 j = 0;
    u16 a = 0;
    bpf_for(j, 0, key__sz) {
        u8 c = key[j];
        _next(*s, c, s, &a);

        if ((a & a_start_capture) != 0) {
            u8 cid = a & a_id_mask & MAX_MATCH_MASK;
            return cid;
        }
    }

    return -1;
}

__noinline __weak int _add_dynamic_table_entry(const struct msg_ctx *ctx __arg_nonnull, u32 idx, const struct hdr_match *key __arg_nonnull, const struct hdr_match *val __arg_nonnull) {
    const u8 *key_ptr = _extract_match(ctx, key, true);
    const u8 *val_ptr = _extract_match(ctx, val, false);
    if (!key_ptr || !val_ptr) return -1;

    struct dynamic_table_key dt_key = _new_dynamic_table_key(&ctx->conn, idx);

    struct header_field dt_val = { 0 };
    u16 key_len = (key->in_msg) ? key->len & 0x1F : 0x1F;
    bpf_probe_read_kernel(dt_val.key, key_len, key_ptr);
    bpf_probe_read_kernel(dt_val.val, val->len & 0x1F, val_ptr);

    bpf_map_update_elem(&dynamic_table, &dt_key, &dt_val, BPF_ANY);
    bpf_debug("add to dynamic table: %d", idx);
    bpf_debug("key { %d %d %d}", key->idx, key->len, key->in_msg);
    bpf_debug("val { %d %d %d}", val->idx, val->len, val->in_msg);

    return 0;
}

static __always_inline int _parse_from(const struct msg_ctx *ctx, u16 start, u16 end, u16* s, struct parse_res *pres, u16 *null_prefix) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;
    if (end < len) len = end & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    if (data + 9 > data_end) return 0;

    u8 type = data[3];
    u8 flags = data[4];
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &ctx->conn);
    if (!dt_info) {
        struct dynamic_table_info new_info = {
            .size = 0,
            .count = 0,
            .max_size = 100,
        };
        bpf_map_update_elem(&dynamic_table_info, &ctx->conn, &new_info, BPF_ANY);

        dt_info = bpf_map_lookup_elem(&dynamic_table_info, &ctx->conn);
        if (!dt_info) return 0;
    }

    u32 n = 0, m = 0;
    u32 i = 0, k = 0;
    u8 j = 0;
    s8 cid = -1;
    u8 add_to_dt = 0;
    enum h2_parse_state ps = H2_IDX;
    struct hdr_match key = {
        .idx = 0,
        .len = 0,
        .in_msg = true,
    };

    bpf_for(i, start, len+1) {

        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == *null_prefix) {
            *null_prefix = i + 1;
            continue;
        }

        _parse_hpack(c, &ps, &n, &m, &k, &j);
        bpf_debug("%d: %d %d -> %d (%d)", i, ps, n, k, j);

        if (j != 0 && !PS_IS_STR(ps)) continue;

        if (ps == H2_IDX) {
            add_to_dt = (u8)(n == 6);
            *s = s_any;
            struct header_field *hf;
            int idx = _get_table_entry(&ctx->conn, k, dt_info->size, &hf);
            if (hf == NULL) {
                cid = -1;
                continue;
            }

            cid = _match_header_key(hf->key, 32, s);
            if (cid >= 0) {
                // check if we are replacing the exisiting entry, or taking
                // the one in the table
                if (n == 7) {
                    pres->ms[cid & MAX_MATCH_MASK] = (struct hdr_match) {
                        .idx = idx,
                        .len = 31,
                        .in_msg = false,
                    };
                }
            }
            key.idx = k;
            key.in_msg = false;
        }
        else if (ps == H2_KEY_LEN) {
            key.len = k;
            key.in_msg = true;
        }
        else if (ps == H2_KEY) {
            u16 a = 0;
            _next(*s, c, s, &a);

            if ((a & a_start_capture) != 0) {
                cid = a & a_id_mask & MAX_MATCH_MASK;
            }
        }
        else if (ps == H2_VAL_LEN) {
            dt_info->size += add_to_dt;

            if (cid >= 0) {
                struct hdr_match val = (struct hdr_match) {
                    .idx = i + 1,
                    .len = k,
                    .in_msg = true,
                };
                if (add_to_dt) {
                    dt_info->count++;
                    _add_dynamic_table_entry(ctx, STATIC_TABLE_SIZE + dt_info->count, &key, &val);
                }

                pres->ms[cid & MAX_MATCH_MASK] = val;
                cid = -1;
            }
        }
    }

    return i;
}

static __always_inline int _parse_msg_from(const struct sk_msg_md *msg, u16 start, u16 end, u16* s, struct parse_res *pres) {
    struct msg_ctx ctx = _new_msg_ctx(msg);
    return _parse_from(&ctx, start, end, s, pres, NULL);
}

static __always_inline int _parse_skb_from(const struct __sk_buff *skb, u16 start, u16 end, u16* s, struct parse_res *pres, u16 *null_prefix) {
    struct msg_ctx ctx = _new_skb_ctx(skb);
    return _parse_from(&ctx, start, end, s, pres, null_prefix);
}

SEC("freplace")
int parse_msg(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + 9 > data_end) return 0;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    bool padded = flags & 0x08;
    u8 hdr_len = (padded) ? 10 : 9;

    bpf_debug("Parsing HTTP/2 message with length %d, type %d, flags %d", len, type, flags);

    if (type != 0x01) {
        return len + hdr_len;
    }

    if (bpf_msg_pull_data(msg, 0, len+hdr_len, 0) < 0) {
        return -(data_end - data);
    }

    u16 s = s_any;
    int res = _parse_msg_from(msg, hdr_len, len+hdr_len, &s, pres);
    if (len + hdr_len > res) return -1;

    return res;
}

SEC("freplace")
int parse_skb(struct __sk_buff *skb, struct parse_res *pres __arg_nonnull, u16 *null_prefix) {
    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;

    if (data + 9 > data_end) return 0;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    bool padded = flags & 0x08;
    u8 hdr_len = (padded) ? 10 : 9;

    bpf_debug("Parsing HTTP/2 sk_buff with length %d, type %d, flags %d", len, type, flags);

    if (type != 0x01) {
        return len + hdr_len;
    }

    if (bpf_skb_pull_data(skb, len+hdr_len) < 0) {
        return -(data_end - data);
    }

    u16 s = s_any;
    int res = _parse_skb_from(skb, hdr_len, len+hdr_len, &s, pres, null_prefix);
    if (len + hdr_len > res) return -1;

    return res;
}

SEC("freplace")
int parse_buf(const struct bpf_dynptr *buf_ptr, struct ip4_conn *conn, struct parse_res *pres __arg_nonnull, u16 *null_prefix) {
    u8 *data = bpf_dynptr_data(buf_ptr, 0, 9);
    if (data == NULL) return -1;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    bool padded = flags & 0x08;
    u8 hdr_len = (padded) ? 10 : 9;

    bpf_debug("Parsing HTTP/2 buf with length %d, type %d, flags %d", len, type, flags);

    if (type != 0x01) {
        return len + hdr_len;
    }

    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_any;

    data = bpf_dynptr_data(buf_ptr, 0, len + hdr_len);
    if (data == NULL) return -1;

    u8 *data_end = data + len + hdr_len;
    struct msg_ctx ctx = {
        .data = data,
        .data_end = data_end,
        .conn = *conn
    };

    int res = _parse_from(&ctx, hdr_len, len+hdr_len, &s, pres, null_prefix);

    return res;
}

SEC("freplace")
bool matched(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
    return (m.len > 0);
}

SEC("freplace")
int extract_match(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx, struct hdr_str* str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -1;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
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
