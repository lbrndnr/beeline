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

#define HEADER_FIELD_MAXLEN 128
#define HEADER_FIELD_MASK (HEADER_FIELD_MAXLEN - 1)

struct header_field {
    u8 key[HEADER_FIELD_MAXLEN];
    u8 key_len;
    u8 val[HEADER_FIELD_MAXLEN];
    u8 val_len;
};

#define STATIC_TABLE_SIZE 61
#define SETTINGS_HEADER_TABLE_SIZE 0x1

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

struct dynamic_table_entry {
    struct header_field field;
    u32 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct dynamic_table_key);
	__type(value, struct dynamic_table_entry);
} dynamic_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dynamic_table_entry);
} dynamic_table_entry SEC(".maps");

struct dynamic_table_info {
    u32 count;
    u32 size;
    u32 max_size;
    u32 deleted;
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

#define HPACK_HUFF_MAXLEN 30

static const u8 huff_count[HPACK_HUFF_MAXLEN + 2] = {
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3,
    0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4, 0
};

static const u32 huff_first_code[HPACK_HUFF_MAXLEN + 2] = {
    0, 0, 0, 0, 0, 0, 20, 92, 248, 508, 1016, 2042, 4090, 8184, 16380, 32764,
    65534, 131068, 262136, 524272, 1048550, 2097116, 4194258, 8388568, 16777194,
    33554412, 67108832, 134217694, 268435426, 536870910, 1073741820, 0
};

#define HPACK_HUFF_STEP(c, b) do {                              \
    code = (code << 1) | (((c) >> (b)) & 1u);                   \
    len++;                                                      \
    if (len > HPACK_HUFF_MAXLEN) {                                \
        code = 0;                                                \
        len = 0;                                                 \
    }                                                             \
    else {                                                        \
        u32 rel = code - huff_first_code[len];                    \
        if (rel < huff_count[len]) {                              \
            n++;                                                 \
            code = 0;                                             \
            len = 0;                                             \
        }                                                         \
    }                                                              \
} while (0)

static __always_inline u32 hpack_huffman_decoded_len(const u8 *src, u16 src__sz) {
    u32 code = 0, len = 0, n = 0;
    u32 i = 0;

    bpf_for (i, 0, src__sz) {
        u8 c = src[i];
        HPACK_HUFF_STEP(c, 7);
        HPACK_HUFF_STEP(c, 6);
        HPACK_HUFF_STEP(c, 5);
        HPACK_HUFF_STEP(c, 4);
        HPACK_HUFF_STEP(c, 3);
        HPACK_HUFF_STEP(c, 2);
        HPACK_HUFF_STEP(c, 1);
        HPACK_HUFF_STEP(c, 0);
    }

    return n;
}

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

static __always_inline struct dynamic_table_key _new_dynamic_table_key(const struct ip4_conn *conn, u32 idx) {
    return (struct dynamic_table_key) {
        .conn = *conn,
        .idx = idx
    };
}

static __always_inline u32 _get_dynamic_table_index(const struct dynamic_table_info *dt_info __arg_nonnull, u32 idx) {
    u32 end_idx = STATIC_TABLE_SIZE + dt_info->count + dt_info->deleted;
    return (end_idx - idx) + STATIC_TABLE_SIZE;
}

static __always_inline void _extract_match(const struct msg_ctx *ctx, const struct hdr_match *m, bool is_key, u8 **out, u32 *len) {
    if (m->in_msg) {
        if (ctx->data + m->idx + m->len > ctx->data_end) return;
        *out = ctx->data + m->idx;
        *len = m->len;
        return;
    }

    struct dynamic_table_entry *entry = NULL;
    if (m->idx > STATIC_TABLE_SIZE) {
        struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &ctx->conn);
        if (dt_info == NULL) return;

        u32 idx = _get_dynamic_table_index(dt_info, m->idx);
        struct dynamic_table_key key = _new_dynamic_table_key(&ctx->conn, idx);
        entry = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        u32 key = m->idx;
        entry = bpf_map_lookup_elem(&static_table, &key);
    }

    if (entry == NULL) return;
    barrier(); // this is needed so that clang doesn't reorder the null check

    if (is_key) {
        *out = entry->field.key;
        *len = entry->field.key_len;
    } else {
        *out = entry->field.val;
        *len = entry->field.val_len;
    }
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

static const u8 hpack_prefix_len[16] = {
    4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7
};

static __always_inline int _next_hpack(u8 c, enum h2_parse_state *ps __arg_nonnull, u32 *n __arg_nonnull, u32 *k __arg_nonnull, u8 *j __arg_nonnull) {
    if (*ps == H2_KEY_LEN || *ps == H2_VAL_LEN) {
        *ps = PS_LEN_TO_STR(*ps);
        *j = *k-1;
        *n = 0;
    }
    else if (*ps == H2_IDX && *k == 0 && (*n == 6 || *n == 4)) {
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
        *n = hpack_prefix_len[c >> 4];
    }

    *k = 0;

    return 0;
}

static __always_inline void _parse_hpack(u8 c, enum h2_parse_state *ps, u32 *n, u32 *m, u32 *k, u8 *j) {
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

    if (!PS_IS_STR(*ps)) {
        u8 mask = (1 << *n) - 1;
        *k = c & mask;
        *j = (*k == mask);
    }
}

static __always_inline void _get_lru_dynamic_table_entry(const struct ip4_conn *conn __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, struct dynamic_table_entry **entry) {
    u32 end_idx = STATIC_TABLE_SIZE + dt_info->count + dt_info->deleted - 1;
    bpf_trace("dt: getting LRU entry at index %d", end_idx);
    struct dynamic_table_key key = _new_dynamic_table_key(conn, end_idx);
    *entry = bpf_map_lookup_elem(&dynamic_table, &key);
}

static __always_inline void _get_table_entry(const struct ip4_conn *conn __arg_nonnull, const struct dynamic_table_info *dt_info __arg_nonnull, u32 idx, struct header_field **hf) {
    if (idx > STATIC_TABLE_SIZE) {
        u32 dt_idx = _get_dynamic_table_index(dt_info, idx);
        struct dynamic_table_key key = _new_dynamic_table_key(conn, dt_idx);

        bpf_trace("lookup dt: %d (hpack: %d)", dt_idx, idx);

        // `field` is the first member of `dynamic_table_entry`, so this cast
        // preserves NULL and avoids an extra branch on the lookup result.
        *hf = (struct header_field *)bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        *hf = bpf_map_lookup_elem(&static_table, &idx);
    }
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

static __always_inline struct dynamic_table_info* _get_dynamic_table(const struct ip4_conn *conn __arg_nonnull) {
    struct dynamic_table_info *info = bpf_map_lookup_elem(&dynamic_table_info, conn);
    if (info) return info;

    struct dynamic_table_info new_info = {
        .count = 0,
        .size = 0,
        .max_size = 4096,
        .deleted = 0,
    };
    bpf_map_update_elem(&dynamic_table_info, conn, &new_info, BPF_ANY);
    return bpf_map_lookup_elem(&dynamic_table_info, conn);
}

// evicts the least recently used entries from the dynamic table to make room for the new entry of size `new_entry_size`.
// returns the number of bytes freed.
__noinline __weak u32 _try_evict_dynamic_table_entries(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, u32 new_entry_size) {
    bpf_trace("dt: try evicting %dB (%d actual entries)", new_entry_size, dt_info->count);

    u32 freed = 0;
    bpf_repeat(dt_info->count) {
        if (dt_info->size + new_entry_size < dt_info->max_size) break;

        struct dynamic_table_entry *last_entry;
        _get_lru_dynamic_table_entry(&ctx->conn, dt_info, &last_entry);
        if (!last_entry) {
            bpf_error("dt: no entries");
            break;
        }

        bpf_trace("dt: evicting LRU entry");
        dt_info->count--;
        dt_info->deleted++;
        freed += last_entry->size;

        struct dynamic_table_key key = _new_dynamic_table_key(&ctx->conn, dt_info->count - 1);
        bpf_map_delete_elem(&dynamic_table, &key);
    }

    bpf_trace("dt: evicted %dB", freed);
    dt_info->size -= freed;

    return freed;
}

__noinline __weak int _add_dynamic_table_entry(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, const struct hdr_match *key __arg_nonnull, const struct hdr_match *val __arg_nonnull) {
    u8 *key_ptr = NULL;
    u32 key_len = 0;
    _extract_match(ctx, key, true, &key_ptr, &key_len);
    if (!key_ptr) return -1;

    u8 *val_ptr = NULL;
    u32 val_len = 0;
    _extract_match(ctx, val, false, &val_ptr, &val_len);
    if (!val_ptr) return -1;

    key_len = key_len & HEADER_FIELD_MASK;
    val_len = val_len & HEADER_FIELD_MASK;

    int per_cpu_key = 0;
    struct dynamic_table_entry *dt_val = bpf_map_lookup_elem(&dynamic_table_entry, &per_cpu_key);
    if (!dt_val) return -1;

    u32 idx = STATIC_TABLE_SIZE + dt_info->count;
    struct dynamic_table_key dt_key = _new_dynamic_table_key(&ctx->conn, idx);

    __builtin_memset(dt_val, 0, sizeof(*dt_val));
    int ret = bpf_probe_read_kernel(dt_val->field.key, key_len, key_ptr);
    dt_val->field.key_len = !ret * key_len;

    ret = bpf_probe_read_kernel(dt_val->field.val, val_len, val_ptr);
    dt_val->field.val_len = !ret * val_len;

    u16 key_len_decoded = hpack_huffman_decoded_len(dt_val->field.key, key_len);
    u16 val_len_decoded = hpack_huffman_decoded_len(dt_val->field.val, val_len);
    dt_val->size = key_len_decoded + val_len_decoded + 32;

    _try_evict_dynamic_table_entries(ctx, dt_info, dt_val->size);
    if (dt_info->size + dt_val->size > dt_info->max_size) {
        bpf_debug("dt: entry size %d exceeds max size %d", dt_val->size, dt_info->max_size);
        return -1;
    }

    bpf_map_update_elem(&dynamic_table, &dt_key, dt_val, BPF_ANY);

    dt_info->size += dt_val->size;
    dt_info->count += 1;

    bpf_debug("dt: add with index %d, key size: %d, val size: %d, new total size %d", dt_key.idx, key_len_decoded, val_len_decoded, dt_info->size);
    bpf_debug("dt: add key { %d %d %d }", key->idx, key->len, key->in_msg);
    bpf_debug("dt: add val { %d %d %d }", val->idx, val->len, val->in_msg);

    return 0;
}

static __always_inline int _parse_stg_from(const struct msg_ctx *ctx, u16 start, u16 end, u16 *s, struct parse_res *pres, u16 *null_prefix) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;
    if (end < len) len = end & MAX_BYTES;
    if (data + 9 > data_end) return 0;

    u8 type = data[3];
    u8 flags = data[4];
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    if (!dt_info) return 0;

    u32 i = 0;
    u8 j = 0;
    u16 id = 0;
    u32 val = 0;

    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == *null_prefix) {
            *null_prefix = i + 1;
            continue;
        }

        if (j < 2) {
            id = (id << 8) | c;
        }
        else {
            val = (val << 8) | c;
        }
        j++;

        if (j == 6) {
            if (id == SETTINGS_HEADER_TABLE_SIZE) {
                dt_info->max_size = (u16)val;
                bpf_debug("stg: table header size: %u", (u16)val);
            }
            j = 0;
            id = 0;
            val = 0;
        }
    }

    return i;
}

static __always_inline int _parse_hdr_from(const struct msg_ctx *ctx, u16 start, u16 end, u16 *s, struct parse_res *pres, u16 *null_prefix) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;
    if (end < len) len = end & MAX_BYTES;
    if (data + 9 > data_end) return 0;

    u8 type = data[3];
    u8 flags = data[4];
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    if (!dt_info) return 0;

    u32 n = 0, m = 0, i = 0, k = 0;
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
        bpf_trace("hdr: hpack idx: %d, ps: %d, n: %d, k: %d, j: %d", i, ps, n, k, j);

        if (j != 0 && !PS_IS_STR(ps)) continue;
        if (ps == H2_IDX) {
            add_to_dt = (u8)(n == 6);
            *s = s_any;
            struct header_field *hf;
            _get_table_entry(&ctx->conn, dt_info, k, &hf);
            if (hf == NULL) {
                cid = -1;
                continue;
            }

            cid = _match_header_key(hf->key, hf->key_len, s);
            if (cid >= 0) {
                // check if we are replacing the exisiting entry, or taking
                // the one in the table
                if (n == 7) {
                    pres->ms[cid & MAX_MATCH_MASK] = (struct hdr_match) {
                        .idx = k,
                        .len = HEADER_FIELD_MASK,
                        .in_msg = false,
                    };
                }
            }
            key.idx = k;
            key.in_msg = false;
        }
        else if (ps == H2_KEY_LEN) {
            key.idx = i + 1;
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
            struct hdr_match val = (struct hdr_match) {
                .idx = i + 1,
                .len = k,
                .in_msg = true,
            };

            if (add_to_dt) {
                _add_dynamic_table_entry(ctx, dt_info, &key, &val);
            }

            if (cid >= 0) {
                pres->ms[cid & MAX_MATCH_MASK] = val;
                cid = -1;
            }
        }
    }

    return i;
}

static __always_inline int _parse_skb_from(const struct __sk_buff *skb, u16 start, u16 end, u16 *s, struct parse_res *pres, u16 *null_prefix) {
    struct msg_ctx ctx = _new_skb_ctx(skb);
    return _parse_hdr_from(&ctx, start, end, s, pres, null_prefix);
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

    bool is_hdr = (type == 0x01);
    bool is_stg = (type == 0x04);
    if (!is_hdr && !(is_stg && flags == 0)) {
        return len + hdr_len;
    }

    if (bpf_msg_pull_data(msg, 0, len+hdr_len, 0) < 0) {
        return -(data_end - data);
    }

    u16 s = s_any;
    struct msg_ctx ctx = _new_msg_ctx(msg);

    int res;
    if (is_hdr) {
        res = _parse_hdr_from(&ctx, hdr_len, len+hdr_len, &s, pres, NULL);
    } else {
        res = _parse_stg_from(&ctx, hdr_len, len+hdr_len, &s, pres, NULL);
    }

    if (len > hdr_len + res) return -1;

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

    int res = _parse_hdr_from(&ctx, hdr_len, len+hdr_len, &s, pres, null_prefix);

    return res;
}

SEC("freplace")
bool matched(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
    return (m.len > 0);
}

SEC("freplace")
int extract_match(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx, struct hdr_str *str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -1;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    struct msg_ctx ctx = _new_msg_ctx(msg);
    u8 *ptr = NULL;
    u32 len = 0;
    _extract_match(&ctx, &m, false, &ptr, &len);
    if (ptr == NULL) return -1;

    *str = (struct hdr_str) {
        .len = len,
        .ptr = ptr
    };
    return 0;
}
