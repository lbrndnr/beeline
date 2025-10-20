#include "beeline.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <sys/cdefs.h>

enum h2_parse_state {
    // integers
    H2_IDX = 0,
    H2_KEY_LEN = 1,
    H2_VAL_LEN = 2,

    // strings
    H2_KEY = 3,
    H2_VAL = 4,
};

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
    u16 current_size;
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

struct parse_res parse_res = { 0 };

static __always_inline void new_ip4conn(const struct sk_msg_md *msg, struct ip4_conn *conn) {
    *conn = (struct ip4_conn) {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };
}

static __always_inline void new_table_key(const struct sk_msg_md *msg, u32 idx, struct dynamic_table_key *key) {
    *key = (struct dynamic_table_key) {
        .conn = { 0 },
        .idx = idx
    };
    new_ip4conn(msg, &key->conn);
}

static __always_inline u8* _extract_match(const struct sk_msg_md *msg, const struct hdr_match *m, bool is_key) {
    if (m->in_msg) {
        u8 *data = (u8 *)(long)msg->data;
        u8 *data_end = (u8 *)(long)msg->data_end;

        if (data + m->idx + m->len > data_end) return NULL;
        return data + m->idx;
    }

    struct header_field *hf = NULL;
    if (m->idx > STATIC_TABLE_SIZE) {
        struct dynamic_table_key key = { 0 };
        new_table_key(msg, m->idx, &key);
        hf = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        hf = bpf_map_lookup_elem(&static_table, &m->idx);
    }

    if (hf == NULL) return NULL;
    return (is_key) ? hf->key : hf->val;
}

SEC("freplace")
int extract_match(const struct sk_msg_md *msg, u8 idx, struct hdr_str* str __arg_nonnull) {
    struct hdr_match m = parse_res.ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    u8 *ptr = _extract_match(msg, &m, false);
    if (!ptr) return -1;

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

static __always_inline u8 _next_hpack(enum h2_parse_state *ps, u32 *n, u32 k) {
    if (*ps == H2_IDX && *n == 7) {
        *ps = H2_IDX;
        *n = 7;
        return 0;
    }
    if (*ps == H2_IDX && (k == 64 || k == 0)) {
        *ps = H2_KEY_LEN;
        *n = 7;
        return 0;
    }
    if (*ps == H2_IDX && (*n == 6 || *n == 4)) {
        *ps = H2_VAL_LEN;
        *n = 7;
        return 0;
    }
    if (*ps == H2_KEY_LEN) {
        *ps = H2_KEY;
        return k-1;
    }
    if (*ps == H2_VAL_LEN) {
        *ps = H2_VAL;
        return k-1;
    }

    *ps = H2_IDX;
    return 0;
}

static __always_inline bool _parse_hpack(u8 c, enum h2_parse_state *ps, u32 *n, u32 *m, u32 *k) {
    bool msb = (c & 128) == 128;

    if (*ps == H2_IDX) {
        *k = 0;

        if (msb) {
            *n = 7;
            *m = 0;
        }
        else if (c == 64) {
            *k = 0;
            *n = 6;
            *m = 0;
            return true;
        }
        else if ((c & 192) == 64) {
            *n = 6;
            *m = 0;
        }
        else if (c == 0) {
            *k = 0;
            *n = 4;
            *m = 0;
            return true;
        }
        else if ((c & 240) == 0) {
            *n = 4;
            *m = 0;
        }
    }

    if (*ps == H2_IDX || *ps == H2_KEY_LEN || *ps == H2_VAL_LEN) {
        u8 mask = (1 << *n) - 1;
        c &= mask;

        if (c < mask) {
            *k = c;
        }
        else {
            *k += c * (1 << *m);
            *m += 7;
            return false;
        }
    }

    return true;
}

__noinline __weak s8 _parse_table_entry(const struct sk_msg_md *msg, u16 *s __arg_nonnull, u32 idx, struct parse_res *pres __arg_nonnull) {
    struct header_field *hf = NULL;
    if (idx > STATIC_TABLE_SIZE) {
        struct dynamic_table_key key = { 0 };
        new_table_key(msg, idx, &key);
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

__noinline __weak int _add_table_entry(const struct sk_msg_md *msg, u32 idx, const struct hdr_match *key __arg_nonnull, const struct hdr_match *val __arg_nonnull) {
    u8 *key_ptr = _extract_match(msg, key, true);
    u8 *val_ptr = _extract_match(msg, val, false);
    if (!key_ptr || !val_ptr) return -1;

    struct dynamic_table_key dt_key = { 0 };
    new_table_key(msg, idx, &dt_key);

    struct header_field dt_val = { 0 };
    u16 key_len = (key->in_msg) ? key->len & 0x1F : 0x1F;
    bpf_probe_read_kernel(dt_val.key, key_len, key_ptr);
    bpf_probe_read_kernel(dt_val.val, val->len & 0x1F, val_ptr);

    bpf_map_update_elem(&dynamic_table, &dt_key, &dt_val, BPF_ANY);
    bpf_log("add to dynamic table: %d", idx);
    bpf_log("key { %d %d %d}", key->idx, key->len, key->in_msg);
    bpf_log("val { %d %d %d}", val->idx, val->len, val->in_msg);

    return 0;
}

static __always_inline int _parse_h2_from(const struct sk_msg_md *msg, u16 start, u16* s, struct parse_res *pres) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    if (data + 9 > data_end) return -1;

    // u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct ip4_conn conn = { 0 };
    new_ip4conn(msg, &conn);
    struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &conn);
    if (!dt_info) {
        struct dynamic_table_info new_info = {
            .current_size = 0,
            .max_size = 100,
        };
        bpf_map_update_elem(&dynamic_table_info, &conn, &new_info, BPF_ANY);

        dt_info = bpf_map_lookup_elem(&dynamic_table_info, &conn);
        if (!dt_info) return -1;
    }

    u32 n = 0, m = 0;
    u32 i = 0, k = 0;
    u8 j = 0;
    s8 cid = -1;
    enum h2_parse_state ps = H2_IDX;
    struct hdr_match key = { 0 };

    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        if (j == 0) {
            bool done = _parse_hpack(c, &ps, &n, &m, &k);
            if (done && ps == H2_IDX) {
                bpf_log("parsed idx: %d", k);

                *s = s_any;
                cid = _parse_table_entry(msg, s, k, pres);
                key = (struct hdr_match) {
                    .idx = (n == 6) ? k : 0,
                    .len = 0,
                    .in_msg = (k == 64),
                };
            }
            else if (done && ps == H2_KEY_LEN) {
                key.len = k;
            }
            else if (done && ps == H2_VAL_LEN && cid >= 0) {
                // check if we need to add current hf to dynamic table
                if (key.idx > 0) {
                    struct hdr_match val = (struct hdr_match) {
                        .idx = i + 1,
                        .len = k,
                        .in_msg = true,
                    };

                    if (_add_table_entry(msg, dt_info->current_size + STATIC_TABLE_SIZE + 1, &key, &val) == 0) {
                        dt_info->current_size += 1;
                    }
                }

                bpf_log("capture: %d {%d, %d}", cid, i, k);
                pres->ms[cid & MAX_MATCH_MASK] = (struct hdr_match) {
                    .idx = i+1,
                    .len = k,
                    .in_msg = true,
                };
                cid = -1;
            }

            j = _next_hpack(&ps, &n, k);
        }
        else {
            j--;
        }
    }

    return i;
}

SEC("freplace")
int parse_h2(struct sk_msg_md *msg) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + 9 > data_end) return -1;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];

    bpf_log("Parsing HTTP/2 message with length %d, type %d", len, type);

    if (type != 0x01) {
        return len + 9;
    }

    u16 s = s_any;
    int res = _parse_h2_from(msg, 9, &s, &parse_res);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h2_from(msg, -res, &s, &parse_res);
    }

    return res + 9;
}
