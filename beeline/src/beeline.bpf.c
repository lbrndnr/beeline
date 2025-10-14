#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef bpf_clamp_uminmax
#define bpf_clamp_uminmax(VAR, UMIN, UMAX)                                                         \
    asm volatile("if %0 >= %[min] goto +2\n"                                                       \
                 "%0 = %[min]\n"                                                                   \
                 "goto +2\n"                                                                       \
                 "if %0 <= %[max] goto +1\n"                                                       \
                 "%0 = %[max]\n"                                                                   \
                 : "+r"(VAR)                                                                       \
                 : [min] "i"(UMIN), [max] "i"(UMAX))
#endif

#ifdef BL_LOG_LEVEL
    #if BL_LOG_LEVEL == 0
        #define bpf_log(...) (0)
        #define bpf_err(...) (0)
    #elif BL_LOG_LEVEL == 1
        #define bpf_log(...) (0)
        #define bpf_err(...) bpf_printk(__VA_ARGS__)
    #elif BL_LOG_LEVEL == 2
        #define bpf_log(...) bpf_printk(__VA_ARGS__)
        #define bpf_err(...) bpf_printk(__VA_ARGS__)
    #endif
#else
    #define bpf_log(...) (0)
    #define bpf_err(...) (0)
#endif

enum h2_parse_state {
    // integers
    H2_IDX = 1,
    H2_LIT_IDX = 2,
    H2_KEY_LEN = 3,
    H2_VAL_LEN = 4,

    // strings
    H2_KEY = 5,
    H2_VAL = 6,
};

struct hdr_match {
    u16 idx;
    u16 len;
    u8 src;
    u32 sid;
};

struct hdr_str {
    u32 len;
    u8* ptr;
};

enum h2_hdr_src {
    HDR_SRC_MSG = 1,
    HDR_SRC_ST = 2,
    HDR_SRC_DT = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 61);
    __type(key, u32);
    __type(value, u8[64]);
} static_table SEC(".maps");

struct dynamic_table {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, u32);
	__type(value, u8[64]);
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 16384);
    __type(key, u32);
	__array(values, struct dynamic_table);
} dynamic_tables SEC(".maps");

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

struct trans {
    u16 state;
    u16 action;
};

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0xFFFE
#define MAX_MATCH_MASK 31
#define MAX_STATES 256
#define MAX_TRANS 256
#define MAX_MATCHES 32

volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];
struct hdr_match ms[MAX_MATCHES] = { 0 };

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

static __always_inline int _parse_h1_from(const struct sk_msg_md *msg, u16 start, struct hdr_match *ms, u32* cidx, u16* s) {
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

            ms[rid] = (struct hdr_match) {
                .idx = cidx[cid],
                .len = i - cidx[cid],
                .src = HDR_SRC_DT
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

SEC("freplace")
int parse_h1(struct sk_msg_md *msg) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    int res = _parse_h1_from(msg, 0, ms, cidx, &s);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h1_from(msg, -res, ms, cidx, &s);
    }

    return res;
}

static __always_inline void _next_h2(enum h2_parse_state *ps, u32 *n, u32 k) {
    if (*ps == H2_LIT_IDX && k == 0) {
        *ps = H2_KEY_LEN;
        *n = 7;
    }
    if (*ps == H2_LIT_IDX) {
        *ps = H2_VAL_LEN;
        *n = 7;
    }
    else if (*ps == H2_KEY_LEN) {
        *ps = H2_KEY;
        *n = 0;
    }
    else if (*ps == H2_KEY && k == 0) {
        *ps = H2_VAL_LEN;
        *n = 0;
    }
    else if (*ps == H2_KEY) {
        *ps = H2_KEY;
        *n = 0;
    }
    else if (*ps == H2_VAL && k == 0) {
        *ps = 0;
        *n = 0;
    }
    else if (*ps == H2_VAL) {
        *ps = H2_VAL;
        *n = 0;
    }
    else if (*ps == H2_VAL_LEN) {
        *ps = H2_VAL;
        *n = 0;
    }
    else {
        *ps = 0;
        *n = 0;
    }

    bpf_clamp_uminmax(*ps, 0, 6);
}

static __always_inline bool _parse_h2_hpack(u8 c, enum h2_parse_state *ps, u32 *n, u32 *m, u32 *k) {
    bool msb = (c & 128) == 128;

    if (*ps == 0) {
        if (msb) {
            *ps = H2_IDX;
            *n = 7;
            *m = 0;
        }
        else if (c == 64) {
            *ps = H2_IDX;
            *k = c;
            *m = 0;
            return true;
        }
        else if ((c & 192) == 64) {
            *ps = H2_IDX;
            *n = 6;
            *m = 0;
        }
        else if ((c & 240) == 0) {
            *ps = H2_IDX;
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

            if (msb) {
                *m += 7;
                return false;
            }
        }
    }

    return true;
}

static __always_inline int _parse_h2_from(const struct sk_msg_md *msg, u16 start, struct hdr_match *ms, u16* s) {
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

    struct dynamic_table *dynamic_table = bpf_map_lookup_elem(&dynamic_tables, &stream_id);
    // if (!dynamic_table) return -1;

    u32 n = 0, m = 0;
    u32 i = 0, k = 0;
    u16 a = 0;
    enum h2_parse_state ps = 0;

    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];
        enum h2_hdr_src idx_src = _parse_h2_hpack(c, &ps, &n, &m, &k);

        if (idx_src > 0 && ps == H2_IDX) {
            bpf_log("parsed idx: %d", k);

            // void *table = (k <= 61) ? (void*)&static_table : (void*)dynamic_table;
            u8 *entry = bpf_map_lookup_elem(&static_table, &k);
            if (!entry) return -1;

            ps = 0;
            *s = s_any;
            u8 j = 0;
            bpf_for(j, 0, 64) {
                u8 c = entry[j & 0x3F];
                _next(*s, c, s, &a);

                if ((a & a_start_capture) != 0) {
                    u8 cid = a & a_id_mask & MAX_MATCH_MASK;
                    bpf_log("capture: %d {%d, %d, %d}", cid, k, 64-j, HDR_SRC_ST);
                    ms[cid & 0x1F] = (struct hdr_match) {
                        .idx = k,
                        .len = 63-j,
                        .src = HDR_SRC_ST,
                    };
                    a = 0;
                    break;
                }
            }
        }
    }

    return 0;
}

SEC("freplace")
int parse_h2(struct sk_msg_md *msg) {
    if (!msg) return -1;

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
    int res = _parse_h2_from(msg, 9, ms, &s);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h2_from(msg, -res, ms, &s);
    }

    return res + 9;
}

SEC("freplace")
int extract_match(struct sk_msg_md *msg, u8 idx, struct hdr_str* str) {
    if (!msg || !str) return -1;

    struct hdr_match m = ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;
    str->len = m.len;

    if (m.src == HDR_SRC_MSG) {
        u8 *data = (u8 *)(long)msg->data;
        u8 *data_end = (u8 *)(long)msg->data_end;

        if (data + m.idx + m.len > data_end) return -1;

        str->ptr = data + m.idx;
        return 0;
    }

    if (m.src == HDR_SRC_ST) {
        u32 idx = m.idx;
        u8 *data = bpf_map_lookup_elem(&static_table, &idx);
        if (!data) return -1;
        str->ptr = data + 64 - m.len;
        return 0;
    }

    // if (m->src == HDR_SRC_DT) {
    //     struct dynamic_table *dt = bpf_map_lookup_elem(&dynamic_tables, &sid);
    //     if (!dt) return -1;

    //     return bpf_map_lookup_elem(dt, &m->idx);
    // }

    return -1;
}
