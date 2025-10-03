#include "beeline.h"

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
    H2_IDX = 1,
    H2_LIT_IDX = 2,
    H2_KEY_LEN = 3,
    H2_VAL_LEN = 4,

    H2_KEY = 5,
    H2_VAL = 6,
};

struct dynamic_table {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 100);
    __type(value, u32);
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

__always_inline int parse_h1(struct sk_msg_md *msg, struct prange *pranges) {
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

static __always_inline int _parse_h2_from(const struct sk_msg_md *msg, u16 start, struct prange *pranges, u32* cidx, u16* fs) {
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

    struct dynamic_table *dt = bpf_map_lookup_elem(&dynamic_tables, &stream_id);

    u32 i = 0, k = 0;
    u32 n = 0, m = 0;
    enum h2_parse_state ps = 0;

    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        bool msb = (c & 0x80) != 0;

        bpf_log("i: %d, ps: %d", i, ps);

        if (ps == 0) {
            bool literal = (c & 0x40) != 0;

            if (msb) {
                n = 7;
                m = 0;
                c &= 127; // remove the most significant bit
                ps = H2_IDX;
            }
            else if (literal) {
                n = 6;
                m = 0;
                c &= 0x3F; // remove the two most significant bits
                ps = H2_LIT_IDX;
            }
        }

        if (ps != H2_KEY && ps != H2_VAL) {
            if (c < (1 << n) - 1) {
                k = c;
                _next_h2(&ps, &n, k);
            }
            else {
                k += (c & 127) * (1 << m);

                if (msb) {
                    m += 7;
                    continue;
                }
                else {
                    _next_h2(&ps, &n, k);
                }
            }

            bpf_log("i: %d -> k: %d", i, k);
        }
        else {
            bpf_log("i: %d -> c: %c, huffman: %d", i, c, msb);
            k -= 1;
            // _next_h2(&ps, &n, k);
        }

        // u16 a = 0;
        // _next(*s, c, s, &a);

        // if (*s == s_any) {
        //     _next(s_any, c, s, &a);
        // }

        // // it should never happen that any of these cases are true simultaneously
        // // but it makes the verifier happy when we don't use else if here
        // if ((a & a_start_capture) != 0) {
        //     u16 cid = a & a_id_mask & MAX_MATCH_MASK;
        //     bpf_log("Start capture range (%d, ?) in [%d, ...]", cid, i);
        //     cidx[cid] = i;
        // }
        // if ((a & a_end_capture) != 0) {
        //     u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
        //     u16 rid = a & a_id_2_mask & MAX_MATCH_MASK;
        //     bpf_log("End capture range (%d, %d) in [%d, %d]", cid, rid, cidx[cid], i - cidx[cid]);

        //     pranges[rid] = (struct prange) {
        //         .idx = cidx[cid],
        //         .len = i - cidx[cid]
        //     };

        //     cidx[cid] = i;
        // }
        // if ((a & a_done) != 0) {
        //     bpf_log("Done parsing at %d", i);
        //     return i-1;
        // }
    }

    return -len;
}

__always_inline int parse_h2(struct sk_msg_md *msg, struct prange *pranges) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + 9 > data_end) return -1;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];

    bpf_log("Parsing HTTP/2 message with length %d, type %d", len, type);

    if (type != 0x01) {
        return len + 9;
    }

    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    int res = _parse_h2_from(msg, 9, pranges, cidx, &s);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h2_from(msg, -res, pranges, cidx, &s);
    }

    return res + 9;
}
