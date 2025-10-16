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

struct ip4_addr {
    u32 ip4;
    u32 port;
};

struct ip4_conn {
    struct ip4_addr local;
    struct ip4_addr remote;
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
#define MAX_STATES 512
#define MAX_TRANS 128
#define MAX_MATCHES 32

volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];

struct parse_res {
    struct hdr_match ms[MAX_MATCHES];
};

struct parse_res parse_res = { 0 };

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
                .src = 0
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
    int res = _parse_h1_from(msg, 0, parse_res.ms, cidx, &s);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h1_from(msg, -res, parse_res.ms, cidx, &s);
    }

    return res;
}

SEC("freplace")
int extract_match(struct sk_msg_md *msg, u8 idx, struct hdr_str* str) {
    if (!msg || !str) return -1;

    struct hdr_match m = parse_res.ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + m.idx + m.len > data_end) return -1;

    str->ptr = data + m.idx;
    str->len = m.len;

    return 0;
}
