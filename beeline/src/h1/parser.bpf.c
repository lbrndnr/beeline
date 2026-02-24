#include "beeline.h"

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


#define MAX_STATES 512
#define MAX_TRANS 128
volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];

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

static __always_inline int _parse_from(u8 *data, u8 *data_end, u16 start, struct hdr_match *ms, u32* cidx, u16* s) {
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

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
                .len = i - cidx[cid] -1,
                .in_msg = true
            };

            cidx[cid] = i;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return i+1;
        }
    }

    return -len;
}

SEC("freplace")
int parse_msg(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;
    int res = _parse_from(data, data_end, 0, pres->ms, cidx, &s);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        u8 *data = (u8 *)(long)msg->data;
        u8 *data_end = (u8 *)(long)msg->data_end;

        res = _parse_from(data, data_end, -res, pres->ms, cidx, &s);
    }

    return res;
}

SEC("freplace")
int parse_buf(const struct bpf_dynptr* buf_ptr, u32 len, struct parse_res *pres __arg_nonnull) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;

    u8 *data = bpf_dynptr_data(buf_ptr, 0, 64);
    if (data == NULL) return -1;

    u8 *data_end = data + 64;

    int res = _parse_from(data, data_end, 0, pres->ms, cidx, &s);

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

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + m.idx + m.len > data_end) return -1;

    str->ptr = data + m.idx;
    str->len = m.len;

    return 0;
}
