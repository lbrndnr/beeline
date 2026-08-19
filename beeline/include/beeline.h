#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// The interface between a BPF program and the parsers beeline attaches to it:
// the types a parser reports its results in, and the macros declaring the
// functions it replaces.

#ifndef __BEELINE_H__
#define __BEELINE_H__

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy

// The number of bytes a parser walks at most. Bounding the length of a message
// bounds the parsing loop.
#define MAX_BYTES 0x7FFF

// The number of matches a `parse_res` holds, i.e. the number of ranges a parser
// can be configured to capture.
#define MAX_MATCHES 32

// Masks a match id down to a valid index into `parse_res`, so that the verifier
// can see that the access is in bounds.
#define MAX_MATCH_MASK 31

// Clamps VAR into [UMIN, UMAX]. It is written in inline assembly so that clang
// cannot reason the bounds away again, which would leave the verifier without a
// range for VAR.
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

// An IPv4 endpoint. `ip4` is stored the way the kernel hands it out, in network
// byte order, `port` in host byte order.
struct ip4_addr {
    u32 ip4;
    u32 port;
};

// The pair of endpoints identifying a connection. Beeline keys the state it
// keeps per connection with it, e.g. the dynamic table of an HTTP/2 peer.
struct ip4_conn {
    struct ip4_addr local;
    struct ip4_addr remote;
};

// A single captured header field. If `in_msg` is set, `idx` is the offset of
// the field in the parsed message and `len` its length. Otherwise the field was
// not spelled out on the wire and `idx` is the HPACK index it has to be read
// from the static or the dynamic table with.
struct hdr_match {
    u16 idx;
    u16 len;
    bool in_msg;
};

// A borrowed string, pointing either into the parsed message or into one of the
// HPACK tables. It is only valid for as long as the program does not invalidate
// the pointers of the message it was extracted from.
struct hdr_str {
    u32 len;
    const u8* ptr;
};

// The result of parsing a single message, holding one entry per match id the
// parser was configured with. It is what `matched` and `extract_match` read the
// captured ranges out of.
struct parse_res {
    struct hdr_match ms[MAX_MATCHES];
};

// The header of the HTTP/2 frame a parsed message starts with.
struct h2_frame {
    u32 sid;
    u8 type;
    u8 flags;

    // The number of entries in the dynamic table of the connection this frame
    // belongs to, before and after decoding it. A target program that answers
    // some requests without forwarding them to user space (e.g. beeline's
    // example fast path) can compare `dt_count_before` against what it last
    // handed to user space to see how far the two tables have drifted apart,
    // and take `dt_count` as the state user space reaches once it has decoded
    // this frame itself.
    u32 dt_count_before;
    u32 dt_count;

    // The maximum size the dynamic table may reach, i.e. the value of the
    // peer's `SETTINGS_HEADER_TABLE_SIZE`. Replaying a table into another
    // decoder means telling it that size too, or it evicts at the wrong point.
    u32 dt_max_size;
};

// The number of bytes of a name or a value that are kept in a dynamic table
// entry. Longer fields are truncated, which bounds the copies for the
// verifier. Must stay in sync with `HEADER_FIELD_MAXLEN` of h2/parser.bpf.c.
#define BEELINE_H2_FIELD_MAXLEN 128

// A single field of the HPACK static or dynamic table, stored Huffman encoded,
// i.e. the way it appears on the wire.
struct header_field {
    u8 key[BEELINE_H2_FIELD_MAXLEN];
    u8 key_len;
    u8 val[BEELINE_H2_FIELD_MAXLEN];
    u8 val_len;
};

// A single transition of the DFA a parser walks: the state it leads to, and the
// action to run upon entering that state. The action is a bit field, see the
// `a_*` constants of the parser programs for its encoding.
struct trans {
    u16 state;
    u16 action;
};

// Stubs for the parser programs beeline attaches with `freplace`.
//
// A program that uses a beeline parser declares the functions it passes to the
// `replace_*` builder methods with these macros. Each one expands to a global
// (`__noinline`) function with the exact signature the corresponding parser
// program expects.

#ifndef __sink
#define __sink(expr) asm volatile("" : "+g"(expr))
#endif

// Creates `name`, a stub for the HTTP/1.x message parser
// (`h1::Parser::replace_parse_msg`).
#define BEELINE_H1_PARSE_MSG(name)                                                                 \
    __noinline int name(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull) {             \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole message, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_msg_pull_data(msg, 0, msg->size, 0);                                                   \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/1.x sk_buff parser
// (`h1::Parser::replace_parse_skb`).
#define BEELINE_H1_PARSE_SKB(name)                                                                 \
    __noinline int name(struct __sk_buff *skb, struct parse_res *pres __arg_nonnull,               \
                        u16 *null_prefix) {                                                        \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(pres);                                                                              \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole sk_buff, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_skb_pull_data(skb, skb->len);                                                          \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/1.x buffer parser
// (`h1::Parser::replace_parse_buf`).
#define BEELINE_H1_PARSE_BUF(name)                                                                 \
    __noinline int name(const struct bpf_dynptr *buf_ptr, u32 len,                                 \
                        struct parse_res *pres __arg_nonnull, u16 *null_prefix) {                  \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(buf_ptr);                                                                           \
        __sink(len);                                                                               \
        __sink(pres);                                                                              \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/2 message parser
// (`h2::Parser::replace_parse_msg`).
#define BEELINE_H2_PARSE_MSG(name)                                                                 \
    __noinline int name(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull,               \
                        struct h2_frame *frame __arg_nonnull) {                                    \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(frame);                                                                             \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole message, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_msg_pull_data(msg, 0, msg->size, 0);                                                   \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/2 sk_buff parser
// (`h2::Parser::replace_parse_skb`).
#define BEELINE_H2_PARSE_SKB(name)                                                                 \
    __noinline int name(struct __sk_buff *skb, struct parse_res *pres __arg_nonnull,               \
                        struct h2_frame *frame __arg_nonnull, u16 *null_prefix) {                  \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(pres);                                                                              \
        __sink(frame);                                                                             \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole sk_buff, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_skb_pull_data(skb, skb->len);                                                          \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/2 buffer parser
// (`h2::Parser::replace_parse_buf`).
#define BEELINE_H2_PARSE_BUF(name)                                                                 \
    __noinline int name(const struct bpf_dynptr *buf_ptr, struct ip4_conn *conn,                   \
                        struct parse_res *pres __arg_nonnull,                                      \
                        struct h2_frame *frame __arg_nonnull, u16 *null_prefix) {                  \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(buf_ptr);                                                                           \
        __sink(conn);                                                                              \
        __sink(pres);                                                                              \
        __sink(frame);                                                                             \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reporting whether the match at `idx` was found
// (`replace_matched`).
#define BEELINE_MATCHED(name)                                                                      \
    __noinline bool name(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull,  \
                         u8 idx) {                                                                 \
        bool ret = false;                                                                          \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reading the match at `idx` out of `msg`
// (`replace_extract`).
#define BEELINE_EXTRACT_MATCH(name)                                                                \
    __noinline int name(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull,   \
                        u8 idx, struct hdr_str *str __arg_nonnull) {                               \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(str);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reading the `idx`th entry of the dynamic table of the
// connection a message parsed with an HTTP/2 parser belongs to
// (`h2::Parser::replace_get_dt_entry`). `idx` is counted the HPACK way, i.e. 1
// is the most recently added entry and `dt_count` (see `h2_frame`) the oldest
// still live one. Returns 0 on success, -1 if there is no such entry.
#define BEELINE_H2_GET_DT_ENTRY(name)                                                              \
    __noinline int name(const struct ip4_conn *conn __arg_nonnull, u32 idx,                        \
                        struct header_field *out __arg_nonnull) {                                  \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(conn);                                                                              \
        __sink(idx);                                                                               \
        __sink(out);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

#endif // __BEELINE_H__
