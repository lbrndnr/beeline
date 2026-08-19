#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef __BEELINE_H__
#define __BEELINE_H__

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0x7FFF
#define MAX_MATCHES 32
#define MAX_MATCH_MASK 31

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
    bool in_msg;
};

struct hdr_str {
    u32 len;
    const u8* ptr;
};

struct parse_res {
    struct hdr_match ms[MAX_MATCHES];
};

// The header of the HTTP/2 frame a parsed message starts with.
struct h2_frame {
    u32 sid;
    u8 type;
    u8 flags;
};

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

#endif // __BEELINE_H__
