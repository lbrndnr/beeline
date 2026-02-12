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
    bool in_msg;
};

struct hdr_str {
    u32 len;
    const u8* ptr;
};

struct parse_res {
    struct hdr_match ms[MAX_MATCHES];
};

struct trans {
    u16 state;
    u16 action;
};

#endif // __BEELINE_H__
