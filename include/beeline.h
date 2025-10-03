#ifndef __BEELINE_H__
#define __BEELINE_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct prange {
    u16 idx;
    u16 len;
};

#define MAX_MATCHES 32

int parse_h1(struct sk_msg_md *msg, struct prange *pranges);
int parse_h2(struct sk_msg_md *msg, struct prange *pranges);

#endif /* __BEELINE_H__ */
