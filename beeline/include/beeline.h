#ifndef __BEELINE_H__
#define __BEELINE_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct hdr_match {
    u16 idx;
    u16 len;
    u8 src;
};

#define MAX_MATCHES 32

int bl_parse_h1(struct sk_msg_md *msg, struct hdr_match *ms);
int bl_parse_h2(struct sk_msg_md *msg, u32 *sid, struct hdr_match *ms);

u8* bl_extract_match(struct sk_msg_md *msg, struct hdr_match *m, u32 sid);

#endif /* __BEELINE_H__ */
