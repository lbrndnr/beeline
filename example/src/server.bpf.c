#include "beeline.h"
#include "xbpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define __sink(expr) asm volatile("" : "+g"(expr))

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} sock_map SEC(".maps");

volatile const u32 ip4;
volatile const u32 port;

// Fast path routing table: a fixed-size, userspace-populated table (backed by
// the program's .bss section) holding pre-rendered HTTP responses. Populated by
// userspace before the program is attached.
#define MAX_ROUTES 16
#define MAX_ROUTE_PATH 64
#define MAX_ROUTE_BODY 4096

#define H1_PATH_MID 0
#define H1_CONTENT_LENGTH_MID 1

struct route {
    // the response rendered as HTTP/1.1
    u8 body[MAX_ROUTE_BODY];
    u32 body_len;
};

struct route routes[MAX_ROUTES];

// The request path, zero padded to a fixed size so that it can be hashed.
struct route_key {
    u8 path[MAX_ROUTE_PATH];
};

// Maps a request path to its index in `routes`. A route is reachable under
// several paths, the plain text one and the huffman encoded one h2 puts on the
// wire, hence the two entries per route.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ROUTES);
    __type(key, struct route_key);
    __type(value, u8);
} route_idx SEC(".maps");

__noinline int extract_h1_match(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx, struct hdr_str* str __arg_nonnull) {
    int ret = -1;

	__sink(msg);
	__sink(pres);
	__sink(idx);
	__sink(str);
	__sink(ret);

	return ret;
}

__noinline int parse_h1(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull) {
   	int ret = -1;

	__sink(msg);
	__sink(pres);
	__sink(ret);

	bpf_msg_pull_data(msg, 0, msg->size, 0);

	return ret;
}



// Overwrites `msg` in place with `r`'s pre-rendered response and redirects it
// straight back to the sender's socket (BPF_F_INGRESS), bypassing userspace
// entirely. `sid` is the h2 stream to answer on, or 0 to serve the HTTP/1.1
// rendering. Returns 0 on success, < 0 if the response could not be served.
static __always_inline int serve_route(struct sk_msg_md *msg, struct ip4_conn *ikey, struct route *r) {
    u32 body_len = r->body_len;
    if (body_len == 0 || body_len > MAX_ROUTE_BODY) return -1;

    u32 orig_size = msg->size;

    if (body_len > orig_size) {
        if (bpf_msg_push_data(msg, orig_size, body_len - orig_size, 0) < 0) return -1;
    } else if (body_len < orig_size) {
        if (bpf_msg_pop_data(msg, body_len, orig_size - body_len, 0) < 0) return -1;
    }

    if (bpf_msg_pull_data(msg, 0, body_len, 0) < 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    // after the push/pop above, the message is exactly `body_len` bytes, so
    // the packet bound check below is sufficient on its own to stop the copy
    // at the right place.
    u32 k;
    bpf_for(k, 0, MAX_ROUTE_BODY) {
        if (data + k + 1 > data_end) break;

        u32 idx = k;
        bpf_clamp_uminmax(idx, 0, MAX_ROUTE_BODY - 1);
        data[k] = r->body[idx];
    }

    if (bpf_msg_redirect_hash(msg, &sock_map, ikey, BPF_F_INGRESS) < 0) return -1;

    bpf_msg_apply_bytes(msg, body_len);

    return 0;
}

// Looks up the captured request path in `route_idx` and, on a match, serves
// the pre-rendered response directly from the fast path. Returns 0 if a route
// was served (the caller should return SK_PASS immediately without further
// processing `msg`), < 0 otherwise.
static __always_inline int try_serve_route(struct sk_msg_md *msg, struct ip4_conn *ikey, struct hdr_str *path) {
    if (path->len == 0 || path->len > MAX_ROUTE_PATH) return -1;

    u32 len = path->len;
    bpf_clamp_uminmax(len, 1, MAX_ROUTE_PATH);

    struct route_key key = { 0 };
    if (bpf_probe_read_kernel(key.path, len, path->ptr) < 0) return -1;

    u8 *idx = bpf_map_lookup_elem(&route_idx, &key);
    if (!idx) {
        bpf_warn("No route found for request path");
        return -1;
    };

    u32 i = *idx;
    bpf_clamp_uminmax(i, 0, MAX_ROUTES - 1);

    return serve_route(msg, ikey, &routes[i]);
}

static __always_inline int parse_content_length(const struct hdr_str *content_length) {
    char digits[16] = { 0 };
    u32 n = content_length->len;
    if (n > 0) {
        bpf_clamp_uminmax(n, 1, sizeof(digits) - 1);

        if (bpf_probe_read_kernel(digits, n, content_length->ptr) == 0) {
            unsigned long len = 0;
            if (bpf_strtoul(digits, n, 0, &len) >= 0 && len > 0) {
                return len;
            }
        }
    }

    return -1;
}

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // socket identifeir of the ingress connection
    struct ip4_conn ikey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    bool is_downstream = (ikey.remote.ip4 == ip4 && ikey.remote.port == port);
    bpf_debug("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    struct parse_res pres = { 0 };
    struct hdr_str path = { 0 };
    int path_res = -1;
    u32 sid = 0;

    int msg_len = parse_h1(msg, &pres);
    if (msg_len > 0) {
        struct hdr_str content_length = { 0 };
        if (extract_h1_match(msg, &pres, H1_CONTENT_LENGTH_MID, &content_length) == 0) {
            bpf_trace("content length: %s", content_length.ptr);

            int res = parse_content_length(&content_length);
            if (res > 0) msg_len += res;
        }

        path_res = extract_h1_match(msg, &pres, H1_PATH_MID, &path);
    }

    if (try_serve_route(msg, &ikey, &path) == 0) {
        // the following is a bit wasteful, so we only do it for debugging purposes
        #if BPF_TRACING_LEVEL >= BPF_TRACING_LEVEL_TRACE

        char head[32] = {};
        bpf_probe_read_kernel_str(head, (path.len + 1) & 0x1F, path.ptr);

        bpf_debug("Served request to %s", head);
        #endif
    }
    else {
        bpf_error("Failed to serve file");
    }

    bpf_msg_apply_bytes(msg, msg_len);

    return SK_PASS;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        // we don't want to get called anymore for this connection
        bpf_sock_ops_cb_flags_set(ops, 0);

        struct ip4_conn skey = {
            .local = {
                .ip4 = ops->local_ip4,
                .port = ops->local_port
            },
            .remote = {
                .ip4 = ops->remote_ip4,
                .port = bpf_ntohl(ops->remote_port)
            }
        };

        bpf_debug("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

        if (skey.remote.ip4 == ip4 && skey.remote.port == port) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_error("Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_debug("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}
