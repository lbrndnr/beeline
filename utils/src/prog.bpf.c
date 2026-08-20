#include "beeper.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// The program the integration tests attach a parser to. It parses every message
// travelling in the direction under test and stores what the parser captured in
// `matches`, where the test can read it back from user space.

// The connections that carried an HTTP/2 preface and are parsed as HTTP/2 from
// then on.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} upgraded_conns SEC(".maps");
u32 num_upgraded_conns = 0;

// The sockets of the server under test, i.e. the ones `msg_verdict` runs on.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} sock_map SEC(".maps");

// The address of the server under test, set by user space before the program is
// loaded.
volatile const u32 ip4;
volatile const u32 port;

// parse the responses the server sends instead of the requests it receives
volatile const bool parse_resp;

// What the parser captured in the message parsed last, keyed by match id. An id
// with nothing captured for it is absent from the map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, char[128]);
} matches SEC(".maps");

// The functions beeper replaces with a parser when a test attaches one.
BEEPER_MATCHED(matched_h1)
BEEPER_EXTRACT_MATCH(extract_h1_match)
BEEPER_H1_PARSE_MSG(parse_h1)

BEEPER_EXTRACT_MATCH(extract_h2_match)
BEEPER_H2_PARSE_MSG(parse_h2)

// Parses the messages of the connection under test and records the captured
// ranges in `matches`. A message that carries the HTTP/2 preface upgrades its
// connection, after which its messages are parsed as HTTP/2.
SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // socket identifier of the ingress connection
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
    bpf_trace("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    // requests travel downstream, responses upstream. only one direction is parsed,
    // the other one would just clear the matches of the first
    if (is_downstream == parse_resp) {
        return SK_PASS;
    }

    bool is_h2 = (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL);
    bool store_matches = false;
    int msg_len = 0;
    struct parse_res pres = { 0 };

    if (is_h2) {
        struct h2_frame frame = { 0 };
        msg_len = parse_h2(msg, &pres, &frame);
        if (msg_len < 0) {
            bpf_error("Failed to parse h2 message: %s", msg->data);
            return SK_PASS;
        }

        store_matches = (msg_len > 9);
    }
    else {
        msg_len = parse_h1(msg, &pres);
        if (msg_len < 0) {
            // It's possible that this fails because we're actually parsing the body.
            // To avoid this, we'd have to parse the content-length to skip the body.
            // Consult the example to see how to do this.
            return SK_PASS;
        }

        if (matched_h1(msg, &pres, 0)) {
            int flag = 1;
            bpf_map_update_elem(&upgraded_conns, &ikey, &flag, BPF_ANY);
            num_upgraded_conns += 1;
        }

        store_matches = true;
    }

    // only store matches if we parsed a HEADER frame
    if (store_matches) {
        u32 i = 0;
        bpf_for(i, 0, 32) {
            struct hdr_str str = { 0 };
            int res = -1;
            if (is_h2) {
                res = extract_h2_match(msg, &pres, i, &str);
            }
            else {
                res = extract_h1_match(msg, &pres, i, &str);
            }

            if (res == 0) {
                u16 len = str.len;
                if (len > 128) len = 128;

                char tmp[128] = {0};
                bpf_probe_read_kernel(tmp, len, str.ptr);
                bpf_map_update_elem(&matches, &i, tmp, BPF_ANY);
            }
            else {
                bpf_map_delete_elem(&matches, &i);
            }
        }
    }

    bpf_debug("Apply verdict to %d/%dB", msg_len, msg->size);
    bpf_msg_apply_bytes(msg, msg_len);

    return SK_PASS;
}

// Adds both ends of every connection to the server under test to `sock_map`, so
// that `msg_verdict` sees the messages travelling on them.
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

        // the client socket carries the requests, the accepted one the responses
        bool is_client = (skey.remote.ip4 == ip4 && skey.remote.port == port);
        bool is_server = (skey.local.ip4 == ip4 && skey.local.port == port);

        if (is_client || is_server) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_error("Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_debug("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}

// Returns the number of connections that were upgraded to HTTP/2.
SEC("syscall")
int get_num_upgraded_conns() {
    return num_upgraded_conns;
}
