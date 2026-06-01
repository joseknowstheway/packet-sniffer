#ifndef FILTER_H
#define FILTER_H

/*
 * filter.h — command-line argument parsing and the packet filter engine.
 *
 * Lets the user narrow the capture to traffic they care about:
 *   sudo ./sniffer -i en0 --proto tcp
 *   sudo ./sniffer -i en0 --proto udp --port 53
 *   sudo ./sniffer -i en0 --host 8.8.8.8
 *   sudo ./sniffer -i en0 --proto tcp --port 443 --host 142.250.80.46
 */

#include <stdint.h>

#include "ip.h"
#include "transport.h"

/* Max length of an interface name buffer the caller must provide to parse_args. */
#define DEVICE_NAME_MAX 256

/*
 * Filter criteria. A zeroed struct means "match everything." Each non-zero
 * field adds an AND condition.
 *
 * Byte-order note (matters for comparisons to work):
 *   filter_ip   — NETWORK byte order, to compare directly with ip->src_ip /
 *                 dest_ip (which we also keep in network order).
 *   filter_port — HOST byte order, to compare with tcp/udp ports (which
 *                 parse_tcp/parse_udp convert to host order).
 */
typedef struct {
    int      filter_proto;  /* IP_PROTOCOL_TCP/UDP/ICMP, or 0 = any protocol */
    uint32_t filter_ip;     /* 0 = no host filter (network byte order)       */
    uint16_t filter_port;   /* 0 = no port filter (host byte order)          */
    int      direction;     /* reserved (0 = both); no CLI flag yet          */
} filter_config_t;

/*
 * Whole-program configuration parsed from argv. Groups the interface, the
 * userspace filter, and the Stage 7 stretch-goal options so a single struct
 * flows from main() into the capture engine.
 */
typedef struct {
    char            device[DEVICE_NAME_MAX]; /* "" = auto-select            */
    filter_config_t filter;                  /* --proto / --port / --host   */
    char            bpf[256];                /* --bpf raw expr; "" = none   */
    int             show_payload;            /* --hex / -x                   */
    char            dumpfile[256];           /* --write file; "" = none      */
} app_config_t;

/*
 * parse_args — parse argv into an app_config_t. On a bad argument, prints
 * usage and exits the process.
 */
void parse_args(int argc, char *argv[], app_config_t *cfg);

/*
 * packet_matches_filter — returns 1 if the packet should be displayed, 0 if it
 * should be silently dropped. `tcp`/`udp` are NULL when the packet isn't that
 * protocol (used only for the port test).
 */
int packet_matches_filter(const ip_header_t *ip,
                          const tcp_header_t *tcp,
                          const udp_header_t *udp,
                          const filter_config_t *filter);

/* 1 if any filter criterion is set (used to decide whether to show non-IPv4
 * frames, which can never match an IP/port/proto filter). */
int filter_is_active(const filter_config_t *filter);

/* Print a one-line summary of the active filters at startup. */
void print_active_filters(const filter_config_t *filter);

#endif /* FILTER_H */
