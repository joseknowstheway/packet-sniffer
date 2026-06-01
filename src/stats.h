#ifndef STATS_H
#define STATS_H

/*
 * stats.h — running capture statistics.
 *
 * Accumulates totals as packets are recorded, then prints a formatted summary
 * (protocol breakdown + top source IPs) when the capture ends.
 */

#include <stdint.h>
#include <time.h>

#include "ip.h"

/* Upper bound on distinct source IPs we track for the "top talkers" list. */
#define MAX_TRACKED_IPS 1024

typedef struct {
    time_t   start_time;     /* set in stats_init, used for duration */

    /* Totals */
    uint64_t total_packets;
    uint64_t total_bytes;

    /* Per-protocol counts */
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;

    /*
     * Parallel arrays: ip_addresses[i] (network byte order) has accumulated
     * ip_bytes[i] bytes. A simple flat table — see stats.c for the trade-off.
     */
    uint32_t ip_addresses[MAX_TRACKED_IPS];
    uint64_t ip_bytes[MAX_TRACKED_IPS];
    int      ip_count;
} capture_stats_t;

/* Zero the struct and stamp the start time. */
void stats_init(capture_stats_t *stats);

/* Fold one (matched) IPv4 packet into the totals. packet_len is the on-wire
 * frame length. Call once per packet that passes the filter. */
void stats_record_packet(capture_stats_t *stats,
                         const ip_header_t *ip,
                         uint32_t packet_len);

/* Print the full formatted summary (calls stats_print_top_ips internally). */
void stats_print_summary(const capture_stats_t *stats);

/* Print the top `n` source IPs by bytes, highest first. */
void stats_print_top_ips(const capture_stats_t *stats, int n);

#endif /* STATS_H */
