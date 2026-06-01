/*
 * stats.c — capture statistics implementation.
 */

#include "stats.h"

#include <arpa/inet.h> /* inet_ntop() */
#include <stdio.h>
#include <stdlib.h>    /* qsort() */
#include <string.h>    /* memset() */

void stats_init(capture_stats_t *stats)
{
    memset(stats, 0, sizeof(*stats));
    stats->start_time = time(NULL);
}

void stats_record_packet(capture_stats_t *stats,
                         const ip_header_t *ip,
                         uint32_t packet_len)
{
    stats->total_packets++;
    stats->total_bytes += packet_len;

    switch (ip->protocol) {
    case IP_PROTOCOL_TCP:  stats->tcp_packets++;  break;
    case IP_PROTOCOL_UDP:  stats->udp_packets++;  break;
    case IP_PROTOCOL_ICMP: stats->icmp_packets++; break;
    default:               stats->other_packets++; break;
    }

    /*
     * Attribute the bytes to the SOURCE IP. Linear scan of the table: O(n) per
     * packet with n up to MAX_TRACKED_IPS. Fine for a CLI tool capturing a home
     * link; a high-throughput collector would use a hash map instead. We note
     * the trade-off rather than over-engineer.
     */
    for (int i = 0; i < stats->ip_count; i++) {
        if (stats->ip_addresses[i] == ip->src_ip) {
            stats->ip_bytes[i] += packet_len;
            return;
        }
    }

    /* New source IP — add it if there's room (otherwise silently ignore). */
    if (stats->ip_count < MAX_TRACKED_IPS) {
        stats->ip_addresses[stats->ip_count] = ip->src_ip;
        stats->ip_bytes[stats->ip_count] = packet_len;
        stats->ip_count++;
    }
}

/* Render a byte count as a human-friendly string (e.g. "2.3 MB"). */
static void format_bytes(uint64_t bytes, char *buf, size_t buf_len)
{
    static const char *units[] = { "B", "KB", "MB", "GB", "TB" };
    double value = (double)bytes;
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        unit++;
    }
    if (unit == 0) {
        snprintf(buf, buf_len, "%.0f %s", value, units[unit]);
    } else {
        snprintf(buf, buf_len, "%.1f %s", value, units[unit]);
    }
}

/* One row for sorting the top-talkers list. */
typedef struct {
    uint32_t ip;
    uint64_t bytes;
} ip_entry_t;

/* qsort comparator: descending by bytes. */
static int cmp_entries_desc(const void *a, const void *b)
{
    const ip_entry_t *x = a;
    const ip_entry_t *y = b;
    if (y->bytes > x->bytes) return 1;
    if (y->bytes < x->bytes) return -1;
    return 0;
}

void stats_print_top_ips(const capture_stats_t *stats, int n)
{
    /* Copy into a local array so we can sort without mutating const stats. */
    ip_entry_t entries[MAX_TRACKED_IPS];
    for (int i = 0; i < stats->ip_count; i++) {
        entries[i].ip = stats->ip_addresses[i];
        entries[i].bytes = stats->ip_bytes[i];
    }
    qsort(entries, (size_t)stats->ip_count, sizeof(entries[0]),
          cmp_entries_desc);

    int limit = (n < stats->ip_count) ? n : stats->ip_count;
    for (int i = 0; i < limit; i++) {
        char ipstr[INET_ADDRSTRLEN];
        char bytestr[16];
        inet_ntop(AF_INET, &entries[i].ip, ipstr, sizeof(ipstr));
        format_bytes(entries[i].bytes, bytestr, sizeof(bytestr));
        printf("    %-15s  %s\n", ipstr, bytestr);
    }
}

/* Percentage of total, guarding against divide-by-zero. */
static double pct(uint64_t part, uint64_t total)
{
    return (total == 0) ? 0.0 : 100.0 * (double)part / (double)total;
}

void stats_print_summary(const capture_stats_t *stats)
{
    long duration = (long)(time(NULL) - stats->start_time);
    char total_bytes_str[16];
    format_bytes(stats->total_bytes, total_bytes_str, sizeof(total_bytes_str));

    printf("========================================\n");
    printf("  CAPTURE SUMMARY\n");
    printf("========================================\n");
    printf("  Duration:        %ld seconds\n", duration);
    /* The %' flag groups thousands per the active locale (set in main). */
    printf("  Total packets:   %'llu\n",
           (unsigned long long)stats->total_packets);
    printf("  Total bytes:     %s\n", total_bytes_str);

    if (stats->total_packets > 0) {
        printf("\n  Protocol breakdown:\n");
        printf("    TCP:   %'llu  (%.1f%%)\n",
               (unsigned long long)stats->tcp_packets,
               pct(stats->tcp_packets, stats->total_packets));
        printf("    UDP:   %'llu  (%.1f%%)\n",
               (unsigned long long)stats->udp_packets,
               pct(stats->udp_packets, stats->total_packets));
        printf("    ICMP:  %'llu  (%.1f%%)\n",
               (unsigned long long)stats->icmp_packets,
               pct(stats->icmp_packets, stats->total_packets));
        printf("    Other: %'llu  (%.1f%%)\n",
               (unsigned long long)stats->other_packets,
               pct(stats->other_packets, stats->total_packets));

        printf("\n  Top source IPs:\n");
        stats_print_top_ips(stats, 5);
    }

    printf("========================================\n");
}
