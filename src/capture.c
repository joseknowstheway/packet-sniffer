/*
 * capture.c — libpcap capture engine (Stage 1).
 *
 * Responsibilities:
 *   - Find/open a live network interface in promiscuous mode.
 *   - Run pcap_loop(), dispatching each captured packet to a callback.
 *   - Handle Ctrl+C (SIGINT) cleanly: stop the loop, print a summary, free
 *     resources.
 *
 * Note on portability: the original project brief targets Linux and suggests
 * pcap_lookupdev(). That function is deprecated; we use pcap_findalldevs()
 * instead, which is the modern API and works identically on macOS and Linux.
 */

#include "capture.h"
#include "ethernet.h"
#include "ip.h"
#include "transport.h"
#include "filter.h"
#include "stats.h"
#include "display.h"

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Capture parameters for pcap_open_live(). */
#define SNAP_LEN     65535  /* bytes to capture per packet (full frame)      */
#define PROMISC_MODE 1      /* 1 = also grab frames not addressed to us       */
#define READ_TIMEOUT 1000   /* ms the kernel may buffer before delivering     */

/*
 * The pcap handle lives at file scope so the SIGINT handler can reach into the
 * loop and stop it. Everything else (filter, stats) is threaded through the
 * callback's user pointer instead — see capture_context_t.
 */
static pcap_t *g_handle = NULL;

/*
 * Context handed to the pcap callback via pcap_loop's user pointer: the
 * read-only filter plus the stats accumulator the handler updates.
 */
typedef struct {
    const filter_config_t *filter;
    capture_stats_t       *stats;
    int                    show_payload; /* --hex */
    pcap_dumper_t         *dumper;       /* --write target, or NULL */
} capture_context_t;

/*
 * handle_sigint — runs when the user presses Ctrl+C.
 *
 * We must do as little as possible here (only async-signal-safe work).
 * pcap_breakloop() is safe to call from a signal handler; it makes the
 * in-progress pcap_loop() return so we can clean up normally back in
 * start_capture().
 */
static void handle_sigint(int signum)
{
    (void)signum; /* unused, but required by the signal() prototype */
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
}

/*
 * packet_handler — called by pcap_loop() once per captured packet.
 *
 *   user   : the user pointer we passed to pcap_loop() — here, the active
 *            filter_config_t (this is libpcap's intended way to pass context).
 *   header : pcap metadata (timestamp, captured length, original length).
 *   packet : raw bytes of the frame, starting at the Ethernet header.
 *
 * Flow: parse every layer into locals, THEN ask the filter whether to display.
 * Filtering before printing is what makes --proto/--port/--host drop packets
 * silently instead of after the fact.
 */
static void packet_handler(unsigned char *user,
                           const struct pcap_pkthdr *header,
                           const unsigned char *packet)
{
    const capture_context_t *ctx = (const capture_context_t *)user;
    const filter_config_t *filter = ctx->filter;

    /*
     * Bounds check FIRST. header->caplen is how many bytes were actually
     * captured (may be less than the real frame). A malformed or truncated
     * frame shorter than an Ethernet header would make parse_ethernet read
     * past the buffer — exactly the class of bug Valgrind/ASan flags later.
     */
    if (header->caplen < ETHERNET_HEADER_LEN) {
        return; /* runt frame — silently drop */
    }

    ethernet_header_t eth;
    parse_ethernet(packet, &eth);

    /*
     * Non-IPv4 frames (ARP, IPv6) carry no IPv4/port info, so they can never
     * satisfy an active filter — drop them when filtering. With no filter, show
     * their [ETH] line so you can still see them on the wire.
     */
    if (eth.ethertype != ETHERTYPE_IP) {
        if (filter_is_active(filter)) {
            return;
        }
        print_ethernet(&eth);
        printf("\n");
        return;
    }

    /* Need the full 20-byte fixed IP header present before we read it. */
    if (header->caplen < ETHERNET_HEADER_LEN + sizeof(ip_header_t)) {
        return;
    }

    ip_header_t ip;
    parse_ip(packet, &ip);
    if (get_ip_version(&ip) != 4) {
        return;
    }

    /*
     * Layer 4 begins at 14 + (IHL*4), not a fixed 34, because IP options vary
     * the header length. A bogus IHL (< 20) means a malformed packet.
     */
    int ip_len = get_ip_header_length(&ip);
    if (ip_len < 20) {
        return;
    }
    size_t l4_offset = ETHERNET_HEADER_LEN + (size_t)ip_len;
    const uint8_t *l4 = packet + l4_offset;

    /*
     * Parse whichever transport header is present into a local, and keep a
     * pointer to it (NULL for the others). The filter needs these to test
     * ports; printing needs them too.
     */
    tcp_header_t tcp;
    udp_header_t udp;
    icmp_header_t icmp;
    const tcp_header_t  *tcp_p  = NULL;
    const udp_header_t  *udp_p  = NULL;
    const icmp_header_t *icmp_p = NULL;

    switch (ip.protocol) {
    case IP_PROTOCOL_TCP:
        if (header->caplen >= l4_offset + sizeof(tcp_header_t)) {
            parse_tcp(l4, &tcp);
            tcp_p = &tcp;
        }
        break;
    case IP_PROTOCOL_UDP:
        if (header->caplen >= l4_offset + sizeof(udp_header_t)) {
            parse_udp(l4, &udp);
            udp_p = &udp;
        }
        break;
    case IP_PROTOCOL_ICMP:
        if (header->caplen >= l4_offset + sizeof(icmp_header_t)) {
            parse_icmp(l4, &icmp);
            icmp_p = &icmp;
        }
        break;
    default:
        break; /* other L4 protocol — the [IP] line still names it */
    }

    /* Decide BEFORE printing. If it doesn't match, drop it silently. */
    if (!packet_matches_filter(&ip, tcp_p, udp_p, filter)) {
        return;
    }

    /* Count it (matched packets only). */
    stats_record_packet(ctx->stats, &ip, (uint32_t)header->len);

    /* If --write was given, append the raw packet to the .pcap file. The file
     * stores original bytes + timestamp so Wireshark can reopen it later. */
    if (ctx->dumper != NULL) {
        pcap_dump((unsigned char *)ctx->dumper, header, packet);
    }

    print_ethernet(&eth);
    print_ip(&ip);
    if (tcp_p != NULL) {
        print_tcp(tcp_p);
    } else if (udp_p != NULL) {
        print_udp(udp_p);
    } else if (icmp_p != NULL) {
        print_icmp(icmp_p);
    }

    /*
     * --hex: preview the application payload that follows the transport header.
     * The payload offset depends on the transport header's own length (TCP is
     * variable; UDP/ICMP are fixed 8 bytes here).
     */
    if (ctx->show_payload) {
        size_t l4_hdr_len = 0;
        if (tcp_p != NULL) {
            int tlen = get_tcp_header_length(tcp_p);
            l4_hdr_len = (tlen < (int)sizeof(tcp_header_t))
                             ? sizeof(tcp_header_t) : (size_t)tlen;
        } else if (udp_p != NULL) {
            l4_hdr_len = sizeof(udp_header_t);
        } else if (icmp_p != NULL) {
            l4_hdr_len = sizeof(icmp_header_t);
        }
        size_t payload_off = l4_offset + l4_hdr_len;
        if (l4_hdr_len > 0 && header->caplen > payload_off) {
            print_payload_preview(packet + payload_off,
                                  header->caplen - payload_off);
        }
    }

    /* Blank line groups each packet's layers for readability. */
    printf("\n");
}

/*
 * auto_select_device — pick a reasonable default interface when the user
 * doesn't pass one with -i.
 *
 * Prefers an interface that is UP, RUNNING, and not loopback (e.g. en0).
 * Falls back to the first device in the list. The returned string is owned
 * by the caller-provided buffer; we copy into it because the pcap device
 * list is freed before we return.
 *
 * returns: 0 on success (name copied into out), non-zero on failure.
 */
static int auto_select_device(char *out, size_t out_len, char *errbuf)
{
    pcap_if_t *devices = NULL;
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        return -1;
    }
    if (devices == NULL) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                 "no network interfaces found (need sudo?)");
        return -1;
    }

    const char *chosen = devices->name; /* default: first in the list */
    for (pcap_if_t *d = devices; d != NULL; d = d->next) {
        int is_loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
        int is_up_running =
            (d->flags & PCAP_IF_UP) && (d->flags & PCAP_IF_RUNNING);
        if (!is_loopback && is_up_running) {
            chosen = d->name;
            break;
        }
    }

    snprintf(out, out_len, "%s", chosen);
    pcap_freealldevs(devices);
    return 0;
}

int start_capture(const app_config_t *cfg)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char chosen_device[256];

    /* Resolve which interface to listen on ("" in cfg means auto-select). */
    if (cfg->device[0] != '\0') {
        snprintf(chosen_device, sizeof(chosen_device), "%s", cfg->device);
    } else if (auto_select_device(chosen_device, sizeof(chosen_device),
                                  errbuf) != 0) {
        fprintf(stderr, "Error finding a device: %s\n", errbuf);
        return 1;
    }

    /* Open the interface for live capture. */
    g_handle = pcap_open_live(chosen_device, SNAP_LEN, PROMISC_MODE,
                              READ_TIMEOUT, errbuf);
    if (g_handle == NULL) {
        fprintf(stderr, "Could not open device '%s': %s\n",
                chosen_device, errbuf);
        fprintf(stderr, "Hint: live capture needs root. Try: sudo %s\n",
                "./sniffer ...");
        return 1;
    }

    /*
     * Verify the link-layer type. Our parser assumes Ethernet II (DLT_EN10MB),
     * where every frame starts with the 14-byte header ethernet.c expects.
     * Other link types (e.g. DLT_NULL on loopback, raw 802.11) have different
     * framing and would produce garbage — so we bail rather than mislead.
     */
    int datalink = pcap_datalink(g_handle);
    if (datalink != DLT_EN10MB) {
        fprintf(stderr,
                "Unsupported link type on '%s': %s. This tool parses "
                "Ethernet (DLT_EN10MB) only.\n",
                chosen_device, pcap_datalink_val_to_name(datalink));
        pcap_close(g_handle);
        g_handle = NULL;
        return 1;
    }

    /*
     * --bpf: compile and install a raw libpcap filter that runs IN THE KERNEL,
     * before packets are ever copied to us. This is how production tools filter
     * efficiently. It composes with our userspace --proto/--port/--host filter.
     */
    if (cfg->bpf[0] != '\0') {
        struct bpf_program program;
        if (pcap_compile(g_handle, &program, cfg->bpf, 1,
                         PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Invalid BPF filter \"%s\": %s\n",
                    cfg->bpf, pcap_geterr(g_handle));
            pcap_close(g_handle);
            g_handle = NULL;
            return 1;
        }
        if (pcap_setfilter(g_handle, &program) == -1) {
            fprintf(stderr, "Couldn't apply BPF filter: %s\n",
                    pcap_geterr(g_handle));
            pcap_freecode(&program);
            pcap_close(g_handle);
            g_handle = NULL;
            return 1;
        }
        pcap_freecode(&program); /* the compiled program is copied in by pcap */
    }

    /* --write: open the .pcap output file (savefile) for pcap_dump(). */
    pcap_dumper_t *dumper = NULL;
    if (cfg->dumpfile[0] != '\0') {
        dumper = pcap_dump_open(g_handle, cfg->dumpfile);
        if (dumper == NULL) {
            fprintf(stderr, "Couldn't open dump file '%s': %s\n",
                    cfg->dumpfile, pcap_geterr(g_handle));
            pcap_close(g_handle);
            g_handle = NULL;
            return 1;
        }
    }

    /* Install the Ctrl+C handler now that we have a handle to break. */
    signal(SIGINT, handle_sigint);

    printf("Listening on %s...\n", chosen_device);
    print_active_filters(&cfg->filter);
    if (cfg->bpf[0] != '\0') {
        printf("BPF filter: %s\n", cfg->bpf);
    }
    if (dumper != NULL) {
        printf("Saving packets to: %s\n", cfg->dumpfile);
    }
    printf("(Press Ctrl+C to stop)\n");

    /* Stats live here in start_capture so they survive past pcap_loop and can
     * be printed safely after it returns. Bundle everything the callback needs
     * into the context for the user pointer. */
    capture_stats_t stats;
    stats_init(&stats);
    capture_context_t ctx = {
        .filter       = &cfg->filter,
        .stats        = &stats,
        .show_payload = cfg->show_payload,
        .dumper       = dumper,
    };

    /*
     * pcap_loop blocks, calling packet_handler for each packet, until:
     *   - it has processed `cnt` packets (we pass -1 = run forever), or
     *   - pcap_breakloop() is called from our SIGINT handler, or
     *   - an error occurs.
     *
     * The 4th argument is libpcap's "user" pointer: we hand it our context so
     * packet_handler can read the filter and update stats without extra
     * globals.
     */
    int loop_result = pcap_loop(g_handle, -1, packet_handler,
                                (unsigned char *)&ctx);
    if (loop_result == -1) {
        fprintf(stderr, "Capture error: %s\n", pcap_geterr(g_handle));
    }

    /*
     * Print the summary HERE — in normal control flow after pcap_loop returns —
     * NOT inside the SIGINT handler. The handler only calls pcap_breakloop();
     * all the unsafe work (printf, qsort, floating point) happens here, where
     * it's allowed. This is the correct, async-signal-safe shutdown pattern.
     */
    printf("\n");
    stats_print_summary(&stats);

    /* Flush and close the .pcap file (if any) before tearing down the handle. */
    if (dumper != NULL) {
        pcap_dump_close(dumper);
    }

    pcap_close(g_handle);
    g_handle = NULL;
    return 0;
}
