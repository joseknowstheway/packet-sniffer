/*
 * display.c — formatted output implementation.
 */

#include "display.h"

#include <arpa/inet.h> /* inet_ntop(), INET_ADDRSTRLEN */
#include <stdio.h>
#include <string.h>    /* strncat(), strlen() */

/*
 * format_mac — write a 6-byte MAC address into `buf` as "aa:bb:cc:dd:ee:ff".
 *
 * `buf` must hold at least 18 bytes (17 chars + NUL). Using a caller-supplied
 * buffer (rather than a static one) keeps this reentrant — important since a
 * single print line formats two MACs.
 */
static void format_mac(const uint8_t mac[6], char *buf, size_t buf_len)
{
    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ethernet(const ethernet_header_t *eth)
{
    char src[18];
    char dst[18];
    format_mac(eth->src_mac, src, sizeof(src));
    format_mac(eth->dest_mac, dst, sizeof(dst));

    printf("[ETH] %s -> %s | Type: %s (0x%04x)\n",
           src, dst, ethertype_name(eth->ethertype), eth->ethertype);
}

void print_ip(const ip_header_t *ip)
{
    /*
     * inet_ntop converts a binary address (network byte order) to its dotted
     * string form. It's the modern, IPv6-ready, thread-safe replacement for
     * inet_ntoa() — which the spec mentions but returns a pointer to a shared
     * static buffer, so two calls in one printf would clobber each other.
     */
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &ip->dest_ip, dst, sizeof(dst));

    printf("[IP]  %s -> %s | Proto: %s | TTL: %u | Len: %u\n",
           src, dst, ip_protocol_name(ip->protocol), ip->ttl,
           ip->total_length);
}

/*
 * tcp_flags_to_string — render the set TCP control flags into `buf` as a
 * space-separated list (e.g. "SYN ACK"), or "none" if no flags are set.
 *
 * Each flag is a single bit in the flags byte; we test it with a bitwise AND
 * against its mask. Order chosen to read the way packet tools commonly show it.
 */
static void tcp_flags_to_string(uint8_t flags, char *buf, size_t buf_len)
{
    buf[0] = '\0';
    struct { uint8_t mask; const char *name; } table[] = {
        { TCP_SYN, "SYN" }, { TCP_ACK, "ACK" }, { TCP_FIN, "FIN" },
        { TCP_RST, "RST" }, { TCP_PSH, "PSH" }, { TCP_URG, "URG" },
    };

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (flags & table[i].mask) {
            if (buf[0] != '\0') {
                strncat(buf, " ", buf_len - strlen(buf) - 1);
            }
            strncat(buf, table[i].name, buf_len - strlen(buf) - 1);
        }
    }

    if (buf[0] == '\0') {
        snprintf(buf, buf_len, "none");
    }
}

void print_tcp(const tcp_header_t *tcp)
{
    char flags[32];
    tcp_flags_to_string(tcp->flags, flags, sizeof(flags));

    printf("[TCP] Port %u -> %u | Flags: %s | Seq: %u | Win: %u\n",
           tcp->src_port, tcp->dest_port, flags, tcp->seq_num,
           tcp->window_size);
}

void print_udp(const udp_header_t *udp)
{
    printf("[UDP] Port %u -> %u | Len: %u\n",
           udp->src_port, udp->dest_port, udp->length);
}

void print_icmp(const icmp_header_t *icmp)
{
    printf("[ICMP] Type: %s | ID: %u | Seq: %u\n",
           icmp_type_name(icmp->type), icmp->id, icmp->sequence);
}

#define PAYLOAD_PREVIEW_BYTES 16

void print_payload_preview(const uint8_t *data, size_t len)
{
    if (len == 0) {
        return;
    }

    size_t shown = (len < PAYLOAD_PREVIEW_BYTES) ? len : PAYLOAD_PREVIEW_BYTES;

    printf("[DATA] ");

    /* Hex column — pad missing bytes with spaces so the ASCII column aligns. */
    for (size_t i = 0; i < PAYLOAD_PREVIEW_BYTES; i++) {
        if (i < shown) {
            printf("%02x ", data[i]);
        } else {
            printf("   ");
        }
    }

    /* ASCII column — printable bytes as-is, everything else as '.'. */
    printf(" |");
    for (size_t i = 0; i < shown; i++) {
        unsigned char c = data[i];
        printf("%c", (c >= 32 && c < 127) ? (char)c : '.');
    }
    printf("|  (%zu bytes payload)\n", len);
}
