#ifndef IP_H
#define IP_H

/*
 * ip.h — Layer 3 (IPv4) parsing.
 *
 * The IPv4 header sits immediately after the 14-byte Ethernet header. It is at
 * least 20 bytes, but can be longer if "options" are present — the IHL field
 * tells you the real length. Bit/field layout (per RFC 791):
 *
 *   byte 0      version (high nibble) + IHL (low nibble)
 *   byte 1      DSCP/ECN (QoS — ignored here)
 *   bytes 2–3   total length (header + payload)
 *   bytes 4–5   identification (fragment reassembly)
 *   bytes 6–7   flags (3 bits) + fragment offset (13 bits)
 *   byte 8      TTL
 *   byte 9      protocol (6=TCP, 17=UDP, 1=ICMP)
 *   bytes 10–11 header checksum
 *   bytes 12–15 source IP address
 *   bytes 16–19 destination IP address
 */

#include <stdint.h>

/* Protocol numbers carried in the IPv4 `protocol` field (IANA-assigned). */
#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP  6
#define IP_PROTOCOL_UDP  17

/*
 * Mirrors the 20-byte fixed portion of the IPv4 header. Like the Ethernet
 * struct, the fields are naturally aligned (uint32_t addresses land on offsets
 * 12 and 16), so sizeof(ip_header_t) == 20 with no padding.
 *
 * After parse_ip(): the multi-byte *numeric* fields (total_length, etc.) are in
 * HOST byte order. src_ip and dest_ip are deliberately left in NETWORK byte
 * order, because that's exactly what inet_ntop(AF_INET, ...) expects.
 */
typedef struct {
    uint8_t  version_ihl;     /* high nibble = version, low nibble = IHL */
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;          /* network byte order */
    uint32_t dest_ip;         /* network byte order */
} ip_header_t;

/*
 * parse_ip
 *   packet : start of the full frame (Ethernet header first). This function
 *            offsets past the Ethernet header internally.
 *   ip     : output struct, byte-order-normalized as described above.
 */
void parse_ip(const uint8_t *packet, ip_header_t *ip);

/* IHL field is a count of 32-bit words; multiply by 4 for the length in bytes
 * (20–60). Needed to find where the transport header begins. */
int get_ip_header_length(const ip_header_t *ip);

/* High nibble of byte 0; should be 4 for IPv4. */
int get_ip_version(const ip_header_t *ip);

/* "TCP", "UDP", "ICMP", or "Other" for the protocol number. */
const char *ip_protocol_name(uint8_t protocol);

#endif /* IP_H */
