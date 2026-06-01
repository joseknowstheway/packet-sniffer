#ifndef ETHERNET_H
#define ETHERNET_H

/*
 * ethernet.h — Layer 2 (Ethernet II frame) parsing.
 *
 * Every frame libpcap hands us on an Ethernet link (DLT_EN10MB) begins with a
 * 14-byte header:
 *
 *   bytes  0–5   destination MAC address
 *   bytes  6–11  source MAC address
 *   bytes 12–13  EtherType (what protocol is inside: IPv4, ARP, IPv6, ...)
 */

#include <stdint.h>

/* Ethernet II header is always exactly 14 bytes (no options). */
#define ETHERNET_HEADER_LEN 14

/* EtherType values (the 2-byte field at offset 12), in HOST byte order. */
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV6 0x86DD

/*
 * Models the on-the-wire Ethernet header. The field order and sizes are chosen
 * to match the wire layout byte-for-byte: 6 + 6 + 2 = 14 bytes, and because the
 * widest member is uint16_t (2-byte alignment) with everything already on even
 * offsets, the compiler adds no padding — sizeof(ethernet_header_t) == 14.
 *
 * After parse_ethernet(), `ethertype` is stored in HOST byte order so callers
 * can compare it against the ETHERTYPE_* constants directly.
 */
typedef struct {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;

/*
 * parse_ethernet
 *   packet : raw frame bytes (must be at least ETHERNET_HEADER_LEN long).
 *   eth    : output; filled with MAC addresses and host-order EtherType.
 */
void parse_ethernet(const uint8_t *packet, ethernet_header_t *eth);

/*
 * ethertype_name — human-readable name for an EtherType (host byte order),
 * e.g. "IPv4", "ARP", "IPv6", or "Unknown".
 */
const char *ethertype_name(uint16_t ethertype);

#endif /* ETHERNET_H */
