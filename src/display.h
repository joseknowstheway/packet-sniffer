#ifndef DISPLAY_H
#define DISPLAY_H

/*
 * display.h — formatted, human-readable output for each parsed layer.
 *
 * Keeping all printing in one module means the parsing code (ethernet.c, etc.)
 * stays pure: it only fills structs. Presentation lives here. As we add layers
 * (IP, TCP/UDP/ICMP), each gets its own print_* function declared below.
 */

#include <stddef.h> /* size_t */

#include "ethernet.h"
#include "ip.h"
#include "transport.h"

/* Prints the Ethernet layer, e.g.
 *   [ETH] ac:de:48:00:11:22 -> ff:ff:ff:ff:ff:ff | Type: IPv4 (0x0800)
 */
void print_ethernet(const ethernet_header_t *eth);

/* Prints the IPv4 layer, e.g.
 *   [IP]  192.168.1.105 -> 142.250.80.46 | Proto: TCP | TTL: 64 | Len: 60
 */
void print_ip(const ip_header_t *ip);

/* Transport-layer printers, e.g.
 *   [TCP] Port 54312 -> 443 | Flags: SYN ACK | Seq: 3842910123 | Win: 65535
 *   [UDP] Port 52341 -> 53 | Len: 45
 *   [ICMP] Type: Echo Request (ping) | ID: 1 | Seq: 4
 */
void print_tcp(const tcp_header_t *tcp);
void print_udp(const udp_header_t *udp);
void print_icmp(const icmp_header_t *icmp);

/* Prints up to the first 16 bytes of `data` as side-by-side hex and ASCII,
 * like a hex editor / Wireshark. `len` is the full payload length (reported in
 * the trailer). Does nothing if len == 0. */
void print_payload_preview(const uint8_t *data, size_t len);

#endif /* DISPLAY_H */
