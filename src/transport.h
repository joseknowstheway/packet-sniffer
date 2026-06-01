#ifndef TRANSPORT_H
#define TRANSPORT_H

/*
 * transport.h — Layer 4 parsing for TCP, UDP, and ICMP.
 *
 * The transport header begins right after the IP header. Because the IP header
 * is variable length (IHL), callers must compute that start as:
 *     packet + ETHERNET_HEADER_LEN + get_ip_header_length(ip)
 * and pass it in as `transport_start`.
 */

#include <stdint.h>

/* ---- TCP -------------------------------------------------------------- */

/*
 * 20-byte fixed TCP header. `data_offset`'s high nibble is the header length in
 * 32-bit words (TCP can carry options, like IP). `flags` holds the control bits
 * below. All fields naturally aligned → sizeof == 20, no padding.
 */
typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;   /* high nibble = header length in 32-bit words */
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

/* TCP control-flag bit masks (the low 6 bits of the flags byte). */
#define TCP_FIN 0x01  /* sender is finished sending          */
#define TCP_SYN 0x02  /* synchronize sequence numbers (open) */
#define TCP_RST 0x04  /* reset / abort the connection        */
#define TCP_PSH 0x08  /* push buffered data to the app        */
#define TCP_ACK 0x10  /* acknowledgment field is valid        */
#define TCP_URG 0x20  /* urgent pointer is valid              */

/* ---- UDP -------------------------------------------------------------- */

typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;     /* header + data */
    uint16_t checksum;
} udp_header_t;

/* ---- ICMP ------------------------------------------------------------- */

typedef struct {
    uint8_t  type;       /* 0 = Echo Reply, 8 = Echo Request (ping), ... */
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} icmp_header_t;

/* ---- API -------------------------------------------------------------- */

void parse_tcp(const uint8_t *transport_start, tcp_header_t *tcp);
void parse_udp(const uint8_t *transport_start, udp_header_t *udp);
void parse_icmp(const uint8_t *transport_start, icmp_header_t *icmp);

/* High nibble of data_offset × 4 = TCP header length in bytes (20–60). */
int get_tcp_header_length(const tcp_header_t *tcp);

/* Human-readable name for an ICMP message type. */
const char *icmp_type_name(uint8_t type);

#endif /* TRANSPORT_H */
