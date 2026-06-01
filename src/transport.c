/*
 * transport.c — Layer 4 parsing implementation (TCP, UDP, ICMP).
 *
 * Same alignment reasoning as ip.c: the transport header sits at a non-aligned
 * offset (14 + IP header length) and TCP contains uint32_t fields, so we memcpy
 * into an aligned local struct rather than casting a misaligned pointer.
 */

#include "transport.h"

#include <arpa/inet.h>  /* ntohs(), ntohl() */
#include <string.h>     /* memcpy() */

void parse_tcp(const uint8_t *transport_start, tcp_header_t *tcp)
{
    memcpy(tcp, transport_start, sizeof(tcp_header_t));

    tcp->src_port    = ntohs(tcp->src_port);
    tcp->dest_port   = ntohs(tcp->dest_port);
    tcp->seq_num     = ntohl(tcp->seq_num);   /* 32-bit → ntohl, not ntohs */
    tcp->ack_num     = ntohl(tcp->ack_num);
    tcp->window_size = ntohs(tcp->window_size);
    tcp->checksum    = ntohs(tcp->checksum);
    tcp->urgent_ptr  = ntohs(tcp->urgent_ptr);
    /* data_offset and flags are single bytes — no byte-order conversion. */
}

void parse_udp(const uint8_t *transport_start, udp_header_t *udp)
{
    memcpy(udp, transport_start, sizeof(udp_header_t));

    udp->src_port  = ntohs(udp->src_port);
    udp->dest_port = ntohs(udp->dest_port);
    udp->length    = ntohs(udp->length);
    udp->checksum  = ntohs(udp->checksum);
}

void parse_icmp(const uint8_t *transport_start, icmp_header_t *icmp)
{
    memcpy(icmp, transport_start, sizeof(icmp_header_t));

    icmp->checksum = ntohs(icmp->checksum);
    icmp->id       = ntohs(icmp->id);
    icmp->sequence = ntohs(icmp->sequence);
    /* type and code are single bytes — no conversion. */
}

int get_tcp_header_length(const tcp_header_t *tcp)
{
    /* High nibble of data_offset, in 32-bit words → ×4 for bytes. */
    return (tcp->data_offset >> 4) * 4;
}

const char *icmp_type_name(uint8_t type)
{
    switch (type) {
    case 0:  return "Echo Reply (ping)";
    case 3:  return "Destination Unreachable";
    case 5:  return "Redirect";
    case 8:  return "Echo Request (ping)";
    case 11: return "Time Exceeded";
    default: return "Other";
    }
}
