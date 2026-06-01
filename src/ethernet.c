/*
 * ethernet.c — Layer 2 parsing implementation.
 */

#include "ethernet.h"

#include <arpa/inet.h>  /* ntohs() */
#include <string.h>     /* memcpy() */

void parse_ethernet(const uint8_t *packet, ethernet_header_t *eth)
{
    /*
     * Interpret the first 14 bytes of the packet AS an Ethernet header by
     * casting the byte pointer to a struct pointer. This is the core trick of
     * the whole sniffer: the struct's layout mirrors the wire format, so
     * `raw->src_mac` reads exactly bytes 6–11, etc. No copying needed to read.
     *
     * We then copy into the caller's `eth` so we can normalize byte order
     * without mutating the original (const) capture buffer.
     */
    const ethernet_header_t *raw = (const ethernet_header_t *)packet;

    /* MAC addresses are raw bytes — no byte-order conversion applies. */
    memcpy(eth->dest_mac, raw->dest_mac, 6);
    memcpy(eth->src_mac, raw->src_mac, 6);

    /*
     * The EtherType is a 16-bit field sent in NETWORK byte order (big-endian).
     * ntohs() ("network to host short") converts it to whatever this machine
     * uses, so the value compares correctly against ETHERTYPE_IP etc.
     */
    eth->ethertype = ntohs(raw->ethertype);
}

const char *ethertype_name(uint16_t ethertype)
{
    switch (ethertype) {
    case ETHERTYPE_IP:   return "IPv4";
    case ETHERTYPE_ARP:  return "ARP";
    case ETHERTYPE_IPV6: return "IPv6";
    default:             return "Unknown";
    }
}
