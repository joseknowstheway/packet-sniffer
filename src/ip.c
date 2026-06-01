/*
 * ip.c — Layer 3 (IPv4) parsing implementation.
 */

#include "ip.h"
#include "ethernet.h"  /* ETHERNET_HEADER_LEN — IP header starts after L2 */

#include <arpa/inet.h> /* ntohs() */
#include <string.h>    /* memcpy() */

void parse_ip(const uint8_t *packet, ip_header_t *ip)
{
    /*
     * Why memcpy instead of a struct-pointer cast like we used for Ethernet?
     *
     * The IP header begins at packet + 14, which is NOT 4-byte aligned. This
     * struct has uint32_t fields (the IP addresses) that require 4-byte
     * alignment. Casting and dereferencing through a misaligned pointer is
     * undefined behavior in C (UBSan would flag it; some CPUs even fault).
     * memcpy reads the bytes safely regardless of alignment and lands them in
     * our properly-aligned local struct. This is the portable, correct idiom.
     */
    memcpy(ip, packet + ETHERNET_HEADER_LEN, sizeof(ip_header_t));

    /* Normalize the multi-byte numeric fields from network to host order. */
    ip->total_length   = ntohs(ip->total_length);
    ip->identification = ntohs(ip->identification);
    ip->flags_fragment = ntohs(ip->flags_fragment);
    ip->checksum       = ntohs(ip->checksum);

    /*
     * src_ip / dest_ip are intentionally NOT converted: inet_ntop(AF_INET, ...)
     * expects the address in network byte order (as it travels on the wire).
     */
}

int get_ip_header_length(const ip_header_t *ip)
{
    /*
     * IHL is the low 4 bits of byte 0, expressed in 32-bit words. A value of 5
     * means 5 * 4 = 20 bytes (the common, option-free case). Masking with 0x0F
     * discards the version nibble in the high 4 bits.
     */
    return (ip->version_ihl & 0x0F) * 4;
}

int get_ip_version(const ip_header_t *ip)
{
    /* Shift the high nibble down; should be 4 for IPv4. */
    return ip->version_ihl >> 4;
}

const char *ip_protocol_name(uint8_t protocol)
{
    switch (protocol) {
    case IP_PROTOCOL_ICMP: return "ICMP";
    case IP_PROTOCOL_TCP:  return "TCP";
    case IP_PROTOCOL_UDP:  return "UDP";
    default:               return "Other";
    }
}
