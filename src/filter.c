/*
 * filter.c — CLI parsing (getopt_long) and the packet filter engine.
 */

#include "filter.h"

#include <arpa/inet.h>  /* inet_pton(), inet_ntop() */
#include <getopt.h>     /* getopt_long(), struct option */
#include <stdio.h>
#include <stdlib.h>     /* strtol(), exit() */
#include <string.h>     /* strcmp() */
#include <strings.h>    /* strcasecmp() */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: sudo %s [-i interface] [filters] [options]\n"
        "\n"
        "Filters (applied in userspace):\n"
        "  -i <interface>    interface to capture on (default: auto-select)\n"
        "  --proto <p>       only tcp, udp, or icmp\n"
        "  --port <N>        only packets with this TCP/UDP source or dest port\n"
        "  --host <IP>       only packets to/from this IPv4 address\n"
        "\n"
        "Options:\n"
        "  --bpf \"<expr>\"    raw libpcap/BPF filter applied in-kernel\n"
        "                    (e.g. --bpf \"tcp and port 80\")\n"
        "  -x, --hex         show a hex+ASCII preview of the payload\n"
        "  -w, --write <f>   also save captured packets to a .pcap file\n"
        "  -h, --help        show this help\n",
        prog);
}

/* Map a --proto string to an IP protocol number, or -1 if unrecognized. */
static int proto_str_to_num(const char *s)
{
    if (strcasecmp(s, "tcp") == 0)  return IP_PROTOCOL_TCP;
    if (strcasecmp(s, "udp") == 0)  return IP_PROTOCOL_UDP;
    if (strcasecmp(s, "icmp") == 0) return IP_PROTOCOL_ICMP;
    return -1;
}

void parse_args(int argc, char *argv[], app_config_t *cfg)
{
    /* Defaults: everything zero → empty filter, auto device, no extras. */
    memset(cfg, 0, sizeof(*cfg));

    /*
     * getopt_long maps each long option to a value we receive from the switch.
     * Long-only options get distinct return codes ('p','P','H','b') so they
     * don't collide with the short flags in the optstring.
     */
    static const struct option long_opts[] = {
        { "proto", required_argument, NULL, 'p' },
        { "port",  required_argument, NULL, 'P' },
        { "host",  required_argument, NULL, 'H' },
        { "bpf",   required_argument, NULL, 'b' },
        { "hex",   no_argument,       NULL, 'x' },
        { "write", required_argument, NULL, 'w' },
        { "help",  no_argument,       NULL, 'h' },
        { NULL,    0,                 NULL,  0  },
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:xw:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            snprintf(cfg->device, sizeof(cfg->device), "%s", optarg);
            break;

        case 'p': {
            int proto = proto_str_to_num(optarg);
            if (proto < 0) {
                fprintf(stderr, "Invalid --proto '%s' (use tcp|udp|icmp)\n",
                        optarg);
                exit(EXIT_FAILURE);
            }
            cfg->filter.filter_proto = proto;
            break;
        }

        case 'P': {
            /* strtol lets us validate the whole token, unlike atoi. */
            char *end;
            long port = strtol(optarg, &end, 10);
            if (*end != '\0' || port < 1 || port > 65535) {
                fprintf(stderr, "Invalid --port '%s' (use 1-65535)\n", optarg);
                exit(EXIT_FAILURE);
            }
            cfg->filter.filter_port = (uint16_t)port;
            break;
        }

        case 'H':
            /* inet_pton writes the address in NETWORK byte order — exactly how
             * we store ip->src_ip/dest_ip, so comparisons need no conversion. */
            if (inet_pton(AF_INET, optarg, &cfg->filter.filter_ip) != 1) {
                fprintf(stderr, "Invalid --host '%s' (use a dotted IPv4)\n",
                        optarg);
                exit(EXIT_FAILURE);
            }
            break;

        case 'b':
            snprintf(cfg->bpf, sizeof(cfg->bpf), "%s", optarg);
            break;

        case 'x':
            cfg->show_payload = 1;
            break;

        case 'w':
            snprintf(cfg->dumpfile, sizeof(cfg->dumpfile), "%s", optarg);
            break;

        case 'h':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);

        default: /* unknown option: getopt_long already printed an error */
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

int filter_is_active(const filter_config_t *filter)
{
    return filter->filter_proto != 0 ||
           filter->filter_ip    != 0 ||
           filter->filter_port  != 0;
}

int packet_matches_filter(const ip_header_t *ip,
                          const tcp_header_t *tcp,
                          const udp_header_t *udp,
                          const filter_config_t *filter)
{
    /* Protocol filter. */
    if (filter->filter_proto != 0 && ip->protocol != filter->filter_proto) {
        return 0;
    }

    /* Host filter: match either direction (source OR destination). */
    if (filter->filter_ip != 0 &&
        ip->src_ip != filter->filter_ip &&
        ip->dest_ip != filter->filter_ip) {
        return 0;
    }

    /* Port filter: match source OR destination port of TCP/UDP. */
    if (filter->filter_port != 0) {
        uint16_t src_port, dest_port;
        if (tcp != NULL) {
            src_port = tcp->src_port;
            dest_port = tcp->dest_port;
        } else if (udp != NULL) {
            src_port = udp->src_port;
            dest_port = udp->dest_port;
        } else {
            /* No ports on this packet (e.g. ICMP) — can't match a port. */
            return 0;
        }
        if (src_port != filter->filter_port &&
            dest_port != filter->filter_port) {
            return 0;
        }
    }

    return 1; /* passed every active criterion */
}

void print_active_filters(const filter_config_t *filter)
{
    if (!filter_is_active(filter)) {
        printf("Filters: none (showing all traffic)\n");
        return;
    }

    printf("Filters:");
    if (filter->filter_proto != 0) {
        printf(" proto=%s", ip_protocol_name((uint8_t)filter->filter_proto));
    }
    if (filter->filter_ip != 0) {
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &filter->filter_ip, ipstr, sizeof(ipstr));
        printf(" host=%s", ipstr);
    }
    if (filter->filter_port != 0) {
        printf(" port=%u", filter->filter_port);
    }
    printf("\n");
}
