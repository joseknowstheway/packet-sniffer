#ifndef CAPTURE_H
#define CAPTURE_H

/*
 * capture.h — libpcap capture interface.
 *
 * Stage 1: open a network interface and run a capture loop that hands every
 * packet to a callback. Higher layers (Ethernet/IP/transport parsing) plug
 * into the callback in later stages.
 */

#include "filter.h"

/*
 * start_capture
 *   cfg : whole-program configuration (interface, filter, and the --bpf/--hex/
 *         --write options).
 *   returns: 0 on success, non-zero on error.
 *
 * Runs until the user interrupts with Ctrl+C (SIGINT), then prints a capture
 * summary and cleans up the pcap handle.
 */
int start_capture(const app_config_t *cfg);

#endif /* CAPTURE_H */
