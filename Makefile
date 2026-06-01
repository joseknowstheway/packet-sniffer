# Makefile — Network Packet Sniffer
#
# Targets:
#   make          build the optimized binary ./sniffer
#   make debug    build ./sniffer-debug with -g + AddressSanitizer
#   make clean    remove all build artifacts
#
# The release and debug builds use SEPARATE output names on purpose: make tracks
# freshness by file timestamp, not by compiler flags, so a single shared output
# would let a stale debug binary masquerade as a release build (and vice versa).
#
# pcap-config emits the right -I/-L/-lpcap flags on both macOS and Linux,
# so the same Makefile works on either platform.

CC           = cc
CFLAGS       = -Wall -Wextra -std=c11 $(shell pcap-config --cflags)
LIBS         = $(shell pcap-config --libs)
SRC          = $(wildcard src/*.c)
TARGET       = sniffer
DEBUG_TARGET = sniffer-debug

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Debug build: symbols + AddressSanitizer (catches buffer overruns / leaks),
# written to its own binary so it never overwrites the release build.
debug: $(DEBUG_TARGET)

$(DEBUG_TARGET): $(SRC)
	$(CC) $(CFLAGS) -g -fsanitize=address -o $(DEBUG_TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET) $(DEBUG_TARGET)
	rm -rf $(TARGET).dSYM $(DEBUG_TARGET).dSYM

.PHONY: debug clean
