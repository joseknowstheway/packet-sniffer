# Makefile — Network Packet Sniffer
#
# Targets:
#   make          build the optimized binary ./sniffer
#   make debug    build with -g and AddressSanitizer for leak/overflow hunting
#   make clean    remove build artifacts
#
# pcap-config emits the right -I/-L/-lpcap flags on both macOS and Linux,
# so the same Makefile works on either platform.

CC      = cc
CFLAGS  = -Wall -Wextra -std=c11 $(shell pcap-config --cflags)
LIBS    = $(shell pcap-config --libs)
SRC     = $(wildcard src/*.c)
TARGET  = sniffer

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Debug build: symbols + AddressSanitizer (catches buffer overruns / leaks,
# which matter once we start casting raw packet bytes onto structs).
debug: $(SRC)
	$(CC) $(CFLAGS) -g -fsanitize=address -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
	rm -rf $(TARGET).dSYM

.PHONY: debug clean
