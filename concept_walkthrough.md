# Concept Walkthrough — Packet Sniffer & Protocol Analyzer

> A running log of the **concepts** behind each stage of the build — written so I
> can *explain every line* in an interview, not just ship code. Each stage lists
> what was built, the key ideas, and the questions a Cisco-style interviewer is
> likely to ask (with answers).
>
> This document grows one section per stage. Code lives in `src/`; the original
> spec is `../packet_sniffer_project.md`.

---

## Table of Contents

- [Stage 1 — Capture Pipeline](#stage-1--capture-pipeline)
- [Stage 2 — Ethernet Frame Parsing (Layer 2)](#stage-2--ethernet-frame-parsing-layer-2)
- [Stage 3 — IPv4 Parsing (Layer 3)](#stage-3--ipv4-parsing-layer-3) *(pending)*
- [Stage 4 — Transport Parsing (Layer 4)](#stage-4--transport-parsing-layer-4) *(pending)*
- [Stage 5 — Filter Engine](#stage-5--filter-engine) *(pending)*
- [Stage 6 — Live Statistics](#stage-6--live-statistics) *(pending)*
- [Stage 7 — Polish & Presentation](#stage-7--polish--presentation) *(pending)*
- [Field Notes — Why Traffic May Not Be Visible](#field-notes--why-traffic-may-not-be-visible)

---

## Stage 1 — Capture Pipeline

**Files:** `main.c`, `capture.c`, `capture.h`, `Makefile`
**Goal:** open a network interface and run a loop that hands every captured
packet to a callback. No decoding yet — just prove the pipeline works.

### Key concepts

**1. How libpcap captures traffic.**
libpcap is a userspace library over the OS kernel's packet-capture facility
(BPF — the Berkeley Packet Filter — on macOS/BSD; `AF_PACKET` sockets on Linux).
The kernel copies frames off the NIC into a buffer your process reads. This is
why capture needs **root**: you're reading raw link-layer traffic, not a normal
per-process socket.

**2. `pcap_open_live(device, snaplen, promisc, to_ms, errbuf)` — the four knobs.**
- **snaplen** — max bytes to copy per packet. We use `65535` (whole frame). A
  smaller value (e.g. 96) captures only headers — faster, less memory, but you
  lose payload.
- **promisc** — promiscuous mode. `1` tells the NIC to deliver *all* frames on
  the wire, not just those addressed to our MAC. Without it you'd miss traffic
  between other hosts on the segment. (On switched/Wi-Fi networks you still only
  see what reaches your port, but it's the right flag to set.)
- **to_ms** — read timeout. The kernel may batch packets for up to this many ms
  before waking us, trading a little latency for far fewer syscalls (throughput).
- **errbuf** — caller-provided `char[PCAP_ERRBUF_SIZE]` where pcap writes a
  human-readable error string. A recurring libpcap idiom.

**3. The callback model: `pcap_loop()`.**
`pcap_loop(handle, -1, packet_handler, user)` blocks and calls `packet_handler`
once per packet. `-1` means "run forever." This is an **inversion of control** /
event-loop pattern — we register a handler and pcap drives it. The handler
signature gives us pcap metadata (`struct pcap_pkthdr`: timestamp, `caplen`,
`len`) plus a pointer to the raw bytes.

**4. `caplen` vs `len`.** `len` is the frame's real on-wire length; `caplen` is
how many bytes were actually captured (≤ snaplen). **Always parse against
`caplen`** — that's the memory you actually have.

**5. Clean shutdown: SIGINT + `pcap_breakloop()`.**
Ctrl+C raises `SIGINT`. A signal handler runs at an arbitrary point, so it may
only call **async-signal-safe** functions. `pcap_breakloop()` is safe and simply
makes the blocked `pcap_loop()` return — so all the real cleanup (printing the
summary, `pcap_close()`) happens back in normal code, not in the handler. Doing
`printf`/`free` directly in a signal handler is a classic bug.

**6. Portability choice — `pcap_findalldevs()` not `pcap_lookupdev()`.**
The spec suggests `pcap_lookupdev()`, which is **deprecated** (and returns a
pointer to a static buffer — not thread-safe). `pcap_findalldevs()` is the modern
API: it returns a linked list of interfaces we walk to pick a live, non-loopback
one, then free with `pcap_freealldevs()`.

### Likely interview questions

- *Why does packet capture require root?* → You're reading raw link-layer frames
  via a kernel facility (BPF), which bypasses normal per-process socket
  isolation.
- *What's promiscuous mode?* → NIC delivers all frames on the segment, not just
  ones addressed to our MAC.
- *Why not call `printf` in a signal handler?* → It's not async-signal-safe;
  re-entering stdio mid-write can deadlock/corrupt. Set a flag or call a safe
  function (`pcap_breakloop`) and do real work in the main flow.
- *Difference between `caplen` and `len`?* → captured vs. true length; parse
  against `caplen` to stay in-bounds.

---

## Stage 2 — Ethernet Frame Parsing (Layer 2)

**Files:** `ethernet.c`, `ethernet.h`, `display.c`, `display.h`
(+ wired into `capture.c`)
**Goal:** decode the 14-byte Ethernet header — source/dest MAC and EtherType.

### Key concepts

**1. The pointer cast — `(const ethernet_header_t *)packet`.**
libpcap gives us a flat `const uint8_t *`. Casting it to a struct pointer tells
the compiler "interpret these bytes with this layout," so `raw->src_mac` *is*
bytes 6–11. **This works only because the struct has no padding:** 6 + 6 + 2 = 14
bytes, every field sits on an even offset, and the widest member is `uint16_t`
(2-byte alignment), so the compiler inserts nothing. If padding crept in,
`raw->ethertype` would read the wrong bytes. This is the #1 thing interviewers
probe about struct-overlay parsing.

**2. Network byte order and `ntohs()`.**
Network protocols standardized on **big-endian** ("network byte order") so hosts
of differing native endianness interoperate. EtherType `0x0800` arrives as bytes
`08 00`. A little-endian machine (your ARM Mac) reading those raw gets `0x0008` —
wrong. `ntohs()` ("network-to-host short") swaps them into host order. There's
also `ntohl()` for 32-bit, and `htons()/htonl()` for the reverse direction.

**3. Why MAC addresses are NOT byte-swapped.**
A MAC is a 6-byte *array*, not a multi-byte integer — there's no numeric "order"
to reverse. We `memcpy` the bytes verbatim. Only multi-byte *numeric* fields
(EtherType, lengths, ports, addresses-as-integers) get `ntoh*`. Mixing this up is
a common bug.

**4. Separation of concerns: parse vs. display.**
`ethernet.c` only fills a struct (and normalizes byte order); `display.c` formats
it for humans. This keeps parsing pure and testable, and means later layers (IP,
TCP) follow the same `parse_* → print_*` shape. `format_mac()` takes a
caller-supplied buffer so it's **reentrant** — one log line formats two MACs, so
a shared static buffer would clobber itself.

**5. Defensive bounds check, first.**
The handler rejects frames shorter than `ETHERNET_HEADER_LEN` (14) *before* the
cast. A runt/truncated frame would otherwise make the cast read past the buffer —
undefined behavior, and exactly what `make debug` (AddressSanitizer) flags. Real
parsers validate length before every dereference.

**6. Link-type guard — `pcap_datalink()`.**
The parser assumes Ethernet II (`DLT_EN10MB`), where every frame opens with the
14-byte header. Loopback (`DLT_NULL`) and raw 802.11 use *different* framing, so
we reject anything else instead of emitting garbage. Checking the link type is
what separates a real tool from a demo.

### Reading the output

```
[ETH] ac:de:48:00:11:22 -> ff:ff:ff:ff:ff:ff | Type: IPv4 (0x0800)
```
- `ff:ff:ff:ff:ff:ff` destination = **broadcast** (e.g. ARP "who has this IP?").
- `33:33:...` destination = **IPv6 multicast**.
- `01:00:5e:...` = IPv4 multicast. Normal unicast is the NIC's burned-in MAC.

### Likely interview questions

- *Why is the struct cast safe here but risky in general?* → Layout matches the
  wire only when there's no padding; you must verify offsets/alignment (or use a
  packed struct / `memcpy` field-by-field).
- *When do you apply `ntohs`/`ntohl` and when not?* → Only on multi-byte numeric
  fields; never on byte arrays like MACs.
- *What's an EtherType?* → 2-byte field at offset 12 naming the upper-layer
  protocol (0x0800 IPv4, 0x86DD IPv6, 0x0806 ARP) — it's how you know what to
  parse next.
- *How would you detect/handle a malformed packet?* → Bounds-check `caplen`
  against each header size before parsing; ASan/Valgrind to catch overruns.

---

## Stage 3 — IPv4 Parsing (Layer 3)

**Files:** `ip.c`, `ip.h` (+ `print_ip` in `display.c`, dispatch in `capture.c`)
**Goal:** decode the IPv4 header — addresses, protocol, TTL, length — but only
for frames whose EtherType is IPv4.

### Key concepts

**1. Bit masking a packed byte (`version_ihl`).**
Byte 0 packs two 4-bit fields into 8 bits:
- `version_ihl >> 4` → high nibble → IP version (should be 4).
- `version_ihl & 0x0F` → low nibble → IHL.
This is the "bit masking for flags and fields" the Cisco JD calls out, and it
recurs constantly in protocol parsing.

**2. Why IHL exists and the `* 4`.**
IP headers are normally 20 bytes but can carry options up to 60. Instead of
spending a whole byte on a length, the designers stored a count of **32-bit
words**, so IHL=5 means 5 × 4 = 20 bytes. You must multiply by 4, and you need
this to locate Layer 4: `packet + 14 + get_ip_header_length(ip)`.

**3. `memcpy` instead of a struct-pointer cast — the alignment fix.**
The IP header starts at `packet + 14`, which is **not** 4-byte aligned, and the
struct has `uint32_t` address fields requiring 4-byte alignment. Casting and
dereferencing a misaligned pointer is **undefined behavior** (UBSan flags it;
some CPUs fault). `memcpy` reads bytes safely regardless of alignment into a
properly-aligned local struct. Ethernet could cast because nothing was wider
than 2 bytes and it sat at offset 0; IP cannot. **Knowing why Stage 2 casts but
Stage 3 copies is a strong interview signal.**

**4. `inet_ntop()` over `inet_ntoa()`.**
Both render a 32-bit address as a dotted string. `inet_ntoa()` (which the spec
mentions) returns a pointer to a **shared static buffer**, so two calls in one
`printf` clobber each other. `inet_ntop()` writes into a caller buffer, is
thread-safe, and supports IPv6. It expects the address in **network byte
order** — which is exactly why `parse_ip` leaves `src_ip`/`dest_ip` unswapped
while converting the other numeric fields with `ntohs`.

**5. TTL (Time To Live).**
Each router that forwards a packet decrements TTL by 1; at 0 the packet is
dropped and an ICMP "time exceeded" is returned. Prevents routing loops and is
the mechanism behind `traceroute`. Typical initial values: 64 (Linux/macOS),
128 (Windows).

### Likely interview questions

- *How do you extract version and header length from one byte?* → high/low
  nibble via `>> 4` and `& 0x0F`; IHL is in 32-bit words so ×4 for bytes.
- *Why memcpy the IP header instead of casting like Ethernet?* → alignment:
  uint32_t fields at a non-4-aligned offset → casting is UB; memcpy is safe.
- *Why `inet_ntop` over `inet_ntoa`?* → reentrancy/thread-safety (no shared
  static buffer) and IPv6 support; needs network-order input.
- *What does TTL do and how does traceroute exploit it?* → loop prevention via
  per-hop decrement; traceroute sends increasing TTLs to map each hop.
- *How do you find where the TCP/UDP header starts?* →
  `14 (Ethernet) + IHL*4`, not a fixed 34, because of IP options.

---

## Stage 4 — Transport Parsing (Layer 4)

**Files:** `transport.c`, `transport.h` (+ `print_tcp/udp/icmp` in `display.c`,
protocol dispatch in `capture.c`)
**Goal:** decode TCP, UDP, and ICMP — ports, sequence numbers, TCP flags, ICMP
types. Completes the Ethernet → IP → Transport pipeline (milestone checkpoint).

### Key concepts

**1. Protocol dispatch — `switch (ip.protocol)`.**
The IP header's `protocol` byte (6=TCP, 17=UDP, 1=ICMP) selects the parser.
Each layer names the next: EtherType did L2→L3, the protocol number does L3→L4.
A real network stack is nested dispatch exactly like this.

**2. Variable offset — `14 + IHL*4`, never a hardcoded `34`.**
The transport header's position depends on the IP header length (options!), so
`l4_offset = ETHERNET_HEADER_LEN + get_ip_header_length(ip)`. Hardcoding 34 is
the most common hand-rolled-parser bug: fine until a packet carries IP options,
then everything downstream silently misreads. We also reject IHL < 20.

**3. `ntohl` vs `ntohs` — operand size matters.**
TCP seq/ack are **32-bit** → `ntohl`; ports/window/checksum are 16-bit →
`ntohs`. Wrong one = byte-swapped garbage. `data_offset` and `flags` are single
bytes → no conversion (a 1-byte value has no order).

**4. Decoding TCP flags with bitwise AND.**
The flags byte packs 6 control bits. `flags & TCP_SYN` is non-zero iff SYN is
set; we loop a mask→name table to build "SYN ACK", etc. These flags are the TCP
state machine: SYN (open) → SYN ACK (server reply) → ACK (established); FIN
closes gracefully, RST aborts. Watching `SYN` / `SYN ACK` / `ACK` in sequence is
the **three-way handshake** live.

**5. `data_offset` mirrors IHL.**
TCP can carry options (window scaling, SACK, timestamps), so its header is
20–60 bytes, encoded as 32-bit words in the high nibble of `data_offset`.
`get_tcp_header_length()` (high nibble × 4) is needed to skip past it for the
Stage 7 payload-preview stretch goal.

**6. Defense in depth / memory safety.**
Every transport parse is preceded by a `caplen` bounds check against that
header's size, and `parse_*` use `memcpy` (alignment-safe) like the IP parser.
The `make debug` AddressSanitizer build compiles and runs clean — this is the
"memory-safe C, validated at every layer" story for the resume.

### Likely interview questions

- *How does the sniffer know whether a packet is TCP or UDP?* → the IP
  `protocol` byte; dispatch on it.
- *Where does the TCP header start?* → 14 + IP header length (IHL×4), not a
  constant — because IP options vary the length.
- *When ntohl vs ntohs?* → 32-bit fields (seq/ack, IP addrs) use ntohl; 16-bit
  (ports, lengths) use ntohs; single bytes need neither.
- *Walk me through the TCP three-way handshake.* → client SYN → server SYN+ACK
  → client ACK; visible directly in the flags this tool prints.
- *How do you read individual flag bits out of a byte?* → bitwise AND with a
  single-bit mask per flag.
- *What's ICMP used for?* → control/diagnostics (ping = echo request/reply,
  unreachable, time-exceeded → traceroute), not application data.

---

## Stage 5 — Filter Engine

**Files:** `filter.c`, `filter.h` (+ `parse_args` moved out of `main.c`, handler
restructured in `capture.c`)
**Goal:** `--proto`, `--port`, `--host` flags that drop non-matching packets
silently.

### Key concepts

**1. `getopt_long()` — parsing `--long` flags.**
`getopt` handles only single-char flags (`-i`); `getopt_long()` adds GNU-style
`--proto`. You provide a `struct option[]` table mapping each long name to a
return code — here `--proto/--port/--host` → `'p'/'P'/'H'` so they don't
collide with `-i`/`-h`. The standard C idiom for CLI parsing.

**2. The byte-order trap in filtering (the subtle one).**
A comparison like `ip->src_ip == filter->filter_ip` only works if both sides are
in the same byte order. Two consistent conventions:
- **IP addresses** stay in **network** order (`inet_pton` writes network order;
  `parse_ip` left addresses unswapped). ✅
- **Ports** are in **host** order (`parse_tcp/udp` already `ntohs`'d them;
  `--port` parsed as a plain int). ✅
Mismatching these is the classic "my filter matches nothing" bug.

**3. `inet_pton()` — inverse of `inet_ntop()`.**
Converts `"8.8.8.8"` → 4 binary bytes in network order; its return value
(1/0/-1) doubles as validation, which is how `999.1.1.1` is rejected.

**4. `strtol` over `atoi` for `--port`.**
`atoi("99x")` silently returns 99; `strtol` gives an `endptr` to confirm the
whole token was numeric, plus range-check 1–65535. Proper untrusted-input
validation.

**5. parse → filter → print (control-flow restructure).**
The doc requires filtering before display, so the handler now parses all layers
into locals, calls `packet_matches_filter()`, then prints only on a match. The
filter receives `tcp_p`/`udp_p` (NULL for the wrong protocol) so a port filter
on a portless packet (ICMP) correctly fails to match.

**6. libpcap's user pointer instead of another global.**
The filter is passed as `pcap_loop`'s 4th argument; pcap hands it back to the
callback as `user`. Cleaner than global state — using the API's intended
context mechanism.

### Likely interview questions

- *How do you parse long command-line options in C?* → `getopt_long` with a
  `struct option` table.
- *Why might an IP filter silently match nothing?* → byte-order mismatch between
  the stored address and the comparison value.
- *Difference between `inet_pton`/`inet_ntop` and the older `inet_addr`/
  `inet_ntoa`?* → pton/ntop are IPv6-capable, reentrant, and validate input.
- *Why `strtol` instead of `atoi`?* → error detection + range validation of the
  full token.
- *How do you pass per-capture context into a libpcap callback?* → the `user`
  pointer argument of `pcap_loop`/`pcap_dispatch`.

---

## Field Notes — Why Traffic May Not Be Visible

> Surfaced while testing the Stage 5 `--proto udp --port 53` filter: a DNS lookup
> with `dig @8.8.8.8 cisco.com` appeared, but `nslookup github.com` and plain
> `dig github.com` produced nothing. The sniffer wasn't broken — it captured
> exactly what crossed the interface it was bound to.

**The core rule: a sniffer only sees the one interface it is bound to.**
`pcap_open_live(device, ...)` attaches to a single interface (e.g. `en0`). Any
traffic that travels over a *different* interface is completely invisible to
that capture. This is the first thing to check when "expected" traffic doesn't
show up.

**Common reasons captured traffic may be missing:**

1. **Wrong interface / traffic on another interface.** The classic case is a
   **VPN**: tunnel interfaces (`utun0`, `tun0`, `ppp0`, ...) carry traffic
   *inside* an encrypted tunnel, so it never appears as plaintext on the
   physical NIC. If DNS uses the system resolver and that resolver is reached
   through the VPN, queries ride `utunN`, not `en0`. (Meanwhile a query forced
   to a split-tunneled destination like `8.8.8.8` may still ride `en0` and be
   visible — which is exactly the asymmetry observed.)

2. **Caching — the packet is never sent.** A cached DNS answer (or any cached
   result) produces no network traffic at all. Force a fresh request (e.g. a
   random subdomain, or query a server directly) to guarantee a packet.

3. **Encrypted / alternative transport.** DNS-over-HTTPS (DoH) and DNS-over-TLS
   (DoT) send lookups as TCP:443 / TCP:853, so a `udp port 53` filter sees
   nothing even though DNS is happening. The same idea applies broadly: traffic
   may use a different protocol/port than assumed.

4. **Switched networks limit promiscuous mode.** On a switched LAN or Wi-Fi, a
   switch/AP only forwards frames destined for your host (plus broadcast/
   multicast), so promiscuous mode still won't reveal *other* hosts'
   unicast traffic. You generally see only your own machine's traffic. (To see
   everything you'd need a SPAN/mirror port or a hub.)

5. **Link type / offload quirks.** Capturing on the wrong DLT (loopback, raw
   Wi-Fi) yields different framing; and NIC offloads (checksum/segmentation)
   can make locally-generated packets look unusual to the capture point.

**Diagnostic commands (macOS):**
```bash
scutil --dns | grep -E 'nameserver|if_index'   # which resolver, which interface
ifconfig | grep -A3 utun                        # is a VPN tunnel active?
```

**Interview takeaway:** "A sniffer only sees the interface it's bound to, and
modern DNS often isn't plaintext UDP:53." Being able to reason about *where*
traffic flows (interface, tunnel, cache, transport) — not just how to parse it —
is exactly the network-fluency a systems/networking role wants.

---

## Stage 6 — Live Statistics

**Files:** `stats.c`, `stats.h` (+ `capture_context_t` and post-loop summary in
`capture.c`, `setlocale` in `main.c`)
**Goal:** per-protocol counts, total bytes, top-5 source IPs, summary on Ctrl+C.

### Key concepts

**1. The signal-safety payoff (headline).**
`printf`/`malloc`/`qsort` are not async-signal-safe; calling them from a signal
handler can deadlock or corrupt. So the SIGINT handler still only calls
`pcap_breakloop()`. That returns control to `start_capture`, where the summary
(printf, qsort, floating point) prints in **normal flow**. This is a deliberate,
correct **deviation from the project doc**, which said to print from the handler.
Articulating "the doc's approach is unsafe; here's why and the fix" is strong
senior-leaning judgment.

**2. Threading context without globals.**
The callback needs both the filter and the stats. Instead of more file-scope
globals, they're bundled into `capture_context_t` and passed via pcap's `user`
pointer. Stats are a **local in `start_capture`**, so they outlive the loop and
are still in scope to print afterward.

**3. `uint64_t` counters — overflow awareness.**
A busy link pushes millions of packets/bytes; 32-bit byte counters wrap at ~4 GB
in minutes. 64-bit won't realistically overflow. Sizing integers to expected
magnitude is a systems instinct.

**4. Top-talkers algorithm + honest trade-off.**
Recording is a linear scan of the IP table (O(n) per packet) — fine for a CLI on
a home link; a high-throughput collector would use a hash map. The comment names
the limitation rather than hiding it. Top-5 copies into a local array and
`qsort`s descending, on a copy so `const` stats aren't mutated.

**5. `qsort` comparator correctness.**
Compares `uint64_t` byte counts via explicit `>`/`<`, NOT `(int)(y - x)` —
subtracting two `uint64_t` and truncating to `int` can overflow and flip the
sign, silently corrupting the sort. A classic subtle bug.

**6. Human-readable formatting.**
`format_bytes` divides by 1024 up the unit ladder (B→KB→MB…); `%'llu` groups
thousands using the locale (`setlocale(LC_ALL, "")` in `main`). Makes demo
output look professional.

### Likely interview questions

- *Why not print your summary in the signal handler?* → not async-signal-safe;
  set a flag / break the loop and print in normal context.
- *How did you get data into the pcap callback without globals?* → the `user`
  pointer carrying a context struct.
- *Why 64-bit counters?* → avoid overflow on high-volume captures.
- *What's wrong with `return a - b;` in a qsort comparator on unsigned/large
  values?* → integer overflow/truncation flips ordering; compare explicitly.
- *What's the complexity of your top-talkers tracking and how would you scale
  it?* → O(n) linear scan; a hash map (IP→bytes) for high throughput.

---

## Stage 7 — Polish & Presentation

**Files:** `README.md`, this doc, `config`-style refactor in `filter.h`/`main.c`,
plus all three stretch goals wired through `capture.c`/`display.c`.
**Goal:** make the repo something a Cisco engineer wants to read, and add the
optional-but-impressive features.

### Key concepts

**1. BPF passthrough — in-kernel filtering (`--bpf`).**
`pcap_compile()` turns a text expression like `"tcp and port 80"` into BPF
bytecode; `pcap_setfilter()` installs it. The filter then runs **in the kernel**,
so non-matching packets are dropped *before* being copied to userspace — far
more efficient than our userspace filter, and how production tools (tcpdump,
Wireshark) work. We `pcap_freecode()` the program after installing (libpcap
copies it in). It composes with our own `--proto/--port/--host` filter.

**2. Writing a `.pcap` file (`--write`).**
`pcap_dump_open()` returns a `pcap_dumper_t` savefile handle; `pcap_dump()`
appends each packet's original bytes plus its capture timestamp in the standard
pcap format, which Wireshark/tcpdump can reopen. `pcap_dump_close()` flushes on
exit. This closes the loop between a from-scratch tool and the industry standard.

**3. Hex + ASCII payload preview (`--hex`).**
Classic hexdump layout: a fixed-width hex column (padded so rows align) beside a
printable-ASCII column (bytes outside 32–126 shown as `.`). The payload offset is
`14 + IP header + transport header` — and the transport header length is itself
variable for TCP (`data_offset`), which is why `get_tcp_header_length()` from
Stage 4 matters here.

**4. Memory-safety verification (the macOS reality).**
The brief says run Valgrind, but Valgrind is unreliable on Apple Silicon. The
equivalent story: build with `make debug` (AddressSanitizer — compile-time
instrumentation that catches overflows/use-after-free/leaks at runtime) and use
Apple's `leaks` tool. Being able to say "I used ASan and `leaks` because Valgrind
isn't viable on arm64 macOS" shows real platform fluency.

**5. A config struct instead of growing the filter struct.**
The new options (`--bpf/--hex/--write`) aren't filter criteria, so they went into
a separate `app_config_t` that bundles device + filter + options. Keeping the
`filter_config_t` focused on matching is a small design-hygiene call worth being
able to justify.

**6. Honest git history.**
Because git was deferred to the end, the commits all carry one date and can't
honestly portray the real multi-session timeline; a fabricated per-stage log
would also contain non-compiling intermediate states. So the repo uses a clean,
coherent commit structure, and *this* document carries the real progression.
Lesson for next time: commit per stage from day one.

### Likely interview questions

- *What's the difference between a BPF/kernel filter and filtering in your own
  code?* → BPF drops packets in-kernel before the userspace copy — less overhead;
  userspace filtering is more flexible but sees every packet.
- *How would you save captures for later analysis?* → `pcap_dump_*` to a `.pcap`
  file that Wireshark reads.
- *How did you check for memory bugs?* → AddressSanitizer build + `leaks`
  (Valgrind isn't viable on arm64 macOS); bounds checks at every layer.
- *Why a separate config struct?* → separation of concerns — options aren't
  filter criteria.
