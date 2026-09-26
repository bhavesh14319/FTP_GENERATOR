# Phase 1 walkthrough: read packets and identify TCP flows

This phase answers: **“Can the program safely read this capture and tell me which TCP conversations it contains?”**

It does not reconstruct a file yet. For that, the next phase must put TCP payload segments into sequence-number order, then FTP control messages must connect a transfer command to its data flow.

## Build and run

From this directory:

```bash
g++ -std=c++17 -Wall -Wextra -Wpedantic main.cpp -o ftp-recover
./ftp-recover /home/bhavesh/capture/ftp-small.pcap
```

For the supplied capture, look for two important rows: the FTP control flow using port `21`, and the passive data flow using server port `1076`. The two byte counts on a row mean bytes sent in each of the two canonical endpoint directions; they are not packet-order byte streams.

## Packet path through the program

```text
PCAP global header
  -> packet record header
     -> Ethernet header
        -> IPv4 header
           -> TCP header
              -> normalized flow key + direction counters
```

The program uses `std::vector<uint8_t>` for raw packet bytes. This matters: later, file payloads must remain bytes and must not be converted to text.

## Functions and data structures in `main.cpp`

### `be16` and `be32`

These decode 16-bit and 32-bit **big-endian** values. Ethernet, IPv4, and TCP store multi-byte numbers in network byte order. For example, TCP port bytes `00 15` become decimal 21. Reading bytes explicitly avoids struct padding, unaligned access, and host-endian assumptions.

### `read16` and `read32`

Classic PCAP's own header fields use the byte order indicated by the file's magic number, which may differ from network byte order. These helpers select little-endian or big-endian decoding for capture metadata. Do not use these helpers for IP/TCP fields; those always use `be16` / `be32`.

### `Endpoint`

An endpoint is an IPv4 address plus TCP port. The `ip` integer stores the first address octet in the high byte, so `ipText()` can print `192.168.111.130` by shifting out one octet at a time. Its comparison operator gives endpoints a stable sort order.

### `FlowKey`

A TCP connection is bidirectional. To avoid creating separate flows for `A -> B` and `B -> A`, the parser sorts the pair of endpoints and always stores the smaller endpoint first. `FlowKey` compares those canonical pairs so they can be keys in `std::map`.

Direction is preserved separately: direction `0` means packet source equals the canonical first endpoint; direction `1` means it came from the second endpoint. This is why both upload and download byte counts can be reported without losing packet direction.

### `FlowStats`

For now, this stores packet counts and TCP payload byte counts in both directions, plus whether a SYN or FIN flag was observed. It is summary metadata, not the actual reassembled stream. Later phases will retain the individual sequence-numbered payload segments.

### `ipText`

Formats the 32-bit IPv4 address for human-readable output. The shifts extract octets from most significant to least significant byte.

### `readExact`

Reads exactly the requested number of bytes. A capture can be truncated, so callers check its return value before interpreting a header or packet. This helper prevents partially read data from being treated as a valid structure.

### `parsePacket`

This function receives one captured Ethernet frame and either updates the flow map or increments the skipped-packet count:

1. Checks that the Ethernet header is at least 14 bytes.
2. Reads EtherType. It accepts IPv4 (`0x0800`) and skips other link payloads in this first version.
3. Checks the minimum IPv4 header, version, IHL, total length, and captured bytes. IHL can exceed 20 bytes when IPv4 options exist.
4. Accepts only TCP protocol number 6. It skips fragmented IPv4 datagrams because full IP fragment reassembly is not implemented yet.
5. Checks the minimum TCP header and TCP data offset. The offset can also exceed 20 bytes when TCP options exist.
6. Computes TCP payload size as `IPv4 total length - IPv4 header length - TCP header length`.
7. Builds the canonical endpoint pair, determines packet direction, and increments that direction's counters.
8. Reads SYN and FIN flags for a basic connection lifecycle hint.

Every size check happens before reading fields at that offset. This is the main defense against malformed or truncated packets.

### `run`

`run` owns the capture-reading workflow:

1. Opens the named file in binary mode.
2. Reads the 24-byte classic PCAP global header and recognizes the four classic magic encodings (little/big endian and micro/nanosecond timestamps).
3. Checks the link type. This starter supports Ethernet (`1`) only.
4. Repeatedly reads each 16-byte packet record header, validates captured length, reads the frame bytes, and calls `parsePacket`.
5. Stops cleanly with a warning if the final record is truncated.
6. Prints the total packet count, skipped count, and per-flow summary.

PCAPNG uses a different block format, so it is rejected with a specific message rather than misread as classic PCAP.

### `main`

`main` checks command-line usage, calls `run`, and converts exceptions into a concise error and nonzero exit code. This keeps file and format errors from terminating the program with an uncaught exception.

## Expected flow interpretation for the sample

The `ftp-small.pcap` capture showed:

- Control flow: `192.168.111.130:37194` ↔ `44.241.66.173:21`.
- Passive data flow: `192.168.111.130:46562` ↔ `44.241.66.173:1076`.
- The server's `227` response advertised port `1076`: `4 * 256 + 52`.
- The data direction for `STOR test.txt` is client to server.

Phase 1 can show those two flows and payload byte counts. It cannot yet prove which payload bytes form `test.txt`, because it does not retain TCP sequence numbers or parse FTP control state.

## Current limits (intentional for this phase)

- Classic PCAP only; PCAPNG is reported unsupported.
- Ethernet II carrying IPv4 only; no IPv6, VLAN tags, or IP fragment reassembly.
- TCP payload lengths are counted but payload bytes and sequence numbers are not retained.
- FTP is not parsed yet, so port 21 is only a control-flow candidate.
- A flow seen on a dynamic port is not automatically an FTP data flow.

Keeping these limits explicit makes it possible to add one networking concept at a time without claiming incomplete support.
