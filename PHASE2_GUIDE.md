# Phase 2 walkthrough: TCP sequence-aware reassembly

## What this phase adds

Phase 1 counted how many TCP payload bytes appeared in packets. Phase 2 keeps the actual payload bytes and sequence numbers, then orders them into contiguous TCP byte runs. This is necessary because TCP packet order is not guaranteed to equal byte-stream order.

This phase still does **not** parse FTP commands or write files. It produces per-direction reassembly statistics and keeps the ordered bytes available for later FTP/file layers.

## Build and run

```bash
cd /home/bhavesh/Projects/FTP_REGENERATOR
cmake -S . -B build
cmake --build build
./build/ftp-recover /path/to/capture.pcap
```

For your larger PDF capture, find the FTP control flow on port 21, then its `227` passive reply. The advertised data port should identify the data flow. In the new report, look for the reassembly line where bytes go from your VM to that server port.

## The new data types (`TCPReassembler.hpp`)

### `PayloadSegment`

Stores one TCP packet's sequence number, whether the SYN flag is present, and a copy of that packet's payload bytes. The payload remains a `std::vector<uint8_t>` so binary bytes are preserved exactly.

TCP's SYN flag consumes one sequence number. Therefore, when a segment has SYN, its first payload byte is at `sequence + 1`; `reassembleTcpStream()` accounts for that.

### `ReassembledRun`

Stores a contiguous sequence range and its ordered bytes. A stream can have multiple runs if there is a missing sequence range. Keeping separate runs prevents the program from pretending missing bytes were captured.

### `ReassemblyResult`

Summarizes the output:

- `capturedPayloadBytes`: sum of payload bytes in every packet, including retransmissions.
- `uniquePayloadBytes`: bytes retained once in the ordered runs.
- `overlappingBytes`: bytes that arrived again in an overlapping segment.
- `conflictingOverlapBytes`: overlapped positions where the new packet differs from the already retained byte. The first captured value is kept, and the conflict is reported.
- `gapCount` / `gapBytes`: missing sequence ranges between observed data, or missing bytes at an observed stream boundary.
- `sawSyn` / `sawFin`: whether the capture contained the connection's start/end marker for this direction.
- `complete()`: true only when SYN and FIN boundaries are known, there are no sequence gaps, and overlapping bytes do not conflict.

`complete()` describes the observed TCP payload stream, not whether the FTP server replied with success. FTP completion is a separate application-level fact for a later phase.

## Reassembly function (`TCPReassembler.cpp`)

### `sequenceDistance(sequence, anchor)`

TCP sequence numbers are 32-bit counters and wrap from `0xffffffff` back to zero. This helper subtracts the chosen anchor and interprets the result as the nearest signed offset. For example, a sequence just before the anchor gets a negative offset, and a small wrapped-forward sequence gets a small positive offset.

Like TCP's own sequence comparisons, this signed-offset method assumes the relevant stream range is less than half the 32-bit sequence space (`2^31` bytes) from the anchor.

### `reassembleTcpStream(segments, synSequence, finSequence)`

1. Finds the first non-empty payload segment. If there are no payloads, it returns an empty summary.
2. Chooses the byte-stream anchor. When a SYN was captured, the first stream byte is `SYN sequence + 1`; otherwise, the first observed payload is the anchor and the true beginning remains unknown.
3. Gives each payload segment a signed offset from the anchor and sorts segments by that offset. Thus, an input order such as sequence `1005`, then `1000` becomes byte order `1000`, then `1005`.
4. Joins adjacent/overlapping payload ranges into a `ReassembledRun`.
5. Counts overlap as retransmitted/duplicate bytes. If overlapping bytes disagree, it retains the earlier captured value and increments `conflictingOverlapBytes`.
6. Starts a new run when the next segment begins after the current run ends. The missing interval is counted as a gap; the code does not fill it with zeroes.
7. If SYN or FIN was captured, checks whether the first/last observed payload aligns with those boundaries. Missing prefix/suffix bytes or a boundary mismatch keeps the stream from being marked complete.

The vector is sorted by sequence position, not timestamp or packet-list order. That is how the function handles ordinary out-of-order delivery.

## Changes in `main.cpp`

### `FlowStats`

In addition to the Phase 1 counters, each direction now stores:

- The sequence number from its SYN packet, if captured.
- The sequence position of its FIN, if captured.
- A list of payload-bearing `PayloadSegment`s.

Payload-free ACK and handshake packets still count in the packet totals, but they are not placed in the payload-segment list.

### `parsePacket()` additions

After validating the TCP header, the parser reads the TCP sequence number. It records SYN and FIN sequence boundaries per direction. For a FIN packet, its position is calculated after the packet payload (and after SYN if a packet has both flags). When a packet has payload, the bytes are copied into a `PayloadSegment` for that flow and direction.

### Flow report additions

After each flow summary, the program calls `reassembleTcpStream()` for every direction that contained payload and prints captured versus unique byte totals, run count, gap sizes, overlap counts, and whether the stream boundaries appear complete.

For the small test capture, the PDF/text upload direction should have one contiguous run. For a larger PDF, it should still be one run if all TCP payload bytes were captured; it will contain many payload segments joined in sequence order.

## How to read the new report fields

Example shape:

```text
Reassembled 192.168.111.130:36060 -> 44.241.66.173:1083
| payload segments 77 | captured bytes 364566 | unique ordered bytes 364566
| contiguous runs 1 | gaps 0 (0 bytes) | overlapping bytes 0
| conflicting overlap bytes 0 | SYN seen | FIN seen | complete boundaries
```

- If captured bytes exceed unique bytes, the difference is overlapping/retransmitted payload.
- `contiguous runs 1` and `gaps 0` mean every observed byte joins into one continuous range.
- Each following `run N` line gives its starting TCP sequence number and byte length. “Through X (exclusive)” means X is the sequence number immediately after the run's final byte. Sequence numbers wrap at 2^32.
- `gaps > 0` means some sequence range was not present in the capture; do not treat those bytes as reconstructed.
- `partial/uncertain` means a start or end boundary was not observed, a gap exists, or an overlap conflict exists.

## Current limits

- The app retains payload bytes in memory; very large captures will need resource limits or streaming storage.
- It reports ordered runs but does not yet write any run to disk.
- It does not yet parse the FTP control stream to associate a data flow with `STOR` or `RETR`.
- Sequence-distance unwrapping is bounded to less than `2^31` bytes from the anchor.
- IPv4 fragments, IPv6, VLAN tags, and PCAPNG remain unsupported as documented in Phase 1.
