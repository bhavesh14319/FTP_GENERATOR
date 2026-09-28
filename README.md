# FTP Recover

FTP Recover is a command-line C++17 application that analyzes a classic PCAP packet capture, summarizes IPv4/TCP connections, identifies FTP control conversations, and reconstructs files from supported passive FTP transfers when the captured TCP data is sufficiently complete.

It is intended for analyzing captures you are authorized to inspect. Plain FTP is unencrypted, so packet captures may contain credentials and private file contents.

## What it supports

- Classic PCAP (microsecond or nanosecond timestamps) with Ethernet link type.
- Ethernet II, IPv4, and TCP parsing, with bidirectional flow summaries.
- TCP payload ordering by sequence number, duplicate and overlap accounting, gap reporting, and SYN/FIN boundary checks.
- FTP control parsing on port 21, including redaction of `PASS` arguments in displayed commands.
- Passive FTP transfer association for `PASV` and `EPSV`, and file transfer commands `STOR`, `APPE`, and `RETR`.
- Binary output for a matched data stream, plus a CSV manifest describing the reconstruction result.

PCAPNG, non-Ethernet link types, IPv6, VLAN tags, IP fragment reassembly, active FTP (`PORT`/`EPRT`), and FTP control connections on nonstandard ports are not supported. Unsupported or malformed packets are skipped or reported as errors as appropriate. A successful FTP reply alone does not prove that all file bytes were captured.

## Build

Requirements: CMake 3.16 or newer and a C++17-compatible compiler.

```sh
cmake -S . -B build
cmake --build build
```

This produces the `ftp-recover` executable in the build directory.

## Run

```sh
./build/ftp-recover <capture.pcap> [output-directory]
```

For example:

```sh
./build/ftp-recover session.pcap recovered
```

If the output directory is omitted, files are written under `recovered/`. The directory is created if needed. The program prints capture totals, TCP flow summaries, reassembly statistics, parsed FTP control messages, passive transfer associations, and each reconstruction outcome.

## Components

| Component | Files | Responsibility |
| --- | --- | --- |
| Capture reader and packet parser | `main.cpp` | Reads classic PCAP records; validates Ethernet, IPv4, and TCP headers; collects packet and flow statistics. |
| Flow and transfer orchestration | `main.cpp` | Groups both directions of a TCP connection, selects FTP control candidates on port 21, associates passive data flows, and coordinates reconstruction. |
| TCP reassembler | `TCPReassembler.hpp/.cpp` | Orders payload by sequence number, removes duplicate overlap, preserves observed bytes, and reports gaps, conflicting overlaps, and boundary completeness. |
| FTP control parser | `FTPParser.hpp/.cpp` | Parses client commands and server replies from reassembled control streams. It redacts password arguments from displayed `PASS` commands. |
| FTP transfer tracker | `FTPTransferTracker.hpp/.cpp` | Pairs passive `PASV`/`EPSV` replies with subsequent `STOR`, `APPE`, or `RETR` commands and determines data direction. |
| File reconstructor | `FileReconstructor.hpp/.cpp` | Writes safe-named binary files when stream evidence permits and records every candidate transfer in the manifest. |

## Output and completeness

The output directory contains reconstructed files (when possible) and `manifest.csv`. Remote names are reduced to a safe basename; unsafe characters are replaced, long names are shortened, and collisions receive numeric suffixes. Existing files are not overwritten.

- `complete`: contiguous data was observed with SYN and FIN boundaries and no conflicting overlap.
- `partial`: contiguous observed bytes were saved with a `.partial` suffix because a TCP boundary was missing.
- `gapped_not_written`: sequence gaps were found, so separated byte runs were not incorrectly concatenated.
- `conflict_not_written`: conflicting overlapping bytes or an inconsistent FIN boundary made output unsafe.
- `no_matching_data_flow` / `ambiguous_not_written`: the transfer had no matching passive data connection or multiple connections matched.

The manifest includes the FTP command and remote name, matched data flow, output filename, status, captured and unique byte counts, gap and overlap statistics, and a note. Treat the manifest and output files as sensitive data too.

## Project notes

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and current implementation boundaries. The `PHASE*_GUIDE.md` files document the development phases.
