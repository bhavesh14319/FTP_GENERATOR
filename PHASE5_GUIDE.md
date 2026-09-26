# Phase 5 walkthrough: write reconstructed transfer bytes

## What this phase adds

The program now writes bytes from a matched FTP data stream to disk using binary mode and creates a CSV manifest describing each transfer. It only writes a normal filename when the TCP stream is complete. A gap-free stream missing a SYN or FIN boundary is saved with a `.partial` suffix. Streams with sequence gaps or conflicting overlaps are not written as files.

## Build and run

```bash
cd /home/bhavesh/Projects/FTP_REGENERATOR
cmake -S . -B build
cmake --build build
./build/ftp-recover /path/to/capture.pcap
```

The default output directory is `recovered/` under the current working directory. To choose a directory explicitly:

```bash
./build/ftp-recover /path/to/capture.pcap /path/to/output-directory
```

When run from the project root, recovered files and `manifest.csv` appear under `/home/bhavesh/Projects/FTP_REGENERATOR/recovered/`. That directory is ignored by Git.

## `FileReconstructor.hpp`

### `TransferRecord`

Stores one transfer's FTP command and remote name, matched data-flow description, output filename, byte/gap/overlap counts, status, and explanatory note. It becomes a row in `manifest.csv`.

### `FileReconstructor`

Owns the output directory and transfer records. Its public functions are:

- `initialize()`: create the output directory or return a clear error.
- `recordTransfer()`: record association/reassembly results, write eligible raw bytes, and return the resulting status.
- `writeManifest()`: write all records as CSV after transfers have been processed.

## `FileReconstructor.cpp`

### `safeBaseName`

Takes only the final path component of the server-provided filename. It handles both `/` and `\\` separators, replaces other unsafe characters, strips leading dots, and limits name length. This prevents a remote filename such as `../../outside/file.pdf` from writing outside the output directory.

### `uniquePath`

Checks whether a proposed output filename already exists. If it does, it tries suffixes such as `file-1.pdf` or `file-2.pdf`; existing files are not overwritten.

### `csvField`

Quotes a manifest field and doubles embedded quote marks, keeping filenames and notes valid CSV values.

### `initialize`

Creates the destination directory and verifies that the path is a directory. Filesystem errors are reported to the caller.

### `recordTransfer`

This is the main safety decision for a reconstructed file:

1. Copies the transfer metadata and TCP-quality metrics into a record.
2. Does not write when the endpoint match is ambiguous or absent.
3. Does not write when there are sequence gaps, multiple separated runs, conflicting overlapping bytes, or an inconsistent FIN boundary.
4. If the stream is complete, writes the received bytes under a sanitized filename.
5. If the stream is contiguous but its SYN or FIN boundary was not captured, writes the observed bytes with a `.partial` suffix and records the reason.
6. For an observed complete zero-byte transfer, it can create an empty file.

The output uses `std::ofstream` with `std::ios::binary`. It writes the `uint8_t` vector directly, without converting it to text or changing any byte. It flushes and closes the file, checks for errors, and removes a failed output file when possible.

### `writeManifest`

Creates `manifest.csv` with one row per transfer candidate, including unmatched or ambiguous candidates. Status values distinguish `complete`, `partial`, and cases where no file was written, such as `gapped_not_written`.

## Integration in `main.cpp`

The data-flow matcher collects all flows matching the passive endpoint and client address. It writes a file only when there is exactly one matching flow. It chooses client-to-server bytes for `STOR`/`APPE` and server-to-client bytes for `RETR`, then passes that direction's TCP reassembly result to `FileReconstructor`.

The program accepts an optional output-directory argument. With no second argument, it uses `recovered` relative to the current working directory. At the end, it writes the manifest and prints its path.

## How to validate the PDF manually

After running the app, inspect the output and compare hashes:

```bash
sha256sum /path/to/original.pdf recovered/original.pdf
```

Matching hashes show that the reconstructed bytes equal the local original. A `.partial` suffix or a non-complete manifest status means the capture did not provide a fully bounded, gap-free stream. Do not rename such a file to remove `.partial` until it has been independently checked.

## Current limits

- Passive FTP (`PASV` / `EPSV`) only; active FTP (`PORT` / `EPRT`) is not implemented.
- Only one unambiguous data TCP flow can be matched to a transfer candidate.
- Gapped streams are recorded in the manifest but not materialized as files, because concatenating runs would shift later bytes to the wrong file positions.
- The program does not hash the output itself; compare against the original when available.
- It does not yet support PCAPNG, IPv6, VLAN tags, or fragmented IPv4 datagrams.
