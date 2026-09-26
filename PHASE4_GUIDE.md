# Phase 4 walkthrough: associate passive FTP transfers with TCP flows

## What this phase adds

The program now connects passive FTP control messages to the separate data connection:

1. Read a `PASV` / `EPSV` command from the client stream.
2. Parse its `227` / `229` server reply to learn the server data IP/port.
3. Associate the endpoint with a following `STOR`, `APPE`, or `RETR` command.
4. Find a captured TCP flow from the FTP client IP to that passive server endpoint.
5. Select the expected payload direction and show its reassembly byte/gap summary.

This phase reports the association. It does **not** write the reconstructed bytes to disk yet.

## Build and run

```bash
cd /home/bhavesh/Projects/FTP_REGENERATOR
cmake -S . -B build
cmake --build build
./build/ftp-recover /path/to/capture.pcap > build/ftp-report.txt
```

Search the report for `FTP passive transfer associations`. A successful match looks like:

```text
STOR document.pdf | passive endpoint 44.241.66.173:1083 | expected data direction client -> server
  matched data flow 192.168.111.130:36060 -> 44.241.66.173:1083
  | captured bytes 364566 | unique ordered bytes 364566 | gaps 0 (0 bytes)
  | complete TCP boundaries
```

The exact port, filename, and byte counts depend on the capture.

## `FTPTransferTracker.hpp`

### `TransferCandidate`

Describes one transfer command and the expected passive server endpoint:

- `command`: `STOR`, `APPE`, or `RETR`.
- `remoteName`: the path/name argument from the command.
- `dataServerIp` and `dataServerPort`: parsed from `227` (PASV) or `229` (EPSV).
- `clientSendsData`: true for uploads (`STOR`, `APPE`) and false for downloads (`RETR`).

### `trackPassiveTransfers`

Takes client-side FTP messages and server-side FTP messages for one port-21 flow. It returns transfer candidates that have a recognizable passive endpoint and a filename.

## `FTPTransferTracker.cpp`

### `parseUnsigned` and `trim`

These parse numeric FTP reply fields without accepting trailing junk, and remove whitespace around a field.

### `parsePasv`

Finds the parenthesized six-number tuple in a `227` response:

```text
(h1,h2,h3,h4,p1,p2)
```

It builds the IPv4 address from `h1` through `h4`, and the port as `p1 * 256 + p2`. If the server advertises `0.0.0.0`, it uses the control connection's server IP instead. Invalid octets or port zero are rejected.

### `parseEpsv`

Finds the port in the `229` response's delimiter format, such as `|||6446|`. EPSV does not include an IP address, so the data IP is the FTP control server's IP.

### `commandParts`

Splits a client command into a command word and the remaining argument. It uppercases the command word for case-insensitive matching while preserving the filename argument.

### `trackPassiveTransfers`

First it collects parseable `227` and `229` replies in server-stream order. Then it walks the client commands:

- On `PASV` or `EPSV`, it assigns the next passive reply as the current data endpoint.
- On `STOR`, `APPE`, or `RETR`, it creates a transfer candidate and consumes that endpoint.
- On `LIST`, `NLST`, or `MLSD`, it consumes the endpoint without calling it a file transfer. Directory listings also use a data connection.

Replies are paired with passive commands in order. This is appropriate for the simple, sequential FTP sessions used so far. Correlating command/reply timing robustly for pipelined commands and failed negotiations is a future refinement.

## Integration and matching in `main.cpp`

While printing parsed control messages, `main.cpp` retains the client and server message lists for each port-21 flow. After all TCP flows are known, it asks the tracker for transfer candidates.

For each candidate, it searches the other flows for:

- An endpoint matching the advertised passive server IP and port.
- The other endpoint's IP matching the FTP control client's IP.

The client's ephemeral data port is not known from the FTP command; the captured TCP flow supplies it. Once matched, the command determines the payload direction: client-to-server for STOR/APPE, server-to-client for RETR. The report then summarizes the reassembled bytes in that direction.

If no matching flow exists, the capture may have missed the data connection, the server's PASV address may differ because of NAT, or the transfer may use active FTP. The current tracker supports passive PASV/EPSV only.

## Next phase

Phase 5 adds binary file output, safe output names, collision handling, and a manifest that records partial/incomplete status.
