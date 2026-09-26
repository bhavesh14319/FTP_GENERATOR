# Phase 3 walkthrough: parse FTP control messages

## What this phase adds

The program now takes a reassembled TCP byte stream from a port-21 flow, splits it into FTP control lines, and labels client commands versus server replies. It redacts `PASS` arguments before printing them.

The next phase adds passive-mode transfer association: it uses `PASV`/`227` or `EPSV`/`229` plus `STOR`/`APPE`/`RETR` to find the matching TCP data flow. File writing follows after association.

## Build and run

```bash
cd /home/bhavesh/Projects/FTP_REGENERATOR
cmake -S . -B build
cmake --build build
./build/ftp-recover /path/to/capture.pcap > build/ftp-report.txt
```

Open `build/ftp-report.txt` and find `FTP control candidate`. The following lines show the reassembled control stream in each direction and then the parsed messages.

## Parser data structures (`FTPParser.hpp`)

### `MessageKind`

Identifies each complete line as a client `Command`, server `Reply`, or unclassified `Other` line.

### `Message`

Stores the safe-to-display text, the reply status code when the line is a server reply, and whether the reply starts a multiline response (`xyz-...`). A reply such as `227 Entering Passive Mode ...` has code 227; a command such as `STOR file.pdf` is a client command.

### `ParseResult`

Contains parsed messages and two flags: whether the stream ended with a partial line, and whether any line exceeded the parser's 8192-byte limit.

## Functions (`FTPParser.cpp`)

### `upperAscii`

Makes a command token uppercase for case-insensitive matching. It is used to recognize `PASS` even if the client sends it in lowercase.

### `isCommandToken`

Checks that the first word looks like an FTP command token: one to four alphanumeric characters. This prevents arbitrary text from being labeled as a command.

### `parseLine`

- For client-to-server text, it extracts the first word as the command.
- If that command is `PASS`, it stores only `PASS <redacted>` and discards the password argument.
- Other command lines are kept for display, including transfer names such as `STOR test.pdf`.
- For server-to-client text, it recognizes the FTP reply form: three digits followed by a space or hyphen. The digits become `replyCode`; a hyphen marks a multiline reply start.
- Lines that do not match those shapes are retained as `Other` rather than causing a parse failure.

### `parseControlStream`

Consumes the already-reassembled byte vector for one direction. It scans to each LF byte, removes a preceding CR when present, and passes the complete line to `parseLine`. It does not use packet boundaries as line boundaries; an FTP command can have been split across several TCP segments before reassembly.

Lines over 8192 bytes are omitted and noted. Any trailing bytes after the last LF are reported as an incomplete line rather than treated as a complete command/reply.

## Integration in `main.cpp`

The flow is a control candidate when either endpoint uses TCP port 21. For each direction, the program first reassembles the bytes. It parses them only if there is one contiguous run with no gaps, conflicting overlaps, or FIN-boundary mismatch.

The endpoint using port 21 identifies the server-to-client direction. The opposite direction is client-to-server. The program passes that role to `parseControlStream` and prints the resulting lines with `command` or `reply` labels.

The parser does not require FIN to have appeared before it can parse complete CRLF lines. This allows a capture that stops while the control connection is still open to show its complete messages, while the reassembly summary still labels the stream boundary as uncertain.

## How this connects to the PDF upload

In the control output, look for:

```text
command: PASV
reply 227: 227 Entering Passive Mode (...)
command: STOR your-file.pdf
reply 150: ...
reply 226: ...
```

The `227` line gives the passive server IP and port. The next phase will use that endpoint plus the client/server addresses and transfer state to identify which non-port-21 TCP flow belongs to `STOR your-file.pdf`.

The FTP control stream contains credentials in plain FTP. `PASS` arguments are redacted by the program; still keep the original PCAP private because it contains the password bytes.
