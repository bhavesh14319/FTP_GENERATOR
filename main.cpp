#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "FileReconstructor.hpp"
#include "FTPParser.hpp"
#include "FTPTransferTracker.hpp"
#include "TCPReassembler.hpp"

namespace {

uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

uint16_t read16(const uint8_t* p, bool little) {
    return little ? static_cast<uint16_t>(p[0] | (p[1] << 8)) : be16(p);
}

uint32_t read32(const uint8_t* p, bool little) {
    if (!little) return be32(p);
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

struct Endpoint {
    uint32_t ip{}; // Stored in host integer form, with the first IPv4 octet in the high byte.
    uint16_t port{};
    bool operator<(const Endpoint& other) const {
        return std::tie(ip, port) < std::tie(other.ip, other.port);
    }
};

struct FlowKey {
    Endpoint first;
    Endpoint second;
    bool operator<(const FlowKey& other) const {
        return std::tie(first, second) < std::tie(other.first, other.second);
    }
};

struct FlowStats {
    uint64_t packets[2]{};
    uint64_t payloadBytes[2]{};
    bool sawSyn[2]{};
    bool sawFin[2]{};
    std::optional<uint32_t> synSequence[2];
    std::optional<uint32_t> finSequence[2];
    std::vector<tcp::PayloadSegment> payloadSegments[2];
};

std::string ipText(uint32_t ip) {
    return std::to_string((ip >> 24) & 255) + "." +
           std::to_string((ip >> 16) & 255) + "." +
           std::to_string((ip >> 8) & 255) + "." +
           std::to_string(ip & 255);
}

bool readExact(std::istream& in, uint8_t* out, size_t size) {
    in.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(size));
    return static_cast<size_t>(in.gcount()) == size;
}

void parsePacket(const std::vector<uint8_t>& frame, std::map<FlowKey, FlowStats>& flows,
                 uint64_t& skipped) {
    // Example frame: [Ethernet: 14 bytes][IPv4: usually 20][TCP: usually 20][payload].
    // For an FTP control packet, the payload might contain text such as "USER bob\r\n".

    // Ethernet II needs 14 bytes: destination MAC (6), source MAC (6), and EtherType (2).
    // If the frame is shorter, count it as skipped and stop before reading outside the buffer.
    if (frame.size() < 14) { ++skipped; return; }

    // Bytes 0..13 are Ethernet; the next header (IPv4, if supported) starts at byte 14.
    size_t offset = 14;

    // Ethernet bytes 12..13 identify the next protocol. be16 reads the value in network byte order.
    const uint16_t etherType = be16(frame.data() + 12);

    // 0x0800 means IPv4. This parser does not handle other Ethernet payload types.
    if (etherType != 0x0800) { ++skipped; return; }

    // IPv4's minimum header is 20 bytes; verify those bytes were captured before inspecting them.
    if (frame.size() < offset + 20) { ++skipped; return; }

    // Point to the first byte of the IPv4 header (byte 14 of the Ethernet frame).
    const uint8_t* ip = frame.data() + offset;

    // The high four bits of IPv4 byte 0 are the IP version; value 4 means IPv4.
    if ((ip[0] >> 4) != 4) { ++skipped; return; }

    // The low four bits of IPv4 byte 0 give header length in 4-byte words; 5 means 20 bytes.
    // A larger value is possible when the IPv4 header contains options.
    const size_t ipHeaderLen = static_cast<size_t>(ip[0] & 0x0f) * 4;

    // IPv4 bytes 2..3 give total IP packet length, including the IP header and TCP data.
    const uint16_t totalLen = be16(ip + 2);

    // Validate lengths before using them: header >= 20, total >= header, and the captured frame
    // must contain the complete declared IP packet. Otherwise, skip this malformed/truncated frame.
    if (ipHeaderLen < 20 || totalLen < ipHeaderLen || frame.size() < offset + ipHeaderLen ||
        frame.size() < offset + totalLen) { ++skipped; return; }

    // IPv4 byte 9 identifies the next protocol; value 6 means TCP (UDP, for example, is 17).
    if (ip[9] != 6) { ++skipped; return; }

    // IPv4 bytes 6..7 hold fragment flags and fragment offset.
    const uint16_t frag = be16(ip + 6);

    // Reject later fragments (nonzero offset) and packets marked "more fragments".
    // This program does not reassemble IP fragments, so it cannot safely parse their TCP headers.
    if ((frag & 0x1fff) != 0 || (frag & 0x2000) != 0) { ++skipped; return; }

    // TCP starts after the IPv4 header; use its actual length so IPv4 options are accounted for.
    const uint8_t* tcp = ip + ipHeaderLen;

    // Bytes remaining in the IP packet after its IP header: TCP header plus TCP payload.
    const size_t tcpAvailable = totalLen - ipHeaderLen;

    // A TCP header must be at least 20 bytes before its fields can be read.
    if (tcpAvailable < 20) { ++skipped; return; }

    // TCP byte 12's upper four bits give header length in 4-byte words; 5 means 20 bytes.
    const size_t tcpHeaderLen = static_cast<size_t>(tcp[12] >> 4) * 4;

    // Reject a too-short TCP header or a header extending beyond the IP packet.
    if (tcpHeaderLen < 20 || tcpHeaderLen > tcpAvailable) { ++skipped; return; }

    // Read source IP (IPv4 offset 12) and source port (TCP offset 0) into one endpoint.
    Endpoint src{be32(ip + 12), be16(tcp)};

    // Read destination IP (IPv4 offset 16) and destination port (TCP offset 2).
    Endpoint dst{be32(ip + 16), be16(tcp + 2)};

    // Compare endpoints so both directions of one connection can share a stable flow key.
    const bool srcFirst = src < dst;

    // Store the lesser endpoint first regardless of which endpoint sent this packet.
    FlowKey key{srcFirst ? src : dst, srcFirst ? dst : src};

    // Look up this connection's statistics, creating a new FlowStats entry if needed.
    FlowStats& stats = flows[key];

    // Direction 0 is canonical first->second; direction 1 is second->first.
    const unsigned direction = srcFirst ? 0 : 1;

    // Count this packet in its direction, even if it carries no payload (for example, a pure ACK).
    ++stats.packets[direction];

    // TCP byte 13 contains flags including SYN (0x02) and FIN (0x01).
    const uint8_t flags = tcp[13];

    // Payload is whatever remains in the IP packet after both IP and TCP headers.
    const size_t payloadLen = tcpAvailable - tcpHeaderLen;

    // TCP bytes 4..7 contain the sequence number used later to order stream bytes.
    const uint32_t sequence = be32(tcp + 4);

    // Count bytes observed in packets. Retransmitted bytes count again here; reassembly deduplicates later.
    stats.payloadBytes[direction] += payloadLen;

    // Remember whether this direction has had a SYN flag; SYN establishes a stream boundary.
    stats.sawSyn[direction] |= (flags & 0x02) != 0;

    // Remember whether this direction has had a FIN flag; FIN marks the sender's stream ending.
    stats.sawFin[direction] |= (flags & 0x01) != 0;

    // Save the first SYN sequence number for this direction, if this packet carries SYN.
    if ((flags & 0x02) != 0 && !stats.synSequence[direction].has_value())
        stats.synSequence[direction] = sequence;

    // Save the first FIN's expected payload end. Payload advances by payloadLen; SYN also consumes
    // one sequence number when SYN and FIN happen to be set on the same packet.
    if ((flags & 0x01) != 0 && !stats.finSequence[direction].has_value())
        stats.finSequence[direction] = sequence + static_cast<uint32_t>(payloadLen) +
                                       ((flags & 0x02) != 0 ? 1U : 0U);

    // Only packets with payload add application bytes to the stream; pure ACKs have none to save.
    if (payloadLen > 0) {
        // Make a record carrying this packet's TCP payload for later sequence-aware reassembly.
        tcp::PayloadSegment segment;

        // Preserve the TCP sequence number, which identifies where these payload bytes belong.
        segment.sequence = sequence;

        // Preserve SYN because its sequence number comes before any payload in that segment.
        segment.syn = (flags & 0x02) != 0;

        // Copy bytes after the TCP header through the end of TCP data in this IP packet.
        // Example: if payloadLen is 10, this copies exactly 10 bytes such as "USER bob\r\n".
        segment.bytes.assign(tcp + tcpHeaderLen, tcp + tcpAvailable);

        // Save in this flow's direction. std::move transfers the vector instead of copying it again.
        stats.payloadSegments[direction].push_back(std::move(segment));
    }
}

int run(const std::string& path, const std::string& outputDirectory) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open input file: " + path);

    std::array<uint8_t, 24> global{};
    if (!readExact(in, global.data(), global.size()))
        throw std::runtime_error("file is too short to contain a classic PCAP header");

    bool little = false;
    bool supportedMagic = true;
    bool nano = false;
    if (global[0] == 0xd4 && global[1] == 0xc3 && global[2] == 0xb2 && global[3] == 0xa1) little = true;
    else if (global[0] == 0xa1 && global[1] == 0xb2 && global[2] == 0xc3 && global[3] == 0xd4) little = false;
    else if (global[0] == 0x4d && global[1] == 0x3c && global[2] == 0xb2 && global[3] == 0xa1) { little = true; nano = true; }
    else if (global[0] == 0xa1 && global[1] == 0xb2 && global[2] == 0x3c && global[3] == 0x4d) { little = false; nano = true; }
    else supportedMagic = false;
    if (!supportedMagic) throw std::runtime_error("unsupported capture format (expected classic PCAP; PCAPNG is not supported yet)");

    const uint16_t versionMajor = read16(global.data() + 4, little);
    const uint16_t versionMinor = read16(global.data() + 6, little);
    if (versionMajor != 2 || versionMinor != 4)
        throw std::runtime_error("unsupported classic PCAP version " +
                                 std::to_string(versionMajor) + "." +
                                 std::to_string(versionMinor) + " (expected 2.4)");

    const uint32_t linkType = read32(global.data() + 20, little);
    if (linkType != 1) throw std::runtime_error("unsupported link type " + std::to_string(linkType) + "; this version requires Ethernet");
    const uint32_t snapLen = read32(global.data() + 16, little);
    if (snapLen == 0 || snapLen > (64u * 1024u * 1024u))
        throw std::runtime_error("invalid or unreasonably large PCAP snapshot length");

    std::map<FlowKey, FlowStats> flows;
    std::map<FlowKey, std::vector<ftp::Message>> controlClientMessages;
    std::map<FlowKey, std::vector<ftp::Message>> controlServerMessages;
    uint64_t packets = 0, skipped = 0;
    std::array<uint8_t, 16> packetHeader{};
    while (in.peek() != std::char_traits<char>::eof()) {
        if (!readExact(in, packetHeader.data(), packetHeader.size())) {
            std::cerr << "warning: truncated packet header at end of capture\n";
            break;
        }
        const uint32_t captured = read32(packetHeader.data() + 8, little);
        const uint32_t original = read32(packetHeader.data() + 12, little);
        if (captured > snapLen || captured > (64u * 1024u * 1024u))
            throw std::runtime_error("invalid packet length in capture");
        if (original < captured)
            std::cerr << "warning: packet original length is smaller than captured length\n";
        std::vector<uint8_t> frame(captured);
        if (!readExact(in, frame.data(), frame.size())) {
            std::cerr << "warning: truncated packet data at end of capture\n";
            break;
        }
        ++packets;
        parsePacket(frame, flows, skipped);
    }

    FileReconstructor reconstructor(outputDirectory);
    std::string outputError;
    if (!reconstructor.initialize(outputError)) throw std::runtime_error(outputError);

    std::cout << "Classic PCAP, " << (nano ? "nanosecond" : "microsecond")
              << " timestamps; Ethernet link type\n"
              << "Packets read: " << packets << "\n"
              << "Packets skipped (unsupported protocol or malformed): " << skipped << "\n"
              << "Bidirectional IPv4/TCP flows: " << flows.size() << "\n\n";
    for (const auto& [key, value] : flows) {
        const bool ftpCandidate = key.first.port == 21 || key.second.port == 21;
        std::cout << (ftpCandidate ? "FTP control candidate: " : "TCP flow: ")
                  << ipText(key.first.ip) << ":" << key.first.port << " <-> "
                  << ipText(key.second.ip) << ":" << key.second.port << " | packets "
                  << value.packets[0] << "/" << value.packets[1] << " | TCP payload bytes "
                  << value.payloadBytes[0] << "/" << value.payloadBytes[1]
                  << ((value.sawSyn[0] || value.sawSyn[1]) ? " | SYN seen" : "")
                  << ((value.sawFin[0] || value.sawFin[1]) ? " | FIN seen" : "") << "\n";

        for (unsigned direction = 0; direction < 2; ++direction) {
            if (value.payloadSegments[direction].empty()) continue;
            const Endpoint& from = direction == 0 ? key.first : key.second;
            const Endpoint& to = direction == 0 ? key.second : key.first;
            const tcp::ReassemblyResult stream = tcp::reassembleTcpStream(
                value.payloadSegments[direction], value.synSequence[direction],
                value.finSequence[direction]);
            std::cout << "  Reassembled " << ipText(from.ip) << ":" << from.port << " -> "
                      << ipText(to.ip) << ":" << to.port
                      << " | payload segments " << value.payloadSegments[direction].size()
                      << " | captured bytes " << stream.capturedPayloadBytes
                      << " | unique ordered bytes " << stream.uniquePayloadBytes
                      << " | contiguous runs " << stream.runs.size()
                      << " | gaps " << stream.gapCount << " (" << stream.gapBytes << " bytes)"
                      << " | overlapping bytes " << stream.overlappingBytes
                      << " | conflicting overlap bytes " << stream.conflictingOverlapBytes
                      << " | SYN " << (stream.sawSyn ? "seen" : "not seen")
                      << " | FIN " << (stream.sawFin ? "seen" : "not seen")
                      << (stream.boundaryMismatch ? " | FIN sequence mismatch" : "")
                      << " | " << (stream.complete() ? "complete boundaries" : "partial/uncertain")
                      << "\n";
            for (size_t runIndex = 0; runIndex < stream.runs.size(); ++runIndex) {
                const tcp::ReassembledRun& run = stream.runs[runIndex];
                const uint32_t nextSequence = run.firstSequence +
                                              static_cast<uint32_t>(run.bytes.size());
                std::cout << "    run " << runIndex << ": sequence " << run.firstSequence
                          << " through " << nextSequence << " (exclusive), "
                          << run.bytes.size() << " ordered bytes\n";
            }

            if (ftpCandidate) {
                if (stream.gapCount != 0 || stream.runs.size() != 1 ||
                    stream.conflictingOverlapBytes != 0 || stream.boundaryMismatch) {
                    std::cout << "    FTP control parsing skipped: stream is not one clean contiguous run\n";
                } else {
                    const bool fromServer = from.port == 21;
                    const ftp::ParseResult parsed = ftp::parseControlStream(
                        stream.runs.front().bytes, !fromServer);
                    if (fromServer) controlServerMessages[key] = parsed.messages;
                    else controlClientMessages[key] = parsed.messages;
                    std::cout << "    FTP control lines ("
                              << (fromServer ? "server -> client" : "client -> server")
                              << "): " << parsed.messages.size() << "\n";
                    for (const ftp::Message& message : parsed.messages) {
                        if (message.kind == ftp::MessageKind::Command) {
                            std::cout << "      command: " << message.text << "\n";
                        } else if (message.kind == ftp::MessageKind::Reply) {
                            std::cout << "      reply " << message.replyCode << ": " << message.text;
                            if (message.multilineStart) std::cout << " (multiline start)";
                            std::cout << "\n";
                        } else {
                            std::cout << "      line: " << message.text << "\n";
                        }
                    }
                    if (parsed.incompleteTrailingLine)
                        std::cout << "      note: trailing control bytes did not end with LF\n";
                    if (parsed.overlongLine)
                        std::cout << "      note: at least one control line exceeded the 8192-byte limit\n";
                }
            }
        }
    }

    std::cout << "\nFTP passive transfer associations:\n";
    for (const auto& [controlKey, clientMessages] : controlClientMessages) {
        const auto serverIt = controlServerMessages.find(controlKey);
        if (serverIt == controlServerMessages.end()) continue;

        const Endpoint& controlServer = controlKey.first.port == 21
            ? controlKey.first : controlKey.second;
        const Endpoint& controlClient = controlKey.first.port == 21
            ? controlKey.second : controlKey.first;
        const std::vector<ftp::TransferCandidate> transfers = ftp::trackPassiveTransfers(
            clientMessages, serverIt->second, controlServer.ip);

        for (const ftp::TransferCandidate& transfer : transfers) {
            std::cout << "  " << transfer.command << " " << transfer.remoteName
                      << " | passive endpoint " << ipText(transfer.dataServerIp) << ":"
                      << transfer.dataServerPort << " | expected data direction "
                      << (transfer.clientSendsData ? "client -> server" : "server -> client")
                      << "\n";

            struct DataFlowMatch {
                const FlowKey* key{};
                const FlowStats* stats{};
                unsigned clientToServerDirection{};
            };
            std::vector<DataFlowMatch> matches;
            for (const auto& [dataKey, dataStats] : flows) {
                if (dataKey.first.port == 21 || dataKey.second.port == 21) continue;
                unsigned clientToServerDirection = 0;
                bool endpointMatch = false;
                if (dataKey.first.ip == transfer.dataServerIp &&
                    dataKey.first.port == transfer.dataServerPort &&
                    dataKey.second.ip == controlClient.ip) {
                    clientToServerDirection = 1; // Canonical second endpoint is the client.
                    endpointMatch = true;
                } else if (dataKey.second.ip == transfer.dataServerIp &&
                           dataKey.second.port == transfer.dataServerPort &&
                           dataKey.first.ip == controlClient.ip) {
                    clientToServerDirection = 0; // Canonical first endpoint is the client.
                    endpointMatch = true;
                }
                if (!endpointMatch) continue;

                matches.push_back({&dataKey, &dataStats, clientToServerDirection});
            }
            if (matches.empty()) {
                std::cout << "    no matching data TCP flow was found in the capture\n";
                const TransferRecord record = reconstructor.recordTransfer(
                    transfer, "", nullptr, 0, false,
                    "No TCP flow matched the passive server endpoint and FTP client IP");
                std::cout << "    reconstruction: " << record.status << "\n";
            } else if (matches.size() > 1) {
                std::cout << "    warning: multiple data flows matched this passive endpoint\n";
                const TransferRecord record = reconstructor.recordTransfer(
                    transfer, "multiple matching flows", nullptr, 0, true,
                    "Ambiguous passive endpoint; no file was written");
                std::cout << "    reconstruction: " << record.status << "\n";
            } else {
                const DataFlowMatch& match = matches.front();
                const FlowKey& dataKey = *match.key;
                const FlowStats& dataStats = *match.stats;
                const unsigned dataDirection = transfer.clientSendsData
                    ? match.clientToServerDirection : 1U - match.clientToServerDirection;
                const tcp::ReassemblyResult dataStream = tcp::reassembleTcpStream(
                    dataStats.payloadSegments[dataDirection], dataStats.synSequence[dataDirection],
                    dataStats.finSequence[dataDirection]);
                const Endpoint& dataSource = dataDirection == 0 ? dataKey.first : dataKey.second;
                const Endpoint& dataDestination = dataDirection == 0 ? dataKey.second : dataKey.first;
                const std::string dataFlow = ipText(dataSource.ip) + ":" +
                    std::to_string(dataSource.port) + " -> " + ipText(dataDestination.ip) + ":" +
                    std::to_string(dataDestination.port);
                std::cout << "    matched data flow " << dataFlow << " | captured bytes "
                          << dataStats.payloadBytes[dataDirection] << " | unique ordered bytes "
                          << dataStream.uniquePayloadBytes << " | gaps " << dataStream.gapCount
                          << " (" << dataStream.gapBytes << " bytes) | "
                          << (dataStream.complete() ? "complete TCP boundaries" : "partial/uncertain TCP stream")
                          << "\n";
                const TransferRecord record = reconstructor.recordTransfer(
                    transfer, dataFlow, &dataStream, dataStats.payloadBytes[dataDirection], false, "");
                std::cout << "    reconstruction: " << record.status;
                if (!record.outputFile.empty()) std::cout << " | file " << record.outputFile;
                if (!record.note.empty()) std::cout << " | " << record.note;
                std::cout << "\n";
            }
        }
    }

    if (!reconstructor.writeManifest(outputError)) throw std::runtime_error(outputError);
    std::cout << "\nReconstruction manifest: "
              << (std::filesystem::path(outputDirectory) / "manifest.csv").string() << "\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: ftp-recover <capture.pcap> [output-directory]\n";
        return 2;
    }
    try {
        return run(argv[1], argc == 3 ? argv[2] : "recovered");
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
