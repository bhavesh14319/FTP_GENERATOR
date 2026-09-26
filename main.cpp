#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

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
    bool sawSyn{};
    bool sawFin{};
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
    // Ethernet II header: 6-byte destination, 6-byte source, 2-byte EtherType.
    if (frame.size() < 14) { ++skipped; return; }
    size_t offset = 14;
    const uint16_t etherType = be16(frame.data() + 12);
    if (etherType != 0x0800) { ++skipped; return; } // First version: IPv4 only.

    // IPv4 header length is variable because options may be present.
    if (frame.size() < offset + 20) { ++skipped; return; }
    const uint8_t* ip = frame.data() + offset;
    if ((ip[0] >> 4) != 4) { ++skipped; return; }
    const size_t ipHeaderLen = static_cast<size_t>(ip[0] & 0x0f) * 4;
    const uint16_t totalLen = be16(ip + 2);
    if (ipHeaderLen < 20 || totalLen < ipHeaderLen || frame.size() < offset + ipHeaderLen ||
        frame.size() < offset + totalLen) { ++skipped; return; }
    if (ip[9] != 6) { ++skipped; return; } // TCP protocol number.
    const uint16_t frag = be16(ip + 6);
    if ((frag & 0x1fff) != 0 || (frag & 0x2000) != 0) { ++skipped; return; }

    const uint8_t* tcp = ip + ipHeaderLen;
    const size_t tcpAvailable = totalLen - ipHeaderLen;
    if (tcpAvailable < 20) { ++skipped; return; }
    const size_t tcpHeaderLen = static_cast<size_t>(tcp[12] >> 4) * 4;
    if (tcpHeaderLen < 20 || tcpHeaderLen > tcpAvailable) { ++skipped; return; }

    Endpoint src{be32(ip + 12), be16(tcp)};
    Endpoint dst{be32(ip + 16), be16(tcp + 2)};
    const bool srcFirst = src < dst;
    FlowKey key{srcFirst ? src : dst, srcFirst ? dst : src};
    FlowStats& stats = flows[key];
    const unsigned direction = srcFirst ? 0 : 1;
    ++stats.packets[direction];
    stats.payloadBytes[direction] += tcpAvailable - tcpHeaderLen;
    const uint8_t flags = tcp[13];
    stats.sawSyn |= (flags & 0x02) != 0;
    stats.sawFin |= (flags & 0x01) != 0;
}

int run(const std::string& path) {
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

    const uint32_t linkType = read32(global.data() + 20, little);
    if (linkType != 1) throw std::runtime_error("unsupported link type " + std::to_string(linkType) + "; this version requires Ethernet");
    const uint32_t snapLen = read32(global.data() + 16, little);
    if (snapLen == 0 || snapLen > (64u * 1024u * 1024u))
        throw std::runtime_error("invalid or unreasonably large PCAP snapshot length");

    std::map<FlowKey, FlowStats> flows;
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
                  << (value.sawSyn ? " | SYN seen" : "")
                  << (value.sawFin ? " | FIN seen" : "") << "\n";
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: ftp-recover <capture.pcap>\n";
        return 2;
    }
    try {
        return run(argv[1]);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
