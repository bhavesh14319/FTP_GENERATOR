#include "FTPTransferTracker.hpp"

#include <charconv>
#include <cctype>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace ftp {
namespace {

struct PassiveTarget {
    uint32_t ip{};
    uint16_t port{};
};

std::string upper(std::string value) {
    for (char& ch : value)
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    return value;
}

std::string trim(std::string_view value) {
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return std::string(value.substr(first, last - first));
}

bool parseUnsigned(std::string_view text, unsigned& value) {
    if (text.empty()) return false;
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

std::optional<PassiveTarget> parsePasv(const std::string& reply, uint32_t controlServerIp) {
    const size_t open = reply.find('(');
    const size_t close = reply.find(')', open == std::string::npos ? 0 : open + 1);
    if (open == std::string::npos || close == std::string::npos) return std::nullopt;

    const std::string_view body(reply.data() + open + 1, close - open - 1);
    unsigned values[6]{};
    size_t start = 0;
    for (size_t i = 0; i < 6; ++i) {
        const size_t comma = body.find(',', start);
        const size_t end = (i == 5) ? body.size() : comma;
        if (end == std::string_view::npos || end < start ||
            !parseUnsigned(trim(body.substr(start, end - start)), values[i]) || values[i] > 255)
            return std::nullopt;
        if (i < 5 && comma == std::string_view::npos) return std::nullopt;
        start = end + 1;
    }
    if (start != body.size() + 1) return std::nullopt;

    uint32_t ip = (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3];
    const uint16_t port = static_cast<uint16_t>(values[4] * 256 + values[5]);
    if (ip == 0) ip = controlServerIp; // Some servers advertise 0.0.0.0 behind NAT.
    if (port == 0) return std::nullopt;
    return PassiveTarget{ip, port};
}

std::optional<PassiveTarget> parseEpsv(const std::string& reply, uint32_t controlServerIp) {
    const size_t open = reply.find('(');
    const size_t close = reply.find(')', open == std::string::npos ? 0 : open + 1);
    if (open == std::string::npos || close == std::string::npos || close <= open + 4)
        return std::nullopt;

    const std::string_view body(reply.data() + open + 1, close - open - 1);
    const char delimiter = body[0];
    if (body.size() < 5 || body[1] != delimiter || body[2] != delimiter || body.back() != delimiter)
        return std::nullopt;
    const size_t portStart = 3;
    const size_t portEnd = body.find(delimiter, portStart);
    unsigned port = 0;
    if (portEnd == std::string_view::npos ||
        !parseUnsigned(body.substr(portStart, portEnd - portStart), port) ||
        port == 0 || port > 65535)
        return std::nullopt;
    return PassiveTarget{controlServerIp, static_cast<uint16_t>(port)};
}

std::pair<std::string, std::string> commandParts(const std::string& line) {
    const size_t split = line.find_first_of(" \t");
    const std::string command = upper(line.substr(0, split));
    if (split == std::string::npos) return {command, {}};
    size_t argumentStart = line.find_first_not_of(" \t", split);
    if (argumentStart == std::string::npos) return {command, {}};
    return {command, line.substr(argumentStart)};
}

} // namespace

std::vector<TransferCandidate> trackPassiveTransfers(
    const std::vector<Message>& clientMessages,
    const std::vector<Message>& serverMessages,
    uint32_t controlServerIp) {
    // Replies are collected in order. A matching failed/passive response can
    // be handled more precisely once control-message timestamps are retained.
    std::vector<std::optional<PassiveTarget>> passiveReplies;
    for (const Message& message : serverMessages) {
        if (message.kind != MessageKind::Reply) continue;
        if (message.replyCode == 227)
            passiveReplies.push_back(parsePasv(message.text, controlServerIp));
        else if (message.replyCode == 229)
            passiveReplies.push_back(parseEpsv(message.text, controlServerIp));
    }

    std::vector<TransferCandidate> transfers;
    size_t replyIndex = 0;
    std::optional<PassiveTarget> currentPassive;
    for (const Message& message : clientMessages) {
        if (message.kind != MessageKind::Command) continue;
        const auto [command, argument] = commandParts(message.text);

        if (command == "PASV" || command == "EPSV") {
            currentPassive.reset();
            if (replyIndex < passiveReplies.size()) currentPassive = passiveReplies[replyIndex];
            ++replyIndex;
            continue;
        }

        if (command == "STOR" || command == "APPE" || command == "RETR") {
            if (currentPassive.has_value() && !argument.empty()) {
                transfers.push_back({command, argument, currentPassive->ip,
                                     currentPassive->port,
                                     command == "STOR" || command == "APPE"});
            }
            currentPassive.reset();
            continue;
        }

        // A listing consumes the negotiated passive data channel too. Do not
        // incorrectly attach its data socket to a later RETR/STOR command.
        if (command == "LIST" || command == "NLST" || command == "MLSD")
            currentPassive.reset();
    }
    return transfers;
}

} // namespace ftp
