#include "FTPParser.hpp"

#include <algorithm>
#include <cstddef>
#include <cctype>
#include <utility>

namespace ftp {
namespace {

constexpr size_t kMaximumControlLine = 8192;

std::string upperAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

bool isCommandToken(const std::string& token) {
    if (token.empty() || token.size() > 4) return false;
    return std::all_of(token.begin(), token.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0;
    });
}

std::string safeDisplay(const std::string& line) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(line.size());
    for (unsigned char ch : line) {
        if (ch == '\t' || (ch >= 0x20 && ch != 0x7f)) {
            output.push_back(static_cast<char>(ch));
        } else {
            output += "\\x";
            output.push_back(hex[ch >> 4]);
            output.push_back(hex[ch & 0x0f]);
        }
    }
    return output;
}

Message parseLine(std::string line, bool fromClient) {
    Message message;
    if (fromClient) {
        const size_t separator = line.find_first_of(" \t");
        const std::string command = upperAscii(line.substr(0, separator));
        if (isCommandToken(command)) {
            message.kind = MessageKind::Command;
            if (command == "PASS") {
                // Never copy a password from a PCAP into logs or reports.
                message.text = "PASS <redacted>";
            } else {
                message.text = safeDisplay(line);
            }
        } else {
            message.text = safeDisplay(line);
        }
        return message;
    }

    if (line.size() >= 4 && std::isdigit(static_cast<unsigned char>(line[0])) &&
        std::isdigit(static_cast<unsigned char>(line[1])) &&
        std::isdigit(static_cast<unsigned char>(line[2])) &&
        (line[3] == ' ' || line[3] == '-')) {
        message.kind = MessageKind::Reply;
        message.replyCode = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        message.multilineStart = line[3] == '-';
    }
    message.text = safeDisplay(line);
    return message;
}

} // namespace

ParseResult parseControlStream(const std::vector<uint8_t>& bytes, bool fromClient) {
    ParseResult result;
    size_t lineStart = 0;

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] != '\n') {
            if (i - lineStart > kMaximumControlLine) result.overlongLine = true;
            continue;
        }

        size_t lineEnd = i;
        if (lineEnd > lineStart && bytes[lineEnd - 1] == '\r') --lineEnd;
        const size_t lineLength = lineEnd - lineStart;
        if (lineLength > kMaximumControlLine) {
            result.overlongLine = true;
            Message omitted;
            omitted.text = "[overlong FTP control line omitted]";
            result.messages.push_back(std::move(omitted));
        } else {
            std::string line;
            line.reserve(lineLength);
            for (size_t j = lineStart; j < lineEnd; ++j)
                line.push_back(static_cast<char>(bytes[j]));
            result.messages.push_back(parseLine(std::move(line), fromClient));
        }
        lineStart = i + 1;
    }

    if (lineStart < bytes.size()) result.incompleteTrailingLine = true;
    return result;
}

} // namespace ftp
