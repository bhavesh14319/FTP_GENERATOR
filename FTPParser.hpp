#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ftp {

enum class MessageKind {
    Command,
    Reply,
    Other
};

struct Message {
    MessageKind kind{MessageKind::Other};
    std::string text;       // Safe-to-display line; PASS arguments are redacted.
    int replyCode{-1};      // 100-599 for recognized server reply lines.
    bool multilineStart{};  // Reply uses "xyz-" form to start a multiline response.
};

struct ParseResult {
    std::vector<Message> messages;
    bool incompleteTrailingLine{};
    bool overlongLine{};
};

// Parse one already-reassembled FTP control direction. The caller supplies
// true for client-to-server bytes and false for server-to-client bytes.
ParseResult parseControlStream(const std::vector<uint8_t>& bytes, bool fromClient);

} // namespace ftp
