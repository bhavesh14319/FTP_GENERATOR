#pragma once

#include "FTPParser.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ftp {

struct TransferCandidate {
    std::string command;       // STOR, APPE, or RETR.
    std::string remoteName;
    uint32_t dataServerIp{};   // Advertised by PASV, or control server for EPSV.
    uint16_t dataServerPort{};
    bool clientSendsData{};    // true for STOR/APPE; false for RETR.
};

// Pairs passive replies with PASV/EPSV requests in their stream order, then
// attaches the active passive endpoint to subsequent file-transfer commands.
std::vector<TransferCandidate> trackPassiveTransfers(
    const std::vector<Message>& clientMessages,
    const std::vector<Message>& serverMessages,
    uint32_t controlServerIp);

} // namespace ftp
