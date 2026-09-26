#pragma once

#include "FTPTransferTracker.hpp"
#include "TCPReassembler.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

struct TransferRecord {
    std::string command;
    std::string remoteName;
    std::string dataFlow;
    std::string outputFile;
    std::string status;
    std::string note;
    uint64_t capturedBytes{};
    uint64_t uniqueBytes{};
    uint64_t gapCount{};
    uint64_t gapBytes{};
    uint64_t overlapBytes{};
    uint64_t conflictingOverlapBytes{};
};

class FileReconstructor {
public:
    explicit FileReconstructor(std::filesystem::path outputDirectory);

    bool initialize(std::string& error);
    TransferRecord recordTransfer(const ftp::TransferCandidate& transfer,
                                  const std::string& dataFlow,
                                  const tcp::ReassemblyResult* stream,
                                  uint64_t capturedBytes,
                                  bool ambiguous,
                                  const std::string& note);
    bool writeManifest(std::string& error) const;

private:
    std::filesystem::path outputDirectory_;
    std::vector<TransferRecord> records_;
};
