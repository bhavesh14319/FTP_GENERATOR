#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace tcp {

// One captured TCP segment that has application payload.
struct PayloadSegment {
    uint32_t sequence{}; // TCP sequence number from the packet header.
    bool syn{};          // SYN consumes one sequence number before the payload.
    std::vector<uint8_t> bytes;
};

// A run is a contiguous range of observed stream bytes. Separate runs mean
// there is a sequence-number gap between them; callers must not join them as
// if the missing bytes were present.
struct ReassembledRun {
    uint32_t firstSequence{};
    std::vector<uint8_t> bytes;
};

struct ReassemblyResult {
    uint64_t capturedPayloadBytes{};
    uint64_t uniquePayloadBytes{};
    uint64_t overlappingBytes{};
    uint64_t conflictingOverlapBytes{};
    uint64_t gapBytes{};
    uint64_t gapCount{};
    bool sawSyn{};
    bool sawFin{};
    bool boundaryMismatch{};
    std::vector<ReassembledRun> runs;

    bool complete() const {
        return sawSyn && sawFin && gapCount == 0 && conflictingOverlapBytes == 0 &&
               !boundaryMismatch;
    }
};

// Orders payload by TCP sequence number, removes duplicate overlap, retains
// the first captured byte if overlapping retransmissions disagree, and
// reports missing sequence ranges instead of filling them with fake bytes.
ReassemblyResult reassembleTcpStream(const std::vector<PayloadSegment>& segments,
                                     std::optional<uint32_t> synSequence,
                                     std::optional<uint32_t> finSequence);

} // namespace tcp
