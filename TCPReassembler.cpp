#include "TCPReassembler.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace tcp {
namespace {

struct LocatedSegment {
    int64_t offset{};
    const PayloadSegment* segment{};
};

// Interpret the unsigned subtraction as the nearest signed distance on the
// TCP sequence-number ring. This handles 32-bit wrap as long as all observed
// bytes are within 2^31 bytes of the chosen anchor.
int64_t sequenceDistance(uint32_t sequence, uint32_t anchor) {
    const uint32_t distance = sequence - anchor;
    if (distance <= 0x7fffffffU) return static_cast<int64_t>(distance);
    return static_cast<int64_t>(distance) - 0x100000000LL;
}

} // namespace

ReassemblyResult reassembleTcpStream(const std::vector<PayloadSegment>& segments,
                                     std::optional<uint32_t> synSequence,
                                     std::optional<uint32_t> finSequence) {
    ReassemblyResult result;
    result.sawSyn = synSequence.has_value();
    result.sawFin = finSequence.has_value();

    const PayloadSegment* anchorSegment = nullptr;
    for (const PayloadSegment& segment : segments) {
        if (!segment.bytes.empty()) {
            anchorSegment = &segment;
            break;
        }
    }
    if (anchorSegment == nullptr) return result;

    // TCP SYN occupies one sequence number, so data in a SYN segment begins
    // at sequence + 1. Most data segments do not have SYN set.
    const uint32_t anchor = synSequence.has_value()
        ? *synSequence + 1U
        : anchorSegment->sequence + (anchorSegment->syn ? 1U : 0U);

    std::vector<LocatedSegment> ordered;
    ordered.reserve(segments.size());
    for (const PayloadSegment& segment : segments) {
        if (segment.bytes.empty()) continue;
        result.capturedPayloadBytes += segment.bytes.size();
        const uint32_t payloadSequence = segment.sequence + (segment.syn ? 1U : 0U);
        ordered.push_back({sequenceDistance(payloadSequence, anchor), &segment});
    }
    std::stable_sort(ordered.begin(), ordered.end(), [](const LocatedSegment& left,
                                                        const LocatedSegment& right) {
        return left.offset < right.offset;
    });

    // If we observed SYN, the stream begins at SYN sequence + 1. A first
    // payload segment later than that means the capture is missing a prefix.
    if (synSequence.has_value() && !ordered.empty() && ordered.front().offset > 0) {
        ++result.gapCount;
        result.gapBytes += static_cast<uint64_t>(ordered.front().offset);
    }

    int64_t runOffset = 0;
    std::vector<uint8_t> runBytes;
    bool haveRun = false;

    auto finishRun = [&]() {
        if (!haveRun) return;
        const uint32_t runSequence = anchor + static_cast<uint32_t>(runOffset);
        result.uniquePayloadBytes += runBytes.size();
        result.runs.push_back({runSequence, std::move(runBytes)});
        runBytes.clear();
        haveRun = false;
    };

    for (const LocatedSegment& located : ordered) {
        const std::vector<uint8_t>& bytes = located.segment->bytes;
        const int64_t segmentStart = located.offset;
        const int64_t segmentEnd = segmentStart + static_cast<int64_t>(bytes.size());

        if (!haveRun) {
            runOffset = segmentStart;
            runBytes = bytes;
            haveRun = true;
            continue;
        }

        const int64_t runEnd = runOffset + static_cast<int64_t>(runBytes.size());
        if (segmentStart > runEnd) {
            ++result.gapCount;
            result.gapBytes += static_cast<uint64_t>(segmentStart - runEnd);
            finishRun();
            runOffset = segmentStart;
            runBytes = bytes;
            haveRun = true;
            continue;
        }

        const int64_t overlapEnd = std::min(runEnd, segmentEnd);
        if (segmentStart < overlapEnd) {
            for (int64_t position = segmentStart; position < overlapEnd; ++position) {
                const size_t existingIndex = static_cast<size_t>(position - runOffset);
                const size_t incomingIndex = static_cast<size_t>(position - segmentStart);
                ++result.overlappingBytes;
                if (runBytes[existingIndex] != bytes[incomingIndex])
                    ++result.conflictingOverlapBytes;
            }
        }

        // Keep the already stored bytes for overlaps (first captured segment
        // wins). Append only new bytes beyond the current contiguous run.
        if (segmentEnd > runEnd) {
            const size_t appendFrom = static_cast<size_t>(runEnd - segmentStart);
            runBytes.insert(runBytes.end(), bytes.begin() + static_cast<std::ptrdiff_t>(appendFrom),
                            bytes.end());
        }
    }

    const int64_t observedEnd = runOffset + static_cast<int64_t>(runBytes.size());
    finishRun();

    // FIN's sequence number is the expected end position of application data.
    // If FIN is beyond the final observed payload, bytes are missing at the end.
    if (finSequence.has_value()) {
        const int64_t expectedEnd = sequenceDistance(*finSequence, anchor);
        if (expectedEnd > observedEnd) {
            ++result.gapCount;
            result.gapBytes += static_cast<uint64_t>(expectedEnd - observedEnd);
        } else if (expectedEnd < observedEnd) {
            result.boundaryMismatch = true;
        }
    }
    return result;
}

} // namespace tcp
