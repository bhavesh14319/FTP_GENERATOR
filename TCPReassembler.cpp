#include "TCPReassembler.hpp"

#include <algorithm>  // std::min and std::stable_sort.
#include <cstddef>    // std::ptrdiff_t for iterator offsets.
#include <cstdint>    // Fixed-width TCP sequence-number types.
#include <utility>    // std::move when storing completed runs.
#include <vector>

namespace tcp {
namespace {

// A lightweight view of one segment after locating it relative to the stream anchor.
// offset is signed so segments before the anchor (e.g. wrap-aware comparisons) can be represented.
struct LocatedSegment {
    int64_t offset{};                       // Payload start, measured in bytes from the anchor.
    const PayloadSegment* segment{};        // Points to the original segment; payload is not copied here.
};

// Convert two 32-bit TCP sequence numbers into the nearest signed distance between them.
// TCP sequence numbers wrap at 2^32; this works when observed bytes are less than 2^31 apart.
int64_t sequenceDistance(uint32_t sequence, uint32_t anchor) {
    // Unsigned subtraction naturally wraps modulo 2^32.
    const uint32_t distance = sequence - anchor;

    // A value in the lower half of the ring means sequence is at/after anchor.
    if (distance <= 0x7fffffffU) return static_cast<int64_t>(distance);

    // A value in the upper half is interpreted as a negative distance before the anchor.
    return static_cast<int64_t>(distance) - 0x100000000LL;
}

} // namespace

ReassemblyResult reassembleTcpStream(const std::vector<PayloadSegment>& segments,
                                     std::optional<uint32_t> synSequence,
                                     std::optional<uint32_t> finSequence) {
    // Start with zero counts, no runs, and no boundary mismatch.
    ReassemblyResult result;

    // Preserve whether this direction's SYN and FIN sequence boundaries were supplied by the caller.
    result.sawSyn = synSequence.has_value();
    result.sawFin = finSequence.has_value();

    // Find a segment containing payload; control-only TCP packets carry no stream bytes.
    const PayloadSegment* anchorSegment = nullptr;
    for (const PayloadSegment& segment : segments) {
        // The first nonempty payload segment is a fallback anchor if we did not capture SYN.
        if (!segment.bytes.empty()) {
            anchorSegment = &segment;
            break;
        }
    }

    // With no payload segments there are no bytes to reorder, so return the boundary metadata.
    if (anchorSegment == nullptr) return result;

    // SYN consumes one sequence number. If SYN was captured at 1000, the data anchor is 1001.
    // Without SYN, anchor at the first observed payload's sequence (adjusting if that segment has SYN).
    const uint32_t anchor = synSequence.has_value()
        ? *synSequence + 1U
        : anchorSegment->sequence + (anchorSegment->syn ? 1U : 0U);

    // Build a sortable list of sequence offsets and pointers to the original payload segments.
    std::vector<LocatedSegment> ordered;
    ordered.reserve(segments.size());

    // Convert each payload segment's TCP sequence number to an offset from the chosen anchor.
    for (const PayloadSegment& segment : segments) {
        // Ignore empty payloads; they do not contribute stream bytes.
        if (segment.bytes.empty()) continue;

        // Count all captured payload, including bytes repeated by TCP retransmissions.
        result.capturedPayloadBytes += segment.bytes.size();

        // A SYN on this segment consumes one sequence number before the segment's payload starts.
        const uint32_t payloadSequence = segment.sequence + (segment.syn ? 1U : 0U);

        // Save relative position plus a pointer; bytes stay in the input vector for now.
        ordered.push_back({sequenceDistance(payloadSequence, anchor), &segment});
    }

    // Reorder by TCP sequence position, not by packet capture order.
    // Stable sort preserves input order only when two segments have the same offset.
    std::stable_sort(ordered.begin(), ordered.end(), [](const LocatedSegment& left,
                                                        const LocatedSegment& right) {
        return left.offset < right.offset;
    });

    // With a known SYN boundary, the first payload should start at anchor (offset 0).
    // A positive first offset means the capture missed a prefix of the stream.
    if (synSequence.has_value() && !ordered.empty() && ordered.front().offset > 0) {
        ++result.gapCount;
        result.gapBytes += static_cast<uint64_t>(ordered.front().offset);
    }

    // Working state for the currently assembled contiguous run.
    int64_t runOffset = 0;                  // Run start relative to anchor.
    std::vector<uint8_t> runBytes;           // Ordered bytes accumulated for this run.
    bool haveRun = false;                    // Whether runBytes currently represents a run.

    // Close the current run and add it to the result. Called at a gap and after the final segment.
    auto finishRun = [&]() {
        // Nothing to store until a segment has started a run.
        if (!haveRun) return;

        // Convert relative run offset back into its first TCP sequence number (with 32-bit wrap).
        const uint32_t runSequence = anchor + static_cast<uint32_t>(runOffset);

        // Every byte stored in this run is unique; overlapping copies were not appended.
        result.uniquePayloadBytes += runBytes.size();

        // Move the assembled bytes into the result instead of making another full copy.
        result.runs.push_back({runSequence, std::move(runBytes)});

        // Reset the temporary buffer and mark that a new run has not started yet.
        runBytes.clear();
        haveRun = false;
    };

    // Visit segments from lowest sequence offset to highest, merging them into runs.
    for (const LocatedSegment& located : ordered) {
        // Read the captured bytes and their half-open sequence-offset range [start, end).
        const std::vector<uint8_t>& bytes = located.segment->bytes;
        const int64_t segmentStart = located.offset;
        const int64_t segmentEnd = segmentStart + static_cast<int64_t>(bytes.size());

        // The first sorted segment starts the first run.
        if (!haveRun) {
            runOffset = segmentStart;
            runBytes = bytes;
            haveRun = true;
            continue;
        }

        // Sequence position immediately after the last byte currently in the run.
        const int64_t runEnd = runOffset + static_cast<int64_t>(runBytes.size());

        // Worked example (anchor sequence 5001): after "ABCDE" at seq 5001, runEnd is offset 5
        // (next sequence 5006). A segment at seq 5004 starts at offset 3, so it overlaps;
        // a segment at seq 5006 starts exactly at runEnd, so it is adjacent.
        // If the next segment instead starts at seq 5010 (offset 9), offsets 5..8 are missing: 4 bytes.
        if (segmentStart > runEnd) {
            // Example: a run ending at seq 5016 and a new segment starting at seq 5020
            // leave seq 5016..5019 absent, so this records one gap containing 4 bytes.
            ++result.gapCount;
            result.gapBytes += static_cast<uint64_t>(segmentStart - runEnd);

            // Keep runs separate across missing bytes; never fabricate or concatenate a gap.
            finishRun();
            runOffset = segmentStart;
            runBytes = bytes;
            haveRun = true;
            continue;
        }

        // The shared portion ends at whichever end comes first: existing run or incoming segment.
        // Example: run [offset 0, 5) has "ABCDE"; incoming seq 5004 "DEFGH" is [3, 8).
        // Their shared positions are offsets 3 and 4 (the bytes "DE"), so overlapEnd is 5.
        const int64_t overlapEnd = std::min(runEnd, segmentEnd);

        // If incoming starts before that shared end, compare/count all sequence positions in common.
        if (segmentStart < overlapEnd) {
            for (int64_t position = segmentStart; position < overlapEnd; ++position) {
                // Index of this same sequence position in the accumulated run.
                const size_t existingIndex = static_cast<size_t>(position - runOffset);

                // Index of this same sequence position in the incoming segment.
                const size_t incomingIndex = static_cast<size_t>(position - segmentStart);

                // Count a retransmitted/duplicate byte even when its value agrees.
                ++result.overlappingBytes;

                // If byte values disagree, retain the already accumulated byte and report the conflict.
                if (runBytes[existingIndex] != bytes[incomingIndex])
                    ++result.conflictingOverlapBytes;
            }
        }

        // Append only the incoming suffix beyond the existing run; do not duplicate overlapping bytes.
        if (segmentEnd > runEnd) {
            // Number of incoming bytes already covered by run; append starting just after runEnd.
            const size_t appendFrom = static_cast<size_t>(runEnd - segmentStart);

            // Continuing the example: "DEFGH" has 2 overlapping bytes ("DE"), so append from
            // incoming index 2, adding "FGH" and extending the run from "ABCDE" to "ABCDEFGH".
            // Next, seq 5006 "FGHIJ" overlaps 3 bytes ("FGH"), then appends "IJ".
            runBytes.insert(runBytes.end(), bytes.begin() + static_cast<std::ptrdiff_t>(appendFrom),
                            bytes.end());
        }
    }

    // Save the final run's ending offset before finishRun moves its bytes into result.runs.
    const int64_t observedEnd = runOffset + static_cast<int64_t>(runBytes.size());
    finishRun();

    // A FIN sequence marks the expected end of payload for this direction.
    if (finSequence.has_value()) {
        // Compare expected FIN boundary with the observed end, relative to the anchor.
        const int64_t expectedEnd = sequenceDistance(*finSequence, anchor);

        // FIN is beyond captured payload: some bytes at the end are missing.
        if (expectedEnd > observedEnd) {
            ++result.gapCount;
            result.gapBytes += static_cast<uint64_t>(expectedEnd - observedEnd);

        // Payload extends beyond the reported FIN position: boundaries are inconsistent.
        } else if (expectedEnd < observedEnd) {
            result.boundaryMismatch = true;
        }
    }

    // Return ordered runs plus completeness, gap, overlap, and boundary information.
    return result;
}

} // namespace tcp
