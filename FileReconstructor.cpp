#include "FileReconstructor.hpp"

#include <cctype>
#include <fstream>
#include <limits>
#include <system_error>
#include <utility>

namespace {

std::string safeBaseName(const std::string& remoteName) {
    std::string normalized = remoteName;
    for (char& ch : normalized) if (ch == '\\') ch = '/';
    const size_t slash = normalized.find_last_of('/');
    std::string base = slash == std::string::npos ? normalized : normalized.substr(slash + 1);

    std::string safe;
    safe.reserve(base.size());
    for (unsigned char ch : base) {
        const bool allowed = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                             (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        safe.push_back(allowed ? static_cast<char>(ch) : '_');
    }
    while (!safe.empty() && safe.front() == '.') safe.erase(safe.begin());
    if (safe.empty() || safe == "." || safe == "..") safe = "ftp-file.bin";
    if (safe.size() > 120) safe.resize(120);
    return safe;
}

std::filesystem::path uniquePath(const std::filesystem::path& directory,
                                 const std::string& baseName, bool partial) {
    const std::filesystem::path base(baseName);
    const std::string stem = base.stem().string();
    const std::string extension = base.extension().string();
    for (uint64_t suffix = 0; ; ++suffix) {
        std::string name = stem;
        if (suffix != 0) name += "-" + std::to_string(suffix);
        name += extension;
        if (partial) name += ".partial";
        const std::filesystem::path candidate = directory / name;
        std::error_code ec;
        const bool exists = std::filesystem::exists(candidate, ec);
        if (ec) throw std::filesystem::filesystem_error("cannot inspect output path", candidate, ec);
        if (!exists) return candidate;
    }
}

std::string csvField(const std::string& value) {
    std::string escaped = "\"";
    for (char ch : value) {
        if (ch == '"') escaped += "\"\"";
        else escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

} // namespace

FileReconstructor::FileReconstructor(std::filesystem::path outputDirectory)
    : outputDirectory_(std::move(outputDirectory)) {}

bool FileReconstructor::initialize(std::string& error) {
    std::error_code ec;
    std::filesystem::create_directories(outputDirectory_, ec);
    if (ec) {
        error = "cannot create output directory '" + outputDirectory_.string() + "': " + ec.message();
        return false;
    }
    if (!std::filesystem::is_directory(outputDirectory_, ec) || ec) {
        error = "output path is not a directory: " + outputDirectory_.string();
        return false;
    }
    return true;
}

TransferRecord FileReconstructor::recordTransfer(const ftp::TransferCandidate& transfer,
                                                  const std::string& dataFlow,
                                                  const tcp::ReassemblyResult* stream,
                                                  uint64_t capturedBytes,
                                                  bool ambiguous,
                                                  const std::string& note) {
    TransferRecord record;
    record.command = transfer.command;
    record.remoteName = transfer.remoteName;
    record.dataFlow = dataFlow;
    record.capturedBytes = capturedBytes;
    record.note = note;

    if (stream != nullptr) {
        record.uniqueBytes = stream->uniquePayloadBytes;
        record.gapCount = stream->gapCount;
        record.gapBytes = stream->gapBytes;
        record.overlapBytes = stream->overlappingBytes;
        record.conflictingOverlapBytes = stream->conflictingOverlapBytes;
    }

    if (ambiguous) {
        record.status = "ambiguous_not_written";
    } else if (stream == nullptr) {
        record.status = "no_matching_data_flow";
    } else if (stream->gapCount != 0 || stream->runs.size() > 1) {
        record.status = "gapped_not_written";
        record.note = "TCP sequence gaps are present; runs were not concatenated";
    } else if (stream->conflictingOverlapBytes != 0 || stream->boundaryMismatch) {
        record.status = "conflict_not_written";
        record.note = "overlapping payload or FIN boundary is inconsistent";
    } else if (stream->runs.empty() && !stream->complete()) {
        record.status = "empty_partial_not_written";
        record.note = "no payload bytes and complete TCP boundaries were not observed";
    } else {
        const bool complete = stream->complete();
        const std::vector<uint8_t> empty;
        const std::vector<uint8_t>& bytes = stream->runs.empty() ? empty : stream->runs.front().bytes;
        if (bytes.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
            record.status = "write_failed";
            record.note = "reconstructed stream is too large for the output write operation";
            records_.push_back(record);
            return record;
        }
        const std::filesystem::path path = uniquePath(outputDirectory_, safeBaseName(transfer.remoteName),
                                                      !complete);
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) {
            record.status = "write_failed";
            record.note = "could not open output file";
        } else {
            if (!bytes.empty()) {
                output.write(reinterpret_cast<const char*>(bytes.data()),
                             static_cast<std::streamsize>(bytes.size()));
            }
            output.flush();
            output.close();
            if (!output) {
                record.status = "write_failed";
                record.note = "write or flush failed";
                std::error_code removeError;
                std::filesystem::remove(path, removeError);
            } else {
                record.status = complete ? "complete" : "partial";
                record.outputFile = path.filename().string();
                if (!complete)
                    record.note = "contiguous observed bytes saved with .partial suffix; a TCP boundary was not captured";
            }
        }
    }

    records_.push_back(record);
    return record;
}

bool FileReconstructor::writeManifest(std::string& error) const {
    const std::filesystem::path path = outputDirectory_ / "manifest.csv";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot open manifest for writing: " + path.string();
        return false;
    }
    out << "command,remote_name,data_flow,output_file,status,captured_bytes,unique_bytes,gap_count,gap_bytes,overlap_bytes,conflicting_overlap_bytes,note\n";
    for (const TransferRecord& record : records_) {
        out << csvField(record.command) << ',' << csvField(record.remoteName) << ','
            << csvField(record.dataFlow) << ',' << csvField(record.outputFile) << ','
            << csvField(record.status) << ',' << record.capturedBytes << ','
            << record.uniqueBytes << ',' << record.gapCount << ',' << record.gapBytes << ','
            << record.overlapBytes << ',' << record.conflictingOverlapBytes << ','
            << csvField(record.note) << '\n';
    }
    out.flush();
    if (!out) {
        error = "failed while writing manifest: " + path.string();
        return false;
    }
    return true;
}
