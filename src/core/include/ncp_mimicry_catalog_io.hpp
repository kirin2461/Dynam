#pragma once

/**
 * @file ncp_mimicry_catalog_io.hpp
 * @brief Safe, versioned file IO for ReferenceProfileCatalog descriptors
 *
 * Provides the persistence layer for future `--mimicry-catalog <file>` and
 * `validate-catalog <file>` tooling: a deterministic, bounded, versioned
 * binary container holding COMPLETE ProfileDescriptor records (including the
 * artifact signature and content_hash — not just canonical hash payloads).
 *
 * Container format (all integers little-endian, fixed field order, no
 * padding, no host-dependent encoding — deterministic across runs and
 * platforms):
 *
 *   offset  size  field
 *   0       8     magic: "NCPMCAT\x01"
 *   8       4     container_version (u32, must equal kContainerVersion)
 *   12      4     flags (u32, reserved, must be 0)
 *   16      4     descriptor_count (u32, <= Limits::max_descriptors)
 *   20      ..    records: descriptor_count x { u32 record_len, record body }
 *   end-32  32    BLAKE2b-256 checksum over ALL preceding bytes
 *
 * Each record body is the full field-by-field encoding of one
 * ProfileDescriptor (identity, wire range, capabilities, size/IAT models,
 * joint model, burst, FSM, padding/header, MTU, provenance, derivation
 * bounds, artifact signature, content hash). The record body superset of
 * canonical_serialize() additionally carries signature + content_hash, so a
 * loaded descriptor can be policy-checked by the catalog exactly as if it
 * had been built in memory.
 *
 * Security properties:
 *   - Hard bounds everywhere before allocation: file size, record count,
 *     per-record byte length, string length, vector element counts and
 *     signature length are all checked against Limits. The schema is flat
 *     (fixed depth 2: container -> record); there is no recursion, so no
 *     depth exhaustion is possible.
 *   - Truncation, trailing data, checksum mismatch, enum/flag overflow and
 *     duplicate (profile_id, revision) inside the file are all rejected
 *     with stable machine-readable error codes.
 *   - load_file() registers every descriptor through
 *     ReferenceProfileCatalog::register_profile() — the EXTERNAL,
 *     policy-checked path. SignaturePolicy::ENFORCE is fully preserved; the
 *     IO layer never touches the trusted built-in path and contains no
 *     trust bypass.
 *   - Records never contain private keys, payload bytes, PCAP content or IP
 *     addresses: only public Ed25519 signatures/key ids, content hashes and
 *     the statistical model metadata defined by ProfileDescriptor.
 *   - Errors are structured and non-sensitive (stable code + human message
 *     + byte offset + record index; no key material, no file contents).
 *
 * No global state (libsodium one-time init aside), no third-party
 * dependencies beyond libsodium (already REQUIRED by the catalog).
 */

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "ncp_reference_profile_catalog.hpp"

namespace ncp {

class MimicryCatalogIo {
public:
    /// Container version written by serialize()/save_file() and accepted by
    /// the parsers. Unknown newer/older versions are rejected.
    static constexpr uint32_t kContainerVersion = 1;

    /// 8-byte magic, includes an in-band format major byte (0x01).
    static constexpr char kMagic[8] = {'N', 'C', 'P', 'M', 'C', 'A', 'T', '\x01'};

    /// record field value used in Error::record when the failure is at the
    /// container-header level rather than inside a specific record.
    static constexpr uint32_t kNoRecord = 0xFFFFFFFFu;

    // ---- resource bounds (checked BEFORE any allocation) ----
    struct Limits {
        uint64_t max_file_bytes = 8u * 1024u * 1024u;  ///< whole container
        uint32_t max_descriptors = 256;   ///< records per container
        uint32_t max_record_bytes = 256u * 1024u;      ///< one record body
        uint32_t max_string_len = 128;    ///< any single string field
        uint32_t max_capabilities = 32;
        uint32_t max_mix_components = 16;
        uint32_t max_fsm_states = 64;
        uint32_t max_fsm_transitions = 256;
        uint32_t max_captures = 32;
        uint32_t max_signature_bytes = 64;  ///< detached Ed25519 = 64

        /// Align the IO bounds with an existing catalog Limits instance
        /// (count/string/vector limits mirror the validation bounds).
        static Limits from_catalog(const ReferenceProfileCatalog::Limits& cl);
    };

    /// Structured, non-sensitive error: stable machine-readable `code`,
    /// human-readable `message` (never contains key material, payload data
    /// or file contents), plus best-effort position information.
    struct Error {
        std::string code;     ///< e.g. "truncated", "checksum_mismatch"
        std::string message;  ///< human-readable detail
        uint64_t byte_offset = 0;         ///< parse position (0 if n/a)
        uint32_t record = kNoRecord;      ///< record index (kNoRecord if n/a)
    };

    /// Result of a successful parse: every descriptor fully reconstructed
    /// (signature + content_hash included), in file order.
    struct ParsedFile {
        uint32_t container_version = 0;
        std::vector<ProfileDescriptor> descriptors;
    };

    // ---- parsing (pure: no validation semantics, no trust decisions) ----

    /// Parse a container from memory. Enforces all Limits before
    /// allocation; rejects truncation, trailing bytes, checksum mismatch,
    /// out-of-range enum/boolean values, oversized strings/vectors and
    /// duplicate (profile_id, revision) pairs within the file.
    static bool parse_bytes(const std::vector<uint8_t>& bytes,
                            ParsedFile& out, Error& err, const Limits& lim);
    /// parse_bytes with default Limits.
    static bool parse_bytes(const std::vector<uint8_t>& bytes,
                            ParsedFile& out, Error& err);

    /// Parse a container from the filesystem. Read errors map to
    /// "io_open_failed" / "io_read_failed" / "file_too_large" (the size
    /// bound is checked before the file body is read).
    static bool parse_file(const std::string& path, ParsedFile& out,
                           Error& err, const Limits& lim);
    /// parse_file with default Limits.
    static bool parse_file(const std::string& path, ParsedFile& out,
                           Error& err);

    // ---- serialization (deterministic) ----

    /// Deterministic container bytes for a set of descriptors. Records are
    /// sorted by (profile_id, revision); capability and capture lists are
    /// order-normalised exactly like canonical_serialize(), so equal
    /// descriptor sets always produce byte-identical output regardless of
    /// input ordering. Normalisation never changes a descriptor's
    /// content_hash (the canonical form is already order-normalised).
    static std::vector<uint8_t> serialize(
        const std::vector<ProfileDescriptor>& descriptors);

    /// Write serialize(descriptors) to `path`. Returns false with
    /// "io_write_failed" on any write error.
    static bool save_file(const std::string& path,
                          const std::vector<ProfileDescriptor>& descriptors,
                          Error& err);

    /// Deterministic snapshot of every descriptor registered in `catalog`
    /// (sorted by canonical id via list()). Intended for tooling such as
    /// exporting the legacy built-in profiles. Exported built-ins are
    /// unsigned; re-importing them goes through the EXTERNAL policy path
    /// like any other file record.
    static std::vector<uint8_t> export_catalog_bytes(
        const ReferenceProfileCatalog& catalog);

    /// export_catalog_bytes() + write to `path`.
    static bool export_catalog(const ReferenceProfileCatalog& catalog,
                               const std::string& path, Error& err);

    // ---- loading (policy-checked registration) ----

    /// Parse `path` and register every descriptor through
    /// catalog.register_profile() — the external, policy-checked path.
    /// SignaturePolicy::ENFORCE is preserved: unsigned or untrusted records
    /// are rejected by the catalog itself; this layer adds no trust bypass.
    ///
    /// On parse failure returns false with `err` set and registers nothing.
    /// On registration failure returns false with err.code ==
    /// "registration_failed"; records before the failing one are already
    /// registered (the catalog exposes no removal API). Per-descriptor
    /// outcomes are appended to `outcomes` when non-null.
    static bool load_file(
        const std::string& path, ReferenceProfileCatalog& catalog,
        std::vector<ReferenceProfileCatalog::RegisterOutcome>* outcomes,
        Error& err, const Limits& lim);
    /// load_file with default Limits.
    static bool load_file(
        const std::string& path, ReferenceProfileCatalog& catalog,
        std::vector<ReferenceProfileCatalog::RegisterOutcome>* outcomes,
        Error& err);

    // ---- validate-catalog support ----

    /// Parse `path` and run the catalog's structural/semantic validation
    /// (validate_descriptor) over every record WITHOUT registering anything
    /// and without touching the trust store. Returns false only on
    /// container-level errors (parse/read failures); per-descriptor issues
    /// are reported via `issues_out` as (canonical_id, issues) pairs and do
    /// not affect the return value — a structurally valid file with invalid
    /// descriptors still returns true so tooling can list every issue.
    static bool validate_file(
        const std::string& path, const ReferenceProfileCatalog& catalog,
        std::vector<std::pair<std::string, std::vector<ValidationIssue>>>&
            issues_out,
        Error& err, const Limits& lim);
    /// validate_file with default Limits.
    static bool validate_file(
        const std::string& path, const ReferenceProfileCatalog& catalog,
        std::vector<std::pair<std::string, std::vector<ValidationIssue>>>&
            issues_out,
        Error& err);
};

} // namespace ncp
