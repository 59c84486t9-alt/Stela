/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_INPUT_H
#define STELA_METAL_INPUT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define STELA_METAL_INPUT_ABI 1u
#define STELA_METAL_INPUT_MTLB 1u
#define STELA_METAL_INPUT_RAW_AIR 2u
#define STELA_METAL_INIT(type) {sizeof(type), STELA_METAL_INPUT_ABI}
enum stela_metal_input_status {
   STELA_METAL_INPUT_OK = 0,
   STELA_METAL_INPUT_INVALID = 1,
   STELA_METAL_INPUT_ABI_MISMATCH = 2,
   STELA_METAL_INPUT_LIMIT = 3,
   STELA_METAL_INPUT_PARSE = 4,
   STELA_METAL_INPUT_ALLOCATION = 5,
   STELA_METAL_INPUT_INDEX = 6,
   STELA_METAL_INPUT_NOT_ARCHIVE = 7,
};
struct stela_metal_input_limits {
   uint32_t size, abi, kind, max_entries;
   uint64_t max_bytes;
};
struct stela_metal_input_error {
   uint32_t size, abi, status, parser_kind;
   uint64_t offset;
};
struct stela_metal_input_info {
   uint32_t size, abi, kind, entry_count;
   uint64_t original_bytes;
   uint8_t original_sha256[32];
   uint32_t platform, format_major, format_minor, library_kind, target_os;
   uint32_t minimum_os_major, minimum_os_minor;
};
struct stela_metal_input_entry {
   uint32_t size, abi, kind, air_major, air_minor, language_major, language_minor;
   uint32_t reserved;
   uint64_t module_offset, module_bytes;
   uint8_t module_sha256[32];
};
/* Counts exclude ENDT. Ranges include it and use original snapshot offsets.
 * Absent streams are (count,offset,bytes)=(0,0,0); an ENDT-only stream has
 * count0/bytes4. These are structural facts, NOT reflection/no-constants proof. */
struct stela_metal_input_entry_metadata {
   uint32_t size, abi, function_tags, public_tags, private_tags, header_tags;
   uint64_t function_offset, function_bytes, public_offset, public_bytes;
   uint64_t private_offset, private_bytes, header_offset, header_bytes;
};
struct stela_metal_input_view {
   uint32_t size, abi;
   const uint8_t *bytes;
   uint64_t length;
   uint64_t original_offset; /* UINT64_MAX for copied names. */
};
struct stela_metal_input;
/* Local, same-process/CPU C ABI only. NEVER serialize pointers/handles in IPC.
 * The helper uses normal hosted Rust/macOS allocation; no hardware crate,
 * custom allocator, LLVM implementation or Metal device is linked by this package.
 *
 * Open owns a byte snapshot and validates container/framing, NOT LLVM semantics,
 * compiler provenance, target/GPU support or an executable pipeline. Raw AIR has
 * no archive entries: pass its raw view to the real shared LLVM inspector.
 * MTLB entry AIR queries verify the selected digest using the canonical parser.
 * The helper must run that same inspector and cross-check names/stages/versions
 * before publishing any Metal function manifest. Unknown fields stay visible.
 *
 * Limits bound the function-table reserve before allocation. parser_kind 17 is
 * ResourceLimit and returns the existing LIMIT status; codes 1..16 are unchanged.
 * Limits/output records must carry exact sizeof(record)/ABI1. Error is optional
 * and, when supplied, points to a complete error record. Failures preserve every
 * output except error. Bytes are immutable borrowed views until destroy; caller
 * must serialize destruction with all accesses. Close the one owning slot once;
 * destroy(NULL or an empty slot) is harmless. Do not copy owning raw handles. */
uint32_t stela_metal_input_open(const struct stela_metal_input_limits *,
   const uint8_t *, uint64_t, struct stela_metal_input **,
   struct stela_metal_input_error *);
uint32_t stela_metal_input_info(const struct stela_metal_input *,
   struct stela_metal_input_info *, struct stela_metal_input_error *);
uint32_t stela_metal_input_entry(const struct stela_metal_input *, uint32_t,
   struct stela_metal_input_entry *, struct stela_metal_input_error *);
/* Additive ABI1 query. RAW_AIR returns NOT_ARCHIVE, preserving output. */
uint32_t stela_metal_input_entry_metadata(const struct stela_metal_input *, uint32_t,
   struct stela_metal_input_entry_metadata *, struct stela_metal_input_error *);
uint32_t stela_metal_input_name(const struct stela_metal_input *, uint32_t,
   struct stela_metal_input_view *, struct stela_metal_input_error *);
/* index must be zero for RAW_AIR. Archive AIR is the selected original module's
 * raw LLVM bitcode. The original wrapped bytes remain retained and hashed. */
uint32_t stela_metal_input_air(const struct stela_metal_input *, uint32_t,
   struct stela_metal_input_view *, struct stela_metal_input_error *);
/* Entire original retained bytes, including container metadata/unknown fields
 * and wrapper. Use this immutable view for authenticated helper output; do not
 * re-read a caller buffer after parsing and assume it is still the same input. */
uint32_t stela_metal_input_original(const struct stela_metal_input *,
   struct stela_metal_input_view *, struct stela_metal_input_error *);
void stela_metal_input_destroy(struct stela_metal_input **);
#ifdef __cplusplus
}
#endif
#endif
