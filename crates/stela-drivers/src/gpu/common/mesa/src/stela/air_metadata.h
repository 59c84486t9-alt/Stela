/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_METADATA_H
#define STELA_AIR_METADATA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define AIR_MAX_ARGUMENTS 128
#define AIR_MAX_METADATA_OPERANDS 256
#define AIR_MAX_BITCODE_BYTES (64u * 1024u * 1024u)

enum stela_air_error_kind {
   STELA_AIR_OK,
   STELA_AIR_INPUT,
   STELA_AIR_LLVM_VERSION,
   STELA_AIR_BITCODE,
   STELA_AIR_VERIFY,
   STELA_AIR_TARGET,
   STELA_AIR_METADATA,
   STELA_AIR_ARGUMENT,
   STELA_AIR_CONTROL_FLOW,
   STELA_AIR_INSTRUCTION,
   STELA_AIR_TYPE,
   STELA_AIR_MEMORY,
   STELA_AIR_LIMIT,
   STELA_AIR_ALLOCATION,
};

struct stela_air_error {
   enum stela_air_error_kind kind;
   unsigned instruction; /* Zero-based instruction ordinal, not source line. */
   char detail[256];
};

enum stela_air_buffer_access {
   STELA_AIR_READ = 1,
   STELA_AIR_WRITE = 2,
   STELA_AIR_READ_WRITE = 3,
};

struct stela_air_buffer {
   unsigned argument;
   unsigned index; /* air.location_index; not an LLVM parameter byte offset. */
   unsigned address_space;
   enum stela_air_buffer_access access;
   unsigned type_size; /* Zero when the input omits this optional reflection. */
   unsigned type_alignment;
};


/* Borrowed callback views expire on callback return. Inspection validates LLVM,
 * module/entry ABI and metadata, not executable-body support, bindings, GPU
 * capability, or compiler provenance. Only actual air.kernel entries are
 * exposed; unsupported metadata/stages remain explicit. */
struct stela_air_inspection {
   const char *target;
   size_t target_bytes;
   unsigned air_minor, language_major, language_minor;
   bool denorms_disable, fast_math;
};
enum stela_air_primitive {
   STELA_AIR_PRIMITIVE_UNKNOWN,
   STELA_AIR_CHAR, STELA_AIR_UCHAR, STELA_AIR_SHORT, STELA_AIR_USHORT,
   STELA_AIR_INT, STELA_AIR_UINT, STELA_AIR_LONG, STELA_AIR_ULONG, STELA_AIR_FLOAT,
};

struct stela_air_argument_info {
   struct stela_air_buffer buffer;
   unsigned kind; /* 1=buffer, 2=thread_position_in_grid. */
   unsigned components;
   bool plain_buffer_type;
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
   enum stela_air_primitive primitive;
   unsigned type_components; /* 1..4 only for known reflected builtin types. */
   bool used; /* Actual uses in this AIR module, not a final machine-code liveness claim. */
};
struct stela_air_entry {
   const char *name;
   size_t name_bytes;
   unsigned argument_count;
   const struct stela_air_argument_info *arguments;
   bool reflection_complete; /* Bounded plain-resource reflection; see README. */
};
typedef bool (*stela_air_visit_entry)(const struct stela_air_inspection *,
                                     const struct stela_air_entry *, void *);
bool stela_air_inspect(const void *bitcode, size_t size, unsigned max_entries,
                       stela_air_visit_entry visit, void *data,
                       struct stela_air_error *error);
/* Additive render-only descriptor API. These enums are neither MTLFunctionType
 * nor MTLB TYPE values. Every string/array is borrowed through callback return.
 * This validates selected entry ABI/reflection, not body execution or hardware.
 * Legacy stela_air_inspect continues its original compute-only acceptance. */
enum stela_air_stage { STELA_AIR_VERTEX = 1, STELA_AIR_FRAGMENT = 2 };
enum stela_air_stage_semantic {
   STELA_AIR_STAGE_BUFFER = 1, STELA_AIR_VERTEX_ID, STELA_AIR_POSITION,
   STELA_AIR_VARYING, STELA_AIR_RENDER_TARGET,
};
enum stela_air_interpolation {
   STELA_AIR_INTERPOLATION_NONE, STELA_AIR_PERSPECTIVE,
   STELA_AIR_NO_PERSPECTIVE,
};
struct stela_air_struct_member {
   unsigned offset, size;
   enum stela_air_primitive primitive;
   unsigned components;
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
};
struct stela_air_stage_io {
   enum stela_air_stage_semantic semantic;
   unsigned argument; /* LLVM argument or ordered return leaf, as applicable. */
   struct stela_air_buffer buffer; /* Only STAGE_BUFFER; AS2 remains readonly. */
   enum stela_air_primitive primitive;
   unsigned components;
   enum stela_air_interpolation interpolation;
   bool center, used;
   unsigned location, index; /* RENDER_TARGET attachment / dual-source index. */
   const char *name, *type_name, *identifier;
   size_t name_bytes, type_name_bytes, identifier_bytes;
   unsigned member_count;
   const struct stela_air_struct_member *members;
};
struct stela_air_stage_entry {
   enum stela_air_stage stage;
   bool framebuffer_fetch_present, framebuffer_fetch_enabled; /* Compile option, never a fetch operation. */
   const char *name;
   size_t name_bytes;
   unsigned input_count, output_count;
   const struct stela_air_stage_io *inputs, *outputs;
};
typedef bool (*stela_air_visit_stage)(const struct stela_air_inspection *,
                                     const struct stela_air_stage_entry *, void *);
bool stela_air_inspect_stage(const void *, size_t, const char *entry,
                             enum stela_air_stage, stela_air_visit_stage, void *,
                             struct stela_air_error *);

/* One validated VS/FS varying map. Identifiers borrow from the supplied entry
 * descriptors; caller must own/copy those strings beyond inspector callbacks.
 * Location is relative to NIR VARYING_SLOT_VAR0, not a hardware register.
 * Exact opaque identifier/type matching, bounded by explicit target IO slots;
 * no source-name/hash exceptions or invented interpolation. Failure preserves
 * rows/count. Successful rows must remain live through stage translation. These
 * same-process values require readable UTF-8 identifiers with exact byte extents;
 * duplicate IDs/locations/types and target slot limits are checked before effects. */
struct stela_air_varying_slot {
   const char *identifier;
   size_t identifier_bytes;
   enum stela_air_primitive primitive;
   unsigned components, location;
};
bool stela_air_link_stage_io(const struct stela_air_stage_entry *vertex,
                             const struct stela_air_stage_entry *fragment,
                             unsigned max_slots, struct stela_air_varying_slot *rows,
                             unsigned capacity, unsigned *count,
                             struct stela_air_error *);

/* Compiler implementation only. Ordinary metadata consumers need no LLVM or
 * NIR headers and receive no LLVM objects. Define before the first include. */
#ifdef STELA_AIR_METADATA_INTERNAL
#include "llvm-c/Core.h"
#include "llvm-c/Target.h"
/* Shared decoder state, borrowed from the caller's real LLVM module. No NIR,
 * resource mapping or GPU/Metal object is created by metadata inspection. */
struct stela_air_metadata {
   LLVMModuleRef module;
   LLVMTargetDataRef layout;
   struct stela_air_error *error;
   unsigned air_minor, language_major, language_minor;
   unsigned max_device_buffers, max_threadgroup_buffers, max_constant_buffers;
   bool render; /* Additive decoder mode; legacy compute remains false. */
   bool framebuffer_fetch_present, framebuffer_fetch_enabled;
   bool denorms_disable, fast_math;
};

bool stela_air_md_string(LLVMValueRef value, const char *expected);
bool stela_air_md_uint(LLVMValueRef value, unsigned *number);
bool stela_air_md_node(struct stela_air_metadata *m, LLVMValueRef node,
                       LLVMValueRef *operands, unsigned *count);
bool stela_air_named_md(struct stela_air_metadata *m, const char *name,
                        LLVMValueRef *operands, unsigned *count);
bool stela_air_metadata_layout(struct stela_air_metadata *m);
bool stela_air_metadata_validate(struct stela_air_metadata *m);
/* One LLVM-only storage validator shared by conservative reflection and NIR.
 * These describe the qualified ABI, not compiler provenance or GPU limits.
 * No shared storage is allocated here; only actually used globals are lowered
 * by the selected entry's original NIR path. Errors use m->error; observational
 * consumers must supply their own local error state. */
bool stela_air_metadata_shared_profile(struct stela_air_metadata *m);
bool stela_air_metadata_shared_global(struct stela_air_metadata *m, LLVMValueRef global,
                                      uint64_t *size, unsigned *alignment);
bool stela_air_metadata_shared_globals(struct stela_air_metadata *m);

struct stela_air_argument {
   LLVMValueRef value; /* Borrowed, decoder/compiler internal only. */
   struct stela_air_buffer buffer;
   bool is_buffer;
   unsigned components; /* Scalar/uint3 thread-position input. */
   bool plain_buffer_type; /* Reflected MSL builtin scalar/vector, not a struct. */
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
   enum stela_air_primitive primitive;
   unsigned type_components;
   bool used;
};
struct stela_air_kernel {
   unsigned count;
   struct stela_air_argument arguments[AIR_MAX_ARGUMENTS];
};
bool stela_air_metadata_kernel(struct stela_air_metadata *m, LLVMValueRef fn,
                               struct stela_air_kernel *kernel);
struct stela_air_render {
   struct stela_air_stage_entry entry;
   struct stela_air_stage_io inputs[AIR_MAX_ARGUMENTS], outputs[AIR_MAX_ARGUMENTS];
   struct stela_air_struct_member members[AIR_MAX_ARGUMENTS];
   unsigned member_count;
   struct stela_air_kernel arguments;
};
bool stela_air_metadata_stage(struct stela_air_metadata *, LLVMValueRef,
                              enum stela_air_stage, struct stela_air_render *);
bool stela_air_metadata_stage_map(struct stela_air_metadata *, const struct stela_air_render *,
                                 const struct stela_air_varying_slot *, unsigned count, unsigned max_slots);
bool stela_air_metadata_stage_buffer_type(struct stela_air_metadata *,
                                          const struct stela_air_stage_io *, LLVMTypeRef);


#endif
#ifdef __cplusplus
}
#endif
#endif
