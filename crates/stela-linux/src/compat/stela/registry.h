/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_REGISTRY_H
#define STELA_LINUX_REGISTRY_H
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/stddef.h>

/* Ordinary target C ABI, LP64 x86-64 only. Immutable descriptors/code/strings
 * must remain pinned for the image lifetime. A public C pointer is not an
 * untrusted serialized input; the producer proves complete readable objects. */
#define STELA_LINUX_REGISTRY_ABI 1U
#define STELA_LINUX_REG_SYNC 1U
#define STELA_LINUX_REG_EARLY_LEVEL (-2)
#define STELA_LINUX_REG_ROOTFS_LEVEL (-3)
#define STELA_LINUX_REG_CONSOLE_LEVEL (-4)
enum stela_linux_registration_kind {
 STELA_LINUX_REG_INIT = 1, STELA_LINUX_REG_MODULE_INIT,
 STELA_LINUX_REG_EXIT, STELA_LINUX_REG_MODULE_EXIT,
 STELA_LINUX_REG_PARAMETER, STELA_LINUX_REG_SETUP, STELA_LINUX_REG_EARLY,
 STELA_LINUX_REG_INFO, STELA_LINUX_REG_DEVICE, STELA_LINUX_REG_CONSOLE,
};
struct stela_linux_build_group {
 u32 abi_version, domain_ordinal, group_ordinal, reserved;
 const char *module_name, *module_file, *provenance;
};
struct stela_linux_build_unit {
 u32 abi_version, ordinal;
 const struct stela_linux_build_group *group;
 const char *source_path, *provenance;
};
struct stela_linux_registration_header {
 u32 abi_version;
 u16 kind;
 s8 level;
 u8 flags;
 u32 unit_ordinal, emission_sequence;
};
#define STELA_LINUX_RECORD_FIELDS \
 struct stela_linux_registration_header header; \
 const struct stela_linux_build_group *group; \
 const struct stela_linux_build_unit *unit
struct stela_linux_init_record {
 STELA_LINUX_RECORD_FIELDS;
 const char *label;
 initcall_t target;
};
struct stela_linux_exit_record {
 STELA_LINUX_RECORD_FIELDS;
 const char *label;
 exitcall_t target;
};
struct stela_linux_parameter_record {
 STELA_LINUX_RECORD_FIELDS;
 const char *label;
 const struct kernel_param *target;
};
struct stela_linux_setup_record {
 STELA_LINUX_RECORD_FIELDS;
 const char *label;
 int (*target)(char *);
};
struct stela_linux_info_record {
 STELA_LINUX_RECORD_FIELDS;
 const char *tag, *text;
};
struct stela_linux_device_record {
 STELA_LINUX_RECORD_FIELDS;
 const char *type;
 const void *table;
 size_t size;
};
#undef STELA_LINUX_RECORD_FIELDS

/* Arrays retain reviewed selected-TU/link order then emission sequence, never
 * filesystem order. The group/unit arrays cover ALL selected objects including
 * those without registration records. The normal root extracts record owners;
 * separate ALL-object linkage is still a mandatory qualification. */
struct stela_linux_registry_image {
 u32 abi_version, reserved;
 const struct stela_linux_init_record *const *inits;
 size_t init_count;
 const struct stela_linux_exit_record *const *exits;
 size_t exit_count;
 const struct stela_linux_parameter_record *const *parameters;
 size_t parameter_count;
 const struct stela_linux_info_record *const *infos;
 size_t info_count;
 const struct stela_linux_device_record *const *devices;
 size_t device_count;
 const struct stela_linux_setup_record *const *setups;
 size_t setup_count;
 const struct stela_linux_build_group *const *groups;
 size_t group_count;
 const struct stela_linux_build_unit *const *units;
 size_t unit_count;
};
enum stela_linux_registry_stage {
 STELA_LINUX_STAGE_CONSOLE, STELA_LINUX_STAGE_EARLY,
 STELA_LINUX_STAGE_PURE, STELA_LINUX_STAGE_CORE, STELA_LINUX_STAGE_POSTCORE,
 STELA_LINUX_STAGE_ARCH, STELA_LINUX_STAGE_SUBSYS, STELA_LINUX_STAGE_FS,
 STELA_LINUX_STAGE_DEVICE, STELA_LINUX_STAGE_LATE, STELA_LINUX_STAGE_DONE,
};
enum stela_linux_registration_state {
 STELA_LINUX_RECORD_NOT_RUN, STELA_LINUX_RECORD_RUNNING,
 STELA_LINUX_RECORD_ZERO, STELA_LINUX_RECORD_POSITIVE,
 STELA_LINUX_RECORD_NEGATIVE,
};
struct stela_linux_registration_status {
 u32 state, kind, unit_ordinal, emission_sequence;
 s32 returned;
 s32 level;
 u64 invocations, warnings, consumed;
};
struct stela_linux_registry_report {
 u64 invocations, returned_zero, returned_positive, returned_negative;
 u64 warnings, consumed, unhandled;
 s32 last_error;
 u32 next_stage, terminal;
};
struct stela_linux_registry_unknown_options {
 int (*unhandled_option)(void *context, char *complete_option);
 void *context;
};
struct stela_linux_registry_retirement {
 /* Exact complete image/group membership, not a single device idle query.
  * The callback actually stops/drains all consumers, including their final
  * self-enqueued RCU callbacks. Original rcu_barrier below joins callbacks
  * already queued by exit/parameter cleanup; it cannot stop a producer or
  * promise completion of future descendants. Each exit/free helper owns its
  * last-callback join before releasing callback data. No production authority
  * is created by this API. Borrowed only until this call returns. */
 const struct stela_linux_registry_image *image;
 const struct stela_linux_build_group *const *groups;
 size_t group_count;
 int (*drain_all_consumers)(void *context);
 void *context;
};
struct stela_linux_registry;
/* Original next_arg uses unsigned token indices: length <= UINT_MAX; larger
 * inputs fail E2BIG before reading token bytes or invoking any callback. */
int stela_linux_registry_begin(const struct stela_linux_registry_image *,
 const char *bytes, size_t length, struct stela_linux_registry **out);
int stela_linux_registry_early_parameters(struct stela_linux_registry *,
 struct stela_linux_registry_report *);
int stela_linux_registry_initial_parameters(struct stela_linux_registry *,
 const struct stela_linux_registry_unknown_options *, struct stela_linux_registry_report *);
int stela_linux_registry_run_stage(struct stela_linux_registry *, unsigned int,
 struct stela_linux_registry_report *);
/* Stable status index: init, exit, parameter, info, device, setup arrays. */
/* Source-owned declared prerequisite by exact actual image/record identity.
 * Reaching a later stage is not success: stage execution continues on errors.
 * No initializer/getter callback, lookup by label or implicit readiness.
 * This is historical success only: caller separately keeps exact source
 * context/module lifetime and declared init phase; it is no device/I/O grant. */
int stela_linux_registry_require_success(const struct stela_linux_registry *,
 const struct stela_linux_registry_image *, const struct stela_linux_init_record *);
int stela_linux_registry_status(const struct stela_linux_registry *, size_t,
 struct stela_linux_registration_status *);
/* Original NULL/tail/ERR_PTR result from an already-attempted pass0..9.
 * A tail borrows the registry token storage until successful retirement. */
int stela_linux_registry_parse_result(const struct stela_linux_registry *, unsigned int, char **);
int stela_linux_registry_retire(struct stela_linux_registry **,
 const struct stela_linux_registry_retirement *);
/* Run an image's initcalls as start_kernel does, once per boot. */
int stela_linux_start(const struct stela_linux_registry_image *,
 struct stela_linux_registry **);

static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8 && sizeof(long) == 8 && sizeof(int) == 4);
static_assert(sizeof(initcall_t) == 8 && sizeof(exitcall_t) == 8);
static_assert(sizeof(struct stela_linux_registration_header) == 16);
static_assert(offsetof(struct stela_linux_registration_header, level) == 6);
static_assert(offsetof(struct stela_linux_registration_header, unit_ordinal) == 8);
#define STELA_LINUX_RECORD_LAYOUT(type, last, bytes) \
 static_assert(offsetof(struct type, group) == 16); \
 static_assert(offsetof(struct type, unit) == 24); \
 static_assert(offsetof(struct type, last) == 40); \
 static_assert(sizeof(struct type) == bytes && __alignof__(struct type) == 8)
STELA_LINUX_RECORD_LAYOUT(stela_linux_init_record, target, 48);
STELA_LINUX_RECORD_LAYOUT(stela_linux_exit_record, target, 48);
STELA_LINUX_RECORD_LAYOUT(stela_linux_parameter_record, target, 48);
STELA_LINUX_RECORD_LAYOUT(stela_linux_setup_record, target, 48);
STELA_LINUX_RECORD_LAYOUT(stela_linux_info_record, text, 48);
STELA_LINUX_RECORD_LAYOUT(stela_linux_device_record, table, 56);
#undef STELA_LINUX_RECORD_LAYOUT
static_assert(sizeof(struct stela_linux_build_group) == 40);
static_assert(sizeof(struct stela_linux_build_unit) == 32);
static_assert(sizeof(struct stela_linux_registry_image) == 136);
static_assert(sizeof(struct stela_linux_registration_status) == 48);
static_assert(sizeof(struct stela_linux_registry_report) == 72);
#endif
