/* SPDX-License-Identifier: GPL-2.0-only */
/* Registration emission is projected from Linux init.h/moduleparam.h/module.h
 * at cc9de5d4b5ab6459f5774946aa3195ad51236fa8. Callback bodies are untouched.
 * Opt in AFTER original declarations and BEFORE the selected original TU.
 * Existing partial helper builds must not force this header. */
#ifndef STELA_LINUX_REGISTRATION_H
#define STELA_LINUX_REGISTRATION_H
#ifdef __cplusplus
#error "static registry capture requires a C translation unit"
#endif
#include <linux/module.h>
#include <stela/registry.h>
#if defined(MODULE) || defined(CONFIG_MODULES)
#error "static registry requires actual built-in Linux semantics"
#endif
#if !defined(STELA_LINUX_REG_DOMAIN) || !defined(STELA_LINUX_REG_UNIT) || \
    !defined(STELA_LINUX_REG_UNIT_ORDINAL) || !defined(STELA_LINUX_REG_GROUP_SYMBOL)
#error "registration requires explicit reviewed domain, TU and Kbuild group"
#endif

/* The manifest scanner enforces ASCII letter/alphanumeric domain/TU tokens.
 * One __COUNTER__ argument is expanded once before it is pasted/reused. */
#define STELA_REG_NAME_I(domain, unit, kind, seq) \
 stela_linux_reg__##domain##__##unit##__##kind##__##seq
#define STELA_REG_NAME_II(domain, unit, kind, seq) \
 STELA_REG_NAME_I(domain, unit, kind, seq)
#define STELA_REG_NAME(kind, seq) \
 STELA_REG_NAME_II(STELA_LINUX_REG_DOMAIN, STELA_LINUX_REG_UNIT, kind, seq)
#define STELA_REG_TEXT_I(domain, unit, seq) stela_linux_info__##domain##__##unit##__##seq
#define STELA_REG_TEXT_II(domain, unit, seq) STELA_REG_TEXT_I(domain, unit, seq)
#define STELA_REG_TEXT(seq) STELA_REG_TEXT_II(STELA_LINUX_REG_DOMAIN, STELA_LINUX_REG_UNIT, seq)
#define STELA_REG_UNIT_I(domain, unit) stela_linux_unit__##domain##__##unit
#define STELA_REG_UNIT_II(domain, unit) STELA_REG_UNIT_I(domain, unit)
#define STELA_REG_UNIT STELA_REG_UNIT_II(STELA_LINUX_REG_DOMAIN, STELA_LINUX_REG_UNIT)
extern const struct stela_linux_build_group STELA_LINUX_REG_GROUP_SYMBOL;
extern const struct stela_linux_build_unit STELA_REG_UNIT;
#define STELA_REG_CAPTURE_I(domain, unit) stela_linux_capture__##domain##__##unit
#define STELA_REG_CAPTURE_II(domain, unit) STELA_REG_CAPTURE_I(domain, unit)
/* Proves capture was included even for selected units with no registrations. */
const struct stela_linux_build_unit *const
 STELA_REG_CAPTURE_II(STELA_LINUX_REG_DOMAIN, STELA_LINUX_REG_UNIT) __used = &STELA_REG_UNIT;
#define STELA_REG_HEADER(kind, lev, fl, seq) \
 { STELA_LINUX_REGISTRY_ABI, kind, lev, fl, STELA_LINUX_REG_UNIT_ORDINAL, seq }
#define STELA_REG_CONTEXT &STELA_LINUX_REG_GROUP_SYMBOL, &STELA_REG_UNIT
#define STELA_REG_INIT_I(fn, kind, lev, fl, code, seq) \
 const struct stela_linux_init_record STELA_REG_NAME(code, seq) __used = { \
  STELA_REG_HEADER(kind, lev, fl, seq), STELA_REG_CONTEXT, __stringify(fn), fn }
#define STELA_REG_INIT(fn, kind, lev, fl, code, seq) \
 STELA_REG_INIT_I(fn, kind, lev, fl, code, seq)
#define STELA_REG_EXIT_I(fn, kind, code, seq) \
 const struct stela_linux_exit_record STELA_REG_NAME(code, seq) __used = { \
  STELA_REG_HEADER(kind, -1, 0, seq), STELA_REG_CONTEXT, __stringify(fn), fn }
#define STELA_REG_EXIT(fn, kind, code, seq) STELA_REG_EXIT_I(fn, kind, code, seq)

/* Preserve the actual IDs supported by original __define_initcall. */
#define STELA_REG_LEVEL_early STELA_LINUX_REG_EARLY_LEVEL
#define STELA_REG_LEVEL_rootfs STELA_LINUX_REG_ROOTFS_LEVEL
#define STELA_REG_SYNC_early 0
#define STELA_REG_SYNC_rootfs 0
#define STELA_REG_LEVEL_0 0
#define STELA_REG_SYNC_0 0
#define STELA_REG_LEVEL_1 1
#define STELA_REG_SYNC_1 0
#define STELA_REG_LEVEL_1s 1
#define STELA_REG_SYNC_1s STELA_LINUX_REG_SYNC
#define STELA_REG_LEVEL_2 2
#define STELA_REG_SYNC_2 0
#define STELA_REG_LEVEL_2s 2
#define STELA_REG_SYNC_2s STELA_LINUX_REG_SYNC
#define STELA_REG_LEVEL_3 3
#define STELA_REG_SYNC_3 0
#define STELA_REG_LEVEL_3s 3
#define STELA_REG_SYNC_3s STELA_LINUX_REG_SYNC
#define STELA_REG_LEVEL_4 4
#define STELA_REG_SYNC_4 0
#define STELA_REG_LEVEL_4s 4
#define STELA_REG_SYNC_4s STELA_LINUX_REG_SYNC
#define STELA_REG_LEVEL_5 5
#define STELA_REG_SYNC_5 0
#define STELA_REG_LEVEL_5s 5
#define STELA_REG_SYNC_5s STELA_LINUX_REG_SYNC
#define STELA_REG_LEVEL_6 6
#define STELA_REG_SYNC_6 0
#define STELA_REG_LEVEL_6s 6
#define STELA_REG_SYNC_6s STELA_LINUX_REG_SYNC
#define STELA_REG_LEVEL_7 7
#define STELA_REG_SYNC_7 0
#define STELA_REG_LEVEL_7s 7
#define STELA_REG_SYNC_7s STELA_LINUX_REG_SYNC

#undef __define_initcall
#define __define_initcall(fn, id) \
 STELA_REG_INIT(fn, STELA_LINUX_REG_INIT, STELA_REG_LEVEL_##id, \
                STELA_REG_SYNC_##id, i, __COUNTER__);
#undef module_init
#define module_init(fn) \
 STELA_REG_INIT(fn, STELA_LINUX_REG_MODULE_INIT, 6, 0, m, __COUNTER__);
#undef __exitcall
#define __exitcall(fn) STELA_REG_EXIT(fn, STELA_LINUX_REG_EXIT, x, __COUNTER__)
#undef module_exit
#define module_exit(fn) STELA_REG_EXIT(fn, STELA_LINUX_REG_MODULE_EXIT, e, __COUNTER__);
#undef console_initcall
#define console_initcall(fn) \
 STELA_REG_INIT(fn, STELA_LINUX_REG_CONSOLE, STELA_LINUX_REG_CONSOLE_LEVEL, \
                0, c, __COUNTER__);

/* Exact original kernel_param declaration, including its symbol identity.
 * Only platform section emission is replaced, then a sidecar roots it. */
#define STELA_REG_PARAM_I(prefix, name, ops, arg, perm, level, flags, seq) \
 static_assert(sizeof("" prefix) - 1 <= __MODULE_NAME_LEN); \
 static const char __param_str_##name[] = prefix #name; \
 static struct kernel_param __moduleparam_const __param_##name \
  __used __aligned(__alignof__(struct kernel_param)) = { \
   __param_str_##name, THIS_MODULE, ops, VERIFY_OCTAL_PERMISSIONS(perm), \
   level, flags, { arg } }; \
 const struct stela_linux_parameter_record STELA_REG_NAME(p, seq) __used = { \
  STELA_REG_HEADER(STELA_LINUX_REG_PARAMETER, level, 0, seq), STELA_REG_CONTEXT, \
  __param_str_##name, &__param_##name }
#define STELA_REG_PARAM(prefix, name, ops, arg, perm, level, flags, seq) \
 STELA_REG_PARAM_I(prefix, name, ops, arg, perm, level, flags, seq)
#undef __module_param_call
#define __module_param_call(prefix, name, ops, arg, perm, level, flags) \
 STELA_REG_PARAM(prefix, name, ops, arg, perm, level, flags, __COUNTER__)

/* The setup target may genuinely be NULL for an obsolete option. */
#define STELA_REG_SETUP_KIND_0 STELA_LINUX_REG_SETUP
#define STELA_REG_SETUP_KIND_1 STELA_LINUX_REG_EARLY
#define STELA_REG_SETUP_CODE_0 s
#define STELA_REG_SETUP_CODE_1 a
#define STELA_REG_SETUP_I(str, fn, early, seq) \
 const struct stela_linux_setup_record \
 STELA_REG_NAME(STELA_REG_SETUP_CODE_##early, seq) __used = { \
  STELA_REG_HEADER(STELA_REG_SETUP_KIND_##early, -1, 0, seq), \
  STELA_REG_CONTEXT, str, fn }
#define STELA_REG_SETUP(str, fn, early, seq) STELA_REG_SETUP_I(str, fn, early, seq)
#undef __setup_param
#define __setup_param(str, unique_id, fn, early) \
 STELA_REG_SETUP(str, fn, early, __COUNTER__)

#define STELA_REG_INFO_I(tag, info, seq) \
 static_assert(sizeof(info) - 1 == __builtin_strlen(info), \
  "MODULE_INFO(" #tag ", ...) contains embedded NUL byte"); \
 static const char STELA_REG_TEXT(seq)[] __used __aligned(1) = \
  __MODULE_INFO_PREFIX __stringify(tag) "=" info; \
 const struct stela_linux_info_record STELA_REG_NAME(f, seq) __used = { \
  STELA_REG_HEADER(STELA_LINUX_REG_INFO, -1, 0, seq), STELA_REG_CONTEXT, \
  __stringify(tag), STELA_REG_TEXT(seq) }
#define STELA_REG_INFO(tag, info, seq) STELA_REG_INFO_I(tag, info, seq)
#undef MODULE_INFO
#define MODULE_INFO(tag, info) STELA_REG_INFO(tag, info, __COUNTER__)

/* Original declaration's type and address are compiler-checked here. This
 * metadata does not register a driver or manufacture any matching IDs. */
#define STELA_REG_DEVICE_I(type, name, seq) \
 const struct stela_linux_device_record STELA_REG_NAME(d, seq) __used = { \
  STELA_REG_HEADER(STELA_LINUX_REG_DEVICE, -1, 0, seq), STELA_REG_CONTEXT, \
  __stringify(type), &(name), sizeof(name) }
#define STELA_REG_DEVICE(type, name, seq) STELA_REG_DEVICE_I(type, name, seq)
#undef MODULE_DEVICE_TABLE
#define MODULE_DEVICE_TABLE(type, name) STELA_REG_DEVICE(type, name, __COUNTER__)
#endif
