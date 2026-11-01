/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* LLVM's private configuration: what compat/libc, and the C library of the
 * machine building its own tool, both offer. A function neither needs stays undefined, so its users
 * take LLVM's portable path. */
#ifndef CONFIG_H
#define CONFIG_H
#include "llvm/Config/llvm-config.h"
#define BUG_REPORT_URL ""
#define ENABLE_BACKTRACES 0
#define ENABLE_CRASH_OVERRIDES 0
#define LLVM_ENABLE_CRASH_DUMPS 0
#define LLVM_WINDOWS_PREFER_FORWARD_SLASH 0
#define HAVE_CRASHREPORTER_INFO 0
#define HAVE_DECL_ARC4RANDOM 0
#define HAVE_DECL_FE_ALL_EXCEPT 1
#define HAVE_DECL_FE_INEXACT 1
#ifdef _WIN32
#define HAVE_DECL_STRERROR_S 1
#else
#define HAVE_DECL_STRERROR_S 0
#define HAVE_GETPAGESIZE 1
#define HAVE_ISATTY 1
#define HAVE_PTHREAD_H 1
#define HAVE_SYSCONF 1
#define HAVE_SYS_MMAN_H 1
#ifdef __APPLE__
#define HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC 1
#else
#define HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC 1
#endif
#define HAVE_UNISTD_H 1
#endif
#define HAVE_ICU 0
#define HAVE_WINDOWS_ICU 0
#define HAVE_ICONV 0
#define LLVM_VERSION_PRINTER_SHOW_HOST_TARGET_INFO 0
#define LLVM_VERSION_PRINTER_SHOW_BUILD_CONFIG 0
#define LTDL_SHLIB_EXT ""
#define LLVM_PLUGIN_EXT ""
#define PACKAGE_NAME "LLVM"
#define PACKAGE_STRING "LLVM 23.1.4"
#define PACKAGE_VERSION "23.1.4"
#define PACKAGE_VENDOR ""
#define LLVM_GISEL_COV_ENABLED 0
#define LLVM_SUPPORT_XCODE_SIGNPOSTS 0
#endif
