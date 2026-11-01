/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* LLVM's public configuration, as CMake would state it for Stela's build. */
#ifndef LLVM_CONFIG_H
#define LLVM_CONFIG_H
#define LLVM_DEFAULT_TARGET_TRIPLE "arm64-apple-macosx"
#define LLVM_ENABLE_THREADS 0
#define LLVM_HAS_ATOMICS 1
/* The image's C calling convention, in the object format MCJIT loads. */
#define LLVM_HOST_TRIPLE "x86_64-pc-win32-elf"
#define LLVM_NATIVE_ARCH X86
#define LLVM_NATIVE_ASMPRINTER LLVMInitializeX86AsmPrinter
#define LLVM_NATIVE_DISASSEMBLER LLVMInitializeX86Disassembler
#define LLVM_NATIVE_TARGET LLVMInitializeX86Target
#define LLVM_NATIVE_TARGETINFO LLVMInitializeX86TargetInfo
#define LLVM_NATIVE_TARGETMC LLVMInitializeX86TargetMC
#define LLVM_HAS_X86_TARGET 1
#ifndef _WIN32
#define LLVM_ON_UNIX 1
#define HAVE_SYSEXITS_H 1
#endif
#define LLVM_USE_INTEL_JITEVENTS 0
#define LLVM_USE_OPROFILE 0
#define LLVM_USE_PERF 0
#define LLVM_VERSION_MAJOR 23
#define LLVM_VERSION_MINOR 1
#define LLVM_VERSION_PATCH 4
#define LLVM_VERSION_STRING "23.1.4"
#define LLVM_FORCE_ENABLE_STATS 0
#define LLVM_ENABLE_ZLIB 0
#define LLVM_ENABLE_ZSTD 0
#define LLVM_UNREACHABLE_OPTIMIZE 1
#define LLVM_ENABLE_IO_SANDBOX 0
#define LLVM_ENABLE_DIA_SDK 0
#define LLVM_ENABLE_TELEMETRY 0
#define LLVM_ENABLE_DEBUGLOC_TRACKING_COVERAGE 0
#define LLVM_ENABLE_DEBUGLOC_TRACKING_ORIGIN 0
#define LLVM_ENABLE_ONDISK_CAS 0
#endif
