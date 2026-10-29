/* SPDX-License-Identifier: MIT */
/*
 * The build configuration LLVM's C headers include. The AIR bridge calls the
 * C API of a shared LLVM 23 library and initializes no target, so it states
 * none of that library's configuration: C declarations
 * keep their default visibility, no native target is named and the target
 * lists beside this file are empty.
 */
#ifndef STELA_LLVM_CONFIG_H
#define STELA_LLVM_CONFIG_H
#endif
