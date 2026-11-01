// SPDX-License-Identifier: MIT
// What LLVM's Host.cpp includes.
#pragma once

struct utsname {
	char sysname[1];
	char release[1];
	char version[1];
};

#ifdef __cplusplus
extern "C"
#endif
	int uname(struct utsname *info);
