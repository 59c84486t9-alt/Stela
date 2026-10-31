/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_SYSMACROS_H
#define STELA_LIBC_SYS_SYSMACROS_H
#define major(device) ((unsigned int)((device) >> 8) & 0xfff)
#define minor(device) ((unsigned int)(device) & 0xff)
#define makedev(major, minor) (((unsigned long)(major) << 8) | (minor))
#endif
