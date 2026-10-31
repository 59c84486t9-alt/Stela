/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYSLOG_H
#define STELA_LIBC_SYSLOG_H
#include <sys/cdefs.h>
#include <stdarg.h>
__BEGIN_DECLS
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_INFO 6
#define LOG_DEBUG 7
#define LOG_PID 1
#define LOG_NDELAY 8
#define LOG_USER 8
void openlog(const char *name, int option, int facility);
void syslog(int priority, const char *format, ...);
void vsyslog(int priority, const char *format, va_list arguments);
__END_DECLS
#endif
