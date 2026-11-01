/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_STDIO_H
#define STELA_LIBC_STDIO_H
#include <sys/cdefs.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
__BEGIN_DECLS
typedef struct __file FILE;
extern FILE *const stdin;
extern FILE *const stdout;
extern FILE *const stderr;
#define EOF (-1)
#define BUFSIZ 8192
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
int printf(const char *format, ...) __attribute__((format(printf, 1, 2)));
int fprintf(FILE *file, const char *format, ...) __attribute__((format(printf, 2, 3)));
/* Linux's environment shares the image and has these four names for its own
 * format language. */
int sprintf(char *buffer, const char *format, ...) __asm__("stela_libc_sprintf")
	__attribute__((format(printf, 2, 3)));
int snprintf(char *buffer, size_t size, const char *format, ...) __asm__("stela_libc_snprintf")
	__attribute__((format(printf, 3, 4)));
int asprintf(char **buffer, const char *format, ...) __attribute__((format(printf, 2, 3)));
int vprintf(const char *format, va_list arguments);
int vfprintf(FILE *file, const char *format, va_list arguments);
int vsprintf(char *buffer, const char *format, va_list arguments) __asm__("stela_libc_vsprintf");
int vsnprintf(char *buffer, size_t size, const char *format, va_list arguments)
	__asm__("stela_libc_vsnprintf");
int vasprintf(char **buffer, const char *format, va_list arguments);
int sscanf(const char *input, const char *format, ...);
int puts(const char *text);
int putchar(int c);
int fputs(const char *text, FILE *file);
int fputc(int c, FILE *file);
#define putc fputc
/* There are no files: these fail as a missing file does. */
FILE *fopen(const char *path, const char *mode);
FILE *fdopen(int fd, const char *mode);
FILE *popen(const char *command, const char *mode);
int pclose(FILE *file);
FILE *open_memstream(char **buffer, size_t *size);
int fclose(FILE *file);
size_t fread(void *buffer, size_t size, size_t count, FILE *file);
size_t fwrite(const void *buffer, size_t size, size_t count, FILE *file);
int fflush(FILE *file);
int fseek(FILE *file, long offset, int whence);
long ftell(FILE *file);
int ferror(FILE *file);
int feof(FILE *file);
int fileno(FILE *file);
char *fgets(char *buffer, int size, FILE *file);
int getc(FILE *file);
void rewind(FILE *file);
int remove(const char *path);
int rename(const char *from, const char *to);
void perror(const char *prefix);
__END_DECLS
#endif
