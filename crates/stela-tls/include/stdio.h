#pragma once
#include <stddef.h>
#include <stdarg.h>
typedef struct stela_opaque_FILE FILE;
extern FILE *stderr; extern FILE *stdout;
#define EOF (-1)
int printf(const char*,...); int fprintf(FILE*,const char*,...); int snprintf(char*,size_t,const char*,...); int vsnprintf(char*,size_t,const char*,va_list); int vprintf(const char*,va_list); int vfprintf(FILE*,const char*,va_list); void setbuf(FILE*,char*); int sscanf(const char*,const char*,...);
