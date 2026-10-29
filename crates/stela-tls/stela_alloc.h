/* Fixed allocator ABI supplied by the actual Rust global allocator. */
#ifndef STELA_MBED_ALLOC_H
#define STELA_MBED_ALLOC_H
#include <stddef.h>
void *stela_mbedtls_calloc(size_t count,size_t size);
void stela_mbedtls_free(void *pointer);
#endif
