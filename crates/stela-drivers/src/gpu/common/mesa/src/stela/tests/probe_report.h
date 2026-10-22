/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include <stdio.h>

/* Names and reasons are fixed ASCII identifiers supplied by these fixtures,
 * never device strings or shader input. Rust parses every record as JSON.
 */
static inline void
probe_compiled(const char *backend, const char *target, uint32_t bytes)
{
   printf("STELA_GPU_TARGET {\"backend\":\"%s\",\"target\":\"%s\","
          "\"state\":\"compiled\",\"bytes\":%u}\n", backend, target, bytes);
}

static inline void
probe_unsupported(const char *backend, const char *target, const char *reason)
{
   printf("STELA_GPU_TARGET {\"backend\":\"%s\",\"target\":\"%s\","
          "\"state\":\"unsupported\",\"reason\":\"%s\"}\n",
          backend, target, reason);
}
