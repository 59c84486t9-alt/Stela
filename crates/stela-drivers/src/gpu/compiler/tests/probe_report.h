/* SPDX-License-Identifier: MIT */
#ifndef STELA_PROBE_REPORT_H
#define STELA_PROBE_REPORT_H
/* The one machine-readable output of Stela's compiler probes: a line
 * "STELA_RECORD " followed by a JSON object whose "kind" selects its typed
 * schema in xtask/src/gpu/mesa/record.rs. Every other line is diagnostic text.
 * Keys are fixed ASCII identifiers; string values are escaped.
 *
 * Each fixture records the expected outcome of every target before it compiles
 * them, then exactly one outcome per expected target. The compiler task
 * compares the two sets; it lists no targets or counts of its own.
 */
#include "util/mesa-blake3.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECORD_MAX_DEPTH 4

static struct {
   bool opening;
   unsigned depth;
   char closers[RECORD_MAX_DEPTH];
} record_state;

static inline void
record_separator(void)
{
   if (!record_state.opening)
      putchar(',');
   record_state.opening = false;
}

static inline void
record_escaped(const char *value, size_t length)
{
   putchar('"');
   for (size_t i = 0; i < length; i++) {
      const unsigned char c = (unsigned char)value[i];
      if (c == '"' || c == '\\')
         printf("\\%c", c);
      else if (c < 0x20 || c >= 0x7f)
         printf("\\u%04x", c);
      else
         putchar(c);
   }
   putchar('"');
}

static inline void
record_key(const char *key)
{
   record_separator();
   printf("\"%s\":", key);
}

static inline void
record_begin(const char *kind)
{
   fputs("STELA_RECORD {\"kind\":", stdout);
   record_escaped(kind, strlen(kind));
   record_state.opening = false;
   record_state.depth = 0;
}

/* Closes every open object or array, then the record itself. */
static inline void
record_end(void)
{
   while (record_state.depth)
      putchar(record_state.closers[--record_state.depth]);
   puts("}");
   fflush(stdout);
}

static inline void
record_strn(const char *key, const char *value, size_t length)
{
   record_key(key);
   record_escaped(value, length);
}

static inline void
record_str(const char *key, const char *value)
{
   record_strn(key, value, strlen(value));
}

static inline void
record_uint(const char *key, uint64_t value)
{
   record_key(key);
   printf("%" PRIu64, value);
}

static inline void
record_int(const char *key, int64_t value)
{
   record_key(key);
   printf("%" PRId64, value);
}

static inline void
record_bool(const char *key, bool value)
{
   record_key(key);
   fputs(value ? "true" : "false", stdout);
}

static inline void
record_uints(const char *key, const uint32_t *values, unsigned count)
{
   record_key(key);
   putchar('[');
   for (unsigned i = 0; i < count; i++)
      printf("%s%" PRIu32, i ? "," : "", values[i]);
   putchar(']');
}

static inline void
record_open(const char *key, char opener, char closer)
{
   if (record_state.depth == RECORD_MAX_DEPTH) {
      fprintf(stderr, "probe record nesting exceeds %u\n", RECORD_MAX_DEPTH);
      exit(1);
   }
   record_key(key);
   putchar(opener);
   record_state.closers[record_state.depth++] = closer;
   record_state.opening = true;
}

/* A nested object; its members follow until record_close() or record_end(). */
static inline void
record_object(const char *key)
{
   record_open(key, '{', '}');
}

/* An array of strings, appended with record_item(). */
static inline void
record_array(const char *key)
{
   record_open(key, '[', ']');
}

static inline void
record_item(const char *value)
{
   record_separator();
   record_escaped(value, strlen(value));
}

static inline void
record_close(void)
{
   putchar(record_state.closers[--record_state.depth]);
   record_state.opening = false;
}

static inline void
stela_digest(const void *bytes, size_t size, char hex[BLAKE3_HEX_LEN])
{
   blake3_hash hash;
   _mesa_blake3_compute(bytes, size, hash);
   _mesa_blake3_format(hex, hash);
}

static inline void
record_blake3(const char *key, const void *bytes, size_t size)
{
   char hex[BLAKE3_HEX_LEN];
   stela_digest(bytes, size, hex);
   record_str(key, hex);
}

/* Expect code for target, or the named hold. */
static inline void
record_expect(const char *target, const char *hold)
{
   record_begin("expect");
   record_str("target", target);
   record_str("outcome", hold ? "held" : "compiled");
   if (hold)
      record_str("reason", hold);
   record_end();
}

/* Expect target to be refused by design; a refusal is a passing result. */
static inline void
record_expect_refusal(const char *target, const char *reason)
{
   record_begin("expect");
   record_str("target", target);
   record_str("outcome", "refused");
   record_str("reason", reason);
   record_end();
}

/* Expect code, or the named refusal when the input requests what the target
 * refuses by design: an unchanged input's contents are not known up front.
 */
static inline void
record_expect_unless_refused(const char *target, const char *refusal)
{
   record_begin("expect");
   record_str("target", target);
   record_str("outcome", "compiled");
   record_str("unless_refused", refusal);
   record_end();
}

/* Opens a compiled outcome; add facts with record_object("facts"), then
 * finish it with record_end(). */
static inline void
record_compiled(const char *target, uint64_t bytes)
{
   record_begin("compiled");
   record_str("target", target);
   record_uint("bytes", bytes);
}

static inline void
record_held(const char *target, const char *reason)
{
   record_begin("held");
   record_str("target", target);
   record_str("reason", reason);
   record_end();
}

static inline void
record_refused(const char *target, const char *reason)
{
   record_begin("refused");
   record_str("target", target);
   record_str("reason", reason);
   record_end();
}

/* A file the probe wrote into the artifact directory it was given. */
static inline void
record_artifact(const char *name)
{
   record_begin("artifact");
   record_str("path", name);
   record_end();
}

#endif
