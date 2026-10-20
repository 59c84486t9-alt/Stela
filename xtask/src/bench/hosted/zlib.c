// zlib deflate and inflate through the system libz. Compressed sizes can
// differ between libz builds, so they are notes, not checksums.
#include "bench.h"
#include <zlib.h>

static const char *const WORDS[] = {
    "the ",     "quick ",   "brown ",   "fox ",   "jumps ",  "over ",
    "lazy ",    "dog ",     "translat", "ion ",   "native ", "block ",
    "region ",  "register", "\n",       "flags ", "memory ", "0123456789"};

int main(int argc, char **argv) {
  size_t size = bench_scaled(argc, argv, 16u << 20);
  uint8_t *input = malloc(size), *output = malloc(size);
  uLongf bound = compressBound(size);
  uint8_t *compressed = malloc(bound);
  if (!input || !output || !compressed) return 1;
  uint64_t seed = 5;
  for (size_t at = 0; at < size;) {
    uint64_t r = bench_xorshift(&seed);
    const char *word = WORDS[r % (sizeof WORDS / sizeof *WORDS)];
    size_t n = strlen(word);
    if (r >> 60 == 0) {
      // Occasional incompressible bytes.
      input[at++] = (uint8_t)(r >> 8);
      continue;
    }
    for (size_t i = 0; i < n && at < size; i++) input[at++] = (uint8_t)word[i];
  }

  uLongf packed = bound;
  double start = bench_now();
  if (compress2(compressed, &packed, input, size, 6) != Z_OK) return 2;
  double seconds = bench_now() - start;
  char note[64];
  snprintf(note, sizeof note, "compressed=%lu", (unsigned long)packed);
  bench_report("zlib-deflate", seconds, crc32(0, input, (uInt)size), note);

  int passes = 4;
  uint64_t checksum = 0;
  start = bench_now();
  for (int pass = 0; pass < passes; pass++) {
    uLongf unpacked = size;
    if (uncompress(output, &unpacked, compressed, packed) != Z_OK || unpacked != size)
      return 3;
    checksum += crc32(0, output, (uInt)size);
  }
  seconds = bench_now() - start;
  if (memcmp(input, output, size)) return 4;
  bench_report("zlib-inflate", seconds, checksum, note);
  return 0;
}
