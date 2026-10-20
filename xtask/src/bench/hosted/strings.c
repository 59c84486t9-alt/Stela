// The system string and memory routines: memcpy of mixed sizes, and
// strlen, strcmp, memchr and memcmp over a text buffer.
#include "bench.h"

#define BUFFER (1u << 20)

int main(int argc, char **argv) {
  uint8_t *source = malloc(BUFFER), *target = malloc(BUFFER);
  if (!source || !target) return 1;
  uint64_t seed = 6;
  for (size_t i = 0; i < BUFFER; i++) source[i] = (uint8_t)bench_xorshift(&seed);

  static const size_t SIZES[8] = {8, 16, 32, 64, 256, 1024, 4096, 65536};
  uint64_t copies = bench_scaled(argc, argv, 3000000);
  uint64_t checksum = 0;
  double start = bench_now();
  for (uint64_t i = 0; i < copies; i++) {
    size_t size = SIZES[i & 7];
    size_t from = (i * 4099) % (BUFFER - size), to = (i * 8191) % (BUFFER - size);
    memcpy(target + to, source + from, size);
    checksum += target[to + (i % size)];
  }
  bench_report("memcpy-mixed", bench_now() - start, checksum, 0);

  // Text with a NUL roughly every 8 to 263 bytes.
  char *text = malloc(BUFFER + 1);
  if (!text) return 1;
  for (size_t i = 0; i < BUFFER; i++) text[i] = (char)('a' + bench_xorshift(&seed) % 26);
  size_t starts[4096], count = 0;
  for (size_t at = 0; at + 300 < BUFFER && count < 4096;) {
    starts[count++] = at;
    at += 8 + bench_xorshift(&seed) % 256;
    text[at++] = 0;
  }
  text[BUFFER] = 0;
  char *copy = malloc(BUFFER + 1);
  if (!copy) return 1;
  memcpy(copy, text, BUFFER + 1);

  uint64_t rounds = bench_scaled(argc, argv, 600);
  checksum = 0;
  start = bench_now();
  for (uint64_t round = 0; round < rounds; round++) {
    for (size_t i = 0; i < count; i++) {
      const char *s = text + starts[i];
      size_t n = strlen(s);
      checksum += n;
      checksum += (uint64_t)(strcmp(s, copy + starts[i]) == 0);
      const char *hit = memchr(s, 'z', n);
      checksum += hit ? (uint64_t)(hit - s) : 7;
      checksum += (uint64_t)(memcmp(s, copy + starts[i], n) == 0);
    }
    copy[starts[round % count]] ^= 1; // keep one comparison unequal
  }
  bench_report("string-ops", bench_now() - start, checksum, 0);
  return 0;
}
