// A bitwise (table-free) CRC-32 and a bit-twiddling loop: shifts, masks,
// rotates, population counts, leading and trailing zero counts and bit
// reversal.
#include "bench.h"

static uint32_t crc32_bitwise(const uint8_t *p, size_t n, uint32_t crc) {
  crc = ~crc;
  for (size_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xedb88320u & -(crc & 1));
  }
  return ~crc;
}

static uint64_t reverse(uint64_t y) {
  y = ((y >> 1) & 0x5555555555555555ull) | ((y & 0x5555555555555555ull) << 1);
  y = ((y >> 2) & 0x3333333333333333ull) | ((y & 0x3333333333333333ull) << 2);
  y = ((y >> 4) & 0x0f0f0f0f0f0f0f0full) | ((y & 0x0f0f0f0f0f0f0f0full) << 4);
  y = ((y >> 8) & 0x00ff00ff00ff00ffull) | ((y & 0x00ff00ff00ff00ffull) << 8);
  y = ((y >> 16) & 0x0000ffff0000ffffull) | ((y & 0x0000ffff0000ffffull) << 16);
  return (y >> 32) | (y << 32);
}

int main(int argc, char **argv) {
  static uint8_t buffer[65536];
  uint64_t seed = 3;
  for (size_t i = 0; i < sizeof buffer; i++) buffer[i] = (uint8_t)bench_xorshift(&seed);

  uint64_t passes = bench_scaled(argc, argv, 512); // 32 MiB
  uint32_t crc = 0;
  double start = bench_now();
  for (uint64_t pass = 0; pass < passes; pass++)
    crc = crc32_bitwise(buffer, sizeof buffer, crc);
  bench_report("crc32-bitwise", bench_now() - start, crc, 0);

  uint64_t rounds = bench_scaled(argc, argv, 40000000);
  uint64_t x = 0x9e3779b97f4a7c15ull, acc = 0;
  start = bench_now();
  for (uint64_t i = 0; i < rounds; i++) {
    bench_xorshift(&x);
    uint64_t y = reverse(x);
    unsigned s = (unsigned)(acc & 63);
    acc += (uint64_t)__builtin_popcountll(x) + (uint64_t)__builtin_ctzll(x | 1) +
           (uint64_t)__builtin_clzll(x | 1);
    acc ^= (y >> s) | (y << ((64 - s) & 63));
    acc = (acc << 7) ^ (acc >> 3) ^ (uint32_t)(x >> 29);
  }
  bench_report("bit-twiddle", bench_now() - start, acc, 0);
  return 0;
}
