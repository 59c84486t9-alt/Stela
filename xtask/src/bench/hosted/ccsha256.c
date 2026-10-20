// CommonCrypto's SHA-256 (the system library of each architecture).
#include "bench.h"
#include <CommonCrypto/CommonDigest.h>

int main(int argc, char **argv) {
  static uint8_t block[16384];
  uint64_t seed = 2;
  for (size_t i = 0; i < sizeof block; i++) block[i] = (uint8_t)bench_xorshift(&seed);
  uint64_t blocks = bench_scaled(argc, argv, 16384); // 256 MiB
  CC_SHA256_CTX context;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  double start = bench_now();
  CC_SHA256_Init(&context);
  for (uint64_t i = 0; i < blocks; i++) CC_SHA256_Update(&context, block, sizeof block);
  CC_SHA256_Final(digest, &context);
  double seconds = bench_now() - start;
  bench_report("commoncrypto-sha256", seconds,
               bench_fnv(BENCH_FNV_BASIS, digest, sizeof digest), 0);
  return 0;
}
