// Shared helpers of the hosted benchmark workloads. Each program takes an
// optional work scale in percent (default 100) as argv[1], times its kernels
// with CLOCK_MONOTONIC and prints one line per kernel:
//
//   stela-bench KERNEL SECONDS CHECKSUM [NOTE]
//
// The checksum is a 64-bit hex digest of the kernel's results, which must
// agree between the x86_64, arm64 and arm64e builds; NOTE is informational.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Every fixture initializes its inputs on entry; the warm pass runs the same
// complete work once, suppressing only reports. Native and guest use this
// identical wrapper. The second pass resets those inputs and is reported.
#ifdef STELA_BENCH_WARMUP
static __attribute__((noinline)) int stela_bench_run(int argc, char **argv);
static volatile int stela_bench_warming = 1;
static volatile uint64_t stela_bench_warmup_digest;
int main(int argc, char **argv) {
  int status = stela_bench_run(argc, argv);
  if (status) return status;
  stela_bench_warming = 0;
  return stela_bench_run(argc, argv);
}
#define main stela_bench_run
#endif

static double bench_now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static uint64_t bench_scaled(int argc, char **argv, uint64_t work) {
  long scale = argc > 1 ? atol(argv[1]) : 100;
  uint64_t scaled = work * (uint64_t)(scale > 0 ? scale : 100) / 100;
  return scaled ? scaled : 1;
}

static void bench_report(const char *kernel, double seconds, uint64_t checksum,
                         const char *note) {
#ifdef STELA_BENCH_WARMUP
  if (stela_bench_warming) {
    stela_bench_warmup_digest ^= checksum; // Consume every warm result.
    return;
  }
#endif
  printf("stela-bench %s %.6f %016llx%s%s\n", kernel, seconds,
         (unsigned long long)checksum, note ? " " : "", note ? note : "");
  fflush(stdout);
}

// FNV-1a over bytes, continuing from `hash`.
static uint64_t bench_fnv(uint64_t hash, const void *data, size_t bytes) {
  const uint8_t *p = data;
  for (size_t i = 0; i < bytes; i++) hash = (hash ^ p[i]) * 0x100000001b3ull;
  return hash;
}

#define BENCH_FNV_BASIS 0xcbf29ce484222325ull

static uint64_t bench_xorshift(uint64_t *state) {
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return *state = x;
}
