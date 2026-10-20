// libc qsort of 10M ints through a comparison callback.
#include "bench.h"

static int compare(const void *a, const void *b) {
  int x = *(const int *)a, y = *(const int *)b;
  return (x > y) - (x < y);
}

int main(int argc, char **argv) {
  size_t count = bench_scaled(argc, argv, 10000000);
  int *values = malloc(count * sizeof *values);
  if (!values) return 1;
  uint64_t seed = 4;
  for (size_t i = 0; i < count; i++) values[i] = (int)(uint32_t)bench_xorshift(&seed);
  double start = bench_now();
  qsort(values, count, sizeof *values, compare);
  double seconds = bench_now() - start;
  for (size_t i = 1; i < count; i++)
    if (values[i - 1] > values[i]) return 2;
  bench_report("qsort-10m", seconds,
               bench_fnv(BENCH_FNV_BASIS, values, count * sizeof *values), 0);
  free(values);
  return 0;
}
