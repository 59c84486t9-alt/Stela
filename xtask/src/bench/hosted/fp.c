// Floating-point kernels: an n-body simulation (scalar double) and a float
// matrix multiply, once autovectorized and once with vectorization disabled.
// Built with -ffp-contract=off so that every architecture rounds the same.
#include "bench.h"
#include <math.h>

#define BODIES 5
struct body {
  double x, y, z, vx, vy, vz, mass;
};

static void advance(struct body *b, double dt) {
  for (int i = 0; i < BODIES; i++)
    for (int j = i + 1; j < BODIES; j++) {
      double dx = b[i].x - b[j].x, dy = b[i].y - b[j].y, dz = b[i].z - b[j].z;
      double d2 = dx * dx + dy * dy + dz * dz;
      double mag = dt / (d2 * sqrt(d2));
      b[i].vx -= dx * b[j].mass * mag;
      b[i].vy -= dy * b[j].mass * mag;
      b[i].vz -= dz * b[j].mass * mag;
      b[j].vx += dx * b[i].mass * mag;
      b[j].vy += dy * b[i].mass * mag;
      b[j].vz += dz * b[i].mass * mag;
    }
  for (int i = 0; i < BODIES; i++) {
    b[i].x += dt * b[i].vx;
    b[i].y += dt * b[i].vy;
    b[i].z += dt * b[i].vz;
  }
}

#define N 384
static float A[N][N], B[N][N], C[N][N];

static void matmul_vector(void) {
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++) C[i][j] = 0;
    for (int k = 0; k < N; k++) {
      float a = A[i][k];
      for (int j = 0; j < N; j++) C[i][j] += a * B[k][j];
    }
  }
}

static void matmul_scalar(void) {
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++) C[i][j] = 0;
    for (int k = 0; k < N; k++) {
      float a = A[i][k];
#pragma clang loop vectorize(disable) interleave(disable)
      for (int j = 0; j < N; j++) C[i][j] += a * B[k][j];
    }
  }
}

int main(int argc, char **argv) {
  struct body bodies[BODIES] = {
      {0, 0, 0, 0, 0, 0, 39.47841760435743},
      {4.84143144246472090e+00, -1.16032004402742839e+00, -1.03622044471123109e-01,
       6.06326392995832e-01, 2.81198684491626e+00, -2.52183616598876e-02,
       3.769367487038949e-02},
      {8.34336671824457987e+00, 4.12479856412430479e+00, -4.03523417114321381e-01,
       -1.01077434617733e+00, 1.82566237123041e+00, 8.41576137658415e-03,
       1.128632614803951e-02},
      {1.28943695621391310e+01, -1.51111514016986312e+01, -2.23307578892655734e-01,
       1.08279100644154e+00, 8.68713018169608e-01, -1.01086242379581e-02,
       1.723724057059711e-03},
      {1.53796971148509165e+01, -2.59193146099879641e+01, 1.79258772950371181e-01,
       9.79090732243898e-01, 5.94698998647676e-01, -3.47559555040781e-02,
       2.033686869924631e-03}};
  uint64_t steps = bench_scaled(argc, argv, 5000000);
  double start = bench_now();
  for (uint64_t i = 0; i < steps; i++) advance(bodies, 0.01);
  bench_report("nbody-scalar", bench_now() - start,
               bench_fnv(BENCH_FNV_BASIS, bodies, sizeof bodies), 0);

  uint64_t seed = 7;
  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++) {
      A[i][j] = (float)(bench_xorshift(&seed) % 1000) / 999.0f;
      B[i][j] = (float)(bench_xorshift(&seed) % 1000) / 999.0f;
    }
  uint64_t passes = bench_scaled(argc, argv, 16);
  uint64_t checksum = BENCH_FNV_BASIS;
  start = bench_now();
  for (uint64_t pass = 0; pass < passes; pass++) {
    matmul_vector();
    A[pass % N][pass % N] += 1.0f;
    checksum = bench_fnv(checksum, C[pass % N], sizeof C[0]);
  }
  bench_report("matmul-neon", bench_now() - start, checksum, 0);

  passes = bench_scaled(argc, argv, 4);
  checksum = BENCH_FNV_BASIS;
  start = bench_now();
  for (uint64_t pass = 0; pass < passes; pass++) {
    matmul_scalar();
    A[pass % N][pass % N] += 1.0f;
    checksum = bench_fnv(checksum, C[pass % N], sizeof C[0]);
  }
  bench_report("matmul-scalar", bench_now() - start, checksum, 0);
  return 0;
}
