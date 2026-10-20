// A register-machine bytecode interpreter with switch dispatch, running a
// program with data-dependent branches.
#include "bench.h"

enum { MOVI, ADD, SUB, MUL, XOR, AND, SHR, SHL, ADDI, JNZ, JLT, JODD, DEC, HALT };

struct op {
  uint8_t code, a, b, c;
  int32_t imm;
};

static uint64_t run(const struct op *program, uint64_t *r) {
  const struct op *pc = program;
  uint64_t executed = 0;
  for (;;) {
    executed++;
    const struct op o = *pc++;
    switch (o.code) {
    case MOVI: r[o.a] = (uint64_t)(int64_t)o.imm; break;
    case ADD: r[o.a] = r[o.b] + r[o.c]; break;
    case SUB: r[o.a] = r[o.b] - r[o.c]; break;
    case MUL: r[o.a] = r[o.b] * r[o.c]; break;
    case XOR: r[o.a] = r[o.b] ^ r[o.c]; break;
    case AND: r[o.a] = r[o.b] & r[o.c]; break;
    case SHR: r[o.a] = r[o.b] >> (r[o.c] & 63); break;
    case SHL: r[o.a] = r[o.b] << (r[o.c] & 63); break;
    case ADDI: r[o.a] = r[o.b] + (uint64_t)(int64_t)o.imm; break;
    case JNZ: if (r[o.a]) pc = program + o.imm; break;
    case JLT: if (r[o.a] < r[o.b]) pc = program + o.imm; break;
    case JODD: if (r[o.a] & 1) pc = program + o.imm; break;
    case DEC: r[o.a]--; break;
    case HALT: return executed;
    }
  }
}

int main(int argc, char **argv) {
  uint64_t iterations = bench_scaled(argc, argv, 12000000);
  // r0 counter, r1 LCG state, r2 multiplier, r3 increment, r4 sum, r5 tmp,
  // r6 shift 17, r7 mask, r8 threshold, r9 odd count.
  const struct op program[] = {
      /* 0 */ {MOVI, 2, 0, 0, 1103515245},
      /* 1 */ {MOVI, 3, 0, 0, 12345},
      /* 2 */ {MOVI, 6, 0, 0, 17},
      /* 3 */ {MOVI, 7, 0, 0, 0xffff},
      /* 4 */ {MOVI, 8, 0, 0, 0x8000},
      /* 5 loop */ {MUL, 1, 1, 2, 0},
      /* 6 */ {ADD, 1, 1, 3, 0},
      /* 7 */ {SHR, 5, 1, 6, 0},
      /* 8 */ {AND, 5, 5, 7, 0},
      /* 9 */ {JODD, 5, 0, 0, 14},
      /* 10 */ {JLT, 5, 8, 0, 13},
      /* 11 */ {XOR, 4, 4, 5, 0},
      /* 12 */ {ADDI, 0, 0, 0, 0}, // fall into the shared tail
      /* 13 */ {SHL, 5, 5, 6, 0},
      /* 14 */ {ADD, 4, 4, 5, 0},
      /* 15 */ {ADDI, 9, 9, 0, 1},
      /* 16 */ {DEC, 0, 0, 0, 0},
      /* 17 */ {JNZ, 0, 0, 0, 5},
      /* 18 */ {HALT, 0, 0, 0, 0},
  };
  uint64_t r[16] = {0};
  r[0] = iterations;
  r[1] = 42;
  double start = bench_now();
  uint64_t executed = run(program, r);
  double seconds = bench_now() - start;
  char note[64];
  snprintf(note, sizeof note, "ops=%llu", (unsigned long long)executed);
  bench_report("interpreter", seconds, bench_fnv(BENCH_FNV_BASIS, r, sizeof r), note);
  return 0;
}
