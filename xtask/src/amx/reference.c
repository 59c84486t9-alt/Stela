// Bare-metal driver for the corsix/amx C emulator (selected AMX_VER) on QEMU `virt`.
//
// The batch header at BATCH holds the chain count, steps per chain, AMX
// operation, result-name length and chain stride, then the result file name at
// byte 40. Each chain is a 5120-byte register file, the 384-byte transfer
// buffer and its operands. Every step's FNV-1a digest of the register file and
// buffer is written, followed by the final register file and buffer. Layouts
// match `amx.rs`. start.S sets FPCR.DN, as corsix's hardware comparison did.
#include "emulate.h"

// Selected by the Rust harness; no implicit generation fallback.
uint32_t AMX_VER = STELA_AMX_VER;

#define BATCH 0x41000000ull
#define RESULTS 0x50000000ull
#define CHAINS_OFFSET 0x1000
#define STATE_BYTES 5120
#define BUFFER_BYTES 384

void emulate_AMX_LDX(amx_state*, uint64_t);
void emulate_AMX_LDY(amx_state*, uint64_t);
void emulate_AMX_STX(amx_state*, uint64_t);
void emulate_AMX_STY(amx_state*, uint64_t);
void emulate_AMX_LDZ(amx_state*, uint64_t);
void emulate_AMX_STZ(amx_state*, uint64_t);
void emulate_AMX_LDZI(amx_state*, uint64_t);
void emulate_AMX_STZI(amx_state*, uint64_t);
void emulate_AMX_EXTRX(amx_state*, uint64_t);
void emulate_AMX_EXTRY(amx_state*, uint64_t);
void emulate_AMX_FMA64(amx_state*, uint64_t);
void emulate_AMX_FMS64(amx_state*, uint64_t);
void emulate_AMX_FMA32(amx_state*, uint64_t);
void emulate_AMX_FMS32(amx_state*, uint64_t);
void emulate_AMX_MAC16(amx_state*, uint64_t);
void emulate_AMX_FMA16(amx_state*, uint64_t);
void emulate_AMX_FMS16(amx_state*, uint64_t);
void emulate_AMX_VECINT(amx_state*, uint64_t);
void emulate_AMX_VECFP(amx_state*, uint64_t);
void emulate_AMX_MATINT(amx_state*, uint64_t);
void emulate_AMX_MATFP(amx_state*, uint64_t);
void emulate_AMX_GENLUT(amx_state*, uint64_t);

typedef void (*operation)(amx_state*, uint64_t);
static const operation OPERATIONS[23] = {
    emulate_AMX_LDX, emulate_AMX_LDY, emulate_AMX_STX, emulate_AMX_STY,
    emulate_AMX_LDZ, emulate_AMX_STZ, emulate_AMX_LDZI, emulate_AMX_STZI,
    emulate_AMX_EXTRX, emulate_AMX_EXTRY, emulate_AMX_FMA64, emulate_AMX_FMS64,
    emulate_AMX_FMA32, emulate_AMX_FMS32, emulate_AMX_MAC16, emulate_AMX_FMA16,
    emulate_AMX_FMS16, 0, emulate_AMX_VECINT, emulate_AMX_VECFP,
    emulate_AMX_MATINT, emulate_AMX_MATFP, emulate_AMX_GENLUT,
};

void* memcpy(void* destination, const void* source, size_t length) {
    uint8_t* d = destination;
    const uint8_t* s = source;
    while (length--) *d++ = *s++;
    return destination;
}

void* memset(void* destination, int value, size_t length) {
    uint8_t* d = destination;
    while (length--) *d++ = (uint8_t)value;
    return destination;
}

static uint64_t digest(const uint8_t* state, const uint8_t* buffer) {
    uint64_t hash = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < STATE_BYTES; ++i) hash = (hash ^ state[i]) * 0x100000001b3ull;
    for (size_t i = 0; i < BUFFER_BYTES; ++i) hash = (hash ^ buffer[i]) * 0x100000001b3ull;
    return hash;
}

static long semihost(long call, void* parameters) {
    register long x0 __asm__("x0") = call;
    register void* x1 __asm__("x1") = parameters;
    __asm__ volatile("hlt #0xf000" : "+r"(x0) : "r"(x1) : "memory");
    return x0;
}

static amx_state state;

void reference_main(void) {
    volatile uint64_t* header = (volatile uint64_t*)BATCH;
    uint64_t chains = header[0], steps = header[1], op = header[2], name_bytes = header[3];
    uint64_t stride = header[4];
    uint64_t* results = (uint64_t*)RESULTS;
    uint64_t result_stride = steps + (STATE_BYTES + BUFFER_BYTES) / 8;
    for (uint64_t chain = 0; chain < chains; ++chain) {
        uint8_t* input = (uint8_t*)(BATCH + CHAINS_OFFSET + chain * stride);
        uint8_t* buffer = input + STATE_BYTES;
        const uint64_t* operands = (const uint64_t*)(buffer + BUFFER_BYTES);
        memcpy(&state, input, STATE_BYTES);
        uint64_t* out = results + chain * result_stride;
        for (uint64_t step = 0; step < steps; ++step) {
            OPERATIONS[op](&state, operands[step]);
            out[step] = digest((const uint8_t*)&state, buffer);
        }
        memcpy(out + steps, &state, STATE_BYTES);
        memcpy((uint8_t*)(out + steps) + STATE_BYTES, buffer, BUFFER_BYTES);
    }
    uint64_t parameters[3] = {BATCH + 40, 5, name_bytes};
    long handle = semihost(0x01, parameters);
    parameters[0] = handle;
    parameters[1] = RESULTS;
    parameters[2] = chains * result_stride * 8;
    semihost(0x05, parameters);
    parameters[0] = handle;
    semihost(0x02, parameters);
    parameters[0] = 0x20026;
    parameters[1] = 0;
    semihost(0x18, parameters);
}
