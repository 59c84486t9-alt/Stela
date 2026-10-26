/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_CT_H
#define STELA_INTEL_CT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum stela_intel_ct_region {
    STELA_INTEL_CT_H2G_DESC,
    STELA_INTEL_CT_H2G_COMMANDS,
    STELA_INTEL_CT_G2H_DESC,
    STELA_INTEL_CT_G2H_COMMANDS,
};

enum stela_intel_ct_order {
    STELA_INTEL_CT_ACQUIRE, /* observed firmware tail precedes payload reads */
    STELA_INTEL_CT_RELEASE, /* payload writes precede descriptor publication */
    STELA_INTEL_CT_CONSUME, /* payload reads finish before head permits reuse */
};

enum stela_intel_ct_mmio {
    STELA_INTEL_CT_ROOT_TILE,
    STELA_INTEL_CT_GT,
};

/* All callbacks are mandatory. A mapping owner provides naturally aligned,
 * single-copy 32-bit access, including proper device-memory access for VRAM.
 * Descriptors have 16 words and command regions have the sizes passed to attach.
 * order() performs actual CPU/DMA ordering for the mapped memory type, including
 * WC writes. mmio_write32() performs the actual uncached register write within
 * the selected root-tile or GT aperture. Register residency, force-wake and
 * posted-write ordering must already be guaranteed by the device owner.
 * In particular the notify MMIO write must order the preceding descriptor
 * write, including WC/device-memory descriptor mappings, as Xe's writel does.
 *
 * The context and every mapping remain pinned and accessible until all calls
 * stop. No callback may fail, reenter, allocate, or call guest ARM services.
 * Device removal must first stop and serialize all callers. The owner supplies
 * these guarantees; this table contains no fallback implementations.
 */
struct stela_intel_ct_io {
    void (*read)(void *, enum stela_intel_ct_region, uint32_t word, uint32_t *out, uint32_t count);
    void (*write)(void *, enum stela_intel_ct_region, uint32_t word, const uint32_t *in, uint32_t count);
    void (*zero)(void *, enum stela_intel_ct_region, uint32_t word, uint32_t count);
    void (*order)(void *, enum stela_intel_ct_order);
    void (*mmio_write32)(void *, enum stela_intel_ct_mmio, uint32_t offset, uint32_t value);
};

struct stela_intel_ct {
    const struct stela_intel_ct_io *io;
    void *context;
    uint32_t h2g_size, g2h_size;
    uint32_t h2g_tail, g2h_head;
    bool discrete, media_gt, broken;
};

/* Attach to owner-registered, enabled CT buffers. This reads existing cursors;
 * it does not zero/allocate/map/register/enable a buffer or initialize firmware.
 * The owner serializes all calls (including IRQ receivers), holds runtime power
 * and pre-reserves response credits/tracking before sending any request. Fences,
 * retries, errors, reset, timeout, event dispatch and response-credit return
 * remain with that owner. Input payload storage must not alias the mappings.
 *
 * Errors: -22 invalid arguments; -19 disabled; -71 malformed firmware state;
 * -32 broken transport; -16 no send credits; -28 receive output too small.
 * Corruption marks transport broken until the owner resets and reattaches.
 * Receive uses its retained host head, following upstream's tolerance for
 * descriptor-head rollback on some discrete platforms. Reattachment still
 * requires the real owner's reset/drain lifecycle and exclusive ownership.
 */
int stela_intel_ct_attach(struct stela_intel_ct *, const struct stela_intel_ct_io *,
                          void *context, uint32_t h2g_words, uint32_t g2h_words,
                          bool discrete, bool media_gt);

/* type is an original GUC_HXG_TYPE_{REQUEST,EVENT,FAST_REQUEST}. EVENT use must
 * meet the real VF recovery policy; callers normally use REQUEST/FAST_REQUEST.
 * 0 means packet published and GuC notified, not accepted/executed/completed.
 * -11 means the ring end was NOP-filled and published; the payload was NOT sent.
 * The owner retries after rechecking credits, without reusing a tracked fence.
 */
int stela_intel_ct_send(struct stela_intel_ct *, const uint32_t *action,
                        uint32_t words, uint16_t fence, uint32_t type);

/* Returns the entire CT+HXG message word count, 0 if empty, or a negative error.
 * Valid raw messages are returned unchanged; the owner must parse and dispatch
 * every HXG message type, including failure/retry/busy events. No success or
 * completion is synthesized. Errors leave output and receive cursor unchanged.
 */
int stela_intel_ct_receive(struct stela_intel_ct *, uint32_t *message, size_t capacity);

#endif
