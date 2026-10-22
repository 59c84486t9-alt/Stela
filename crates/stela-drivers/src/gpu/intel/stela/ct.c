/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
/* Native mapping adaptation of h2g_write()/g2h_read() in xe_guc_ct.c.
 * Reuses the firmware ABI and shared header encoding. OS BO/PM/fence/reset
 * policy stays with the real owner rather than emulated Linux objects.
 */
#include "ct.h"
#include "xe_guc_ct_message.h"
#include "regs/xe_guc_ct_regs.h"

enum { DESC_HEAD = 0, DESC_TAIL = 1, DESC_STATUS = 2 };
enum { INVALID_ARGUMENT = -22, NO_DEVICE = -19, PROTOCOL_ERROR = -71,
       BROKEN_PIPE = -32, BUSY = -16, NO_SPACE = -28, AGAIN = -11 };

static bool valid_size(uint32_t words)
{
    /* Leave room for a maximum message plus the ring's empty/full sentinel. */
    return words > GUC_CTB_MSG_MAX_LEN && words <= (UINT32_C(1) << 30) &&
           !(words & (words - 1));
}

static bool valid_io(const struct stela_intel_ct_io *io)
{
    return io && io->read && io->write && io->zero && io->order && io->mmio_write32;
}

static uint32_t read32(const struct stela_intel_ct *ct,
                       enum stela_intel_ct_region region, uint32_t word)
{
    uint32_t value;
    ct->io->read(ct->context, region, word, &value, 1);
    return value;
}

static void write32(const struct stela_intel_ct *ct,
                     enum stela_intel_ct_region region, uint32_t word, uint32_t value)
{
    ct->io->write(ct->context, region, word, &value, 1);
}

static int status(struct stela_intel_ct *ct, enum stela_intel_ct_region region)
{
    uint32_t value = read32(ct, region, DESC_STATUS);
    if (!value) return 0;
    ct->broken = true;
    return value == GUC_CTB_STATUS_DISABLED ? NO_DEVICE : PROTOCOL_ERROR;
}

int stela_intel_ct_attach(struct stela_intel_ct *ct, const struct stela_intel_ct_io *io,
                          void *context, uint32_t h2g_words, uint32_t g2h_words,
                          bool discrete, bool media_gt)
{
    if (!ct || !valid_io(io) || !valid_size(h2g_words) || !valid_size(g2h_words))
        return INVALID_ARGUMENT;
    struct stela_intel_ct candidate = {
        .io = io, .context = context, .h2g_size = h2g_words, .g2h_size = g2h_words,
        .discrete = discrete, .media_gt = media_gt,
    };
    int err = status(&candidate, STELA_INTEL_CT_H2G_DESC);
    if (err) return err;
    err = status(&candidate, STELA_INTEL_CT_G2H_DESC);
    if (err) return err;
    uint32_t h2g_head = read32(&candidate, STELA_INTEL_CT_H2G_DESC, DESC_HEAD);
    candidate.h2g_tail = read32(&candidate, STELA_INTEL_CT_H2G_DESC, DESC_TAIL);
    candidate.g2h_head = read32(&candidate, STELA_INTEL_CT_G2H_DESC, DESC_HEAD);
    uint32_t g2h_tail = read32(&candidate, STELA_INTEL_CT_G2H_DESC, DESC_TAIL);
    if (h2g_head >= h2g_words || candidate.h2g_tail >= h2g_words ||
        candidate.g2h_head >= g2h_words || g2h_tail >= g2h_words)
        return PROTOCOL_ERROR;
    *ct = candidate;
    return 0;
}

static int check(struct stela_intel_ct *ct)
{
    if (!ct || !valid_io(ct->io) || !valid_size(ct->h2g_size) || !valid_size(ct->g2h_size))
        return INVALID_ARGUMENT;
    return ct->broken ? BROKEN_PIPE : 0;
}

static void device_wmb(struct stela_intel_ct *ct)
{
    /* Exact xe_device_wmb() ordering: wmb, then VF_CAP_REG write on dGPU. */
    ct->io->order(ct->context, STELA_INTEL_CT_RELEASE);
    if (ct->discrete)
        ct->io->mmio_write32(ct->context, STELA_INTEL_CT_ROOT_TILE,
                            XE_GUC_CT_FLUSH_REG_ADDR, 0);
}

static void publish_tail(struct stela_intel_ct *ct, uint32_t tail)
{
    device_wmb(ct);
    ct->h2g_tail = tail;
    write32(ct, STELA_INTEL_CT_H2G_DESC, DESC_TAIL, tail);
    /* xe_guc_notify(): 0 to the selected main/media GT notify register. */
    ct->io->mmio_write32(ct->context, STELA_INTEL_CT_GT,
                        ct->media_gt ? XE_GUC_CT_MEDIA_NOTIFY_REG_ADDR :
                                       XE_GUC_CT_NOTIFY_REG_ADDR, 0);
}

int stela_intel_ct_send(struct stela_intel_ct *ct, const uint32_t *action,
                        uint32_t words, uint16_t fence, uint32_t type)
{
    int err = check(ct);
    if (err) return err;
    if (!action || words < GUC_HXG_MSG_MIN_LEN || words > GUC_CTB_MAX_DWORDS ||
        (type != GUC_HXG_TYPE_REQUEST && type != GUC_HXG_TYPE_FAST_REQUEST &&
         type != GUC_HXG_TYPE_EVENT) || (action[0] & ~GUC_HXG_MSG_0_AUX))
        return INVALID_ARGUMENT;
    err = status(ct, STELA_INTEL_CT_H2G_DESC);
    if (err) return err;
    uint32_t head = read32(ct, STELA_INTEL_CT_H2G_DESC, DESC_HEAD);
    uint32_t tail = read32(ct, STELA_INTEL_CT_H2G_DESC, DESC_TAIL);
    if (head >= ct->h2g_size || tail >= ct->h2g_size || tail != ct->h2g_tail) {
        ct->broken = true;
        return PROTOCOL_ERROR;
    }
    uint32_t full_len = words + GUC_CTB_HDR_LEN;
    uint32_t space = (head - tail - 1) & (ct->h2g_size - 1);
    if (full_len > space) return BUSY;
    /* Like h2g_write(), never split an H2G message across the ring end. */
    if (tail + full_len > ct->h2g_size) {
        uint32_t padding = ct->h2g_size - tail;
        if (padding > space) return BUSY;
        ct->io->zero(ct->context, STELA_INTEL_CT_H2G_COMMANDS, tail, padding);
        /* Publish/NOP-notify explicitly, allowing GuC to return wrap credits
         * even if the subsequent payload retry must wait. No payload sent.
         */
        publish_tail(ct, 0);
        return AGAIN;
    }
    uint32_t cmd[2];
    xe_guc_ct_message_header(cmd, words, fence, type, action[0]);
    ct->io->write(ct->context, STELA_INTEL_CT_H2G_COMMANDS, tail, cmd, 2);
    if (words > 1)
        ct->io->write(ct->context, STELA_INTEL_CT_H2G_COMMANDS, tail + 2, action + 1, words - 1);
    publish_tail(ct, (tail + full_len) & (ct->h2g_size - 1));
    return 0;
}

int stela_intel_ct_receive(struct stela_intel_ct *ct, uint32_t *message, size_t capacity)
{
    int err = check(ct);
    if (err) return err;
    if (!message) return INVALID_ARGUMENT;
    err = status(ct, STELA_INTEL_CT_G2H_DESC);
    if (err) return err;
    uint32_t tail = read32(ct, STELA_INTEL_CT_G2H_DESC, DESC_TAIL);
    uint32_t head = ct->g2h_head;
    if (tail >= ct->g2h_size || head >= ct->g2h_size) {
        ct->broken = true;
        return PROTOCOL_ERROR;
    }
    uint32_t avail = (tail - head) & (ct->g2h_size - 1);
    if (!avail) return 0;
    ct->io->order(ct->context, STELA_INTEL_CT_ACQUIRE);
    uint32_t header = read32(ct, STELA_INTEL_CT_G2H_COMMANDS, head);
    uint32_t len = (header & GUC_CTB_MSG_0_NUM_DWORDS) + GUC_CTB_HDR_LEN;
    if (len > avail || len < GUC_CTB_HXG_MSG_MIN_LEN ||
        (header & (GUC_CTB_MSG_0_FORMAT | GUC_CTB_MSG_0_RESERVED))) {
        ct->broken = true;
        return PROTOCOL_ERROR;
    }
    if (len > capacity) return NO_SPACE;
    message[0] = header;
    uint32_t payload_head = (head + 1) & (ct->g2h_size - 1);
    uint32_t first = len - 1;
    if (first > ct->g2h_size - payload_head)
        first = ct->g2h_size - payload_head;
    ct->io->read(ct->context, STELA_INTEL_CT_G2H_COMMANDS, payload_head, message + 1, first);
    if (first < len - 1)
        ct->io->read(ct->context, STELA_INTEL_CT_G2H_COMMANDS, 0,
                     message + 1 + first, len - 1 - first);
    ct->io->order(ct->context, STELA_INTEL_CT_CONSUME);
    ct->g2h_head = (head + len) & (ct->g2h_size - 1);
    write32(ct, STELA_INTEL_CT_G2H_DESC, DESC_HEAD, ct->g2h_head);
    return (int)len;
}
