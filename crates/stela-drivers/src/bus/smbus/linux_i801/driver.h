/* SPDX-License-Identifier: MIT */
#ifndef STELA_I801_H
#define STELA_I801_H
#include <stdint.h>
#include <stddef.h>

struct stela_i801_io {
    uint8_t (*read8)(void *, uint8_t);
    void (*write8)(void *, uint8_t, uint8_t);
    uint64_t (*now_us)(void *);
    void (*delay_us)(void *, uint32_t);
};

void *stela_i801_create(const struct stela_i801_io *, void *, uint16_t, uint8_t,
                        uint32_t, int);
void stela_i801_destroy(void *);
int stela_i801_transfer(void *, uint8_t, uint8_t, uint8_t, int, uint8_t *, uint8_t *);
#endif
