/* SPDX-License-Identifier: MIT */
/* Fixtures shared by the hosted C tests and the Rust integration test. */
#ifndef STELA_AMD_TEST_FIXTURES_H
#define STELA_AMD_TEST_FIXTURES_H
#include <stddef.h>
#include <stdint.h>

/* CHIP_TAHITI, CHIP_BONAIRE, CHIP_VEGA10 and CHIP_IP_DISCOVERY, by index;
 * CHIP_LAST past them. */
uint32_t stela_amd_test_asic(unsigned which);

/* Write a valid IP discovery binary, laid out with Linux's discovery.h, and
 * return its size, or zero if capacity is short. It describes one die with
 * GC 10.3.0.1 (bases 0x1260, 0xa000), SDMA0 5.2.0 (0x12c0), VCN 3.0.0 with
 * encode disabled (0x7800), and UMC 8.7.0 instances 0 and 1 (0x14000,
 * 0x54000), of which the harvest table removes UMC 1. Its GC table is v1.0,
 * its VCN table fuses codecs 0x5 on instance 0, and its MALL table is v2 with
 * 2 MiB per UMC. */
size_t stela_amd_test_discovery(uint8_t *binary, size_t capacity);
#endif
