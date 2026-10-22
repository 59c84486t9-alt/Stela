/* SPDX-License-Identifier: MIT */
#pragma once
#include "intel/compiler/gen/gen.h"
#include <stdio.h>

static inline bool
validate_intel_code(const struct intel_device_info *device, void *context,
                    const void *code, unsigned bytes, const char *target,
                    unsigned *sends)
{
   gen_decode_params decoded = {
      .devinfo = device,
      .raw_bytes = code,
      .raw_bytes_size = bytes,
      .mem_ctx = context,
   };
   if (!gen_decode(&decoded)) {
      for (int i = 0; i < decoded.num_errors; i++)
         fprintf(stderr, "%s: decode %d: %s\n", target,
                 decoded.errors[i].index, decoded.errors[i].msg);
      return false;
   }
   gen_validate_params validation = {
      .devinfo = device,
      .insts = decoded.insts,
      .num_insts = decoded.num_insts,
      .mem_ctx = context,
   };
   bool valid = gen_validate(&validation);
   for (int i = 0; i < validation.num_errors; i++)
      fprintf(stderr, "%s: instruction %d: %s\n", target,
              validation.errors[i].index, validation.errors[i].msg);
   *sends = 0;
   for (int i = 0; i < decoded.num_insts; i++) {
      gen_opcode op = decoded.insts[i].opcode;
      *sends += op == GEN_OP_SEND || op == GEN_OP_SENDC ||
                op == GEN_OP_SENDS || op == GEN_OP_SENDSC;
   }
   /* The fixture's load, store and end-of-thread must survive codegen. */
   if (*sends < 3) {
      fprintf(stderr, "%s: expected load/store/EOT messages, found %u\n",
              target, *sends);
      valid = false;
   }
   return valid;
}
