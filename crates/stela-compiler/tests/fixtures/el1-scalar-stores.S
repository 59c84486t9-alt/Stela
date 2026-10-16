// Authored canonical EL1 scalar-store family inputs.
// Fixed source words independently decoded with Capstone 5.0.6; no original/native proof.
// Each admit is one exact-width store; decline/other never has ScalarStore intent.
.text
u8_unsigned:
    .inst 0x39000c20 // strb w0, [x1, #3] ; admit
u8_unscaled:
    .inst 0x381ff020 // sturb w0, [x1, #-1] ; admit
u8_pre:
    .inst 0x38001c20 // strb w0, [x1, #1]! ; admit
u8_post:
    .inst 0x381ff420 // strb w0, [x1], #0xffffffffffffffff ; admit
u8_reg_uxtw_unscaled:
    .inst 0x38224820 // strb w0, [x1, w2, uxtw] ; admit
u8_reg_uxtw_scaled:
    .inst 0x38225820 // strb w0, [x1, w2, uxtw #0] ; admit
u8_reg_lsl_unscaled:
    .inst 0x38226820 // strb w0, [x1, x2] ; admit
u8_reg_lsl_scaled:
    .inst 0x38227820 // strb w0, [x1, x2, lsl #0] ; admit
u8_reg_sxtw_unscaled:
    .inst 0x3822c820 // strb w0, [x1, w2, sxtw] ; admit
u8_reg_sxtw_scaled:
    .inst 0x3822d820 // strb w0, [x1, w2, sxtw #0] ; admit
u8_reg_sxtx_unscaled:
    .inst 0x3822e820 // strb w0, [x1, x2, sxtx] ; admit
u8_reg_sxtx_scaled:
    .inst 0x3822f820 // strb w0, [x1, x2, sxtx #0] ; admit
u8_sp_zr:
    .inst 0x390003ff // strb wzr, [sp] ; admit
u8_offset_alias:
    .inst 0x390000e7 // strb w7, [x7] ; admit
u16_unsigned:
    .inst 0x79000c20 // strh w0, [x1, #6] ; admit
u16_unscaled:
    .inst 0x781fe020 // sturh w0, [x1, #-2] ; admit
u16_pre:
    .inst 0x78002c20 // strh w0, [x1, #2]! ; admit
u16_post:
    .inst 0x781fe420 // strh w0, [x1], #0xfffffffffffffffe ; admit
u16_reg_uxtw_unscaled:
    .inst 0x78224820 // strh w0, [x1, w2, uxtw] ; admit
u16_reg_uxtw_scaled:
    .inst 0x78225820 // strh w0, [x1, w2, uxtw #1] ; admit
u16_reg_lsl_unscaled:
    .inst 0x78226820 // strh w0, [x1, x2] ; admit
u16_reg_lsl_scaled:
    .inst 0x78227820 // strh w0, [x1, x2, lsl #1] ; admit
u16_reg_sxtw_unscaled:
    .inst 0x7822c820 // strh w0, [x1, w2, sxtw] ; admit
u16_reg_sxtw_scaled:
    .inst 0x7822d820 // strh w0, [x1, w2, sxtw #1] ; admit
u16_reg_sxtx_unscaled:
    .inst 0x7822e820 // strh w0, [x1, x2, sxtx] ; admit
u16_reg_sxtx_scaled:
    .inst 0x7822f820 // strh w0, [x1, x2, sxtx #1] ; admit
u16_sp_zr:
    .inst 0x790003ff // strh wzr, [sp] ; admit
u16_offset_alias:
    .inst 0x790000e7 // strh w7, [x7] ; admit
u32_unsigned:
    .inst 0xb9000c20 // str w0, [x1, #0xc] ; admit
u32_unscaled:
    .inst 0xb81fc020 // stur w0, [x1, #-4] ; admit
u32_pre:
    .inst 0xb8004c20 // str w0, [x1, #4]! ; admit
u32_post:
    .inst 0xb81fc420 // str w0, [x1], #0xfffffffffffffffc ; admit
u32_reg_uxtw_unscaled:
    .inst 0xb8224820 // str w0, [x1, w2, uxtw] ; admit
u32_reg_uxtw_scaled:
    .inst 0xb8225820 // str w0, [x1, w2, uxtw #2] ; admit
u32_reg_lsl_unscaled:
    .inst 0xb8226820 // str w0, [x1, x2] ; admit
u32_reg_lsl_scaled:
    .inst 0xb8227820 // str w0, [x1, x2, lsl #2] ; admit
u32_reg_sxtw_unscaled:
    .inst 0xb822c820 // str w0, [x1, w2, sxtw] ; admit
u32_reg_sxtw_scaled:
    .inst 0xb822d820 // str w0, [x1, w2, sxtw #2] ; admit
u32_reg_sxtx_unscaled:
    .inst 0xb822e820 // str w0, [x1, x2, sxtx] ; admit
u32_reg_sxtx_scaled:
    .inst 0xb822f820 // str w0, [x1, x2, sxtx #2] ; admit
u32_sp_zr:
    .inst 0xb90003ff // str wzr, [sp] ; admit
u32_offset_alias:
    .inst 0xb90000e7 // str w7, [x7] ; admit
u64_unsigned:
    .inst 0xf9000c20 // str x0, [x1, #0x18] ; admit
u64_unscaled:
    .inst 0xf81f8020 // stur x0, [x1, #-8] ; admit
u64_pre:
    .inst 0xf8008c20 // str x0, [x1, #8]! ; admit
u64_post:
    .inst 0xf81f8420 // str x0, [x1], #0xfffffffffffffff8 ; admit
u64_reg_uxtw_unscaled:
    .inst 0xf8224820 // str x0, [x1, w2, uxtw] ; admit
u64_reg_uxtw_scaled:
    .inst 0xf8225820 // str x0, [x1, w2, uxtw #3] ; admit
u64_reg_lsl_unscaled:
    .inst 0xf8226820 // str x0, [x1, x2] ; admit
u64_reg_lsl_scaled:
    .inst 0xf8227820 // str x0, [x1, x2, lsl #3] ; admit
u64_reg_sxtw_unscaled:
    .inst 0xf822c820 // str x0, [x1, w2, sxtw] ; admit
u64_reg_sxtw_scaled:
    .inst 0xf822d820 // str x0, [x1, w2, sxtw #3] ; admit
u64_reg_sxtx_unscaled:
    .inst 0xf822e820 // str x0, [x1, x2, sxtx] ; admit
u64_reg_sxtx_scaled:
    .inst 0xf822f820 // str x0, [x1, x2, sxtx #3] ; admit
u64_sp_zr:
    .inst 0xf90003ff // str xzr, [sp] ; admit
u64_offset_alias:
    .inst 0xf90000e7 // str x7, [x7] ; admit
u8_sp_pre:
    .inst 0x38001fff // strb wzr, [sp, #1]! ; admit
u8_sp_post:
    .inst 0x381ff7ff // strb wzr, [sp], #0xffffffffffffffff ; admit
u8_reg_sp_zr:
    .inst 0x383f7bff // strb wzr, [sp, xzr, lsl #0] ; admit
u8_reg_alias_index:
    .inst 0x38226822 // strb w2, [x1, x2] ; admit
u8_reg_alias_base:
    .inst 0x38226821 // strb w1, [x1, x2] ; admit
u16_sp_pre:
    .inst 0x78002fff // strh wzr, [sp, #2]! ; admit
u16_sp_post:
    .inst 0x781fe7ff // strh wzr, [sp], #0xfffffffffffffffe ; admit
u16_reg_sp_zr:
    .inst 0x783f7bff // strh wzr, [sp, xzr, lsl #1] ; admit
u16_reg_alias_index:
    .inst 0x78226822 // strh w2, [x1, x2] ; admit
u16_reg_alias_base:
    .inst 0x78226821 // strh w1, [x1, x2] ; admit
u32_sp_pre:
    .inst 0xb8004fff // str wzr, [sp, #4]! ; admit
u32_sp_post:
    .inst 0xb81fc7ff // str wzr, [sp], #0xfffffffffffffffc ; admit
u32_reg_sp_zr:
    .inst 0xb83f7bff // str wzr, [sp, xzr, lsl #2] ; admit
u32_reg_alias_index:
    .inst 0xb8226822 // str w2, [x1, x2] ; admit
u32_reg_alias_base:
    .inst 0xb8226821 // str w1, [x1, x2] ; admit
u64_sp_pre:
    .inst 0xf8008fff // str xzr, [sp, #8]! ; admit
u64_sp_post:
    .inst 0xf81f87ff // str xzr, [sp], #0xfffffffffffffff8 ; admit
u64_reg_sp_zr:
    .inst 0xf83f7bff // str xzr, [sp, xzr, lsl #3] ; admit
u64_reg_alias_index:
    .inst 0xf8226822 // str x2, [x1, x2] ; admit
u64_reg_alias_base:
    .inst 0xf8226821 // str x1, [x1, x2] ; admit
u8_unsigned_max:
    .inst 0x393ffc20 // strb w0, [x1, #0xfff] ; admit
u8_unscaled_min:
    .inst 0x38100020 // sturb w0, [x1, #-0x100] ; admit
u8_unscaled_max:
    .inst 0x380ff020 // sturb w0, [x1, #0xff] ; admit
u8_pre_max:
    .inst 0x380ffc20 // strb w0, [x1, #0xff]! ; admit
u8_post_min:
    .inst 0x38100420 // strb w0, [x1], #0xffffffffffffff00 ; admit
u8_reg_all_alias:
    .inst 0x38226842 // strb w2, [x2, x2] ; admit
u16_unsigned_max:
    .inst 0x793ffc20 // strh w0, [x1, #0x1ffe] ; admit
u16_unscaled_min:
    .inst 0x78100020 // sturh w0, [x1, #-0x100] ; admit
u16_unscaled_max:
    .inst 0x780ff020 // sturh w0, [x1, #0xff] ; admit
u16_pre_max:
    .inst 0x780ffc20 // strh w0, [x1, #0xff]! ; admit
u16_post_min:
    .inst 0x78100420 // strh w0, [x1], #0xffffffffffffff00 ; admit
u16_reg_all_alias:
    .inst 0x78226842 // strh w2, [x2, x2] ; admit
u32_unsigned_max:
    .inst 0xb93ffc20 // str w0, [x1, #0x3ffc] ; admit
u32_unscaled_min:
    .inst 0xb8100020 // stur w0, [x1, #-0x100] ; admit
u32_unscaled_max:
    .inst 0xb80ff020 // stur w0, [x1, #0xff] ; admit
u32_pre_max:
    .inst 0xb80ffc20 // str w0, [x1, #0xff]! ; admit
u32_post_min:
    .inst 0xb8100420 // str w0, [x1], #0xffffffffffffff00 ; admit
u32_reg_all_alias:
    .inst 0xb8226842 // str w2, [x2, x2] ; admit
u64_unsigned_max:
    .inst 0xf93ffc20 // str x0, [x1, #0x7ff8] ; admit
u64_unscaled_min:
    .inst 0xf8100020 // stur x0, [x1, #-0x100] ; admit
u64_unscaled_max:
    .inst 0xf80ff020 // stur x0, [x1, #0xff] ; admit
u64_pre_max:
    .inst 0xf80ffc20 // str x0, [x1, #0xff]! ; admit
u64_post_min:
    .inst 0xf8100420 // str x0, [x1], #0xffffffffffffff00 ; admit
u64_reg_all_alias:
    .inst 0xf8226842 // str x2, [x2, x2] ; admit
u32_real_source_operands:
    .inst 0xb900035b // str w27, [x26] ; admit
decline_u8_wb_overlap_pre:
    .inst 0x38001c21 // strb w1, [x1, #1]! ; decline
decline_u8_wb_overlap_post:
    .inst 0x38001421 // strb w1, [x1], #1 ; decline
decline_u8_unprivileged:
    .inst 0x38000820 // sttrb w0, [x1] ; decline
other_u8_load:
    .inst 0x39400c20 // ldrb w0, [x1, #3] ; other
decline_u16_wb_overlap_pre:
    .inst 0x78001c21 // strh w1, [x1, #1]! ; decline
decline_u16_wb_overlap_post:
    .inst 0x78001421 // strh w1, [x1], #1 ; decline
decline_u16_unprivileged:
    .inst 0x78000820 // sttrh w0, [x1] ; decline
other_u16_load:
    .inst 0x79400c20 // ldrh w0, [x1, #6] ; other
decline_u32_wb_overlap_pre:
    .inst 0xb8001c21 // str w1, [x1, #1]! ; decline
decline_u32_wb_overlap_post:
    .inst 0xb8001421 // str w1, [x1], #1 ; decline
decline_u32_unprivileged:
    .inst 0xb8000820 // sttr w0, [x1] ; decline
other_u32_load:
    .inst 0xb9400c20 // ldr w0, [x1, #0xc] ; other
decline_u64_wb_overlap_pre:
    .inst 0xf8001c21 // str x1, [x1, #1]! ; decline
decline_u64_wb_overlap_post:
    .inst 0xf8001421 // str x1, [x1], #1 ; decline
decline_u64_unprivileged:
    .inst 0xf8000820 // sttr x0, [x1] ; decline
other_u64_load:
    .inst 0xf9400c20 // ldr x0, [x1, #0x18] ; other
decline_simd_d:
    .inst 0xfd000020 // str d0, [x1] ; decline
decline_simd_q:
    .inst 0x3d800020 // str q0, [x1] ; decline
decline_stlr_w:
    .inst 0x889ffc20 // stlr w0, [x1] ; decline
decline_stlr_x:
    .inst 0xc89ffc20 // stlr x0, [x1] ; decline
decline_stxr_x:
    .inst 0xc8027c20 // stxr w2, x0, [x1] ; decline
decline_ldxr_x:
    .inst 0xc85f7c20 // ldxr x0, [x1] ; decline
decline_pair_w:
    .inst 0x29000820 // stp w0, w2, [x1] ; decline
decline_prefetch:
    .inst 0xf9800020 // prfm pldl1keep, [x1] ; decline
other_pair_x:
    .inst 0xa9000820 // stp x0, x2, [x1] ; other
other_literal_w:
    .inst 0x18000040 // ldr w0, #0x100008 ; other
other_literal_x:
    .inst 0x58000040 // ldr x0, #0x100008 ; other
other_literal_sw:
    .inst 0x98000040 // ldrsw x0, #0x100008 ; other
other_nop:
    .inst 0xd503201f // nop  ; other
