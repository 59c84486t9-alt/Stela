// Authored source words for the generic EL1 scalar-load boundary.
// Labels are independent one-instruction attempts; no sequential execution.
// Decode receipts are preparation, not original/native execution evidence.
.text
.p2align 2
u8_unsigned:
    .inst 0x39400c20 // ldrb w0, [x1, #3] ; admit
u8_unscaled:
    .inst 0x385ff020 // ldurb w0, [x1, #-1] ; admit
u8_pre:
    .inst 0x38401c20 // ldrb w0, [x1, #1]! ; admit
u8_post:
    .inst 0x385ff420 // ldrb w0, [x1], #0xffffffffffffffff ; admit
u8_reg_uxtw_unscaled:
    .inst 0x38624820 // ldrb w0, [x1, w2, uxtw] ; admit
u8_reg_uxtw_scaled:
    .inst 0x38625820 // ldrb w0, [x1, w2, uxtw #0] ; admit
u8_reg_lsl_unscaled:
    .inst 0x38626820 // ldrb w0, [x1, x2] ; admit
u8_reg_lsl_scaled:
    .inst 0x38627820 // ldrb w0, [x1, x2, lsl #0] ; admit
u8_reg_sxtw_unscaled:
    .inst 0x3862c820 // ldrb w0, [x1, w2, sxtw] ; admit
u8_reg_sxtw_scaled:
    .inst 0x3862d820 // ldrb w0, [x1, w2, sxtw #0] ; admit
u8_reg_sxtx_unscaled:
    .inst 0x3862e820 // ldrb w0, [x1, x2, sxtx] ; admit
u8_reg_sxtx_scaled:
    .inst 0x3862f820 // ldrb w0, [x1, x2, sxtx #0] ; admit
u8_sp_zr:
    .inst 0x394003ff // ldrb wzr, [sp] ; admit
u8_offset_alias:
    .inst 0x394000e7 // ldrb w7, [x7] ; admit
u16_unsigned:
    .inst 0x79400c20 // ldrh w0, [x1, #6] ; admit
u16_unscaled:
    .inst 0x785fe020 // ldurh w0, [x1, #-2] ; admit
u16_pre:
    .inst 0x78402c20 // ldrh w0, [x1, #2]! ; admit
u16_post:
    .inst 0x785fe420 // ldrh w0, [x1], #0xfffffffffffffffe ; admit
u16_reg_uxtw_unscaled:
    .inst 0x78624820 // ldrh w0, [x1, w2, uxtw] ; admit
u16_reg_uxtw_scaled:
    .inst 0x78625820 // ldrh w0, [x1, w2, uxtw #1] ; admit
u16_reg_lsl_unscaled:
    .inst 0x78626820 // ldrh w0, [x1, x2] ; admit
u16_reg_lsl_scaled:
    .inst 0x78627820 // ldrh w0, [x1, x2, lsl #1] ; admit
u16_reg_sxtw_unscaled:
    .inst 0x7862c820 // ldrh w0, [x1, w2, sxtw] ; admit
u16_reg_sxtw_scaled:
    .inst 0x7862d820 // ldrh w0, [x1, w2, sxtw #1] ; admit
u16_reg_sxtx_unscaled:
    .inst 0x7862e820 // ldrh w0, [x1, x2, sxtx] ; admit
u16_reg_sxtx_scaled:
    .inst 0x7862f820 // ldrh w0, [x1, x2, sxtx #1] ; admit
u16_sp_zr:
    .inst 0x794003ff // ldrh wzr, [sp] ; admit
u16_offset_alias:
    .inst 0x794000e7 // ldrh w7, [x7] ; admit
u32_unsigned:
    .inst 0xb9400c20 // ldr w0, [x1, #0xc] ; admit
u32_unscaled:
    .inst 0xb85fc020 // ldur w0, [x1, #-4] ; admit
u32_pre:
    .inst 0xb8404c20 // ldr w0, [x1, #4]! ; admit
u32_post:
    .inst 0xb85fc420 // ldr w0, [x1], #0xfffffffffffffffc ; admit
u32_reg_uxtw_unscaled:
    .inst 0xb8624820 // ldr w0, [x1, w2, uxtw] ; admit
u32_reg_uxtw_scaled:
    .inst 0xb8625820 // ldr w0, [x1, w2, uxtw #2] ; admit
u32_reg_lsl_unscaled:
    .inst 0xb8626820 // ldr w0, [x1, x2] ; admit
u32_reg_lsl_scaled:
    .inst 0xb8627820 // ldr w0, [x1, x2, lsl #2] ; admit
u32_reg_sxtw_unscaled:
    .inst 0xb862c820 // ldr w0, [x1, w2, sxtw] ; admit
u32_reg_sxtw_scaled:
    .inst 0xb862d820 // ldr w0, [x1, w2, sxtw #2] ; admit
u32_reg_sxtx_unscaled:
    .inst 0xb862e820 // ldr w0, [x1, x2, sxtx] ; admit
u32_reg_sxtx_scaled:
    .inst 0xb862f820 // ldr w0, [x1, x2, sxtx #2] ; admit
u32_sp_zr:
    .inst 0xb94003ff // ldr wzr, [sp] ; admit
u32_offset_alias:
    .inst 0xb94000e7 // ldr w7, [x7] ; admit
u64_unsigned:
    .inst 0xf9400c20 // ldr x0, [x1, #0x18] ; admit
u64_unscaled:
    .inst 0xf85f8020 // ldur x0, [x1, #-8] ; admit
u64_pre:
    .inst 0xf8408c20 // ldr x0, [x1, #8]! ; admit
u64_post:
    .inst 0xf85f8420 // ldr x0, [x1], #0xfffffffffffffff8 ; admit
u64_reg_uxtw_unscaled:
    .inst 0xf8624820 // ldr x0, [x1, w2, uxtw] ; admit
u64_reg_uxtw_scaled:
    .inst 0xf8625820 // ldr x0, [x1, w2, uxtw #3] ; admit
u64_reg_lsl_unscaled:
    .inst 0xf8626820 // ldr x0, [x1, x2] ; admit
u64_reg_lsl_scaled:
    .inst 0xf8627820 // ldr x0, [x1, x2, lsl #3] ; admit
u64_reg_sxtw_unscaled:
    .inst 0xf862c820 // ldr x0, [x1, w2, sxtw] ; admit
u64_reg_sxtw_scaled:
    .inst 0xf862d820 // ldr x0, [x1, w2, sxtw #3] ; admit
u64_reg_sxtx_unscaled:
    .inst 0xf862e820 // ldr x0, [x1, x2, sxtx] ; admit
u64_reg_sxtx_scaled:
    .inst 0xf862f820 // ldr x0, [x1, x2, sxtx #3] ; admit
u64_sp_zr:
    .inst 0xf94003ff // ldr xzr, [sp] ; admit
u64_offset_alias:
    .inst 0xf94000e7 // ldr x7, [x7] ; admit
s8w_unsigned:
    .inst 0x39c00c20 // ldrsb w0, [x1, #3] ; admit
s8w_unscaled:
    .inst 0x38dff020 // ldursb w0, [x1, #-1] ; admit
s8w_pre:
    .inst 0x38c01c20 // ldrsb w0, [x1, #1]! ; admit
s8w_post:
    .inst 0x38dff420 // ldrsb w0, [x1], #0xffffffffffffffff ; admit
s8w_reg_uxtw_unscaled:
    .inst 0x38e24820 // ldrsb w0, [x1, w2, uxtw] ; admit
s8w_reg_uxtw_scaled:
    .inst 0x38e25820 // ldrsb w0, [x1, w2, uxtw #0] ; admit
s8w_reg_lsl_unscaled:
    .inst 0x38e26820 // ldrsb w0, [x1, x2] ; admit
s8w_reg_lsl_scaled:
    .inst 0x38e27820 // ldrsb w0, [x1, x2, lsl #0] ; admit
s8w_reg_sxtw_unscaled:
    .inst 0x38e2c820 // ldrsb w0, [x1, w2, sxtw] ; admit
s8w_reg_sxtw_scaled:
    .inst 0x38e2d820 // ldrsb w0, [x1, w2, sxtw #0] ; admit
s8w_reg_sxtx_unscaled:
    .inst 0x38e2e820 // ldrsb w0, [x1, x2, sxtx] ; admit
s8w_reg_sxtx_scaled:
    .inst 0x38e2f820 // ldrsb w0, [x1, x2, sxtx #0] ; admit
s8w_sp_zr:
    .inst 0x39c003ff // ldrsb wzr, [sp] ; admit
s8w_offset_alias:
    .inst 0x39c000e7 // ldrsb w7, [x7] ; admit
s8x_unsigned:
    .inst 0x39800c20 // ldrsb x0, [x1, #3] ; admit
s8x_unscaled:
    .inst 0x389ff020 // ldursb x0, [x1, #-1] ; admit
s8x_pre:
    .inst 0x38801c20 // ldrsb x0, [x1, #1]! ; admit
s8x_post:
    .inst 0x389ff420 // ldrsb x0, [x1], #0xffffffffffffffff ; admit
s8x_reg_uxtw_unscaled:
    .inst 0x38a24820 // ldrsb x0, [x1, w2, uxtw] ; admit
s8x_reg_uxtw_scaled:
    .inst 0x38a25820 // ldrsb x0, [x1, w2, uxtw #0] ; admit
s8x_reg_lsl_unscaled:
    .inst 0x38a26820 // ldrsb x0, [x1, x2] ; admit
s8x_reg_lsl_scaled:
    .inst 0x38a27820 // ldrsb x0, [x1, x2, lsl #0] ; admit
s8x_reg_sxtw_unscaled:
    .inst 0x38a2c820 // ldrsb x0, [x1, w2, sxtw] ; admit
s8x_reg_sxtw_scaled:
    .inst 0x38a2d820 // ldrsb x0, [x1, w2, sxtw #0] ; admit
s8x_reg_sxtx_unscaled:
    .inst 0x38a2e820 // ldrsb x0, [x1, x2, sxtx] ; admit
s8x_reg_sxtx_scaled:
    .inst 0x38a2f820 // ldrsb x0, [x1, x2, sxtx #0] ; admit
s8x_sp_zr:
    .inst 0x398003ff // ldrsb xzr, [sp] ; admit
s8x_offset_alias:
    .inst 0x398000e7 // ldrsb x7, [x7] ; admit
s16w_unsigned:
    .inst 0x79c00c20 // ldrsh w0, [x1, #6] ; admit
s16w_unscaled:
    .inst 0x78dfe020 // ldursh w0, [x1, #-2] ; admit
s16w_pre:
    .inst 0x78c02c20 // ldrsh w0, [x1, #2]! ; admit
s16w_post:
    .inst 0x78dfe420 // ldrsh w0, [x1], #0xfffffffffffffffe ; admit
s16w_reg_uxtw_unscaled:
    .inst 0x78e24820 // ldrsh w0, [x1, w2, uxtw] ; admit
s16w_reg_uxtw_scaled:
    .inst 0x78e25820 // ldrsh w0, [x1, w2, uxtw #1] ; admit
s16w_reg_lsl_unscaled:
    .inst 0x78e26820 // ldrsh w0, [x1, x2] ; admit
s16w_reg_lsl_scaled:
    .inst 0x78e27820 // ldrsh w0, [x1, x2, lsl #1] ; admit
s16w_reg_sxtw_unscaled:
    .inst 0x78e2c820 // ldrsh w0, [x1, w2, sxtw] ; admit
s16w_reg_sxtw_scaled:
    .inst 0x78e2d820 // ldrsh w0, [x1, w2, sxtw #1] ; admit
s16w_reg_sxtx_unscaled:
    .inst 0x78e2e820 // ldrsh w0, [x1, x2, sxtx] ; admit
s16w_reg_sxtx_scaled:
    .inst 0x78e2f820 // ldrsh w0, [x1, x2, sxtx #1] ; admit
s16w_sp_zr:
    .inst 0x79c003ff // ldrsh wzr, [sp] ; admit
s16w_offset_alias:
    .inst 0x79c000e7 // ldrsh w7, [x7] ; admit
s16x_unsigned:
    .inst 0x79800c20 // ldrsh x0, [x1, #6] ; admit
s16x_unscaled:
    .inst 0x789fe020 // ldursh x0, [x1, #-2] ; admit
s16x_pre:
    .inst 0x78802c20 // ldrsh x0, [x1, #2]! ; admit
s16x_post:
    .inst 0x789fe420 // ldrsh x0, [x1], #0xfffffffffffffffe ; admit
s16x_reg_uxtw_unscaled:
    .inst 0x78a24820 // ldrsh x0, [x1, w2, uxtw] ; admit
s16x_reg_uxtw_scaled:
    .inst 0x78a25820 // ldrsh x0, [x1, w2, uxtw #1] ; admit
s16x_reg_lsl_unscaled:
    .inst 0x78a26820 // ldrsh x0, [x1, x2] ; admit
s16x_reg_lsl_scaled:
    .inst 0x78a27820 // ldrsh x0, [x1, x2, lsl #1] ; admit
s16x_reg_sxtw_unscaled:
    .inst 0x78a2c820 // ldrsh x0, [x1, w2, sxtw] ; admit
s16x_reg_sxtw_scaled:
    .inst 0x78a2d820 // ldrsh x0, [x1, w2, sxtw #1] ; admit
s16x_reg_sxtx_unscaled:
    .inst 0x78a2e820 // ldrsh x0, [x1, x2, sxtx] ; admit
s16x_reg_sxtx_scaled:
    .inst 0x78a2f820 // ldrsh x0, [x1, x2, sxtx #1] ; admit
s16x_sp_zr:
    .inst 0x798003ff // ldrsh xzr, [sp] ; admit
s16x_offset_alias:
    .inst 0x798000e7 // ldrsh x7, [x7] ; admit
s32x_unsigned:
    .inst 0xb9800c20 // ldrsw x0, [x1, #0xc] ; admit
s32x_unscaled:
    .inst 0xb89fc020 // ldursw x0, [x1, #-4] ; admit
s32x_pre:
    .inst 0xb8804c20 // ldrsw x0, [x1, #4]! ; admit
s32x_post:
    .inst 0xb89fc420 // ldrsw x0, [x1], #0xfffffffffffffffc ; admit
s32x_reg_uxtw_unscaled:
    .inst 0xb8a24820 // ldrsw x0, [x1, w2, uxtw] ; admit
s32x_reg_uxtw_scaled:
    .inst 0xb8a25820 // ldrsw x0, [x1, w2, uxtw #2] ; admit
s32x_reg_lsl_unscaled:
    .inst 0xb8a26820 // ldrsw x0, [x1, x2] ; admit
s32x_reg_lsl_scaled:
    .inst 0xb8a27820 // ldrsw x0, [x1, x2, lsl #2] ; admit
s32x_reg_sxtw_unscaled:
    .inst 0xb8a2c820 // ldrsw x0, [x1, w2, sxtw] ; admit
s32x_reg_sxtw_scaled:
    .inst 0xb8a2d820 // ldrsw x0, [x1, w2, sxtw #2] ; admit
s32x_reg_sxtx_unscaled:
    .inst 0xb8a2e820 // ldrsw x0, [x1, x2, sxtx] ; admit
s32x_reg_sxtx_scaled:
    .inst 0xb8a2f820 // ldrsw x0, [x1, x2, sxtx #2] ; admit
s32x_sp_zr:
    .inst 0xb98003ff // ldrsw xzr, [sp] ; admit
s32x_offset_alias:
    .inst 0xb98000e7 // ldrsw x7, [x7] ; admit
literal_w:
    .inst 0x18000040 // ldr w0, #0x100008 ; admit
literal_x:
    .inst 0x58000041 // ldr x1, #0x100008 ; admit
literal_sw:
    .inst 0x98000042 // ldrsw x2, #0x100008 ; admit
literal_w_zr:
    .inst 0x1800005f // ldr wzr, #0x100008 ; admit
literal_x_zr:
    .inst 0x5800005f // ldr xzr, #0x100008 ; admit
literal_sw_zr:
    .inst 0x9800005f // ldrsw xzr, #0x100008 ; admit
literal_firmware_w27:
    .inst 0x18000a9b // ldr w27, #0x100150 ; admit
store_u32:
    .inst 0xb9000020 // str w0, [x1] ; explicit decline
unprivileged_u32:
    .inst 0xb8400820 // ldtr w0, [x1] ; explicit decline
ordered_u32:
    .inst 0x88dffc20 // ldar w0, [x1] ; explicit decline
exclusive_u32:
    .inst 0x885f7c20 // ldxr w0, [x1] ; explicit decline
simd_literal:
    .inst 0x1c000040 // ldr s0, #0x100008 ; explicit decline
prefetch_literal:
    .inst 0xd8000000 // prfm pldl1keep, #0x100000 ; explicit decline
constrained_pre_alias:
    .inst 0xf8408c00 //  ; explicit decline
constrained_post_alias:
    .inst 0xf8408400 //  ; explicit decline
reserved_index_extend:
    .inst 0x38620820 //  ; explicit decline
u8_sp_pre:
    .inst 0x38401fff // ldrb wzr, [sp, #1]! ; admit
u8_sp_post:
    .inst 0x385ff7ff // ldrb wzr, [sp], #0xffffffffffffffff ; admit
u8_reg_sp_zr:
    .inst 0x387f7bff // ldrb wzr, [sp, xzr, lsl #0] ; admit
u8_reg_alias_index:
    .inst 0x38626822 // ldrb w2, [x1, x2] ; admit
u8_reg_alias_base:
    .inst 0x38626821 // ldrb w1, [x1, x2] ; admit
u16_sp_pre:
    .inst 0x78402fff // ldrh wzr, [sp, #2]! ; admit
u16_sp_post:
    .inst 0x785fe7ff // ldrh wzr, [sp], #0xfffffffffffffffe ; admit
u16_reg_sp_zr:
    .inst 0x787f7bff // ldrh wzr, [sp, xzr, lsl #1] ; admit
u16_reg_alias_index:
    .inst 0x78626822 // ldrh w2, [x1, x2] ; admit
u16_reg_alias_base:
    .inst 0x78626821 // ldrh w1, [x1, x2] ; admit
u32_sp_pre:
    .inst 0xb8404fff // ldr wzr, [sp, #4]! ; admit
u32_sp_post:
    .inst 0xb85fc7ff // ldr wzr, [sp], #0xfffffffffffffffc ; admit
u32_reg_sp_zr:
    .inst 0xb87f7bff // ldr wzr, [sp, xzr, lsl #2] ; admit
u32_reg_alias_index:
    .inst 0xb8626822 // ldr w2, [x1, x2] ; admit
u32_reg_alias_base:
    .inst 0xb8626821 // ldr w1, [x1, x2] ; admit
u64_sp_pre:
    .inst 0xf8408fff // ldr xzr, [sp, #8]! ; admit
u64_sp_post:
    .inst 0xf85f87ff // ldr xzr, [sp], #0xfffffffffffffff8 ; admit
u64_reg_sp_zr:
    .inst 0xf87f7bff // ldr xzr, [sp, xzr, lsl #3] ; admit
u64_reg_alias_index:
    .inst 0xf8626822 // ldr x2, [x1, x2] ; admit
u64_reg_alias_base:
    .inst 0xf8626821 // ldr x1, [x1, x2] ; admit
s8w_sp_pre:
    .inst 0x38c01fff // ldrsb wzr, [sp, #1]! ; admit
s8w_sp_post:
    .inst 0x38dff7ff // ldrsb wzr, [sp], #0xffffffffffffffff ; admit
s8w_reg_sp_zr:
    .inst 0x38ff7bff // ldrsb wzr, [sp, xzr, lsl #0] ; admit
s8w_reg_alias_index:
    .inst 0x38e26822 // ldrsb w2, [x1, x2] ; admit
s8w_reg_alias_base:
    .inst 0x38e26821 // ldrsb w1, [x1, x2] ; admit
s8x_sp_pre:
    .inst 0x38801fff // ldrsb xzr, [sp, #1]! ; admit
s8x_sp_post:
    .inst 0x389ff7ff // ldrsb xzr, [sp], #0xffffffffffffffff ; admit
s8x_reg_sp_zr:
    .inst 0x38bf7bff // ldrsb xzr, [sp, xzr, lsl #0] ; admit
s8x_reg_alias_index:
    .inst 0x38a26822 // ldrsb x2, [x1, x2] ; admit
s8x_reg_alias_base:
    .inst 0x38a26821 // ldrsb x1, [x1, x2] ; admit
s16w_sp_pre:
    .inst 0x78c02fff // ldrsh wzr, [sp, #2]! ; admit
s16w_sp_post:
    .inst 0x78dfe7ff // ldrsh wzr, [sp], #0xfffffffffffffffe ; admit
s16w_reg_sp_zr:
    .inst 0x78ff7bff // ldrsh wzr, [sp, xzr, lsl #1] ; admit
s16w_reg_alias_index:
    .inst 0x78e26822 // ldrsh w2, [x1, x2] ; admit
s16w_reg_alias_base:
    .inst 0x78e26821 // ldrsh w1, [x1, x2] ; admit
s16x_sp_pre:
    .inst 0x78802fff // ldrsh xzr, [sp, #2]! ; admit
s16x_sp_post:
    .inst 0x789fe7ff // ldrsh xzr, [sp], #0xfffffffffffffffe ; admit
s16x_reg_sp_zr:
    .inst 0x78bf7bff // ldrsh xzr, [sp, xzr, lsl #1] ; admit
s16x_reg_alias_index:
    .inst 0x78a26822 // ldrsh x2, [x1, x2] ; admit
s16x_reg_alias_base:
    .inst 0x78a26821 // ldrsh x1, [x1, x2] ; admit
s32x_sp_pre:
    .inst 0xb8804fff // ldrsw xzr, [sp, #4]! ; admit
s32x_sp_post:
    .inst 0xb89fc7ff // ldrsw xzr, [sp], #0xfffffffffffffffc ; admit
s32x_reg_sp_zr:
    .inst 0xb8bf7bff // ldrsw xzr, [sp, xzr, lsl #2] ; admit
s32x_reg_alias_index:
    .inst 0xb8a26822 // ldrsw x2, [x1, x2] ; admit
s32x_reg_alias_base:
    .inst 0xb8a26821 // ldrsw x1, [x1, x2] ; admit
literal_w_negative:
    .inst 0x18ffffc0 // ldr w0, #0xffff8 ; admit
literal_x_negative:
    .inst 0x58ffffc1 // ldr x1, #0xffff8 ; admit
literal_sw_negative:
    .inst 0x98ffffc2 // ldrsw x2, #0xffff8 ; admit
