/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_FUNNEL_STAGE_TESTS_H
#define STELA_AIR_FUNNEL_STAGE_TESTS_H

/* Independent bit-index reference, applied before the fixture's explicit
 * finite-float output encoding. No floating arithmetic or NaN claim follows. */
static uint64_t
funnel_stage_reference(bool left, uint64_t a, uint64_t b, uint32_t amount)
{
   unsigned k = amount % 64;
   uint64_t result = 0;
   for (unsigned bit = 0; bit < 64; bit++) {
      unsigned source = left ? 64 + bit - k : bit + k;
      unsigned value = source < 64 ? (b >> source) & 1 : (a >> (source - 64)) & 1;
      result |= (uint64_t)value << bit;
   }
   return result;
}

static void
funnel_stage_outputs(nir_shader *nir, bool fragment, const uint32_t expected[4])
{
   unsigned stores = 0;
   nir_foreach_function_impl(impl, nir) {
      CHECK(finite_effect_body(impl));
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            switch (instr->type) {
            case nir_instr_type_alu:
            case nir_instr_type_deref:
            case nir_instr_type_load_const:
               continue;
            case nir_instr_type_jump:
               CHECK(nir_instr_as_jump(instr)->type == nir_jump_return);
               continue;
            case nir_instr_type_intrinsic:
               break;
            default:
               CHECK(false);
            }
            nir_intrinsic_instr *i = nir_instr_as_intrinsic(instr);
            CHECK(i->intrinsic == nir_intrinsic_store_deref);
            nir_deref_instr *deref = nir_src_as_deref(i->src[0]);
            CHECK(deref->deref_type == nir_deref_type_var);
            nir_variable *v = deref->var;
            CHECK(v->data.mode == nir_var_shader_out && v->type == glsl_vec4_type());
            CHECK(v->data.location == (fragment ? FRAG_RESULT_DATA0 : VARYING_SLOT_POS));
            CHECK(!v->data.location_frac && !v->data.index);
            CHECK(i->src[1].ssa->num_components == 4 && i->src[1].ssa->bit_size == 32);
            CHECK(nir_intrinsic_write_mask(i) == 0xf && nir_src_is_const(i->src[1]));
            CHECK(++stores == 1);
            nir_const_value *values = nir_src_as_const_value(i->src[1]);
            for (unsigned lane = 0; lane < 4; lane++)
               CHECK(values[lane].u32 == expected[lane]);
         }
      }
   }
   CHECK(stores == 1);
}

static void
integer_funnel_stage_semantics(void)
{
   const uint32_t amounts[] = {0, 1, 31, 32, 63, 64, 65, 128, UINT32_MAX};
   for (unsigned fragment = 0; fragment < 2; fragment++) {
      for (unsigned case_index = 0; case_index < sizeof(amounts) / sizeof(amounts[0]); case_index++) {
         uint32_t raw = amounts[case_index];
         LLVMMemoryBufferRef input = bitcode(stela_air_funnel_stage_fixture);
         unsigned calls = 0;
         struct stela_air_stage_options o = options(fragment ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX,
                                                     NULL, 0, &calls);
         o.resources.fp_profile = STELA_AIR_FP_IEEE_DEFAULT;
         nir_shader *nir = translate(input, fragment ? "funnel_fragment" : "funnel_vertex", &o);
         CHECK(!calls && !nir->info.num_ssbos);
         LLVMDisposeMemoryBuffer(input);
         unsigned replacements = 0;
         nir_foreach_function_impl(impl, nir) {
            nir_foreach_block(block, impl) {
               nir_foreach_instr_safe(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *i = nir_instr_as_intrinsic(instr);
                  if (i->intrinsic != (fragment ? nir_intrinsic_load_frag_coord : nir_intrinsic_load_vertex_id))
                     continue;
                  nir_builder b = nir_builder_at(nir_before_instr(instr));
                  nir_def *value = fragment ? nir_vec4(&b, nir_imm_int(&b, raw), nir_imm_int(&b, 0),
                                                          nir_imm_int(&b, 0), nir_imm_int(&b, 0)) :
                                             nir_imm_int(&b, raw);
                  replace_def(i, value);
                  replacements++;
               }
            }
         }
         CHECK(replacements == 1);
         fold(nir);
         uint64_t a = ((uint64_t)(raw ^ UINT32_C(0x12345678)) << 32) | raw;
         uint64_t b = a ^ UINT64_C(0xfedcba9876543210);
         uint64_t left = funnel_stage_reference(true, a, b, raw);
         uint64_t right = funnel_stage_reference(false, a, b, raw);
         const uint32_t expected[] = {
            ((uint32_t)left & UINT32_C(0x7fffff)) | UINT32_C(0x3f800000),
            ((uint32_t)(left >> 32) & UINT32_C(0x7fffff)) | UINT32_C(0x3f800000),
            ((uint32_t)right & UINT32_C(0x7fffff)) | UINT32_C(0x3f800000),
            ((uint32_t)(right >> 32) & UINT32_C(0x7fffff)) | UINT32_C(0x3f800000),
         };
         CHECK(nir->info.stage == (fragment ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX));
         funnel_stage_outputs(nir, fragment, expected);
         ralloc_free(nir);
      }
   }
}

#endif
