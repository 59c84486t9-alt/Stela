/* SPDX-License-Identifier: MIT */
/* Original hosted BTI algorithms, not GPU execution or a resource owner. */
#include "gallium/drivers/iris/iris_binding_table.h"
#include "gallium/drivers/crocus/crocus_binding_table.h"
#include "compiler/nir/nir_builder.h"
#include "compiler/nir/nir_serialize.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/dev/intel_device_info.h"
#include "intel/dev/intel_debug.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#error "Binding-table qualification requires assertions"
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__func__,__LINE__,#x); abort(); } } while (0)

void stela_donor_iris_setup(const struct intel_device_info *, struct nir_shader *,
    struct iris_binding_table *, unsigned, unsigned, unsigned, bool);
void stela_donor_crocus_setup(const struct intel_device_info *, struct nir_shader *,
    struct crocus_binding_table *, unsigned, unsigned, unsigned, const struct elk_sampler_prog_key_data *);

static const nir_shader_compiler_options options = {0};
static unsigned cases;

static unsigned count(uint64_t bits)
{
    unsigned n = 0;
    for (unsigned i = 0; i < 64; i++) n += (unsigned)((bits >> i) & 1);
    return n;
}

static uint64_t mask(unsigned n)
{
    CHECK(n <= 64); return n == 64 ? UINT64_MAX : (1ull << n) - 1;
}

static nir_shader *fixture(mesa_shader_stage stage, unsigned buffers, uint64_t used, bool indirect)
{
    nir_builder b = nir_builder_init_simple_shader(stage, &options, "binding_table_fixture");
    b.shader->info.num_ssbos = buffers;
    for (unsigned i = 0; i < buffers; i++) {
        if (!(used & (1ull << i))) continue;
        /* Unknown only in this pure remapping fixture, never substituted for
         * a production resource index or invocation/system value. */
        nir_def *index = indirect ? nir_undef(&b, 1, 32) : nir_imm_int(&b, i);
        nir_load_ssbo(&b, 1, 32, index, nir_imm_int(&b, 0), .align_mul = 4);
        nir_get_ssbo_size(&b, 32, index);
        if (indirect) break;
    }
    nir_shader_gather_info(b.shader, nir_shader_get_entrypoint(b.shader));
    nir_validate_shader(b.shader, "original binding fixture");
    return b.shader;
}

static void equal_nir(const nir_shader *a, const nir_shader *b)
{
    struct blob x, y; blob_init(&x); blob_init(&y);
    nir_serialize(&x, a, true); nir_serialize(&y, b, true);
    CHECK(!x.out_of_memory && !y.out_of_memory && x.size == y.size && !memcmp(x.data, y.data, x.size));
    blob_finish(&x); blob_finish(&y);
}

static void check_case(const struct intel_device_info *dev, bool legacy, mesa_shader_stage stage,
    unsigned buffers, uint64_t used, bool indirect, unsigned targets, bool skip)
{
    CHECK(!indirect || (buffers && used));
    nir_shader *a = fixture(stage, buffers, used, indirect), *b = nir_shader_clone(NULL, a);
    CHECK(b);
    unsigned render_prefix = stage == MESA_SHADER_FRAGMENT ? targets : 0;
    uint64_t active = indirect || skip ? mask(buffers) : used;
    unsigned prefix = render_prefix + (skip ? 1 : 0); /* Original unused constant-UBO group. */
    if (legacy) {
        struct crocus_binding_table current, original;
        struct elk_sampler_prog_key_data key = {0};
        crocus_setup_binding_table(dev, a, &current, render_prefix, 0, 0, &key);
        stela_donor_crocus_setup(dev, b, &original, render_prefix, 0, 0, &key);
        CHECK(!memcmp(&current, &original, sizeof(current)));
        CHECK(current.size_bytes == 4 * (prefix + count(active)));
        CHECK(current.sizes[CROCUS_SURFACE_GROUP_SSBO] == buffers &&
            current.used_mask[CROCUS_SURFACE_GROUP_SSBO] == active);
        for (unsigned i = 0; i < buffers; i++) {
            unsigned expected = active & (1ull << i) ? prefix + count(active & mask(i)) : CROCUS_SURFACE_NOT_USED;
            CHECK(crocus_group_index_to_bti(&current, CROCUS_SURFACE_GROUP_SSBO, i) == expected);
            if (active & (1ull << i)) CHECK(crocus_bti_to_group_index(&current, CROCUS_SURFACE_GROUP_SSBO, expected) == i);
        }
    } else {
        struct iris_binding_table current, original;
        iris_setup_binding_table(dev, a, &current, render_prefix, 0, 0, false);
        stela_donor_iris_setup(dev, b, &original, render_prefix, 0, 0, false);
        CHECK(!memcmp(&current, &original, sizeof(current)));
        CHECK(current.size_bytes == 4 * (prefix + count(active)));
        CHECK(current.surf_count[IRIS_SURFACE_GROUP_SSBO] == buffers &&
            current.used_mask[IRIS_SURFACE_GROUP_SSBO] == active);
        for (unsigned i = 0; i < buffers; i++) {
            unsigned expected = active & (1ull << i) ? prefix + count(active & mask(i)) : IRIS_SURFACE_NOT_USED;
            CHECK(iris_group_index_to_bti(&current, IRIS_SURFACE_GROUP_SSBO, i) == expected);
            if (active & (1ull << i)) CHECK(iris_bti_to_group_index(&current, IRIS_SURFACE_GROUP_SSBO, expected) == i);
        }
    }
    equal_nir(a, b); ralloc_free(a); ralloc_free(b); cases++;
}

int main(int argc, char **argv)
{
    CHECK(argc == 2 && (!strcmp(argv[1], "compact") || !strcmp(argv[1], "uncompacted")));
    bool skip = !strcmp(argv[1], "uncompacted");
    const char *environment = getenv("INTEL_DISABLE_COMPACT_BINDING_TABLE");
    CHECK(environment && !strcmp(environment, skip ? "true" : "false"));
    process_intel_debug_variable(); glsl_type_singleton_init_or_ref();
    const char *names[] = {"ivb", "hsw", "bdw", "tgl", "dg2", "bmg", "ptl"};
    const unsigned sizes[] = {0, 1, 2, 4, 16, 32, 64};
    for (unsigned profile = 0; profile < ARRAY_SIZE(names); profile++) {
        struct intel_device_info dev;
        int pci = intel_device_name_to_pci_device_id(names[profile]);
        CHECK(pci >= 0 && intel_get_device_info_for_build(pci, &dev));
        for (unsigned implementation = 0; implementation < 2; implementation++) {
            bool legacy = implementation != 0;
            if ((legacy && dev.ver > 8) || (!legacy && dev.ver < 8)) continue;
            for (unsigned s = 0; s < 2; s++) for (unsigned n = 0; n < ARRAY_SIZE(sizes); n++) {
                unsigned buffers = sizes[n];
                const uint64_t used[] = {0, mask(buffers), buffers ? 1ull << (buffers - 1) : 0,
                    mask(buffers) & 0xaaaaaaaaaaaaaaaaull, mask(buffers) & 0x8000000080000001ull};
                for (unsigned rt = 0; rt <= 4; rt += rt ? 3 : 1)
                    for (unsigned pattern = 0; pattern < ARRAY_SIZE(used); pattern++) {
                        mesa_shader_stage stage = s ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX;
                        check_case(&dev, legacy, stage, buffers, used[pattern], false, rt, skip);
                        if (buffers && used[pattern]) check_case(&dev, legacy, stage, buffers, used[pattern], true, rt, skip);
                    }
            }
        }
    }
    glsl_type_singleton_decref();
    printf("Original Iris/Crocus BTI: %u source-donor/table/normalized-NIR cases, mode%s; CPU only\n",
        cases, skip ? "uncompacted" : "compact");
    return 0;
}
