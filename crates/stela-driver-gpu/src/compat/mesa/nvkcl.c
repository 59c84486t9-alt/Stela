// SPDX-License-Identifier: MIT
#include "nvkcl.h"

#include "cl/nvk_copy_indirect.h"
#include "nir_builder.h"
#include "nv_push.h"
#include "nv_push_cl90b5.h"
#include "vulkan/vulkan_core.h"

/* Both kernels run one invocation per item, 32 to a workgroup; each compares
 * this with its item count before doing anything. */
static nir_def *item_index(nir_builder *b)
{
	nir_def *group = nir_channel(b, nir_load_workgroup_id(b), 0);
	return nir_iadd(b, nir_load_subgroup_invocation(b), nir_imul_imm(b, group, 32));
}

/* `vk_write_query`: element `index` of the destination, at the width `flags` asks. */
static void write_query(nir_builder *b, nir_def *destination, nir_def *index, nir_def *flags,
			nir_def *value)
{
	nir_push_if(b, nir_test_mask(b, flags, VK_QUERY_RESULT_64_BIT));
	nir_store_global(b, value,
			 nir_iadd(b, destination, nir_u2u64(b, nir_imul_imm(b, index, 8))));
	nir_push_else(b, NULL);
	nir_store_global(b, nir_u2u32(b, value),
			 nir_iadd(b, destination, nir_u2u64(b, nir_imul_imm(b, index, 4))));
	nir_pop_if(b, NULL);
}

void nvk_copy_queries(nir_builder *b, nir_def *pool_addr, nir_def *available_stride,
		      nir_def *reports_start, nir_def *report_count, nir_def *query_stride,
		      nir_def *first_query, nir_def *query_count, nir_def *dst_addr,
		      nir_def *dst_stride, nir_def *flags)
{
	nir_def *i = item_index(b);
	nir_push_if(b, nir_ult(b, i, query_count));

	nir_def *query = nir_u2u64(b, nir_iadd(b, first_query, i));
	nir_def *available_at =
		nir_iadd(b, pool_addr, nir_imul(b, query, nir_u2u64(b, available_stride)));
	nir_def *available = nir_ine_imm(b, nir_load_global(b, 1, 32, available_at), 0);
	nir_def *reports =
		nir_iadd(b, nir_iadd(b, pool_addr, nir_u2u64(b, reports_start)),
			 nir_imul(b, query, nir_u2u64(b, query_stride)));
	nir_def *destination = nir_iadd(b, dst_addr, nir_imul(b, dst_stride, nir_u2u64(b, i)));

	nir_push_if(b, nir_ior(b, available, nir_test_mask(b, flags, VK_QUERY_RESULT_PARTIAL_BIT)));
	nir_variable *report = nir_local_variable_create(b->impl, glsl_uint_type(), "report");
	nir_store_var(b, report, nir_imm_int(b, 0), 1);
	nir_push_loop(b);
	{
		nir_def *r = nir_load_var(b, report);
		nir_break_if(b, nir_uge(b, r, report_count));
		/* Each report is a value and a timestamp, of 8 bytes each. */
		nir_def *at = nir_iadd(b, reports, nir_u2u64(b, nir_imul_imm(b, r, 16)));
		write_query(b, destination, r, flags, nir_load_global(b, 1, 64, at));
		nir_store_var(b, report, nir_iadd_imm(b, r, 1), 1);
	}
	nir_pop_loop(b, NULL);
	nir_pop_if(b, NULL);

	nir_push_if(b, nir_test_mask(b, flags, VK_QUERY_RESULT_WITH_AVAILABILITY_BIT));
	write_query(b, destination, report_count, flags, nir_b2i64(b, available));
	nir_pop_if(b, NULL);

	nir_pop_if(b, NULL);
}

void nvk_copy_indirect(nir_builder *b, nir_def *in, nir_def *in_stride, nir_def *out,
		       nir_def *count)
{
	/* VkCopyMemoryIndirectCommandKHR. */
	enum { SOURCE = 0, DESTINATION = 8, SIZE = 16 };
	/* What the kernel pushes, with the fields that vary at zero. Their words
	 * are the three addresses' and the size's, by the methods' order. */
	uint32_t words[NVK_COPY_INDIRECT_CMD_WORDS];
	enum { SOURCE_HIGH = 1, SOURCE_LOW, DESTINATION_HIGH, DESTINATION_LOW, LENGTH = 6 };
	struct nv_push push;
	struct nv_push *p = &push;
	nv_push_init(p, words, ARRAY_SIZE(words), BITFIELD_BIT(SUBC_NV90B5));
	P_MTHD(p, NV90B5, OFFSET_IN_UPPER);
	P_NV90B5_OFFSET_IN_UPPER(p, 0);
	P_NV90B5_OFFSET_IN_LOWER(p, 0);
	P_NV90B5_OFFSET_OUT_UPPER(p, 0);
	P_NV90B5_OFFSET_OUT_LOWER(p, 0);
	P_MTHD(p, NV90B5, LINE_LENGTH_IN);
	P_NV90B5_LINE_LENGTH_IN(p, 0);
	P_IMMD_WORD(p, NV90B5, LAUNCH_DMA, {
		.data_transfer_type = DATA_TRANSFER_TYPE_PIPELINED,
		.multi_line_enable = MULTI_LINE_ENABLE_FALSE,
		.flush_enable = FLUSH_ENABLE_TRUE,
		.src_memory_layout = SRC_MEMORY_LAYOUT_PITCH,
		.dst_memory_layout = DST_MEMORY_LAYOUT_PITCH,
		.remap_enable = REMAP_ENABLE_FALSE,
	});
	assert(nv_push_dw_count(p) == NVK_COPY_INDIRECT_CMD_WORDS);

	nir_def *i = item_index(b);
	nir_push_if(b, nir_ult(b, i, count));
	nir_def *index = nir_u2u64(b, i);
	nir_def *command = nir_iadd(b, in, nir_imul(b, index, nir_u2u64(b, in_stride)));
	nir_def *source = nir_load_global(b, 1, 64, nir_iadd_imm(b, command, SOURCE));
	nir_def *target = nir_load_global(b, 1, 64, nir_iadd_imm(b, command, DESTINATION));
	nir_def *size = nir_load_global(b, 1, 32, nir_iadd_imm(b, command, SIZE));

	nir_def *values[NVK_COPY_INDIRECT_CMD_WORDS] = {
		[SOURCE_HIGH] = nir_unpack_64_2x32_split_y(b, source),
		[SOURCE_LOW] = nir_unpack_64_2x32_split_x(b, source),
		[DESTINATION_HIGH] = nir_unpack_64_2x32_split_y(b, target),
		[DESTINATION_LOW] = nir_unpack_64_2x32_split_x(b, target),
		[LENGTH] = size,
	};
	nir_def *record = nir_iadd(b, out, nir_imul_imm(b, index, NVK_COPY_INDIRECT_CMD_BYTES));
	for (unsigned word = 0; word < NVK_COPY_INDIRECT_CMD_WORDS; word++) {
		nir_def *value = values[word] ? values[word] : nir_imm_int(b, words[word]);
		nir_store_global(b, value, nir_iadd_imm(b, record, word * 4));
	}
	nir_pop_if(b, NULL);
}
