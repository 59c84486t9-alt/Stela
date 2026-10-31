// SPDX-License-Identifier: MIT
/* Memory the owner holds, as a dma-buf a driver imports like any other. Linux
 * has no pages for it, so a mapping is only device addresses, which is all an
 * importer may read of one. */
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <stela/file.h>

struct exported {
	size_t count;
	struct stela_linux_run runs[] __counted_by(count);
};

static void unmap_entries(struct device *dev, struct sg_table *table, unsigned int count,
			  enum dma_data_direction direction)
{
	struct scatterlist *entry;
	unsigned int index;

	for_each_sgtable_dma_sg(table, entry, index) {
		if (index == count)
			break;
		dma_unmap_phys(dev, sg_dma_address(entry), sg_dma_len(entry), direction, 0);
	}
}

static struct sg_table *map_exported(struct dma_buf_attachment *attachment,
				     enum dma_data_direction direction)
{
	const struct exported *memory = attachment->dmabuf->priv;
	struct device *dev = attachment->dev;
	struct sg_table *table = kzalloc(sizeof(*table), GFP_KERNEL);
	struct scatterlist *entry;
	unsigned int index;

	if (!table)
		return ERR_PTR(-ENOMEM);
	if (sg_alloc_table(table, (unsigned int)memory->count, GFP_KERNEL)) {
		kfree(table);
		return ERR_PTR(-ENOMEM);
	}
	for_each_sgtable_dma_sg(table, entry, index) {
		const struct stela_linux_run *run = &memory->runs[index];
		dma_addr_t address = dma_map_phys(dev, run->physical, run->bytes, direction, 0);

		if (dma_mapping_error(dev, address)) {
			unmap_entries(dev, table, index, direction);
			sg_free_table(table);
			kfree(table);
			return ERR_PTR(-ENOMEM);
		}
		sg_dma_address(entry) = address;
		sg_dma_len(entry) = (unsigned int)run->bytes;
	}
	return table;
}

static void unmap_exported(struct dma_buf_attachment *attachment, struct sg_table *table,
			   enum dma_data_direction direction)
{
	unmap_entries(attachment->dev, table, table->nents, direction);
	sg_free_table(table);
	kfree(table);
}

static void release_exported(struct dma_buf *buffer)
{
	kfree(buffer->priv);
}

static const struct dma_buf_ops exported_ops = {
	.map_dma_buf = map_exported,
	.unmap_dma_buf = unmap_exported,
	.release = release_exported,
};

int stela_linux_export(const struct stela_linux_run *runs, size_t count)
{
	DEFINE_DMA_BUF_EXPORT_INFO(info);
	struct exported *memory = kmalloc(struct_size(memory, runs, count), GFP_KERNEL);
	struct dma_buf *buffer;
	size_t bytes = 0;
	int fd;

	if (!memory)
		return -ENOMEM;
	memory->count = count;
	for (size_t index = 0; index < count; index++) {
		memory->runs[index] = runs[index];
		bytes += runs[index].bytes;
	}
	info.ops = &exported_ops;
	info.size = bytes;
	info.flags = O_RDWR;
	info.priv = memory;
	buffer = dma_buf_export(&info);
	if (IS_ERR(buffer)) {
		kfree(memory);
		return (int)PTR_ERR(buffer);
	}
	/* The buffer's release frees the memory from here on. */
	fd = dma_buf_fd(buffer, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(buffer);
	return fd;
}
