// SPDX-License-Identifier: MIT
/* Linux's sorts, with the interfaces of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 lib/sort.c and lib/list_sort.c: an
 * in-place, unstable heapsort of arrays and a stable merge sort of lists. */
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/sort.h>
#include <linux/string.h>

static void swap_bytes(void *a, void *b, int size)
{
	u8 *x = a, *y = b;

	while (size--) {
		u8 byte = *x;

		*x++ = *y;
		*y++ = byte;
	}
}

static void swap_elements(void *a, void *b, size_t size, swap_func_t swap_func)
{
	if (swap_func)
		swap_func(a, b, (int)size);
	else
		swap_bytes(a, b, (int)size);
}

/* Lets the element at root sink below its larger children in a heap of count
 * elements. */
static void sift_down(char *base, size_t root, size_t count, size_t size, cmp_func_t cmp_func,
		      swap_func_t swap_func)
{
	for (size_t child; (child = 2 * root + 1) < count; root = child) {
		if (child + 1 < count &&
		    cmp_func(base + child * size, base + (child + 1) * size) < 0)
			child++;
		if (cmp_func(base + root * size, base + child * size) >= 0)
			break;
		swap_elements(base + root * size, base + child * size, size, swap_func);
	}
}

void sort(void *base, size_t num, size_t size, cmp_func_t cmp_func, swap_func_t swap_func)
{
	for (size_t root = num / 2; root--;)
		sift_down(base, root, num, size, cmp_func, swap_func);
	for (size_t end = num; end > 1; end--) {
		swap_elements(base, (char *)base + (end - 1) * size, size, swap_func);
		sift_down(base, 0, end - 1, size, cmp_func, swap_func);
	}
}

/* Merges two sorted null-terminated chains linked by next, earlier a first. */
static struct list_head *merge(void *priv, list_cmp_func_t cmp, struct list_head *a,
			       struct list_head *b)
{
	struct list_head *head = NULL, **tail = &head;

	while (a && b) {
		struct list_head **least = cmp(priv, a, b) <= 0 ? &a : &b;

		*tail = *least;
		tail = &(*least)->next;
		*least = (*least)->next;
	}
	*tail = a ? a : b;
	return head;
}

/* Sorted chains of doubling length, as bottom-up merge sort keeps them. */
void list_sort(void *priv, struct list_head *head, list_cmp_func_t cmp)
{
	struct list_head *runs[BITS_PER_LONG] = {}, *list = head->next;

	if (list == head || list->next == head)
		return;
	head->prev->next = NULL;
	while (list) {
		struct list_head *run = list;
		unsigned int rank = 0;

		list = list->next;
		run->next = NULL;
		for (; runs[rank]; rank++) {
			run = merge(priv, cmp, runs[rank], run);
			runs[rank] = NULL;
		}
		runs[rank] = run;
	}
	for (unsigned int rank = 0; rank < ARRAY_SIZE(runs); rank++)
		if (runs[rank])
			list = merge(priv, cmp, runs[rank], list);

	/* Back to a circular list, with its prev links. */
	struct list_head *prev = head;

	for (head->next = list; list; prev = list, list = list->next)
		list->prev = prev;
	prev->next = head;
	head->prev = prev;
}

#ifdef STELA_LINUX_SORT_TEST
#include <stela/test.h>

struct item {
	struct list_head node;
	int key;
	int order;
};

static int compare_ints(const void *a, const void *b)
{
	return *(const int *)a - *(const int *)b;
}

static int compare_items(void *priv, const struct list_head *a, const struct list_head *b)
{
	(void)priv;
	return container_of(a, struct item, node)->key - container_of(b, struct item, node)->key;
}

int main(void)
{
	int values[] = {5, -1, 9, 3, 3, 0, 7, -8, 2};

	sort(values, ARRAY_SIZE(values), sizeof(*values), compare_ints, NULL);
	for (size_t i = 1; i < ARRAY_SIZE(values); i++)
		assert(values[i - 1] <= values[i]);
	sort(values, 0, sizeof(*values), compare_ints, NULL);

	struct item items[11];
	LIST_HEAD(list);

	list_sort(NULL, &list, compare_items);
	assert(list_empty(&list));
	for (int i = 0; i < 11; i++) {
		items[i] = (struct item){.key = (i * 7) % 3, .order = i};
		list_add_tail(&items[i].node, &list);
	}
	list_sort(NULL, &list, compare_items);
	unsigned int count = 0;
	const struct item *previous = NULL, *item;

	list_for_each_entry(item, &list, node) {
		assert(!previous || previous->key < item->key ||
		       (previous->key == item->key && previous->order < item->order));
		assert(!previous || item->node.prev == &previous->node);
		previous = item;
		count++;
	}
	assert(count == 11 && list.prev == &previous->node);
	printf("Linux's sorts passed\n");
	return 0;
}
#endif
