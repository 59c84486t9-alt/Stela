// SPDX-License-Identifier: MIT
#ifdef STELA_LINUX_RECLAIM_TEST
#include <linux/list_lru.h>
#include <stela/linux.h>
#include <stela/test.h>

struct entry {
	struct list_head node;
	enum lru_status result;
	unsigned int visits;
};

static enum lru_status visit(struct list_head *item, struct list_lru_one *list, void *argument)
{
	struct entry *entry = container_of(item, struct entry, node);

	entry->visits++;
	if (entry->result == LRU_REMOVED)
		list_lru_isolate_move(list, item, argument);
	if (entry->result == LRU_STOP)
		spin_unlock(&list->lock);
	return entry->result;
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);
	struct list_lru lru;
	struct entry skip = {.result = LRU_SKIP}, remove = {.result = LRU_REMOVED};
	struct entry stop = {.result = LRU_STOP}, last = {.result = LRU_REMOVED};
	LIST_HEAD(disposed);

	assert(!list_lru_init(&lru));
	INIT_LIST_HEAD(&skip.node);
	INIT_LIST_HEAD(&remove.node);
	INIT_LIST_HEAD(&stop.node);
	INIT_LIST_HEAD(&last.node);
	assert(list_lru_add(&lru, &skip.node, 0, NULL) && !list_lru_add(&lru, &skip.node, 0, NULL));
	assert(list_lru_add(&lru, &remove.node, 0, NULL));
	assert(list_lru_add(&lru, &stop.node, 0, NULL));
	assert(list_lru_add_obj(&lru, &last.node));
	assert(list_lru_del_obj(&lru, &last.node));
	assert(!list_lru_del_obj(&lru, &last.node));
	assert(list_lru_add_obj(&lru, &last.node));
	assert(list_lru_count_node(&lru, 0) == 4);

	/* The stop leaves what follows it; the bound stops a walk early. */
	unsigned long budget = 10;
	assert(list_lru_walk_one(&lru, 0, NULL, visit, &disposed, &budget) == 1 && budget == 7);
	assert(list_first_entry(&disposed, struct entry, node) == &remove && !last.visits);
	assert(list_lru_count_node(&lru, 0) == 3);
	budget = 1;
	assert(!list_lru_walk_node(&lru, 0, visit, &disposed, &budget) && !budget);
	assert(skip.visits == 2 && stop.visits == 1);
	list_lru_destroy(&lru);
	list_lru_destroy(&lru);

	stela_linux_exit();
	printf("Linux reclaim lists passed\n");
	return 0;
}
#endif
