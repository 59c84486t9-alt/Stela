// SPDX-License-Identifier: MIT
/* Linux's reclaim bookkeeping, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 mm/list_lru.c and mm/shrinker.c.
 * Stela's memory owners have no reclaim to run, so a shrinker is never
 * called, and one node holds every list. */
#include <linux/list_lru.h>
#include <linux/shrinker.h>
#include <linux/slab.h>

int __list_lru_init(struct list_lru *lru, bool memcg_aware, struct shrinker *shrinker)
{
	(void)memcg_aware;
	(void)shrinker;
	lru->node = kzalloc_obj(*lru->node);
	if (!lru->node)
		return -ENOMEM;
	spin_lock_init(&lru->node->lru.lock);
	INIT_LIST_HEAD(&lru->node->lru.list);
	return 0;
}

void list_lru_destroy(struct list_lru *lru)
{
	if (!lru->node)
		return;
	kfree(lru->node);
	lru->node = NULL;
}

bool list_lru_add(struct list_lru *lru, struct list_head *item, int nid, struct mem_cgroup *memcg)
{
	(void)nid;
	(void)memcg;
	struct list_lru_one *list = &lru->node->lru;
	bool added = false;

	spin_lock(&list->lock);
	if (list_empty(item)) {
		list_add_tail(item, &list->list);
		list->nr_items++;
		added = true;
	}
	spin_unlock(&list->lock);
	return added;
}

void list_lru_isolate(struct list_lru_one *list, struct list_head *item)
{
	list_del_init(item);
	list->nr_items--;
}

void list_lru_isolate_move(struct list_lru_one *list, struct list_head *item,
			   struct list_head *head)
{
	list_move(item, head);
	list->nr_items--;
}

unsigned long list_lru_count_node(struct list_lru *lru, int nid)
{
	(void)nid;
	return (unsigned long)lru->node->lru.nr_items;
}

/* LRU_ROTATE moves the item to the tail and LRU_SKIP leaves it; a walker that
 * dropped the lock (LRU_RETRY, LRU_REMOVED_RETRY) restarts the list. */
unsigned long list_lru_walk_node(struct list_lru *lru, int nid, list_lru_walk_cb isolate,
				 void *cb_arg, unsigned long *nr_to_walk)
{
	(void)nid;
	struct list_lru_one *list = &lru->node->lru;
	struct list_head *item, *next;
	unsigned long isolated = 0;

	spin_lock(&list->lock);
restart:
	list_for_each_safe(item, next, &list->list) {
		if (!*nr_to_walk)
			break;
		--*nr_to_walk;
		switch (isolate(item, list, cb_arg)) {
		case LRU_REMOVED_RETRY:
			isolated++;
			fallthrough;
		case LRU_RETRY:
			goto restart;
		case LRU_REMOVED:
			isolated++;
			break;
		case LRU_ROTATE:
			list_move_tail(item, &list->list);
			break;
		case LRU_SKIP:
			break;
		case LRU_STOP:
			goto done;
		}
	}
done:
	spin_unlock(&list->lock);
	return isolated;
}

struct shrinker *shrinker_alloc(unsigned int flags, const char *fmt, ...)
{
	struct shrinker *shrinker = kzalloc_obj(*shrinker);

	(void)fmt;
	if (shrinker)
		shrinker->flags = flags;
	return shrinker;
}

void shrinker_register(struct shrinker *shrinker)
{
	shrinker->flags |= SHRINKER_REGISTERED;
}

void shrinker_free(struct shrinker *shrinker)
{
	kfree(shrinker);
}

#ifdef STELA_LINUX_RECLAIM_TEST
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
	assert(list_lru_add(&lru, &last.node, 0, NULL));
	assert(list_lru_count_node(&lru, 0) == 4);

	/* The stop leaves what follows it; the bound stops a walk early. */
	unsigned long budget = 10;
	assert(list_lru_walk_node(&lru, 0, visit, &disposed, &budget) == 1 && budget == 7);
	assert(list_first_entry(&disposed, struct entry, node) == &remove && !last.visits);
	assert(list_lru_count_node(&lru, 0) == 3);
	budget = 1;
	assert(!list_lru_walk_node(&lru, 0, visit, &disposed, &budget) && !budget);
	assert(skip.visits == 2 && stop.visits == 1);
	list_lru_destroy(&lru);
	list_lru_destroy(&lru);

	struct shrinker *shrinker = shrinker_alloc(SHRINKER_NUMA_AWARE, "test");
	assert(shrinker);
	shrinker_register(shrinker);
	assert(shrinker->flags & SHRINKER_REGISTERED);
	shrinker_free(shrinker);
	stela_linux_exit();
	printf("Linux reclaim lists passed\n");
	return 0;
}
#endif
