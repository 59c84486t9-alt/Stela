/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "rbtree_bind.h"
_Static_assert(sizeof(((struct rb_node *)0)->__rb_parent_color) == sizeof(void *), "parent must retain all pointer bits");
_Static_assert(sizeof(struct rb_node) == 3 * sizeof(void *), "node size");
_Static_assert(_Alignof(struct rb_node) == sizeof(void *), "node alignment");
_Static_assert(offsetof(struct rb_node, rb_right) == sizeof(void *), "right offset");
_Static_assert(offsetof(struct rb_node, rb_left) == 2 * sizeof(void *), "left offset");
const unsigned int stela_rb_layout[] = {
    sizeof(void *), sizeof(long), sizeof(((struct rb_node *)0)->__rb_parent_color),
    sizeof(struct rb_node), _Alignof(struct rb_node),
    offsetof(struct rb_node, rb_right), offsetof(struct rb_node, rb_left)
};
struct rb_node *stela_rb_parent(const struct rb_node *node) { return rb_parent(node); }
struct rb_node *stela_rb_parent_internal(const struct rb_node *node) { return __rb_parent(node->__rb_parent_color); }
void stela_rb_parent_store(struct rb_node *node, struct rb_node *parent) { rb_set_parent(node, parent); }
void stela_rb_parent_color_store(struct rb_node *node, struct rb_node *parent, int color) { rb_set_parent_color(node, parent, color); }
void stela_rb_clear(struct rb_node *node) { RB_CLEAR_NODE(node); }
bool stela_rb_empty(const struct rb_node *node) { return RB_EMPTY_NODE(node); }
void stela_rb_link(struct rb_node *node, struct rb_node *parent, struct rb_node **link) { rb_link_node(node, parent, link); }
