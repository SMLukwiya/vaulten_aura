#include "error_lib.h"
#include "radix_lib.h"
#include "utils_lib.h"

/**
 * Dumping Stuff
 */
void a_rax_node_dump(aura_rax_tree_t *t, aura_rax_node_t *node) {
    char buf[4096];
    snprintf(buf, node->prefix_len != 0 ? node->prefix_len + 1 : sizeof("Root"), "%s", node->prefix_len != 0 ? &t->prefix_pool[node->prefix_off] : "Root");

    app_debug(true, 0, "AURA RAX NODE:");
    app_debug(true, 0, "   key -> '%s'", buf);
    app_debug(true, 0, "   flags -> %u", node->flags);
    app_debug(true, 0, "   node is key -> %s", node_is_key(node) ? "Yes" : "no");
    app_debug(true, 0, "   node Level -> %u", node->node_lvl);
    app_debug(true, 0, "   num of chd -> %u", node->num_of_ch);
    app_debug(true, 0, "   parent idx -> %u", node->parent_idx);
    app_debug(true, 0, "   sibling idx -> %u", node->sibling_idx);
    app_debug(true, 0, "   prefix offset -> %u", node->prefix_off);
    app_debug(true, 0, "   prefix len -> %u", node->prefix_len);
    app_debug(true, 0, "   rsrved slot cnt -> %u", node->reserved_slot_cnt);
    app_debug(true, 0, "   next rsrved idx -> %u", node->nxt_reserved_idx);
    app_debug(true, 0, "   node in rsrved slot -> %s", node->in_reserved_slot ? "Yes" : "No");
    app_debug(true, 0, "   Value type: %d", node->data.type);
}

void a_dump_rax_tree(aura_rax_tree_t *t) {
    app_debug(true, 0, "AURA_TREE");
    app_debug(true, 0, "  Root offset: %d", t->root_node_off);
    app_debug(true, 0, "  Capacity: %d", t->node_capacity);
    app_debug(true, 0, "  Count: %d", t->node_cnt);
    app_debug(true, 0, "  Node Array: %p", t->nodes);
    app_debug(true, 0, "  Prefix pool: %p", t->prefix_pool);
    app_debug(true, 0, "  Prefix size: %d", t->prefix_size);
    app_debug(true, 0, "  Prefix used: %d", t->prefix_used);
    app_debug(true, 0, "  Nxt insert idx: %d", t->next_node_insert_idx);
    app_debug(true, 0, "  First leaf off: %d", t->first_leaf_off);
}

void a_dump_node_children(aura_rax_node_t *node) {
    for (int i = 0; i < node->num_of_ch; ++i)
        if (node_is_dense(node))
            app_debug(true, 0, "dump-> ch dense -> %c", node->children.dense.direct_ch[i]);
        else if (node_is_sparse(node))
            app_debug(true, 0, "dump-> ch sparse -> %c", node->children.sparse.ch_entries[i]);
}

/**
 *
 */
#define a_node_idx_from_ptr(t, ptr) (((void *)(ptr) - (void *)(t->nodes)) / sizeof(aura_rax_node_t))

/**
 * Returns the next index for a new node in the tree
 * expanding the tree if space was unavailable.
 * Use the new tree nodes array after calling this function
 * since the nodea array pointer could have moved due to realloc.
 */
static uint32_t aura_new_rax_node(aura_rax_tree_t *t, uint32_t reserved_cnt) {
    /* keep old values and restore on failed reallocation */
    void *old_nodes = t->nodes;
    uint32_t old_capacity = t->node_capacity;

    if ((t->next_node_insert_idx + reserved_cnt) >= t->node_capacity) {
        /* grow array taking into account reserved slots for that node */
        while ((t->next_node_insert_idx + reserved_cnt) >= t->node_capacity)
            t->node_capacity = t->node_capacity > 0 ? t->node_capacity * 2 + reserved_cnt : 1;
        t->nodes = realloc((void *)t->nodes, t->node_capacity * sizeof(aura_rax_node_t));
        if (!t->nodes) {
            t->nodes = old_nodes;
            t->node_capacity = old_capacity;
            return RAX_OFFSET_ERROR;
        }
    }

    uint32_t ret_idx;
    t->node_cnt++;

    ret_idx = t->next_node_insert_idx;
    /* next insert index is 1(for the curr node) + the reserved slots for its children */
    t->next_node_insert_idx += reserved_cnt + 1;

    /* we return the next point we can safely insert */
    return ret_idx;
}

/**
 * Create a new rax tree returning a pointer to it
 * Reserve slot 0 in the nodes array for the root
 * node allocated with with a no flags (dense or sparse)
 * We need to set the capacity before creating the first
 * node, so we don't use 0 as the initial capacity
 */
aura_rax_tree_t *aura_rax_new(void) {
    aura_rax_tree_t *t;
    uint32_t root_idx;

    t = malloc(sizeof(*t));
    if (!t)
        return NULL;
    memset((void *)t, 0, sizeof(*t));

    t->prefix_pool = malloc(128);
    if (!t->prefix_pool)
        return NULL;

    root_idx = aura_new_rax_node(t, 0);
    if (root_idx == RAX_OFFSET_ERROR)
        return NULL;
    t->prefix_size = 128;
    t->prefix_used = 0;
    t->root_node_off = root_idx;
    memset(&t->nodes[root_idx], 0, sizeof(aura_rax_node_t));
    return t;
}

void aura_rax_free(aura_rax_tree_t *t) {
    if (!t)
        return;

    free(t->prefix_pool);
    free(t->nodes);
    free(t);
}

/**
 * We treat root node as a container holder, so it has no node type
 * So we just search for the start index for the actual tree we want
 */
static inline uint32_t a_find_start_offset(aura_rax_tree_t *t, uint8_t c) {
    aura_rax_node_t *root = &t->nodes[t->root_node_off];

    for (int i = 0; i < root->num_of_ch; ++i) {
        if (root->children.dense.direct_ch[c] == c)
            /* direct mapping found, follow this node */
            return root->children.dense.direct_ch[c];

        /* we try and get the start node in the sparse list */
        if (root->children.sparse.ch_entries[i] == c)
            return root->children.sparse.ch_offsets[i];
    }

    return A_RAX_NIL_OFFSET;
}

/**
 *
 */
static inline uint32_t a_find_child_offset(aura_rax_node_t *node, uint8_t c) {
    int i;

    if (node_is_dense(node)) {
        if (c == 0) {
            /* If c=0, we just need the first child that is valid */
            for (i = 0; i < ARRAY_SIZE(node->children.dense.direct_ch); ++i) {
                if (node->children.dense.direct_ch[i] != 0)
                    return node->children.dense.direct_ch[i];
            }
        }
        /* direct mapping, would return 0 if no match */
        return node->children.dense.direct_ch[c];
    } else if (node_is_sparse(node)) {
        for (int i = 0; i < node->num_of_ch; ++i) {
            if (c == 0 && node->children.sparse.ch_entries[i] != 0) {
                /* Just get the first valid child */
                return node->children.sparse.ch_offsets[i];
            }
            if (node->children.sparse.ch_entries[i] == c)
                return node->children.sparse.ch_offsets[i];
        }
    }

    return RAX_OFFSET_ERROR;
}

/**
 *
 */
static inline void a_remove_child(aura_rax_node_t *n, uint8_t c) {
    int i;
    bool found = false;

    if (node_is_dense(n)) {
        n->children.dense.direct_ch[c] = 0;
    } else if (node_is_sparse(n)) {
        for (i = 0; i < n->num_of_ch; ++i) {
            if (n->children.sparse.ch_entries[i] == c)
                found = true;
            /**
             * compact the remaining keys shifting everything
             * after the deleted key one position down
             */
            if (found && i < n->num_of_ch - 1) {
                n->children.sparse.ch_entries[i] = n->children.sparse.ch_entries[i + 1];
                n->children.sparse.ch_offsets[i] = n->children.sparse.ch_offsets[i + 1];
            }
        }
        n->num_of_ch--;
    }
}

/**
 *
 */
static inline size_t a_find_common_prefix_len(aura_rax_tree_t *t, uint32_t node_off, const char *key, size_t key_len) {
    size_t prefix_len = 0, cmp_len;
    const char *prefix_pool = t->prefix_pool;
    aura_rax_node_t *node = &t->nodes[node_off];
    uint32_t offset = node->prefix_off;

    cmp_len = a_min(node->prefix_len, key_len);

    while (prefix_len <= cmp_len && prefix_pool[offset++] == key[prefix_len++])
        ;
    return prefix_len - 1;
}

/**
 *
 */
static inline uint32_t a_store_node_prefix(aura_rax_tree_t *t, uint32_t node_idx, const char *key, size_t key_len, bool is_split) {
    uint32_t offset;
    aura_rax_node_t *parent_node;

    /**
     * When we split, say we have parent key as 'diznutz'
     * If we are split at diz, we should have something like
     *                 (diz)
     *                 /   \
     *                /     \
     *             (nutz)  (new_to_be_added)
     * We just update the parent prefix len to construct 'diz'
     * and we make the new child node assume the offset of 'nutz'
     * so we dont have to use new space in the prefix pool.
     */
    if (is_split) {
        parent_node = &t->nodes[node_idx];
        offset = parent_node->prefix_off + (parent_node->prefix_len - key_len);
        /* update the parent prefix len to reflect the new update */
        parent_node->prefix_len -= key_len;
        return offset;
    }

    /* preserve old values incase we error on reallocation */
    void *old_pool = t->prefix_pool;
    uint32_t old_sz = t->prefix_size;

    if (t->prefix_used + key_len > t->prefix_size) {
        /* allocate new area */
        t->prefix_size *= 2;
        t->prefix_pool = realloc(t->prefix_pool, t->prefix_size);
        if (!t->prefix_pool) {
            t->prefix_pool = old_pool;
            t->prefix_size = old_sz;
            return RAX_OFFSET_ERROR;
        }
    }
    offset = t->prefix_used;
    void *p = memcpy(t->prefix_pool + offset, key, key_len);
    t->prefix_used += key_len;

    return offset;
}

/**
 *
 */
static inline void a_clear_prefix_from_pool(aura_rax_tree_t *t, uint32_t prefix_off, uint32_t len) {
    memset(&t->prefix_pool[prefix_off], 0, len);
}

/**
 *
 */
static inline void a_set_rax_node_value(aura_rax_node_t *n, struct aura_rax_data data) {
    n->data = data;
}

static inline struct aura_rax_data a_get_rax_node_value(aura_rax_node_t *n) {
    return n->data;
}

static inline bool a_node_is_global_root_node(aura_rax_node_t *n) {
    return (n->node_lvl == 0);
}

static inline bool a_node_is_start_node(aura_rax_node_t *n) {
    return (n->node_lvl == 1);
}

static inline bool a_data_is_empty(aura_rax_data data) {
    return data.type == A_RAX_DATA_NONE;
}

/**
 *
 */
void copy_clear_children(aura_rax_tree_t *t, aura_rax_node_t *dest, aura_rax_node_t *src) {
    uint32_t node_idx;

    for (int i = 0; i < src->num_of_ch; ++i)
        if (node_is_dense(src)) {
            dest->children.dense.direct_ch[i] = src->children.dense.direct_ch[i];
            src->children.dense.direct_ch[i] = 0;
        } else if (node_is_sparse(src)) {
            node_idx = src->children.sparse.ch_offsets[i];
            dest->children.sparse.ch_entries[i] = src->children.sparse.ch_entries[i];
            dest->children.sparse.ch_offsets[i] = node_idx;
            /**
             * Update the children parent index to point
             * to the node to which they are being moved to.
             */
            t->nodes[node_idx].parent_idx = a_node_idx_from_ptr(t, dest);
            src->children.sparse.ch_entries[i] = 0;
            src->children.sparse.ch_offsets[i] = 0;
        }
    /* update the children count */
    dest->num_of_ch = src->num_of_ch;
}

/**
 * Generic procedure to create a child, receives:
 * @p_node_idx -> as the parent node index for the new child being created
 * @key and @key_len -> for the new child key
 * @flags -> for the child flags
 * @is_split -> whether we are splitting the parent node or appending a completely new node
 * returns the 'offset' of the just create child in the global array
 */
uint32_t a_create_child_rax_node(
  aura_rax_tree_t *t,
  uint32_t p_node_idx,
  const char *key,
  size_t key_len,
  uint8_t flags,
  bool is_split) {
    aura_rax_node_t *new_node, *p_node, *root_node;
    uint32_t new_node_idx;
    uint32_t prefix_off;
    uint8_t new_char = *key;
    uint32_t reserved_slots = 0;
    bool in_reserved_slot = false;

    p_node = &t->nodes[p_node_idx];
    prefix_off = a_store_node_prefix(t, p_node_idx, key, key_len, is_split);
    if (prefix_off == RAX_OFFSET_ERROR)
        return RAX_OFFSET_ERROR;

    /**
     * Check if we have reserved slots in the root node
     * associated with key, allocate from there and decrease count,
     * If available, the space will be the ones immediately
     * after the parent index
     */
    root_node = p_node;
    while (!a_node_is_global_root_node(root_node) && !a_node_is_start_node(root_node)) {
        uint32_t idx = root_node->parent_idx;
        root_node = &t->nodes[idx];
    }

    if (root_node->reserved_slot_cnt > 0) {
        new_node_idx = root_node->nxt_reserved_idx;
        in_reserved_slot = true;
        root_node->nxt_reserved_idx++;
        root_node->reserved_slot_cnt--;
    } else {
        /**
         * ** Experimental **
         * preserve 5 slots for each root
         */
        reserved_slots = p_node->node_lvl == 0 ? 5 : 0;
        new_node_idx = aura_new_rax_node(t, reserved_slots);
        /* re-acquire parent node incase it moved */
        p_node = &t->nodes[p_node_idx];
    }
    if (new_node_idx == RAX_OFFSET_ERROR)
        return RAX_OFFSET_ERROR;

    new_node = (aura_rax_node_t *)&t->nodes[new_node_idx];
    memset(new_node, 0, sizeof(aura_rax_node_t));
    new_node->flags = flags;
    new_node->prefix_off = prefix_off;
    new_node->prefix_len = key_len;
    new_node->parent_idx = p_node_idx;
    new_node->node_lvl = p_node->node_lvl + 1;
    new_node->reserved_slot_cnt = reserved_slots;
    new_node->in_reserved_slot = in_reserved_slot;
    /* if root node, then it would have reserved slots, otherwise no slots */
    new_node->nxt_reserved_idx = new_node_idx + (!in_reserved_slot && reserved_slots > 0 ? 1 : 0);

    if (is_split) {
        /**
         * If splitting, since the way we split is barbaric,
         * the created new node should inherit the children of
         * the parent, if original key was something like:
         * api.v1.users, if we split at users, we end up with
         * api.v1-->users, now if say split at v1 again, we should end up with
         * api-->v1-->users, v1 has to inherit the children
         * of the original key api.v1, and the new parent api now points to
         * v1, so the original chain is maintained.
         */
        copy_clear_children(t, new_node, p_node);
        /* update new node to be key based on parent */
        if (node_is_key(p_node)) {
            set_node_is_key(new_node);
            clear_node_is_key(p_node);
        }

        /* copy over value if exists */
        if (p_node->data.type != A_RAX_DATA_NONE) {
            a_set_rax_node_value(new_node, p_node->data);
            a_set_rax_node_value(p_node, a_rax_data_init_none());
        }
        p_node->num_of_ch = 0;
    }

    if (node_is_dense(new_node)) {
        p_node->children.dense.direct_ch[new_char] = new_node_idx;
        p_node->num_of_ch++;
    } else if (node_is_sparse(new_node)) {
        p_node->children.sparse.ch_entries[p_node->num_of_ch] = new_char;
        p_node->children.sparse.ch_offsets[p_node->num_of_ch] = new_node_idx;
        p_node->num_of_ch++;
    }

    return new_node_idx;
}

/**
 * Splits the parent key into two parts, for parent and for child,
 * creates a new child node with the child's key and adds
 * as a child of the parent node.
 */
static inline uint32_t split_node(aura_rax_tree_t *t, uint32_t node_idx, uint8_t flags, size_t common_prefix_len) {
    aura_rax_node_t *node = &t->nodes[node_idx];
    char *prefix = &t->prefix_pool[node->prefix_off];
    char *new_key = prefix + common_prefix_len;

    return a_create_child_rax_node(t, node_idx, new_key, node->prefix_len - common_prefix_len, flags, true);
}

/**
 *
 */
bool aura_rax_insert(aura_rax_tree_t *t, const char *key, size_t key_len, uint8_t flags, aura_rax_data data) {
    uint32_t node_idx, new_node_idx, ch_node_idx, root_node_idx = 0;
    aura_rax_node_t *node;
    size_t key_pos, common_prefix_len;

    if (!t || !key || key_len == 0)
        return false;

    node_idx = a_find_start_offset(t, key[0]);

    if (node_idx == A_RAX_NIL_OFFSET) {
        /* new root to insert */
        new_node_idx = a_create_child_rax_node(t, root_node_idx, key, key_len, flags | A_RAX_NODE_KEY, false);
        if (new_node_idx == RAX_OFFSET_ERROR)
            return false;

        if (!a_data_is_empty(data))
            a_set_rax_node_value(&t->nodes[new_node_idx], data);

        return true;
    } else {
        key_pos = 0;

        while (key_pos < key_len && node_idx != 0) {
            node = &t->nodes[node_idx];
            // a_dump_rax_node(t, node);

            common_prefix_len = a_find_common_prefix_len(t, node_idx, &key[key_pos], key_len - key_pos);
            if (common_prefix_len < node->prefix_len) {
                /* split node */
                new_node_idx = split_node(t, node_idx, flags, common_prefix_len);
                if (new_node_idx == RAX_OFFSET_ERROR)
                    /* error splitting node */
                    return false;

                /* node may have moved due to reallocation, so we acquire it again */
                node = &t->nodes[node_idx];
            }

            key_pos += common_prefix_len;
            if (key_pos >= key_len) {
                /**
                 * new key added was part of the existing node,
                 * no need to go any further, we simply mark as a key
                 * and update the value associated with the key!
                 */
                set_node_is_key(node);
                if (!a_data_is_empty(data))
                    a_set_rax_node_value(node, data);

                return true;
            }

            /**
             * We check if new key has a starting node within the
             * current list of child nodes for the current node
             */
            uint8_t next_char = (uint8_t)key[key_pos];
            ch_node_idx = a_find_child_offset(node, next_char);
            if (ch_node_idx == RAX_OFFSET_ERROR) {
                /* no child node associated with next char, so we create one */
                ch_node_idx = a_create_child_rax_node(t, node_idx, &key[key_pos], key_len - key_pos, flags | A_RAX_NODE_KEY, false);
                if (ch_node_idx == RAX_OFFSET_ERROR)
                    return false;
                if (!a_data_is_empty(data))
                    a_set_rax_node_value(&t->nodes[ch_node_idx], data);

                return true;
            }

            /**
             * We have a child node associated with next_char, so we move to it
             * pushing the key_pos to point to first character of this found node
             * and try the process again
             */
            node_idx = ch_node_idx;
        }
    }
    /**
     * We failed
     * Ohhh Sh!!!!t
     */
    return false;
}

/**
 *  Internal lookup helper
 */
static inline uint32_t a_lookup(aura_rax_tree_t *t, uint32_t node_idx, const char *key, size_t key_len) {
    aura_rax_node_t *node;
    size_t key_pos;
    size_t cmp_len;
    const char *prefix;
    char nxt_char;

    key_pos = 0;
    while (key_pos < key_len) {
        node = &t->nodes[node_idx];

        if (node->prefix_len > 0) {
            prefix = &t->prefix_pool[node->prefix_off];

            /**
             * Get the shorter of the two keys to compare
             */
            cmp_len = a_min(key_len - key_pos, node->prefix_len);

            /* We try and match the compare length and see if we get a match */
            if (memcmp(&key[key_pos], prefix, cmp_len) != 0)
                return A_RAX_NIL_OFFSET; /* no match */

            /**
             * We have so far matched the compare length correctly.
             * If prefix_len is greater than key_len, we could not
             * possibly match
             */
            if (node->prefix_len > key_len - key_pos)
                return A_RAX_NIL_OFFSET;

            /**
             * We update the key position in our key
             */
            key_pos += node->prefix_len;
            if (key_pos >= key_len)
                return node_idx;

            nxt_char = (uint8_t)key[key_pos];
            node_idx = a_find_child_offset(node, nxt_char);
            if (node_idx == RAX_OFFSET_ERROR) {
                /* no value */
                return A_RAX_NIL_OFFSET;
            }
            /* debug */
            char buf[256];
            snprintf(buf, t->nodes[node_idx].prefix_len + 1, "%s", &t->prefix_pool[t->nodes[node_idx].prefix_off]);
            // app_debug(true, 0, "--> looking up next char %c from node %s", nxt_char, buf);
        }
    }

    return A_RAX_NIL_OFFSET;
}

/**
 *
 */
aura_rax_node_t *aura_rax_lookup(aura_rax_tree_t *t, const char *key, size_t key_len) {
    aura_rax_node_t *node;
    uint32_t node_idx;
    size_t cmp_len;
    size_t key_pos = 0;
    const char *prefix;
    char nxt_char;

    if (!t || !key || key_len == 0)
        return NULL;

    node_idx = a_find_start_offset(t, key[0]);
    if (node_idx == A_RAX_NIL_OFFSET)
        return NULL;

    node_idx = a_lookup(t, node_idx, key, key_len);

    if (node_idx != A_RAX_NIL_OFFSET) {
        node = &t->nodes[node_idx];
        if (node_is_key(node))
            return node;
    }

    return NULL;
}

/**
 *
 */
bool merge_triple(aura_rax_tree_t *t, aura_rax_node_t *node1, aura_rax_node_t *node2, aura_rax_node_t *node3) {
    uint32_t p_idx, prefix_offset;
    size_t key_len;
    bool are_prefixes_contiguous;

    are_prefixes_contiguous = node1->prefix_off + node1->prefix_len == node2->prefix_off && node2->prefix_off + node2->prefix_len == node3->prefix_off;
    if (are_prefixes_contiguous) {
        /**
         * We just update the length and maintain
         * the offset as is.
         */
        node1->prefix_len += node2->prefix_len + node3->prefix_len;
    } else {
        /**
         * We need to create a new entry in the pool
         * for the new combined key
         */
        key_len = node1->prefix_len + node2->prefix_len + node3->prefix_len;

        char buf[key_len];
        strncpy(buf, &t->prefix_pool[node1->prefix_off], node1->prefix_len);
        strncpy(buf + strlen(buf), &t->prefix_pool[node2->prefix_off], node2->prefix_len);
        strncpy(buf + strlen(buf), &t->prefix_pool[node3->prefix_off], node3->prefix_len);

        /* the node_idx doesn't matter here since we are creating new key area */
        prefix_offset = a_store_node_prefix(t, 0, buf, key_len, false);
        if (prefix_offset == RAX_OFFSET_ERROR)
            return false;
        /* clear old prefixes from pool */
        a_clear_prefix_from_pool(t, node1->prefix_off, node1->prefix_len);
        a_clear_prefix_from_pool(t, node2->prefix_off, node2->prefix_len);
        a_clear_prefix_from_pool(t, node3->prefix_off, node3->prefix_len);

        /* update to new values */
        node1->prefix_len = key_len;
        node1->prefix_off = prefix_offset;
    }

    /**
     * child node could have multiple children or not
     * We just blindly copy them over to the parent node
     */
    copy_clear_children(t, node1, node3);

    /**
     * Let's delete the child and current node
     */
    memset(node2, 0, sizeof(aura_rax_node_t));
    memset(node3, 0, sizeof(aura_rax_node_t));

    /**
     * Let's check if the ch_node and node indexes we deleted are within the
     * reserved slots of its root node,
     * If so, We would need to reach the root node and update
     * reserved slot related stuff.
     */
    if (node3->in_reserved_slot || node2->in_reserved_slot) {
        /**
         * We may already be at the root node, so the while loop
         * won't run, as such, we need to keep the p_idx for the next check.
         */
        // p_idx = a_node_idx_from_ptr(t, node);
        while (!a_node_is_start_node(node1)) {
            p_idx = node1->parent_idx;
            node1 = &t->nodes[p_idx];
        }

        if (node2->in_reserved_slot) {
            node1->reserved_slot_cnt++;
            node1->nxt_reserved_idx = a_node_idx_from_ptr(t, node3);
        }
        if (node3->in_reserved_slot) {
            node1->reserved_slot_cnt++;
            node1->nxt_reserved_idx = a_node_idx_from_ptr(t, node2);
        }
    }
    return true;
}

/**
 *
 */
bool merge_double(aura_rax_tree_t *t, aura_rax_node_t *node1, aura_rax_node_t *node2) {
    uint32_t node_idx, prefix_offset;
    size_t key_len;

    if (node1->prefix_off + node1->prefix_len == node2->prefix_off) {
        /**
         * let's check if the parent and child keys sit contiguous
         * in the prefix pool,  if so, we won't need to create a new
         * slot to hold the merged key, we don't need to update the
         * offset in this case
         */
        node1->prefix_len += node2->prefix_len;
    } else {
        /**
         * Keys are not contiguous, we just create the merged key to
         * insert into prefix pool
         */
        key_len = node1->prefix_len + node2->prefix_len;
        char buf[key_len];

        strncpy(buf, &t->prefix_pool[node1->prefix_off], node1->prefix_len);
        strncpy(buf + strlen(buf), &t->prefix_pool[node2->prefix_off], node2->prefix_len);

        /* the node_idx doesn't matter here since we are creating new key area */
        prefix_offset = a_store_node_prefix(t, 0, buf, key_len, false);
        if (prefix_offset == RAX_OFFSET_ERROR)
            return false;
        /* clear old prefixes from pool */
        a_clear_prefix_from_pool(t, node1->prefix_off, node1->prefix_len);
        a_clear_prefix_from_pool(t, node2->prefix_off, node2->prefix_len);

        /* update to new values */
        node1->prefix_len = key_len;
        node1->prefix_off = prefix_offset;
    }

    /**
     * child node could have multiple children or not
     * We just blindly copy them over to the current node
     */
    copy_clear_children(t, node1, node2);

    /**
     * Let's delete the child node now
     */
    memset(node2, 0, sizeof(aura_rax_node_t));

    /**
     * Let's check if the node2 index we deleted is within the
     * reserved slots of its root node,
     * If so, We would need to reach the root node and update
     * reserved slot related stuff.
     */
    if (node2->in_reserved_slot) {
        /**
         * We may already be at the root node, so the while loop
         * won't run, as such, we need to keep the p_idx for the next check.
         * The use of p_idx here may be confusing since it would normally
         * refer to the parent, but it works here because we
         * are look for the  point of view.
         */
        node_idx = a_node_idx_from_ptr(t, node1);
        while (!a_node_is_start_node(node1)) {
            node_idx = node1->parent_idx;
            node1 = &t->nodes[node_idx];
        }
        node1->reserved_slot_cnt++;
        node1->nxt_reserved_idx = a_node_idx_from_ptr(t, node2);
    }

    return true;
}

/**/
static inline bool is_parent_mergable(aura_rax_node_t *n) {
    return (n->num_of_ch == 1 && !node_is_key(n) && !a_node_is_global_root_node(n));
}

/**/
static inline bool is_current_node_mergable(aura_rax_node_t *n) {
    return (n->num_of_ch <= 1 && !node_is_key(n));
}

/**
 * This is because we can merge the current node to a parent
 * if it's not a key even if it has multiple children
 */
static inline bool is_current_node_mergable_to_parent(aura_rax_node_t *n) {
    return (!node_is_key(n));
}

/**/
static inline bool is_child_node_mergable(aura_rax_node_t *n) {
    return !node_is_key(n);
}

/**
 *
 */
bool aura_rax_remove(aura_rax_tree_t *t, const char *key, size_t key_len, aura_rax_data *node_data) {
    aura_rax_node_t *node, *p_node, *ch_node;
    size_t new_len;
    uint32_t prefix_offset, p_idx, ch_idx;
    bool parent_mergeable = false, curr_mergeable = false, curr_mergeable_to_par = false, ch_mergable = false;

    if (!t || !key || key_len == 0)
        return false;

    node = aura_rax_lookup(t, key, key_len); /** @todo: make this use a_lookup */
    if (!node)
        return false;

    clear_node_is_key(node);

    /**
     * If we need a reference to the data
     * held by the node, we can get it
     */
    if (node_data)
        *node_data = a_get_rax_node_value(node);

    /**
     * Handle the case where the child has no children first
     */
    p_idx = node->parent_idx;
    p_node = &t->nodes[p_idx];

    if (node->num_of_ch == 0) {
        t->node_cnt--;
        /* remove the child that would lead to the deleted node */
        a_remove_child(p_node, t->prefix_pool[node->prefix_off]);

        /**
         * We are about to delete current node
         * We check if it's a root node, then this would
         * have been the last key on the tree rooted at this node
         * In this case we simply clear it, since there would be
         * nothing to process(merge...etc)!
         */
        if (a_node_is_start_node(node)) {
            memset(node, 0, sizeof(aura_rax_node_t));
            return true;
        }

        /* same check to see if node was within reserved slots */
        if (node->in_reserved_slot) {
            while (!a_node_is_start_node(p_node)) {
                p_idx = p_node->parent_idx;
                p_node = &t->nodes[p_idx];
            }

            p_node->reserved_slot_cnt++;
            p_node->nxt_reserved_idx = a_node_idx_from_ptr(t, node);
        }

        /**
         * We need to revert back to the original parent
         * to do some more processing
         */
        p_idx = node->parent_idx;
        p_node = &t->nodes[p_idx];
        /* we can now clear current node since we won't use it anymore */
        memset(node, 0, sizeof(aura_rax_node_t));

        /**
         * We can make the node = p_node, since we are trying to
         * see if the new chain after deletion can ne merged.
         * Let's see if the parent node has a single child remaining
         * that would benefit from merging
         * In this section, we are working exclusively with p_node
         * and ch_node
         */
        node = p_node;
        p_node = &t->nodes[node->parent_idx];
        parent_mergeable = is_parent_mergable(p_node);
        curr_mergeable = is_current_node_mergable(node);
        curr_mergeable_to_par = is_current_node_mergable_to_parent(node);

        if (curr_mergeable && node->num_of_ch == 1) {
            ch_idx = a_find_child_offset(node, 0);
            if (ch_idx == RAX_OFFSET_ERROR) {
                ch_mergable = false;
            } else {
                ch_node = &t->nodes[ch_idx];
                ch_mergable = is_child_node_mergable(ch_node);
            }
        }

        if (!parent_mergeable && (!curr_mergeable || !ch_mergable)) {
            // a_dump_rax_node(t, node);
            return true;
        }

        if (parent_mergeable && curr_mergeable && ch_mergable) {
            // a_dump_rax_node(t, p_node);
            // a_dump_rax_node(t, node);
            // a_dump_rax_node(t, ch_node);
            return merge_triple(t, p_node, node, ch_node);
        }

        if (curr_mergeable && ch_mergable) {
            // a_dump_rax_node(t, node);
            // a_dump_rax_node(t, ch_node);
            return merge_double(t, node, ch_node);
        }

        if (parent_mergeable && curr_mergeable) {
            // a_dump_rax_node(t, p_node);
            // a_dump_rax_node(t, node);
            return merge_double(t, p_node, node);
        }

        /**
         * curr node is not mergeable, but parent and
         * child may be mergeable
         */
        return true;
    }

    /**
     * We check mergeability (not a real word I think!!)
     * of the current node, parent node
     */
    curr_mergeable = is_current_node_mergable(node);

    // p_idx = node->parent_idx;
    // p_node = &t->nodes[p_idx];
    parent_mergeable = is_parent_mergable(p_node);

    /* Let's determine child's mergability */
    if (node->num_of_ch == 1) {
        ch_idx = a_find_child_offset(node, 0);
        if (ch_idx == RAX_OFFSET_ERROR) {
            ch_mergable = false;
        } else {
            ch_node = &t->nodes[ch_idx];
            ch_mergable = is_child_node_mergable(ch_node);
        }
    }

    /**
     * If both parent and child can't be merged to current node, we return early.
     */
    if ((!parent_mergeable && !curr_mergeable) || (!parent_mergeable && !ch_mergable)) {
        // a_dump_rax_node(t, node);
        return true;
    }

    /**
     * Let's check if both parent and child can be merged
     * If this is true, we check for a list of things:
     * - are all the fixes contiguous, if not we merge and create a new slot in pool
     * - if the node's child has children, we copy it directly to node's parent
     * - since we shall be deleting two nodes, we check and update reserved slots
     */
    if (parent_mergeable && curr_mergeable && ch_mergable) {
        // a_dump_rax_node(t, p_node);
        // a_dump_rax_node(t, node);
        // a_dump_rax_node(t, ch_node);
        return merge_triple(t, p_node, node, ch_node);
    }

    /**
     * If the node has one child, we check if the parent and child are a key
     * If both are keys we do not merge
     * If either or all of them are not keys, we can merge them
     */
    if (curr_mergeable && ch_mergable) {
        // a_dump_rax_node(t, node);
        // a_dump_rax_node(t, ch_node);
        return merge_double(t, node, ch_node);
    }

    if (parent_mergeable && curr_mergeable) {
        // a_dump_rax_node(t, p_node);
        // a_dump_rax_node(t, node);
        return merge_double(t, p_node, node);
    }

    /**
     * curr node is not mergeable, but parent and
     * child may be mergeable
     */
    return true;
}

/*-----------ITERATOR STUFF-----------*/
/**
 *
 */
aura_rax_iterator_t aura_rax_iter_begin(aura_rax_tree_t *t, aura_rax_node_cb cb) {
    aura_rax_iterator_t it = {
      .tree = t,
      .curr_node_idx = t->root_node_off,
      .stack_depth = -1,
      .started = false,
      .key_len = 0,
      .cb = cb,
      .t_mode = 0,
    };

    it.stack[++it.stack_depth] = t->root_node_off;
    return it;
}

/**
 *
 */
bool aura_rax_prefix_iter_next(aura_rax_iterator_t *it, const char *prefix, size_t len) {
    uint32_t node_idx;
    size_t key_pos;

    if (!it->started) {
        it->curr_node_idx = a_find_start_offset(it->tree, prefix[0]);
        if (it->curr_node_idx == A_RAX_NIL_OFFSET)
            return false;
        it->started = true;
    }

    /* keep the old index incase of error, @todo: Do I need to?? */
    node_idx = a_lookup(it->tree, it->curr_node_idx, prefix, len);
    if (node_idx == A_RAX_NIL_OFFSET)
        return false;

    it->curr_node_idx = node_idx;
    return true;
}

static inline void append_prefix_to_key(aura_rax_iterator_t *it, uint32_t node_idx) {}

static inline void a_push_to_stack(aura_rax_iterator_t *it, uint32_t node_idx) {
    aura_rax_node_t *node;
    uint32_t ch_idx;

    node = &it->tree->nodes[node_idx];
    if (node_is_dense(node)) {
        /* Push dense kids in reverse order */
        for (int i = 255; i >= 0; --i) {
            if (node->children.dense.direct_ch[i] != 0) {
                ch_idx = node->children.dense.direct_ch[i];

                if (it->key_len < sizeof(it->key_buf) - 1) {
                    it->key_buf[it->key_len++] = (char)i;

                    /* Add prefix if this is the first node */
                    if (it->stack_depth == -1) {
                        append_prefix_to_key(it, node_idx);
                    }
                }
                it->stack[++it->stack_depth] = ch_idx;
            }
        }
    } else if (node_is_sparse(node)) {
        for (int i = 0; i < node->num_of_ch; ++i) {
            ch_idx = node->children.sparse.ch_offsets[i];
            char ch_char = node->children.sparse.ch_entries[i];

            if (it->key_len < sizeof(it->key_buf) - 1) {
                it->key_buf[it->key_len] = (char)ch_char;

                if (it->stack_depth == 1)
                    append_prefix_to_key(it, node_idx);
            }
        }
        if (it->stack_depth >= 0)
            it->key_len++;
    }
}

/**
 * @todo: incomplete
 */
bool aura_rax_iter_next(aura_rax_iterator_t *it, const char **key, size_t *key_len, void **value) {
    aura_rax_node_t *node;
    uint32_t node_idx;

    if (it->stack_depth < 0)
        return false;

    while (it->stack_depth >= 0) {
        node_idx = it->stack[it->stack_depth--];
        node = &it->tree->nodes[node_idx];

        a_push_to_stack(it, node_idx);
    }
}

/**
 *
 */
uint32_t aura_rax_prefix_find_offset(aura_rax_tree_t *t, const char *prefix, size_t len) {
    aura_rax_node_t *node;
    uint32_t start_idx, node_idx;
    size_t key_pos;

    start_idx = a_find_start_offset(t, prefix[0]);
    if (start_idx == A_RAX_NIL_OFFSET)
        return A_RAX_NIL_OFFSET;

    node_idx = a_lookup(t, start_idx, prefix, len);
    if (node_idx == A_RAX_NIL_OFFSET)
        return A_RAX_NIL_OFFSET;

    return node_idx;
}