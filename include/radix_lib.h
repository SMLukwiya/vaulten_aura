#ifndef AURA_RADIX_H
#define AURA_RADIX_H

/*---- RADIX VERSION 1 AKA Poor man's radix tree ----*/
/**
 * Offset based radix implementation, it sounds cute right!
 * but about 500 lines in, it became less cute real quick.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h> /** @todo: check if present in other unix variants */

typedef enum {
    A_RAX_NODE_TYPE_SPARSE = 1, /* Node type sparse */
    A_RAX_NODE_TYPE_DENSE = 2,  /* Node type dense */
    A_RAX_NODE_KEY = 4,
    A_RAX_NODE_LEAF = 8
} aura_rax_node_flags;

#define node_is_sparse(node) isset(&node->flags, 0)
#define node_is_dense(node) isset(&node->flags, 1)
#define node_is_key(node) isset(&node->flags, 2)
#define node_is_leaf(node) isset(&node->flags, 3)

#define set_node_is_key(node) setbit(&node->flags, 2)
#define clear_node_is_key(node) clrbit(&node->flags, 2)

#define RAX_OFFSET_ERROR UINT32_MAX
#define A_RAX_NIL_OFFSET UINT32_MAX

typedef enum {
    A_ITERATIVE,
    A_RECURSIVE
} a_rax_traversal_mode_t;

/* Rax value data types */
typedef enum {
    A_RAX_DATA_NONE,
    A_RAX_DATA_INT,
    A_RAX_DATA_FLOAT,
    A_RAX_DATA_PTR
} aura_rax_data_t;

/* Rax value structure */
typedef struct aura_rax_data {
    union {
        uint64_t int_val;
        void *ptr_val;
    };
    uint8_t type;
} aura_rax_data;

#define a_rax_data_init_none() \
    (aura_rax_data){           \
      .type = A_RAX_DATA_NONE, .int_val = 0}

/* init int value for insertion */
#define a_rax_data_init_int(data)               \
    (aura_rax_data) {                           \
        .type = A_RAX_DATA_INT, .int_val = data \
    }

/* init ptr value for insertion */
#define a_rax_data_init_ptr(data)               \
    (aura_rax_data) {                           \
        .type = A_RAX_DATA_PTR, .ptr_val = data \
    }

/* Rax Node structure */
typedef struct aura_rax_node {
    uint32_t prefix_off; /* offset in prefix string pool */
    uint16_t prefix_len; /* length of str */
    uint8_t num_of_ch;   /* number of valid children used to iteration */
    uint8_t flags;

    uint32_t parent_idx;  /* parent node idx */
    uint32_t sibling_idx; /* Next sibling in iterator order */
    /**
     * last slot in contiguous array for this nodes possible children
     * We waste (or not) some space upfront trying to dedicate slots
     * for this node's child, the hope being there are enough to
     * support cache friendliness
     */
    uint32_t reserved_slot_cnt;
    uint32_t nxt_reserved_idx;
    uint32_t node_lvl; /* node level in the tree, we could use it to determine how many slots to reserve */

    union {
        struct {
            uint8_t ch_entries[20];  /* each entry leads to the edge char a, b, c, d... */
            uint32_t ch_offsets[20]; /* offset into global rax array where the child node lives */
            // uint32_t first_ch;       /* First child for iteration */
        } sparse;
        struct {
            /**
             * Direct mapping character to offset in the radix array
             */
            uint8_t direct_ch[256];
            // uint32_t ch_list[256];
        } dense;
    } children;

    aura_rax_data data;
    /**
     * This holds the next slot in reserved slots for insertion
     * If node does not support slots as is the situation for all
     * non root nodes, it holds the index of the the node.
     * Default is iterative
     */
    bool in_reserved_slot : 1;
} aura_rax_node_t;

/**
 * Radix Tree structure
 */
typedef struct aura_rax_tree {
    aura_rax_node_t *nodes; /* array of nodes */
    char *prefix_pool;
    uint32_t node_cnt;
    uint32_t node_capacity;
    /**
     * points to the next slot where we can insert
     * there could be empty space before this index reserved
     * by individual nodes for themselves are their children
     */
    uint32_t next_node_insert_idx;
    uint32_t prefix_size;
    uint32_t prefix_used;
    uint32_t root_node_off;  /* Real tree root */
    uint32_t first_leaf_off; /* First leave for sequential access */
} aura_rax_tree_t;

/**/
typedef bool (*aura_rax_node_cb)(aura_rax_node_t *);

/**
 * Iterator structure
 */
typedef struct aura_rax_iterator {
    aura_rax_tree_t *tree;
    uint32_t curr_node_idx;
    uint32_t stack[48]; /* stack for DFS */
    int stack_depth;
    char key_buf[256];
    size_t key_len;
    bool started;
    /**
     * traversal mode, can be iterative or recursive,
     * recursive is particular useful for building a blob
     * tree for configs, currently not exposed to folks!
     */
    a_rax_traversal_mode_t t_mode;
    aura_rax_node_cb cb; /* Optional callback, used especially for buliding blob tree */
} aura_rax_iterator_t;

aura_rax_tree_t *aura_rax_new(void);
void aura_rax_free(aura_rax_tree_t *tree);
aura_rax_node_t *aura_rax_lookup(aura_rax_tree_t *tree, const char *key, size_t key_len);
bool aura_rax_insert(aura_rax_tree_t *tree, const char *key, size_t key_len, uint8_t flags, aura_rax_data data);
bool aura_rax_remove(aura_rax_tree_t *tree, const char *key, size_t key_len, aura_rax_data *data);
aura_rax_iterator_t aura_rax_iter_begin(aura_rax_tree_t *tree, aura_rax_node_cb cb);
void a_rax_node_dump(aura_rax_tree_t *t, aura_rax_node_t *node);

/**/
uint32_t aura_rax_prefix_find_offset(aura_rax_tree_t *t, const char *prefix, size_t len);

#endif