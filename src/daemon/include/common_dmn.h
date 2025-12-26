#ifndef AURA_COMMON_DMN_H
#define AURA_COMMON_DMN_H

#include "blobber_lib.h"
#include "radix_lib.h"
#include "yaml_lib.h"
#include <stdint.h>
#include <stdio.h>

/*-------------- BUILD A BLOB FROM RAX STUFF --------------*/
/* Not quite sure where these functions should go for now! */

/** Keep track of each node pair and total count of nodes encountered */
struct node_stack {
    struct {
        uint32_t node_off;   /* current nodes offset (from tree structure) */
        uint32_t parent_off; /* current nodes parent (from tree structure) */
    } node_pair[48];
    uint32_t cnt; /* total node cnt <= 48 */
};

/** Keep track of container nodes that hold single nodes or other container nodes */
struct container_stack {
    struct {
        uint32_t node_off; /* current container node off for matching in node stack */
        uint32_t parent_off;
        uint32_t map_or_arr_node_off; /* map node off or arr node off (from blob structure) */
    } container[48];
    uint32_t cnt;
};

struct aura_builder_stack {
    struct node_stack ns;
    struct container_stack cs;
};

/** */
uint32_t aura_build_blob_from_rax(aura_rax_tree_t *t, st_aura_b_builder *b, struct aura_yml_node *node_arr, const char *prefix, size_t len, struct aura_builder_stack *stack, int *srv_conf_tab);
/** */
uint32_t a_rax_to_stack_builder(aura_rax_tree_t *t, st_aura_b_builder *b, struct aura_yml_node *node_arr, uint32_t node_idx, uint32_t parent_off, struct aura_builder_stack *stack, int *srv_conf_tab);

#endif