#include "common_dmn.h"
#include "error_lib.h"

/*-------------- BUILD A BLOB FROM RAX STUFF --------------*/
/* Not quite sure where these functions should go for now! */

/**
 * This is as crude as it gets over here!!
 */
uint32_t a_rax_to_stack_builder(aura_rax_tree_t *t, st_aura_b_builder *b, struct aura_yml_node *node_arr, uint32_t node_idx, uint32_t parent_off, struct aura_builder_stack *stack, int *conf_tab) {
    aura_rax_node_t *node;
    struct aura_yml_node *yn;
    uint32_t container_off, ch_idx, node_off = 0;

    node = &t->nodes[node_idx];

    if (node->data.type == A_RAX_DATA_INT) {
        /**
         * We push everything to the stack, storing
         * the node offset and parent offset within the
         * us_ctx->node_arr, this should contain all the parsed
         * info from the yaml
         */
        node_off = node->data.int_val;
        yn = &node_arr[node_off];
        stack->ns.node_pair[stack->ns.cnt].node_off = node_off;
        stack->ns.node_pair[stack->ns.cnt].parent_off = parent_off;
        stack->ns.cnt++;

        /**
         * We create the root nodes as we go down the tree,
         * This is so we can know the start offset upfront,
         * otherwise it would be a pain to get another way
         */
        if (yn->type == A_YAML_MAPPING || yn->type == A_YAML_SEQUENCE) {
            if (yn->type == A_YAML_SEQUENCE)
                container_off = aura_blob_b_add_array(b);
            else
                container_off = aura_blob_b_add_map(b);

            /* 0 idx is preserved */
            if (yn->tab_entry != 0) {
                conf_tab[yn->tab_entry] = container_off;
            }

            stack->cs.container[stack->cs.cnt].map_or_arr_node_off = container_off;
            stack->cs.container[stack->cs.cnt].node_off = node_off;
            stack->cs.container[stack->cs.cnt].parent_off = parent_off;
            stack->cs.cnt++;
        }
        if (node->num_of_ch == 0)
            return container_off;
    } else {
        /**
         * If the node is not of the int type,
         * node_off would be zero and that would break
         * the chain of configs, so handle this. We keep
         * the parent_off across such nodes
         */
        node_off = parent_off;
    }

    if (node_is_sparse(node)) {
        for (int i = 0; i < node->num_of_ch; ++i) {
            ch_idx = node->children.sparse.ch_offsets[i];
            a_rax_to_stack_builder(t, b, node_arr, ch_idx, node_off, stack, conf_tab);
        }
    }

    return container_off;
}

/**
 *
 */
uint32_t aura_build_blob_from_rax(aura_rax_tree_t *t, st_aura_b_builder *b, struct aura_yml_node *node_arr, const char *prefix, size_t len, struct aura_builder_stack *stack, int *conf_tab) {
    uint32_t root_off, start_off, node_off, parent_off;
    struct aura_yml_node *yn, *par_yn;
    int res;

    stack->cs.cnt = 0;
    stack->ns.cnt = 0;

    memset(stack, 0, sizeof(*stack));
    start_off = aura_rax_prefix_find_offset(t, prefix, len);
    if (start_off == A_RAX_NIL_OFFSET)
        return 0;

    root_off = a_rax_to_stack_builder(t, b, node_arr, start_off, UINT32_MAX, stack, conf_tab);

    /**
     * We iterate from the last stack entry moving backwards,
     * This is so we can add the scalars in a depth first way.
     */
    for (int i = stack->ns.cnt - 1; i >= 0; --i) {
        node_off = stack->ns.node_pair[i].node_off;
        parent_off = stack->ns.node_pair[i].parent_off;
        par_yn = &node_arr[node_off];

        if (par_yn->type == A_YAML_MAPPING || par_yn->type == A_YAML_SEQUENCE) {
            uint32_t val_off, arr_or_map_off;
            int scalar_cnt = 0;

            /**
             * Let's find the map or arr node_off we created from the recursive fn.
             * This would be the parent that contains this scalars we
             * shall add
             */
            for (int k = 0; k < stack->cs.cnt; ++k) {
                if (stack->cs.container[k].node_off == node_off) {
                    arr_or_map_off = stack->cs.container[k].map_or_arr_node_off;
                    break;
                }
            }

            /**
             * These scalars seen so far would be the children of a mapping or a
             * sequence. So when we encounter the first non scalar, we know we
             * can insert those!
             */
            for (int j = i + 1; j < stack->ns.cnt; ++j) {
                scalar_cnt++;
                yn = &node_arr[stack->ns.node_pair[j].node_off];

                if (yn->type == A_YAML_SCALAR) {
                    if (yn->val_type == A_YAML_NUM)
                        val_off = aura_blob_b_add_num(b, yn->uint_val, A_BLOB_NODE_INT);
                    else if (yn->val_type == A_YAML_STRING)
                        val_off = aura_blob_b_add_str(b, yn->str_val);

                    /* 0 idx is preserved */
                    if (yn->tab_entry != 0) {
                        conf_tab[yn->tab_entry] = val_off;
                    }
                    if (par_yn->type == A_YAML_MAPPING)
                        aura_blob_b_map_add_kv(b, arr_or_map_off, yn->key, val_off);
                    else
                        aura_blob_b_arr_push(b, arr_or_map_off, val_off);
                }
            }

            /**
             * Since we build our blob depth first, child structures would
             * be formed first, therefore, for every non scalar, we also
             * check if it has nested structures that we can add.
             */
            for (int j = 0; j < stack->cs.cnt; ++j) {
                if (node_off == stack->cs.container[j].parent_off) {
                    yn = &node_arr[stack->cs.container[j].node_off];

                    if (par_yn->type == A_YAML_MAPPING)
                        aura_blob_b_map_add_kv(b, arr_or_map_off, yn->key, stack->cs.container[j].map_or_arr_node_off);
                    else
                        aura_blob_b_arr_push(b, arr_or_map_off, stack->cs.container[j].map_or_arr_node_off);
                }
            }

            /**
             * Reduce the scan size on every iteration as we
             * add things to the blob
             */
            stack->ns.cnt -= scalar_cnt + 1;
        }
    }
    return root_off;
}