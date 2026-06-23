#ifndef AURA_BLOBBER_H
#define AURA_BLOBBER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "compiler_lib.h"

typedef enum {
    A_BLOB_NODE_STR,
    A_BLOB_NODE_INT,
    A_BLOB_NODE_UINT,
    A_BLOB_NODE_BOOL,
    A_BLOB_NODE_MAP,
    A_BLOB_NODE_ARR
} aura_blob_type_t;

/* Blob structure */
typedef struct aura_blob_hdr {
    uint32_t magic;
    uint32_t version;
    uint32_t kv_cnt;
    uint32_t arr_cnt;
    uint32_t node_cnt;
    uint32_t str_len;
    uint32_t size;
    uint32_t data_offset;
    uint32_t opaque_data_offset;
    uint32_t opaque_data_len;
    uint32_t tab_offset;
    uint32_t tab_len;
} st_aura_blob_hdr;

/* Blob node structure */
typedef struct aura_blob_node {
    uint32_t type;
    union {
        uint32_t str_offset;
        struct {
            uint32_t kv_idx;
            uint32_t kv_cnt;
            uint8_t initialized;
        } map;
        struct {
            uint32_t arr_idx;
            uint32_t arr_cnt;
            uint8_t initialized;
        } arr;
    };
} st_aura_blob_node;

typedef struct aura_blob_kv_pair {
    uint32_t key_offset;
    uint32_t node_idx;
} st_aura_blob_kv_pair;

typedef struct aura_blob_arr_entry {
    uint32_t node_idx;
} st_aura_blob_arr_entry;

typedef struct aura_blob_builder {
    /* dynamic array of nodes */
    struct aura_blob_node *nodes;
    size_t nodes_cap, nodes_len;

    /* key value pairs */
    struct aura_blob_kv_pair *kvs;
    size_t kvs_cap, kvs_len;

    /* array entries */
    struct aura_blob_arr_entry *arrs;
    size_t arrs_cap, arrs_len;

    /* string buf */
    char *str_buf;
    size_t str_cap, str_len;

    bool initialized;
} st_aura_b_builder;

/**
 * A way of passing blob args around
 */
typedef struct aura_blob_param {
    const st_aura_blob_node *nodes;
    const st_aura_blob_kv_pair *kv_pairs;
    const st_aura_blob_arr_entry *arrs;
    const char *strtab;
} aura_blob_param_st;

/**
 *
 */
void aura_blob_builder_init(st_aura_b_builder *b);
void aura_blob_free(st_aura_b_builder *b);
uint32_t aura_blob_b_add_str(st_aura_b_builder *b, const char *str);
uint32_t aura_blob_b_add_num(st_aura_b_builder *b, uint64_t num, aura_blob_type_t t);
uint32_t aura_blob_b_add_map(st_aura_b_builder *b);
uint32_t aura_blob_b_map_add_kv(st_aura_b_builder *b, uint32_t map_idx, const char *key, uint32_t val_node);
uint32_t aura_blob_b_add_array(st_aura_b_builder *b);
uint32_t aura_blob_b_arr_push(st_aura_b_builder *b, uint32_t arr_idx, uint32_t val_node);
void *aura_serialize_blob(st_aura_b_builder *b, int *table, size_t tab_len, void *opaque, size_t opaque_len);
void aura_dump_blob(const void *base);
uint32_t aura_blob_get_size(const void *base);
const st_aura_blob_node *aura_blob_get_nodes(const void *base);
const st_aura_blob_kv_pair *aura_blob_get_kvs(const void *base);
const st_aura_blob_arr_entry *aura_blob_get_arrs(const void *base);
const char *aura_blob_get_strtab(const void *base);
const int *aura_blob_get_tab(const void *base);

/**
 * Check if we have user data attached to this blob
 */
static inline bool aura_blob_has_opaque_data(const void *base) {
    const st_aura_blob_hdr *hdr;

    hdr = (const st_aura_blob_hdr *)base;
    if (likely(hdr->opaque_data_len > 0 && hdr->opaque_data_offset < hdr->tab_offset))
        return true;

    return false;
}

/**
 * Get attached user data size
 */
static inline size_t aura_blob_get_opaque_data_len(const void *base) {
    const st_aura_blob_hdr *hdr;

    hdr = (const st_aura_blob_hdr *)base;
    return hdr->opaque_data_len;
}

/**
 * Retrieve attached user data
 */
static inline const void *aura_blob_get_opaque_data(const void *base) {
    const st_aura_blob_hdr *hdr;
    uint64_t opaque_off;

    hdr = (const st_aura_blob_hdr *)base;
    opaque_off = hdr->opaque_data_offset;
    if (hdr->opaque_data_len == 0)
        return NULL;

    return (const void *)((char *)base + opaque_off);
}

#endif