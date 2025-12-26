#include "blobber_lib.h"

void aura_blob_builder_init(st_aura_b_builder *b) {
    memset(b, 0, sizeof(*b));
    b->initialized = true;
}

void aura_blob_free(st_aura_b_builder *b) {
    if (!b)
        return;

    if (b->arrs)
        free(b->arrs);
    if (b->kvs)
        free(b->kvs);
    if (b->nodes)
        free(b->nodes);
    if (b->str_buf)
        free(b->str_buf);
    b->initialized = false;
}

/**
 *
 */
static inline size_t a_ensure_str_buf(st_aura_b_builder *b, size_t len) {
    uint32_t old_cap;
    char *old_buf;

    old_cap = b->str_cap;
    old_buf = b->str_buf;
    if (b->str_len + len > b->str_cap) {
        b->str_cap = b->str_cap ? b->str_cap * 2 : 1024;
        while (b->str_len + len > b->str_cap)
            b->str_cap *= 2;

        b->str_buf = realloc(b->str_buf, b->str_cap);
        /* restore old values */
        if (!b->str_buf) {
            b->str_buf = old_buf;
            b->str_cap = old_cap;
            return SIZE_MAX;
        }
    }
    return b->str_len;
}

/**
 *
 */
static inline uint32_t a_blob_b_add_str(st_aura_b_builder *b, const char *str) {
    size_t len;
    uint32_t off;
    size_t res;

    len = strlen(str) + 1; /** @todo: check if I need null termination */
    res = a_ensure_str_buf(b, len);
    if (res == SIZE_MAX)
        return UINT32_MAX;

    off = (uint32_t)b->str_len;
    memcpy(b->str_buf + b->str_len, str, len);
    b->str_len += len;
    return off;
}

/**
 *
 */
static inline size_t a_ensure_nodes(st_aura_b_builder *b, size_t len) {
    uint32_t old_cap;
    st_aura_blob_node *old_node;

    old_cap = b->nodes_cap;
    old_node = b->nodes;
    if (b->nodes_len + len > b->nodes_cap) {
        b->nodes_cap = b->nodes_cap ? b->nodes_cap * 2 : 16;
        while (b->nodes_len + len > b->nodes_cap)
            b->nodes_cap *= 2;

        b->nodes = realloc(b->nodes, b->nodes_cap * sizeof(st_aura_blob_node));
        /* restore old values */
        if (!b->nodes) {
            b->nodes = old_node;
            b->nodes_cap = old_cap;
            return SIZE_MAX;
        }
    }
    return b->nodes_len;
}

/* returns node idx */
uint32_t aura_blob_b_add_str(st_aura_b_builder *b, const char *str) {
    uint32_t idx;
    size_t res;

    res = a_ensure_nodes(b, 1);
    if (res == SIZE_MAX)
        return UINT32_MAX;

    idx = (uint32_t)b->nodes_len++;

    memset(&b->nodes[idx], 0, sizeof(st_aura_blob_node));
    b->nodes[idx].type = A_BLOB_NODE_STR;
    res = a_blob_b_add_str(b, str);
    if (res == UINT32_MAX)
        return UINT32_MAX;

    b->nodes[idx].str_offset = res;
    return idx;
}

uint32_t aura_blob_b_add_num(st_aura_b_builder *b, uint64_t num, aura_blob_type_t t) {
    uint32_t idx;
    size_t res;
    char buf[65];

    res = a_ensure_nodes(b, 1);
    if (res == SIZE_MAX)
        return UINT32_MAX;

    snprintf(buf, sizeof(buf), "%lu", num);
    idx = (uint32_t)b->nodes_len++;

    memset(&b->nodes[idx], 0, sizeof(st_aura_blob_node));
    b->nodes[idx].type = t;
    res = a_blob_b_add_str(b, buf);
    if (res == UINT32_MAX)
        return UINT32_MAX;

    b->nodes[idx].str_offset = res;
    return idx;
}

/**
 *
 */
uint32_t aura_blob_b_add_map(st_aura_b_builder *b) {
    uint32_t idx;
    size_t res;

    res = a_ensure_nodes(b, 1);
    if (res == SIZE_MAX)
        return UINT32_MAX;

    idx = b->nodes_len++;
    memset(&b->nodes[idx], 0, sizeof(st_aura_blob_node));
    b->nodes[idx].type = A_BLOB_NODE_MAP;
    /**
     * We initialize the index just as a placeholder, the
     * true value is created when inserting the first entry
     * into the map
     */
    b->nodes[idx].map.kv_idx = (uint32_t)b->kvs_len;
    b->nodes[idx].map.kv_cnt = 0;
    return idx;
}

/**
 *
 */
static inline size_t a_ensure_kvs(st_aura_b_builder *b, size_t len) {
    uint32_t old_cap;
    st_aura_blob_kv_pair *old_kvs;

    old_cap = b->kvs_cap;
    old_kvs = b->kvs;
    if (b->kvs_len + len > b->kvs_cap) {
        b->kvs_cap = b->kvs_cap ? b->kvs_cap * 2 : 16;
        while (b->kvs_len + len > b->kvs_cap)
            b->kvs_cap *= 2;

        b->kvs = realloc(b->kvs, b->kvs_cap * sizeof(st_aura_blob_kv_pair));
        /* restore old values */
        if (!b->kvs) {
            b->kvs = old_kvs;
            b->kvs_cap = old_cap;
            return SIZE_MAX;
        }
    }
    return b->kvs_len;
}

/**
 *
 */
uint32_t aura_blob_b_map_add_kv(st_aura_b_builder *b, uint32_t map_idx, const char *key, uint32_t val_node) {
    uint32_t key_off;
    size_t res;

    res = a_ensure_kvs(b, 1);
    if (res == SIZE_MAX)
        return UINT32_MAX;

    key_off = a_blob_b_add_str(b, key);
    if (key_off == UINT32_MAX)
        return UINT32_MAX;

    /**
     * We initialize the index when inserting the first kv pair
     * This makes the blobber not so stagnant!, where we can create
     * a node(map or arr) at any point and insert into it at a
     * later point and it would still work, check 'aura_blob_b_add_map'
     */
    if (b->nodes[map_idx].map.initialized == 0) {
        b->nodes[map_idx].map.kv_idx = b->kvs_len;
        b->nodes[map_idx].map.initialized = 1;
    }
    b->kvs[b->kvs_len].key_offset = key_off;
    b->kvs[b->kvs_len].node_idx = val_node;
    b->kvs_len++;
    return b->nodes[map_idx].map.kv_cnt++;
}

/**
 *
 */
static inline size_t a_ensure_arr(st_aura_b_builder *b, size_t len) {
    uint32_t old_cap;
    st_aura_blob_arr_entry *old_arr;

    old_cap = b->arrs_cap;
    old_arr = b->arrs;
    if (b->arrs_len + len > b->arrs_cap) {
        b->arrs_cap = b->arrs_cap ? b->arrs_cap * 2 : 16;
        while (b->arrs_len + len > b->arrs_cap)
            b->arrs_cap *= 2;

        b->arrs = realloc(b->arrs, b->arrs_cap * sizeof(st_aura_blob_arr_entry));
        /* restore old values */
        if (!b->arrs) {
            b->arrs = old_arr;
            b->arrs_cap = old_cap;
            return SIZE_MAX;
        }
    }
    return b->arrs_len;
}

/**
 *
 */
uint32_t aura_blob_b_add_array(st_aura_b_builder *b) {
    uint32_t idx;
    size_t res;

    res = a_ensure_nodes(b, 1);
    if (res == SIZE_MAX)
        return UINT32_MAX;

    /**
     * We initialize the index with a placeholder, the
     * true value is created when inserting the first entry
     * into the arr (see the insertion funcs)
     */
    idx = b->nodes_len++;
    memset(&b->nodes[idx], 0, sizeof(st_aura_blob_node));
    b->nodes[idx].type = A_BLOB_NODE_ARR;
    b->nodes[idx].arr.arr_idx = (uint32_t)b->arrs_len;
    b->nodes[idx].arr.arr_cnt = 0;
    return idx;
}

/**
 *
 */
uint32_t aura_blob_b_arr_push(st_aura_b_builder *b, uint32_t arr_idx, uint32_t val_node) {
    size_t res;

    res = a_ensure_arr(b, 1);
    if (res == SIZE_MAX)
        return UINT32_MAX;

    memset(&b->arrs[b->arrs_len], 0, sizeof(st_aura_blob_arr_entry));
    /**
     * We initialize the index when inserting the first arr entry
     * This makes the blobber more flexible!, s0 we can create
     * a node(map or arr) at any point and insert into it at a
     * later point and it would still work, check (aura_blob_b_add_array)
     */
    if (b->nodes[arr_idx].arr.initialized == 0) {
        b->nodes[arr_idx].arr.arr_idx = b->arrs_len;
        b->nodes[arr_idx].arr.initialized = 1;
    }
    b->arrs[b->arrs_len++].node_idx = val_node;
    return b->nodes[arr_idx].arr.arr_cnt++;
}

/**
 *
 */
void *aura_serialize_blob(st_aura_b_builder *b, int *table, size_t tab_len, void *opaque_data, size_t opaque_len) {
    size_t hdr_sz, nodes_sz, kvs_sz, str_sz, arrs_sz;
    size_t total_sz, data_off, tab_off, tab_sz, opaque_off;
    st_aura_blob_hdr *blob_hdr;
    void *blob;
    char *p;

    hdr_sz = sizeof(st_aura_blob_hdr);
    nodes_sz = sizeof(st_aura_blob_node) * b->nodes_len;
    kvs_sz = sizeof(st_aura_blob_kv_pair) * b->kvs_len;
    arrs_sz = sizeof(st_aura_blob_arr_entry) * b->arrs_len;
    str_sz = b->str_len;
    tab_sz = sizeof(int) * tab_len;

    data_off = hdr_sz;
    tab_off = hdr_sz + nodes_sz + kvs_sz + arrs_sz + str_sz;
    opaque_off = tab_off + tab_sz;
    total_sz = opaque_off + opaque_len;

    blob = malloc(total_sz);
    if (!blob)
        return NULL;

    blob_hdr = (st_aura_blob_hdr *)blob;
    blob_hdr->magic = 10;
    blob_hdr->version = 1;
    blob_hdr->node_cnt = (uint32_t)b->nodes_len;
    blob_hdr->kv_cnt = (uint32_t)b->kvs_len;
    blob_hdr->arr_cnt = (uint32_t)b->arrs_len;
    blob_hdr->str_len = (uint32_t)str_sz;
    blob_hdr->size = (uint32_t)total_sz;
    blob_hdr->data_offset = data_off;
    blob_hdr->opaque_data_offset = opaque_off;
    blob_hdr->opaque_data_len = opaque_len;
    blob_hdr->tab_offset = tab_off;
    blob_hdr->tab_len = tab_len;

    p = (char *)blob + data_off;
    /* copy the tables */
    memcpy(p, b->nodes, nodes_sz);
    p += nodes_sz;
    memcpy(p, b->kvs, kvs_sz);
    p += kvs_sz;
    memcpy(p, b->arrs, arrs_sz);
    p += arrs_sz;
    memcpy(p, b->str_buf, str_sz);
    p += str_sz;
    memcpy(p, table, tab_sz);
    p += tab_sz;
    if (opaque_data && opaque_len > 0) {
        memcpy(p, opaque_data, opaque_len);
    }

    return blob;
}

static inline const st_aura_blob_hdr *aura_blob_get_hdr(const void *base) {
    return (const st_aura_blob_hdr *)base;
}

const st_aura_blob_node *aura_blob_get_nodes(const void *base) {
    const st_aura_blob_hdr *hdr = aura_blob_get_hdr(base);
    return (const st_aura_blob_node *)((char *)base + hdr->data_offset);
}

const st_aura_blob_kv_pair *aura_blob_get_kvs(const void *base) {
    const st_aura_blob_hdr *hdr = aura_blob_get_hdr(base);
    const st_aura_blob_node *nodes = aura_blob_get_nodes(base);
    return (const st_aura_blob_kv_pair *)((char *)nodes + hdr->node_cnt * sizeof(st_aura_blob_node));
}

const st_aura_blob_arr_entry *aura_blob_get_arrs(const void *base) {
    const st_aura_blob_hdr *hdr = aura_blob_get_hdr(base);
    const st_aura_blob_kv_pair *kvs = aura_blob_get_kvs(base);
    return (const st_aura_blob_arr_entry *)((char *)kvs + hdr->kv_cnt * sizeof(st_aura_blob_kv_pair));
}

const char *aura_blob_get_strtab(const void *base) {
    const st_aura_blob_hdr *hdr = aura_blob_get_hdr(base);
    const st_aura_blob_arr_entry *arrs = aura_blob_get_arrs(base);
    return (const char *)((char *)arrs + hdr->arr_cnt * sizeof(st_aura_blob_arr_entry));
}

const int *aura_blob_get_tab(const void *base) {
    const st_aura_blob_hdr *hdr = aura_blob_get_hdr(base);
    return (const int *)((char *)base + hdr->tab_offset);
}

/**
 *
 */
void a_dump_blob_recursive(const void *base, uint32_t node_idx, int indent) {
    const st_aura_blob_node *nodes, *start_node;
    const st_aura_blob_kv_pair *kv_pairs;
    const st_aura_blob_arr_entry *arrs;
    const char *strtab;

    nodes = aura_blob_get_nodes(base);
    kv_pairs = aura_blob_get_kvs(base);
    arrs = aura_blob_get_arrs(base);
    strtab = aura_blob_get_strtab(base);

    start_node = &nodes[node_idx];

    switch (start_node->type) {
    case A_BLOB_NODE_STR:
        const char *s = strtab + start_node->str_offset;
        // sprintf(buf + strlen(buf), "%*s\"%s\"", indent, " ", s);
        syslog(LOG_DEBUG, "%*s\"%s\"", indent, " ", s);
        break;

    case A_BLOB_NODE_INT:
        const char *d = strtab + start_node->str_offset;
        syslog(LOG_DEBUG, "%*s\"%s\"", indent, " ", d);
        break;

    case A_BLOB_NODE_MAP:
        uint32_t cnt = start_node->map.kv_cnt;
        uint32_t kv_idx = start_node->map.kv_idx;
        syslog(LOG_DEBUG, "%*s%s", indent + 2, " ", "{");
        for (uint32_t i = 0; i < cnt; ++i) {
            const st_aura_blob_kv_pair *kv = &kv_pairs[kv_idx + i];
            const char *key = strtab + kv->key_offset;
            syslog(LOG_DEBUG, "%*s%s: \n", indent + 4, " ", key);
            a_dump_blob_recursive(base, kv->node_idx, indent + 4);
        }
        syslog(LOG_DEBUG, "%*s%s", indent + 2, " ", "}");
        break;

    case A_BLOB_NODE_ARR:
        uint32_t a_cnt = start_node->arr.arr_cnt;
        uint32_t a_idx = start_node->arr.arr_idx;
        syslog(LOG_DEBUG, "%*s%s", indent + 2, " ", "[");
        for (uint32_t i = 0; i < a_cnt; ++i) {
            uint32_t el = arrs[a_idx + i].node_idx;
            a_dump_blob_recursive(base, el, indent + 2);
        }
        syslog(LOG_DEBUG, "%*s%s", indent + 2, " ", "]");
        break;

    default:
        syslog(LOG_DEBUG, "Unknown node type %u", start_node->type);
    }
}

/**
 *
 */
void aura_dump_blob(const void *base) {
    const st_aura_blob_hdr *hdr;

    if (!base) {
        syslog(LOG_DEBUG, "Empty");
        return;
    }

    hdr = aura_blob_get_hdr(base);
    syslog(LOG_DEBUG, "AURA BLOB");
    syslog(LOG_DEBUG, "  magic: %d", hdr->magic);
    syslog(LOG_DEBUG, "  version: %d", hdr->version);
    syslog(LOG_DEBUG, "  node cnt: %d", hdr->node_cnt);
    syslog(LOG_DEBUG, "  kvs cnt: %d", hdr->kv_cnt);
    syslog(LOG_DEBUG, "  arr cnt: %d", hdr->arr_cnt);
    syslog(LOG_DEBUG, "  str buf sz: %d", hdr->str_len);
    syslog(LOG_DEBUG, "  tab sz: %d", hdr->tab_len);
    syslog(LOG_DEBUG, "  blob size: %d", hdr->size);
    syslog(LOG_DEBUG, "  data offset: %d", hdr->data_offset);
    syslog(LOG_DEBUG, "  opaque data offset: %d", hdr->opaque_data_offset);

    a_dump_blob_recursive(base, 0, 0);
}

/**
 *
 */
uint32_t aura_blob_get_size(const void *base) {
    const st_aura_blob_hdr *blob_hdr;
    if (!base)
        return UINT32_MAX;

    blob_hdr = aura_blob_get_hdr(base);
    return blob_hdr->size;
}