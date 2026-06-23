#include "h2/hpack.h"
#include "h2/hpack_huffman_tb_srv.h"
#include "h2/server.h"
#include "slab.h"
#include "string_lib.h"

#include <arpa/inet.h>

#define A_DYNAMIC_TABLE_SIZE_UPDATE_MAX_SIZE 5
#define A_CONTENT_LENGTH_HEADER_MAX_SIZE (3 + sizeof(SIZE_T_LONGEST_STR) - 1)
#define A_MIN_PREFIX_BITS 1
#define A_MAX_PREFIX_BITS 8

/* Error strings */
const char hpack_err_missing_mandatory_pseudo_header[] = "missing mandatory pseudo header";
const char hpack_err_invalid_pseudo_header[] = "invalid pseudo header";
const char hpack_err_found_upper_case_in_header_name[] = "found an upper-case letter in header name";
const char hpack_err_unexpected_connection_specific_header[] = "found an unexpected connection-specific header";
const char hpack_err_invalid_content_length_header[] = "invalid content-length header";
const char hpack_soft_err_found_invalid_char_in_header_name[] = "found an invalid character in header name";
const char hpack_soft_err_found_invalid_char_in_header_value[] = "found an invalid character in header value";

// const struct aura_hpack_static_table static_table;
struct aura_hpack_static_table static_table;

int a_hpack_huffman_encode3(uint8_t *dest, size_t dest_len, const uint8_t *src, size_t len);

/**
 * Decode and extract integer into @out
 */
static int a_hpack_decode_integer(const uint8_t **src, const uint8_t *src_end, uint8_t prefix_bits, int64_t *out) {
    uint64_t value;
    int32_t shift;
    uint8_t prefix_max, curr;

    if (prefix_bits < A_MIN_PREFIX_BITS || prefix_bits > A_MAX_PREFIX_BITS)
        return A_HPACK_PROTOCOL_ERR;

    if (*src >= src_end)
        return A_HPACK_COMPRESSION_ERR;

    prefix_max = (uint8_t)((1u << prefix_bits) - 1u);
    curr = **src;
    value = curr & prefix_max;
    (*src)++;
    /* value can fit in the prefix max */
    if (value < prefix_max) {
        *out = (int64_t)value;
        return A_HPACK_OK;
    }

    /* decode upto 8 octets(64 bits, excluding prefix), that is guaranteed not to cause overflow */
    shift = 0;
    while (true) {
        if (*src == src_end)
            return A_HPACK_COMPRESSION_ERR;

        curr = **src;
        (*src)++;

        /* check overflow */
        if (shift >= 56)
            return A_HPACK_COMPRESSION_ERR;

        value += (int64_t)(curr & 127) << shift;
        /* check if this is the last valid byte */
        if ((curr & 128) == 0)
            break;
        shift += 7;
    }
    *out = value;
    return A_HPACK_OK;
}

/**
 * Decodes huffman encoded string,
 * Return the string len on success
 * otherwise returns SIZE_MAX if hard fail
 */
/**
 * Decodes huffman encoded string,
 */
static int a_hpack_decode_huffman(char *dest, const uint8_t *src, size_t len, bool value_is_name, size_t *consumed) {
    char *ptr;
    const uint8_t *src_end;
    uint8_t ch, char_errs = 0;
    const nghttp2_huff_decode e = {0, 0x00, 0}, *entry = &e;

    if (value_is_name && len == 0)
        return A_HPACK_INVALID_NAME_ERR;

    ptr = dest;
    src_end = src + len;
    for (; src < src_end; ++src) {
        ch = *src;
        entry = huff_decode_table[entry->state] + (ch >> 4);
        if (entry->flags & NGHTTP2_HUFF_SYM) {
            *ptr++ = entry->sym;
            char_errs |= (entry->flags & NGHTTP2_HUFF_INVALID_CHARS);
        }
        entry = huff_decode_table[entry->state] + (ch & 0xf);
        if (entry->flags & NGHTTP2_HUFF_SYM) {
            *ptr++ = entry->sym;
            char_errs |= (entry->flags & NGHTTP2_HUFF_INVALID_CHARS);
        }
    }

    if (!(entry->flags & NGHTTP2_HUFF_ACCEPTED))
        return A_HPACK_COMPRESSION_ERR;

    /* validate */
    if (value_is_name) {
        /* pseudo-headers are checked later in 'decode_header' */
        if (!aura_hpack_is_pseudo_header(dest) && (char_errs & NGHTTP2_HUFF_INVALID_FOR_HEADER_NAME) != 0) {
            if ((char_errs & NGHTTP2_HUFF_UPPER_CASE_CHAR) != 0) {
                return A_HPACK_PROTOCOL_ERR;
            }
            return A_HPACK_INVALID_NAME_ERR;
        }
    } else if ((char_errs & NGHTTP2_HUFF_INVALID_FOR_HEADER_VALUE) != 0 || !aura_hpack_header_value_valid(dest, ptr - dest))
        return A_HPACK_INVALID_VALUE_ERR;

    *consumed = ptr - dest;
    return A_HPACK_OK;
}

static int a_hpack_validate_header_name(const uint8_t *src, size_t len) {
    uint8_t ch;

    /* all printable chars, except upper case and separator characters */
    static const char valid_h2_header_name_char[] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 0-31 */
      0,
      1,
      0,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      1,
      1,
      0,
      1,
      1,
      0,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      0,
      0,
      0,
      0, /* 32-63 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      1, /* 64-95 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      1,
      0,
      1,
      0, /*  96-127 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 128-159 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 160-191 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 192-223 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 224-255 */
    };

    if (len == 0)
        return A_HPACK_INVALID_NAME_ERR;
    else {
        for (; len != 0; ++src, --len) {
            ch = *src;
            if (valid_h2_header_name_char[ch] == 0) {
                if (isupper(ch)) {
                    return A_HPACK_INVALID_NAME_ERR;
                }
            }
        }
    }
    return A_HPACK_OK;
}

/**
 *
 */
static int a_hpack_validate_header_value(const uint8_t *src, size_t len) {
    uint8_t ch;

    /* surrounding whitespaces RFC 9113 8.2.1 */
    if (!aura_hpack_header_value_valid(src, len))
        goto invalid;

    /* all printable chars + horizontal tab (RFC 7230 3.2) */
    static const char valid_h2_field_value_char[] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /*    0-31 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /*   32-63 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /*   64-95 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0, /*  96-127 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 128-159 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 160-191 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 192-223 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 224-255 */
    };

    for (; len != 0; ++src, --len) {
        ch = *src;
        if (!valid_h2_field_value_char[ch])
            goto invalid;
    }
    return A_HPACK_OK;

invalid:
    return A_HPACK_INVALID_VALUE_ERR;
}

/** */
static int a_hpack_decode_string(struct aura_mem_ctx *mc, const uint8_t **src, const uint8_t *src_end,
                                 struct aura_iovec **str, bool value_is_name) {
    bool is_huffman;
    int64_t len, consumed;
    int ret;

    if (*src >= src_end)
        return A_HPACK_COMPRESSION_ERR;

    /* huffman flag (MSB == 1) */
    is_huffman = (**src & 0x80) != 0;

    ret = a_hpack_decode_integer(src, src_end, 7, &len);
    if (ret != A_HPACK_OK)
        return ret;

    if (is_huffman) {
        if (len > src_end - *src)
            return A_HPACK_COMPRESSION_ERR;

        *str = aura_iovec_init(mc, len * 2, NULL); /* huffman max compression ratio is >= 0.5 */
        if (!(*str))
            return A_HPACK_INTERNAL_ERR;
        ret = a_hpack_decode_huffman((*str)->base, *src, len, value_is_name, &(*str)->len);
        if (ret != A_HPACK_OK) {
            aura_iovec_destroy(*str);
            return ret;
        }

        (*str)->base[(*str)->len] = '\0';
    } else {
        if (len > src_end - *src)
            return A_HPACK_COMPRESSION_ERR;

        if (value_is_name) {
            if (len == 0)
                return A_HPACK_COMPRESSION_ERR;
            /* pseudo-headers are checked later in 'decode_header' */
            if (!aura_hpack_is_pseudo_header((void *)*src) && (ret = a_hpack_validate_header_name(*src, len)) != A_HPACK_OK)
                return ret;
        } else {
            ret = a_hpack_validate_header_value((char *)*src, len);
            if (ret != A_HPACK_OK)
                return ret;
        }

        *str = aura_iovec_init(mc, len, NULL);
        if (!(*str))
            return A_HPACK_INTERNAL_ERR;
        memcpy((*str)->base, *src, len);
        (*str)->base[len] = '\0';
    }
    *src += len;
    return A_HPACK_OK;
}

static inline void a_hpack_dyn_tab_shrink(struct aura_hpack_dyn_tab *dyn_tab) {
    while (dyn_tab->cnt != 0 && dyn_tab->tab_size > dyn_tab->max_size)
        aura_hpack_header_table_evict_one(dyn_tab);
}

static struct aura_hpack_tab_entry *a_dyn_header_table_get_new_slot(struct aura_mem_ctx *mc,
                                                                    struct aura_hpack_dyn_tab *tb,
                                                                    size_t add, size_t max_num_entries) {
    struct aura_hpack_tab_entry *old_entries;
    size_t old_cap;

    /* adjust size */
    while (tb->cnt > max_num_entries || (tb->cnt != 0 && (tb->tab_size + add) > tb->max_size))
        aura_hpack_header_table_evict_one(tb);

    if (tb->cnt == 0) {
        A_BUG_ON_2(tb->tab_size != 0, true);
        if (add > tb->max_size)
            return NULL;
    }

    old_entries = tb->entries;
    old_cap = tb->cap;
    /* grow the entries if full */
    if (tb->cnt >= tb->cap) {
        tb->cap = tb->cap < 16 ? 16 : tb->cap * 2;
        tb->entries = aura_realloc(mc, tb->entries, (sizeof(*tb->entries) * tb->cap));
        if (tb->entries == NULL) {
            tb->entries = old_entries;
            tb->cap = old_cap;
            return NULL;
        }
    }

    memmove(&tb->entries[1], &tb->entries[0], tb->cnt * sizeof(*tb->entries));
    tb->tab_size += add;
    tb->cnt++;
    return tb->entries;
}

static int a_dyn_header_table_get_new_slot2(struct aura_mem_ctx *mc,
                                            struct aura_hpack_dyn_tab *dyn_tab,
                                            size_t add, size_t max_num_entries,
                                            struct aura_hpack_tab_entry **slot) {
    struct aura_hpack_tab_entry *old_entries;
    size_t old_cap;

    /* adjust size */
    while (dyn_tab->cnt > max_num_entries ||
           (dyn_tab->cnt != 0 && (dyn_tab->tab_size + add) > dyn_tab->max_size))
        aura_hpack_header_table_evict_one(dyn_tab);

    /* Can't add */
    if ((dyn_tab->tab_size + add) > dyn_tab->max_size) {
        *slot = NULL;
        return 0;
    }

    if (dyn_tab->cnt == 0) {
        A_BUG_ON_2(dyn_tab->tab_size != 0, true);
        if (add > dyn_tab->max_size) {
            *slot = NULL;
            return -1;
        }
    }

    old_entries = dyn_tab->entries;
    old_cap = dyn_tab->cap;
    /* grow the entries if full */
    if (dyn_tab->cnt >= dyn_tab->cap) {
        dyn_tab->cap = dyn_tab->cap < 16 ? 16 : dyn_tab->cap * 2;
        dyn_tab->entries = aura_realloc(mc, dyn_tab->entries, (sizeof(*dyn_tab->entries) * dyn_tab->cap));
        if (dyn_tab->entries == NULL) {
            dyn_tab->entries = old_entries;
            dyn_tab->cap = old_cap;
            *slot = NULL;
            return -1;
        }
    }

    memmove(&dyn_tab->entries[1], &dyn_tab->entries[0], dyn_tab->cnt * sizeof(*dyn_tab->entries));
    dyn_tab->tab_size += add;
    dyn_tab->cnt++;
    *slot = dyn_tab->entries;
    return 0;
}

static inline int a_hpack_get_binary_format(uint8_t c) {
    if (0x80u & c)
        return A_HPACK_INDEXED_HDR_FIELD;
    else if (c >= 64) {
        if (0x3f & c)
            return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME;
        else
            return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME;
    } else if ((0xe0u & c) == 0x20u)
        return A_HPACK_DYNAMIC_TABLE_SIZE_UPDATE;
    else if (c >= 16) {
        if (0x0f & c)
            return A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME;
        else
            return A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME;
    } else {
        if (c > 0)
            return A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME;
        else
            return A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME;
    }
}

static int a_hpack_decode_header(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                                 struct aura_intern_tab *intern_tab, struct aura_hpack_tab_entry *nv,
                                 const uint8_t **const src, const uint8_t *src_end) {
    const struct aura_hpack_tab_entry *entry;
    struct aura_interned_str *name, *value;
    struct aura_iovec *str_name, *str_val;
    bool name_is_indexed, value_is_indexed, insert_new_entry;
    int64_t index, new_cap;
    int32_t prefix_len, token;
    int ret, binary_format;

    index = 0;
    prefix_len = -1;
    name_is_indexed = false;
    value_is_indexed = false;
    insert_new_entry = false;
    name = NULL;
    value = NULL;
    ret = A_HPACK_OK;
    for (; *src < src_end;) {
        /* determine the encoding format */
        binary_format = a_hpack_get_binary_format(**src);

        switch (binary_format) {
        case A_HPACK_INDEXED_HDR_FIELD:
            prefix_len = 7;
            name_is_indexed = true;
            value_is_indexed = true;
            break;

        case A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME:
            prefix_len = 6;
            name_is_indexed = true;
            insert_new_entry = true;
            break;

        case A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME:
        case A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME:
        case A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME:
            (*src)++;
            break;

        case A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME:
        case A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME:
            prefix_len = 4;
            name_is_indexed = true;
            break;

        case A_HPACK_DYNAMIC_TABLE_SIZE_UPDATE:
            ret = a_hpack_decode_integer(src, src_end, 5, &new_cap);
            if (ret != A_HPACK_OK) {
                return ret;
            }

            if (new_cap > dyn_tab->max_size) {
                return A_HPACK_COMPRESSION_ERR;
            }

            dyn_tab->max_size = (size_t)new_cap;
            a_hpack_dyn_tab_shrink(dyn_tab);
            continue; /** @todo: test how switch behaves inside for loop with 'continue' */
        default:
            /* protocol error */
            return A_HPACK_PROTOCOL_ERR;
        }

        if (name_is_indexed) {
            ret = a_hpack_decode_integer(src, src_end, prefix_len, &index);
            if (ret != A_HPACK_OK) {
                return ret;
            }

            if (aura_hpack_tab_index_invalid(dyn_tab, index)) {
                return A_HPACK_COMPRESSION_ERR;
            }

            if (index < A_HPACK_DYNAMIC_TAB_HEADER_OFFSET) {
                entry = aura_hpack_static_tab_get_entry(&static_table, index);
            } else {
                entry = aura_hpack_dyn_header_tab_get_entry(dyn_tab, index);
            }

            if (!entry) {
                return A_HPACK_PROTOCOL_ERR;
            }

            /* all names guaranteed to be interned */
            nv->header_field.name = entry->header_field.name;
            nv->header_field.token = entry->header_field.token;
            nv->index = index;

            if (value_is_indexed) {
                if (entry->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                    nv->header_field.value.interned = entry->header_field.value.interned;
                    nv->header_field.flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
                } else {
                    nv->header_field.value.raw = entry->header_field.value.raw;
                    nv->header_field.value.raw.ref_cnt++;
                }
            } else {
                ret = a_hpack_decode_string(mc, src, src_end, &str_val, false);
                /* If hard error, just end, otherwise continue on soft error */
                if (aura_hpack_hdr_err_fatal(ret))
                    return ret;

                /** @todo: some values do not need to be interned (look into that) */
                value = aura_interned_str_find_or_add(intern_tab, str_val->base, str_val->len);
                if (value) {
                    /* switch to interned value */
                    nv->header_field.value.interned = value;
                    nv->header_field.flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
                    aura_iovec_destroy(str_val);
                } else {
                    /* fallback to raw string */
                    nv->header_field.value.raw.str.base = str_val->base;
                    /* No one yet have reference to raw string just created */
                    nv->header_field.value.raw.ref_cnt = 0;
                }
            }
        } else {
            ret = a_hpack_decode_string(mc, src, src_end, &str_name, true);
            /* If hard error, just end, str_name is still NULL at this point */
            if (aura_hpack_hdr_err_fatal(ret))
                return ret;

            /* intern all names */
            name = aura_interned_str_find_or_add(intern_tab, str_name->base, str_name->len);
            aura_iovec_destroy(str_name);
            if (!name) {
                return A_HPACK_INTERNAL_ERR;
            }

            nv->header_field.name = name;

            ret = a_hpack_decode_string(mc, src, src_end, &str_val, false);
            /* If hard error, just end, str_val is still NULL at this point */
            if (aura_hpack_hdr_err_fatal(ret))
                return ret;

            /** @todo: some values do not need to be interned (look into that) */
            value = aura_interned_str_find_or_add(intern_tab, str_val->base, str_val->len);
            if (value) {
                /* switch to interned value  */
                nv->header_field.value.interned = value;
                nv->header_field.flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
                aura_iovec_destroy(str_val);
            } else {
                /* fallback to raw string */
                nv->header_field.value.raw.str.base = str_val->base;
                /* No one yet have reference to raw string just created */
                nv->header_field.value.raw.ref_cnt = 0;
            }

            token = lookup_token(name->data, name->len);
            nv->header_field.token = token;
            nv->index = -1;
        }

        /* add to dynamic table */
        if (insert_new_entry) {
            size_t name_len, value_len;
            name_len = nv->header_field.name->len;
            if (nv->header_field.value.interned) {
                value_len = nv->header_field.value.interned->len;
            } else {
                value_len = nv->header_field.value.raw.str.len;
            }

            struct aura_hpack_tab_entry *entry_slot = a_dyn_header_table_get_new_slot(mc, dyn_tab, name_len + value_len + A_HPACK_HDR_TAB_ENT_OVERHEAD, 128);
            if (entry_slot) {
                memset(entry_slot, 0, sizeof(*entry_slot));
                /* name always interned */
                entry_slot->header_field.name = nv->header_field.name;

                if (nv->header_field.value.interned) {
                    entry_slot->header_field.value.interned = nv->header_field.value.interned;
                    entry_slot->header_field.flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
                } else {
                    entry_slot->header_field.value.raw = nv->header_field.value.raw;
                    entry_slot->header_field.value.raw.ref_cnt++;
                }
                entry_slot->header_field.token = nv->header_field.token;
            }
        }

        return ret;
    }
    return ret;
}

uint8_t *aura_encode_status(uint8_t *dest, int status) {
    A_BUG_ON_2(status < 100 || status > 999, true);

    switch (status) {
#define COMMON_CODE(code, st)  \
    case st:                   \
        *dest++ = 0x80 | code; \
        break;
        COMMON_CODE(8, 200);
        COMMON_CODE(9, 204);
        COMMON_CODE(10, 206);
        COMMON_CODE(11, 304);
        COMMON_CODE(12, 400);
        COMMON_CODE(13, 404);
        COMMON_CODE(14, 500);
#undef COMMON_CODE
    default:
        /* use literal header field without indexing - indexed name */
        *dest++ = 8;
        *dest++ = 3;
        sprintf((char *)dest, "%d", status);
        dest += 3;
        break;
    }
    return dest;
}

uint8_t *aura_encode_content_length(uint8_t *dest, size_t value) {
    char buf[32];
    char *p = buf + sizeof(buf);
    size_t l;

    do {
        *--p = '0' + value % 10;
    } while ((value /= 10) != 0);
    l = buf + sizeof(buf) - p;

    *dest++ = 0x0f; /* 15 */
    *dest++ = 0x0d; /* + 13 = 28(index) */
    *dest++ = (uint8_t)l;
    memcpy(dest, p, l);
    dest += l;

    return dest;
}

void aura_hpack_header_tab_dispose(struct aura_hpack_dyn_tab *hdr_tb) {
    struct aura_hpack_tab_entry *entry;
    size_t idx;

    if (hdr_tb->cnt > 0) {
        idx = 0;
        do {
            entry = &hdr_tb->entries[idx];

            if (!entry->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
                aura_free(entry->header_field.value.raw.str.base);

            idx = (idx + 1) % hdr_tb->cap;
        } while (--hdr_tb->cnt > 0);
    }
    aura_free(hdr_tb->entries);
}

static struct aura_header_field *a_hpack_header_find_or_create(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                                                               struct aura_intern_tab *intern_tab, char *name,
                                                               size_t name_len, char *val, size_t val_len) {
    struct aura_header_field *header_field;
    const struct aura_hpack_tab_entry *tb_entry;
    const struct aura_hpack_tab_entry *e;
    int token;
    bool name_match_found, value_match_found;

    if (name_len == 0)
        return NULL;

    header_field = aura_alloc(mc, sizeof(*header_field));
    if (!header_field)
        return NULL;
    memset(header_field, 0, sizeof(*header_field));

    token = lookup_token(name, name_len);
    name_match_found = false;
    value_match_found = false;
    /* static table entry */
    if (token > 0 && token <= A_TOKEN_WWW_AUTHENTICATE) {
        tb_entry = aura_hpack_static_tab_get_by_token(&static_table, token);
        header_field->name = tb_entry->header_field.name;

        /* Confirm value match */
        for (int i = 0; i < ARRAY_SIZE(static_table.entries); ++i) {
            tb_entry = &static_table.entries[i];
            if (tb_entry->header_field.token == token) {
                if (tb_entry->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                    if (aura_mem_is_eq(val, val_len, tb_entry->header_field.value.interned->data, tb_entry->header_field.value.interned->len)) {
                        header_field->value.interned = tb_entry->header_field.value.interned;
                        header_field->flags = tb_entry->header_field.flags;
                        value_match_found = true;
                        break;
                    }
                }
            }
        }

        /* Create new value entry */
        if (!value_match_found) {
            header_field->value.interned = aura_interned_str_find_or_add(intern_tab, val, val_len);
            /* Fallback to raw string */
            if (!header_field->value.interned) {
                header_field->value.raw.str.base = aura_strndup(mc, val, val_len);
                header_field->value.raw.ref_cnt = 1;
                return header_field;
            } else {
                header_field->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
                return header_field;
            }
        }
        return header_field;
    } else {
        for (int i = 0; i < dyn_tab->cap; ++i) {
            e = &dyn_tab->entries[i];

            if (!aura_mem_is_eq(name, name_len, e->header_field.name->data, e->header_field.name->len)) {
                continue;
            }
            header_field->name = e->header_field.name;
            name_match_found = true;

            if (e->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                if (aura_mem_is_eq(val, val_len, e->header_field.value.interned->data, e->header_field.value.interned->len)) {
                    header_field->value.interned = e->header_field.value.interned;
                    header_field->flags = e->header_field.flags;
                    value_match_found = true;
                    break;
                }
            }
        }

        /* name always interned */
        if (!name_match_found)
            return NULL;

        /* Create value entry */
        if (!value_match_found) {
            header_field->value.interned = aura_interned_str_find_or_add(intern_tab, name, name_len);
            /* Fallback to raw string */
            if (!header_field->value.interned) {
                header_field->value.raw.str.base = aura_strndup(mc, val, val_len);
                header_field->value.raw.str.len = val_len;
                header_field->value.raw.ref_cnt = 1;
            } else {
                header_field->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
            }
        }
        return header_field;
    }
}

/**
 * Determines if value can be packed in a single byte
 */
static inline bool value_is_one_byte(int64_t value, uint32_t prefix_bits) {
    size_t n;

    n = (uint8_t)(1 << prefix_bits) - 1;
    return value < n;
}

size_t a_hpack_encode_int(uint8_t *dest, int64_t value, uint32_t prefix_bits) {
    uint8_t *start;

    if (value_is_one_byte(value, prefix_bits)) {
        *dest |= value;
        return 1;
    }

    start = dest;
    A_BUG_ON_2(value < 0, true);
    *dest++ |= (uint8_t)(1 << prefix_bits) - 1;
    value -= (uint8_t)(1 << prefix_bits) - 1;
    for (; value >= 128; value >>= 7)
        *dest++ = (uint8_t)(0x80 | value);
    *dest++ = (uint8_t)value;
    return dest - start;
}

/**
 *
 */
bool a_hpack_huffman_encode(uint8_t *dest, const uint8_t *src, size_t len) {
    const nghttp2_huff_sym *sym;
    const uint8_t *end;
    uint8_t *dest_start, *dest_end;
    uint64_t bits = 0;
    int bits_left = 40;

    end = src + len;
    dest_start = dest;
    dest_end = dest + len;
    while (src != end) {
        sym = huff_sym_table + *src++;
        bits |= (uint64_t)sym->code << (bits_left - sym->nbits);
        bits_left -= sym->nbits;

        while (bits_left <= 32) {
            *dest_start++ = bits >> 32;
            bits <<= 8;
            bits_left += 8;
            if (dest_start == dest_end)
                return false;
        }
    }

    if (bits_left != 40) {
        bits |= ((uint64_t)1 << bits_left) - 1;
        *dest_start++ = bits >> 32;
    }

    if (dest_start == dest_end)
        return false;

    return true;
}

/**
 * encode raw octets without huffman encoding
 */
static inline size_t a_encode_as_original(uint8_t *dest, const char *s, size_t len) {
    uint8_t *start = dest;
    *dest = '\0';
    dest += a_hpack_encode_int(dest, len, 7);
    memcpy(dest, s, len);
    dest += len;
    return dest - start;
}

/**
 * Calculate the length consumed by huffman for
 * this given string and len
 */
size_t aura_hd_huff_encode_len(const uint8_t *src, size_t len) {
    size_t i;
    size_t nbits = 0;

    for (i = 0; i < len; ++i) {
        nbits += huff_sym_table[src[i]].nbits;
    }
    /* pad the prefix of EOS (256) */
    return (nbits + 7) / 8;
}

/**
 * Encode string
 */
size_t a_hpack_encode_string(uint8_t *dest, const char *s, size_t len) {
    size_t huff_len, head_len;
    uint8_t head[8];
    bool can_huffman, res;

    can_huffman = false;
    huff_len = aura_hd_huff_encode_len(s, len);
    if (huff_len < len)
        can_huffman = true;

    if (can_huffman) {
        res = a_hpack_huffman_encode(dest + 1, (uint8_t *)s, len);

        if (res == true) {
            if (likely(value_is_one_byte(huff_len, 7))) {
                *dest = (uint8_t)(0x80 | huff_len);
                head_len = 1;
            } else {
                head[0] = 1 << 7; // '\x80';                               /* indicate huffman encoded */
                head_len = a_hpack_encode_int(head, huff_len, 7);
                memmove(dest + head_len, dest + 1, huff_len); /* copy encoded string */
                memcpy(dest, head, head_len);                 /* copy length */
            }
            return head_len + huff_len;
        }
    }

    /* fallback */
    return a_encode_as_original(dest, s, len);
}

uint8_t *aura_header_table_adjust_size(struct aura_hpack_dyn_tab *tb, uint32_t new_cap, uint8_t *dest) {
    /**
     * Do nothing if user-supplied value is greater that the current value.
     * We do not allow the peer to increase the memory limit
     */
    if (new_cap >= tb->max_size)
        return dest;

    tb->max_size = new_cap;
    /* excess header fields are evicted until we have space hold current fields */
    a_hpack_dyn_tab_shrink(tb);

    /* Encode dynamic table size pattern: | 0 | 0 | 1 | max_size(5+) | */
    *dest = 0x20;
    dest += a_hpack_encode_int(dest, tb->max_size, 5);
    return dest;
}

static void a_hpack_search_static_table(struct aura_header_field *nv, bool *exact_match) {
    const struct aura_hpack_tab_entry *entry;
    size_t n;

    entry = aura_hpack_static_tab_get_by_token(&static_table, nv->token);
    if (!entry)
        return;

    if (nv->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
        *exact_match = entry->header_field.value.interned == nv->value.interned;
        return;
    }

    if (aura_mem_is_eq(nv->value.raw.str.base, nv->value.raw.str.len, entry->header_field.value.raw.str.base, entry->header_field.value.raw.str.len)) {
        *exact_match = true;
    }
}

/**
 * @todo: combine loop to check both name and value, returning a structure of index and exact_match
 */
static struct aura_hpack_tab_entry *a_hpack_dyn_tab_search_by_name_or_value(struct aura_hpack_dyn_tab *dyn_tab, struct aura_header_field *field, bool is_name) {
    struct aura_hpack_tab_entry *entry;

    for (int i = 0; i < dyn_tab->cnt; ++i) {
        entry = &dyn_tab->entries[i];
        entry->index = i + A_HPACK_DYNAMIC_TAB_HEADER_OFFSET; /* index in dynamic table */

        if (is_name) {
            if (field->name == entry->header_field.name)
                return entry;
        } else {
            if (entry->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                if (field->value.interned == entry->header_field.value.interned)
                    return entry;
            } else {
                if (aura_mem_is_eq(field->value.raw.str.base, field->value.raw.str.len, entry->header_field.value.raw.str.base, entry->header_field.value.raw.str.len))
                    return entry;
            }
        }
    }
    return NULL;
}

/**
 * Some semi-naive way of determining binary format
 */
static hpack_binary_format_rep a_determine_encode_binary_format(struct aura_hpack_dyn_tab *tb,
                                                                struct aura_header_field *header, int *index) {
    struct aura_hpack_tab_entry *tb_entry, *new_tb_entry;
    size_t n;
    bool is_exact_match;

    is_exact_match = false;
    if (header->token > 0 && header->token <= A_TOKEN_WWW_AUTHENTICATE) {
        /* index matches token for now */
        *index = header->token;
        a_hpack_search_static_table(header, &is_exact_match);
    } else {
        /* Match header name */
        tb_entry = a_hpack_dyn_tab_search_by_name_or_value(tb, header, true);
        /* Not existent in header table */
        if (!tb_entry)
            *index = 0;
        else
            *index = tb_entry->index;

        if (*index != 0) {
            if (tb_entry->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                if (header->value.interned == tb_entry->header_field.value.interned)
                    is_exact_match = true;
            } else {
                if (aura_mem_is_eq(header->value.raw.str.base, header->value.raw.str.len, tb_entry->header_field.value.raw.str.base, tb_entry->header_field.value.raw.str.len))
                    is_exact_match = true;
            }
        }
    }

    if (is_exact_match) {
        return A_HPACK_INDEXED_HDR_FIELD;
    }

    if (*index != 0) {
        if (header->token == A_TOKEN_AUTHORIZATION || header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
            return A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME;
        }

        if (header->token == A_TOKEN_LOCATION || header->token == A_TOKEN_CONTENT_LENGTH)
            return A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME;

        return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME;
    } else {
        return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME;
    }
}

/**
 * Encode new value and add to the dynamic header table
 */
static void a_hpack_dyn_tab_add_new_entry(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                                          struct aura_header_field *header) {
    struct aura_hpack_tab_entry *entry_slot;
    const char *name, *value;
    char *str;
    size_t name_len, value_len;

    if (header) {
        name = header->name->data;
        name_len = header->name->len;

        if (header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
            value = header->value.interned->data;
            value_len = header->value.interned->len;
        } else {
            value = header->value.raw.str.base;
            value_len = header->value.raw.str.len;
        }

        entry_slot = a_dyn_header_table_get_new_slot(mc, dyn_tab, name_len + value_len + A_HPACK_HDR_TAB_ENT_OVERHEAD, 128);
        if (entry_slot) {
            memset(entry_slot, 0, sizeof(*entry_slot));
            entry_slot->header_field.name = header->name;

            if (header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                entry_slot->header_field.value.interned = header->value.interned;
                entry_slot->header_field.flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
            } else {
                entry_slot->header_field.value.raw = header->value.raw;
                entry_slot->header_field.value.raw.ref_cnt++;
            }
        }
    }
}

static int a_hpack_dyn_tab_add_new_entry2(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                                          struct aura_header_field *header) {
    struct aura_hpack_tab_entry *entry_slot;
    size_t name_len, value_len;
    int rv;

    name_len = header->name->len;
    if (header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
        value_len = header->value.interned->len;
    else
        value_len = header->value.raw.str.len;

    if (header) {
        rv = a_dyn_header_table_get_new_slot2(mc, dyn_tab, name_len + value_len + A_HPACK_HDR_TAB_ENT_OVERHEAD, 128, &entry_slot);
        if (entry_slot) {
            memset(entry_slot, 0, sizeof(*entry_slot));
            entry_slot->header_field = *header;
            return A_HPACK_OK;
        }

        if (!entry_slot && rv < 0)
            return A_HPACK_INTERNAL_ERR;
    }

    return A_HPACK_OK;
}

/**
 *
 */
static uint8_t *a_encode_header(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                                uint8_t *dest, struct aura_header_field *header) {
    hpack_binary_format_rep binary_format;
    int index;

    binary_format = a_determine_encode_binary_format(dyn_tab, header, &index);
    switch (binary_format) {
    case A_HPACK_INDEXED_HDR_FIELD:
        *dest = 0x80u;
        dest += a_hpack_encode_int(dest, index, 7);
        break;

    case A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME:
    case A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME:
        *dest = 0x10u;
        dest += a_hpack_encode_int(dest, index, 4);
        if (header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) /* header always interned */
            dest += a_encode_as_original(dest, header->value.interned->data, header->value.interned->len);
        else
            dest += a_encode_as_original(dest, header->value.raw.str.base, header->value.raw.str.len);
        break;

    case A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME:
        *dest = 0x40u;
        dest += a_hpack_encode_int(dest, index, 6);
        if (header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
            dest += a_hpack_encode_string(dest, header->value.interned->data, header->value.interned->len);
        else
            dest += a_hpack_encode_string(dest, header->value.raw.str.base, header->value.raw.str.len);
        a_hpack_dyn_tab_add_new_entry(mc, dyn_tab, header);
        break;

    default:
        *dest++ = 0x40u;
        dest += a_hpack_encode_string(dest, header->name->data, header->name->len);

        if (header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
            dest += a_hpack_encode_string(dest, header->value.interned->data, header->value.interned->len);
        else
            dest += a_hpack_encode_string(dest, header->value.raw.str.base, header->value.raw.str.len);
        a_hpack_dyn_tab_add_new_entry(mc, dyn_tab, header);
        break;
    }

    return dest;
}

uint8_t *aura_encode_header(struct aura_mem_ctx *mc, const struct aura_hpack_static_table *static_tab,
                            struct aura_hpack_dyn_tab *dyn_tab, uint8_t *dest,
                            struct aura_header_field *header) {
    return a_encode_header(mc, dyn_tab, dest, header);
}

/**
 *
 */
uint8_t *aura_encode_method(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                            struct aura_intern_tab *intern_tab, uint8_t *dest,
                            struct aura_iovec value) {
    if (aura_mem_is_eq(value.base, value.len, str_lit("GET"))) {
        /* direct static table */
        *dest++ = 0x82;
        return dest;
    }

    if (aura_mem_is_eq(value.base, value.len, str_lit("POST"))) {
        /* direct static table */
        *dest++ = 0x83;
        return dest;
    }

    struct aura_header_field *header;
    header = a_hpack_header_find_or_create(mc, dyn_tab, intern_tab, str_lit(":method"), value.base, value.len);
    return a_encode_header(mc, dyn_tab, dest, header);
}

/**
 *
 */
static uint8_t *encode_scheme(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                              struct aura_intern_tab *intern_tab, uint8_t *dest,
                              struct aura_iovec *scheme) {

    if (aura_mem_is_eq(scheme->base, scheme->len, str_lit("HTTP"))) {
        /* from hpack static table */
        *dest++ = 0x86;
        return dest;
    }

    if (aura_mem_is_eq(scheme->base, scheme->len, str_lit("HTTPS"))) {
        /* from hpack static table */
        *dest++ = 0x87;
        return dest;
    }

    struct aura_header_field *header;
    header = a_hpack_header_find_or_create(mc, dyn_tab, intern_tab, str_lit(":scheme"), scheme->base, scheme->len);
    return a_encode_header(mc, dyn_tab, dest, header);
}

/**
 *
 */
static uint8_t *encode_path(struct aura_mem_ctx *mc, struct aura_hpack_dyn_tab *dyn_tab,
                            struct aura_intern_tab *intern_tab,
                            uint8_t *dest, struct aura_iovec value) {
    if (aura_mem_is_eq(value.base, value.len, str_lit("/"))) {
        *dest++ = 0x84; /* from hpack static table */
        return dest;
    }

    if (aura_mem_is_eq(value.base, value.len, str_lit("/index.html"))) {
        *dest++ = 0x85; /* from hpack static table */
        return dest;
    }

    struct aura_header_field *header;
    header = a_hpack_header_find_or_create(mc, dyn_tab, intern_tab, str_lit(":path"), value.base, value.len);

    return a_encode_header(mc, dyn_tab, dest, header);
}

/**
 *
 */
static uint8_t *encode_literal_header_without_indexing(uint8_t *dest, const struct aura_iovec *name, const struct aura_iovec *value) {
    /* Literal header without indexing, pattern: | 0: | */
    *dest++ = 0;
    dest += a_hpack_encode_string(dest, name->base, name->len);
    dest += a_hpack_encode_string(dest, value->base, value->len);
    return dest;
}

int aura_hpack_load_static_table(struct aura_mem_ctx *mc) {
    struct rfc_static_tab_entry e;
    struct aura_header_field *hdr;
    struct aura_hpack_static_table *stat_tab = (struct aura_hpack_static_table *)&static_table;

    memset(stat_tab, 0, sizeof(*stat_tab));
    if (aura_intern_tab_create2(&stat_tab->intern_tab, mc, 128) < 0)
        return -1;

    for (int i = 1; i < ARRAY_SIZE(rfc_static_table); ++i) {
        e = rfc_static_table[i];
        hdr = &stat_tab->entries[i].header_field;
        memset(hdr, 0, sizeof(*hdr));

        hdr->token = lookup_token(e.name.base, e.name.len);
        hdr->name = aura_interned_str_find_or_add(&stat_tab->intern_tab, e.name.base, e.name.len);
        if (!hdr->name)
            return -1;

        hdr->value.interned = NULL;
        if (e.value.len > 0) {
            hdr->value.interned = aura_interned_str_find_or_add(&stat_tab->intern_tab, e.value.base, e.value.len);
            if (!hdr->value.interned)
                return -1;
        }

        stat_tab->entries[i].index = i;
        memset(&stat_tab->tokens[hdr->token], 0, sizeof(struct aura_token));
        if (!stat_tab->tokens[hdr->token].name) {
            stat_tab->tokens[hdr->token].name = hdr->name;
            stat_tab->tokens[hdr->token].flags = hdr->flags;

            switch (hdr->token) {
            case A_TOKEN_AUTHORIZATION:
                stat_tab->tokens[hdr->token].flags |= (A_HDR_FIELD_FLAG_NO_INDEX | A_HDR_FIELD_FLAG_NO_INTERN);
                break;

            case A_TOKEN_PATH:
            case A_TOKEN_LOCATION:
            case A_TOKEN_CONTENT_LENGTH:
            case A_TOKEN_IF_MODIFIED_SINCE:
            case A_TOKEN_ETAG:
            case A_TOKEN_AGE:
            case A_TOKEN_SET_COOKIE:
            case A_TOKEN_IF_NONE_MATCH:
            case A_TOKEN_DATE:
            case A_TOKEN_USER_AGENT:
            case A_TOKEN_EXPIRES:
                stat_tab->tokens[hdr->token].flags |= A_HDR_FIELD_FLAG_NO_INTERN;
                break;

            default:
                break;
            }
        }
    }

    return 0;
}

/*=======================*/
static inline void a_hpack_dyn_tab_init(struct aura_hpack_dyn_tab *dyn, size_t max_size) {
    memset(dyn, 0, sizeof(*dyn));
    dyn->max_size = max_size;
    dyn->hdr_tab_max_size = max_size;
}

void aura_hpack_hdr_tab_destroy(struct aura_hpack_dyn_tab *dyn_tab) {
    struct aura_hpack_tab_entry *entry;
    size_t idx;

    if (dyn_tab->cnt > 0) {
        idx = 0;
        do {
            entry = &dyn_tab->entries[idx];

            if (!entry->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                aura_free(entry->header_field.value.raw.str.base);
            }

            idx = (idx + 1) % dyn_tab->cap;
        } while (--dyn_tab->cnt > 0);
    }
    aura_free(dyn_tab->entries);
}

int aura_hpacK_decoder_init(struct aura_hpack_decoder *dec, struct aura_mem_ctx *mc, size_t tab_max_size) {
    memset(dec, 0, sizeof(*dec));
    if (aura_sliding_buf_init(&dec->recv_buf, mc, 4096, A_SLIDING_BUF_FL_NONE) < 0)
        return -1;

    a_hpack_dyn_tab_init(&dec->dyn_tab, tab_max_size);
    dec->mc = mc;
    return 0;
}

void aura_hpack_decoder_destroy(struct aura_hpack_decoder *dec) {
    aura_sliding_buf_destroy(&dec->recv_buf);
    aura_hpack_hdr_tab_destroy(&dec->dyn_tab);
}

static size_t a_hpack_count_encoded_len(size_t prefix, size_t n) {
    size_t prefix_max, len = 0;

    prefix_max = (uint8_t)((1 << prefix) - 1);
    /* can fit in one byte */
    if (n < prefix_max)
        return 1;

    len++;
    n -= prefix_max;

    while (n >= 128) {
        len++;
        n >>= 7;
    }

    return len + 1;
}

static ssize_t a_hpack_decode_len(uint8_t *src, const uint8_t *end, size_t *out, size_t *shift,
                                  size_t initial, size_t start_shift, size_t prefix, bool *done) {
    size_t prefix_max = (uint8_t)((1 << prefix) - 1);
    size_t n = initial, add;
    const uint8_t *start = src;
    uint8_t curr;

    *shift = 0, *done = false;
    /* if we are just starting */
    curr = *src++;
    if (n == 0) {
        if ((curr & prefix_max) < prefix_max) {
            *out = (curr & prefix_max);
            *done = true;
            return 1;
        }

        n = prefix_max;
        if (src > end) {
            *out = n;
            return 1;
        }
    }

    while (src <= end) {
        if (start_shift >= 64) {
            app_debug(true, 0, "decoder: shift overflow");
            return -1;
        }

        curr = *src++;
        add = curr & 0x7f;
        if (add > (UINT64_MAX >> start_shift)) {
            app_debug(true, 0, "decoder: integer overflow");
            return -1;
        }

        add <<= start_shift;

        /* if add + n > UINT64_MAX */
        if (UINT64_MAX - add < n) {
            app_debug(true, 0, "decoder: addition overflow");
            return -1;
        }

        n += add;
        /* if no more continuation */
        if ((curr & (1 << 7)) == 0)
            break;

        start_shift += 7;
    }

    *shift = start_shift;
    /* if done */
    if (src <= end) {
        *out = n;
        *done = true;
        return (ssize_t)(src - start);
    }

    *out = n;
    return (ssize_t)(src - start);
}

static size_t a_hpack_huff_get_encode_len(const uint8_t *src, size_t len) {
    size_t nbits = 0;

    for (int i = 0; i < len; ++i) {
        nbits += huff_sym_table[src[i]].nbits;
    }
    return (nbits + 7) / 8;
}

static int a_hpack_huffman_decode(struct aura_hpack_dec_recv_buf *r_buf, uint8_t *state, const uint8_t *src,
                                  size_t len, bool final, int *err) {
    const uint8_t *end;
    uint8_t c;
    const nghttp2_huff_decode entry = {*state, 0x00, 0}, *e = &entry;

    *err = 0;
    end = src + len;
    for (; src < end; ++src) {
        c = *src;
        e = &huff_decode_table[e->state][c >> 4];
        if (e->flags & NGHTTP2_HUFF_SYM) {
            r_buf->base[r_buf->len++] = e->sym;
            *err |= (e->flags & NGHTTP2_HUFF_INVALID_CHARS);
        }

        e = &huff_decode_table[e->state][c & 0xf];
        if (e->flags & NGHTTP2_HUFF_SYM) {
            r_buf->base[r_buf->len++] = e->sym;
            *err |= (e->flags & NGHTTP2_HUFF_INVALID_CHARS);
        }
    }

    *state = e->state;

    if (final && !(e->flags & NGHTTP2_HUFF_ACCEPTED))
        return A_HPACK_COMPRESSION_ERR;

    return A_HPACK_OK;
}

/* Update current table size to new value */
static inline void aura_hpack_dyn_tab_update_curr_size(struct aura_hpack_dyn_tab *tab, size_t max_size) {
    tab->max_size = max_size;
    a_hpack_dyn_tab_shrink(tab);
}

void aura_hpack_enc_update_tab_settings_sz(struct aura_hpack_encoder *enc, size_t max_size) {
    if (enc->dyn_tab.hdr_tab_max_size > max_size)
        a_hpack_dyn_tab_shrink(&enc->dyn_tab);

    enc->send_table_size_update = true;
    enc->dyn_tab.hdr_tab_max_size = max_size;
}

void aura_hpack_dec_update_tab_settings_sz(struct aura_hpack_decoder *dec, size_t max_size) {
    if (dec->dyn_tab.hdr_tab_max_size > max_size) {
        a_hpack_dyn_tab_shrink(&dec->dyn_tab);
        /* Only expect table size updates for decreasing changes */
        dec->state = A_HPACK_STATE_EXPECT_TAB_SIZE_UPDATE;
    }
    dec->dyn_tab.hdr_tab_max_size = max_size;
}

static ssize_t a_hpack_len_read(struct aura_hpack_decoder *dec, const uint8_t *src,
                                const uint8_t *end, size_t maxlen, bool *done) {
    size_t out;
    int rv;

    /* call internal */
    rv = a_hpack_decode_len((uint8_t *)src, end, &out, &dec->shift, dec->len, dec->shift, dec->prefix, done);
    if (rv < 0)
        return A_HPACK_COMPRESSION_ERR;

    if (out > maxlen) {
        /* compression error*/
        return A_HPACK_COMPRESSION_ERR;
    }

    dec->len = out;
    return rv;
}

static ssize_t a_hpack_huff_read(struct aura_hpack_decoder *dec, struct aura_hpack_dec_recv_buf *r_buf,
                                 const uint8_t *in, const uint8_t *end) {
    size_t len;
    bool final;
    int rv, err;

    final = false;
    len = end - in;
    /* if str source contains entire len to decode */
    if (len >= dec->len) {
        len = dec->len;
        final = true;
    }

    rv = a_hpack_huffman_decode(r_buf, &dec->huff_state, in, len, final, &err);
    if (rv < 0)
        return rv;

    /* update len to reflect how many bytes are left to decode */
    dec->len -= len;
    return len;
}

static ssize_t a_hpack_normal_read(struct aura_hpack_decoder *dec, struct aura_hpack_dec_recv_buf *r_buf,
                                   const uint8_t *in, const uint8_t *end) {
    size_t len = a_min(dec->len, (end - in));

    memcpy(r_buf->base + r_buf->len, in, len);
    r_buf->len += len;
    dec->len -= len;
    return len;
}

static inline const struct aura_hpack_tab_entry *a_hpack_get_tab_entry(const struct aura_hpack_static_table *static_tab,
                                                                       struct aura_hpack_dyn_tab *dyn_tab, size_t idx) {
    if (likely(idx < A_HPACK_DYNAMIC_TAB_HEADER_OFFSET))
        return aura_hpack_static_tab_get_entry(static_tab, idx);
    else
        return aura_hpack_dyn_header_tab_get_entry(dyn_tab, idx);
}

static int a_hpack_validate_header(struct aura_header_field *hdr) {
    const uint8_t *name, *value;
    size_t n_len, v_len;
    int rv;

    name = hdr->name->data;
    n_len = hdr->name->len;

    if (n_len == 0)
        return A_HPACK_COMPRESSION_ERR;
    /* pseudo-headers are checked later */
    if (!aura_hpack_is_pseudo_header(name)) {
        rv = a_hpack_validate_header_name(name, n_len);
        if (rv != A_HPACK_OK)
            return rv;
    }

    /* value check */
    if (hdr->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
        value = hdr->value.interned->data;
        v_len = hdr->value.interned->len;
    } else {
        value = hdr->value.raw.str.base;
        v_len = hdr->value.raw.str.len;
    }

    return a_hpack_validate_header_value(value, v_len);
}

static inline int a_hpack_emit_hdr_indexed(struct aura_hpack_dyn_tab *dyn_tab,
                                           struct aura_header_field *hdr, size_t idx) {
    const struct aura_hpack_tab_entry *e = a_hpack_get_tab_entry(&static_table, dyn_tab, idx);

    *hdr = (e->header_field);
    hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
    return a_hpack_validate_header(hdr);
}

static int a_hpack_emit_new_name(struct aura_hpack_decoder *dec,
                                 struct aura_header_field *hdr,
                                 struct aura_intern_tab *intern_tab) {
    struct aura_interned_str *name, *value;
    struct aura_hpack_dec_recv_buf *r_name, *r_value;
    bool should_intern_value;
    int rv;

    // app_debug(true, 0, "a_hpack_emit_new_name >>>>");
    memset(hdr, 0, sizeof(*hdr));
    /* intern all names */
    r_name = &dec->name_recv_buf;
    name = aura_interned_str_find_or_add(intern_tab, r_name->base, r_name->len);
    if (!name) {
        return A_HPACK_INTERNAL_ERR;
    }
    hdr->name = name;
    hdr->token = lookup_token(r_name->base, r_name->len);

    if (dec->never_indexed) {
        hdr->flags |= A_HDR_FIELD_FLAG_NO_INDEX;
    }

    r_value = &dec->value_recv_buf;
    should_intern_value = r_value->len > 0 && r_value->len <= 64 && !(hdr->flags & A_HDR_FIELD_FLAG_NO_INTERN);

    if (r_value->len == 0)
        goto out;

    /* Try and get in static intern table */
    value = aura_interned_str_find((struct aura_intern_tab *)&static_table.intern_tab, r_value->base, r_value->len);
    if (value) {
        hdr->value.interned = value;
        hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
        goto out;
    }

    if (should_intern_value)
        value = aura_interned_str_find_or_add(intern_tab, r_value->base, r_value->len);
    else
        value = aura_interned_str_find(intern_tab, r_value->base, r_value->len);

    if (value) {
        /* switch to interned value  */
        hdr->value.interned = value;
        hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
    } else {
        hdr->value.raw.str.base = aura_strndup(dec->mc, r_value->base, r_value->len);
        hdr->value.raw.str.len = r_value->len;

        /* No one yet have reference to raw string just created */
        hdr->value.raw.ref_cnt = 0;
    }

    if (dec->new_tab_insert) {
        rv = a_hpack_dyn_tab_add_new_entry2(dec->mc, &dec->dyn_tab, hdr);
        if (rv < 0)
            return rv;
    }

out:
    /* consume decoder buffer (+2 for NULL termination) */
    aura_sliding_buf_consume(&dec->recv_buf, (r_name->reserved + r_value->reserved));
    aura_hpack_reset_name_value_recv_buf(dec);

    return a_hpack_validate_header(hdr);
}

static int a_hpack_emit_indexed_name(struct aura_hpack_decoder *dec,
                                     struct aura_header_field *hdr,
                                     struct aura_intern_tab *intern_tab) {
    const struct aura_hpack_tab_entry *e;
    struct aura_interned_str *value;
    struct aura_hpack_dec_recv_buf *r_value;
    bool should_intern_value;
    int rv;

    memset(hdr, 0, sizeof(*hdr));
    /* intern all names */
    e = a_hpack_get_tab_entry(&static_table, &dec->dyn_tab, dec->index);
    hdr->name = e->header_field.name;
    hdr->token = e->header_field.token;
    hdr->flags = e->header_field.flags;
    hdr->flags |= static_table.tokens[hdr->token].flags;

    if (dec->never_indexed) {
        hdr->flags |= A_HDR_FIELD_FLAG_NO_INDEX;
    }

    r_value = &dec->value_recv_buf;
    should_intern_value = r_value->len > 0 && r_value->len <= 64 && !(hdr->flags & A_HDR_FIELD_FLAG_NO_INTERN);

    /* try getting value in static intern table */
    value = aura_interned_str_find((struct aura_intern_tab *)&static_table.intern_tab, r_value->base, r_value->len);
    if (value) {
        hdr->value.interned = value;
        hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
        goto out;
    }

    if (should_intern_value)
        value = aura_interned_str_find_or_add(intern_tab, r_value->base, r_value->len);
    else
        value = aura_interned_str_find(intern_tab, r_value->base, r_value->len);

    if (value) {
        /* switch to interned value  */
        hdr->value.interned = value;
        hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
    } else {
        /* fallback to raw string */
        hdr->value.raw.str.base = aura_strndup(dec->mc, r_value->base, r_value->len);
        hdr->value.raw.str.len = r_value->len;

        /* No one yet have reference to raw string just created */
        hdr->value.raw.ref_cnt = 0;
    }

    if (dec->new_tab_insert) {
        rv = a_hpack_dyn_tab_add_new_entry2(dec->mc, &dec->dyn_tab, hdr);
        if (rv < 0)
            return rv;
    }

out:
    /* consume decoder buffer (+1 for NULL terminator) */
    aura_sliding_buf_consume(&dec->recv_buf, r_value->reserved);
    aura_hpack_reset_name_value_recv_buf(dec);

    return a_hpack_validate_header(hdr);
}

static inline int aura_hpack_decoder_recv_buf_reserve(struct aura_sliding_buf *buf, size_t len,
                                                      struct aura_hpack_dec_recv_buf *r_buf) {

    if (!aura_sliding_buf_ensure_cap(buf, len))
        return A_HPACK_INTERNAL_ERR;

    r_buf->base = aura_sliding_buf_write_ptr(buf);
    r_buf->len = 0;
    r_buf->reserved = len;
    aura_sliding_buf_commit(buf, len);

    return A_HPACK_OK;
}

ssize_t aura_hpack_decode(struct aura_hpack_decoder *dec, const uint8_t *src_in,
                          const uint8_t *end, struct aura_intern_tab *intern_tab,
                          struct aura_header_field *hdr, bool final) {
    const uint8_t *start = src_in;
    uint8_t c;
    bool done, busy = false, should_intern_value;
    int rv;

    if (dec->err_state) {
        return A_HPACK_COMPRESSION_ERR;
    }

    dec->flags = 0;
    while (src_in != end || busy) {
        // aura_hpack_dec_dump(dec);
        busy = false;
        switch (dec->state) {
        case A_HPACK_STATE_EXPECT_TAB_SIZE_UPDATE:
            c = *src_in;
            app_debug(true, 0, "Expecting table update");
            if (!aura_hpack_bin_fmt_hdr_tab_update(c)) {
                rv = A_HPACK_COMPRESSION_ERR;
                goto err;
            }
            /* fall throhugh */
        case A_HPACK_STATE_DECODE_START:
        case A_HPACK_STATE_OP_CODE:
            c = *src_in;
            if (aura_hpack_bin_fmt_hdr_tab_update(c)) {
                app_debug(true, 0, "decoding bin format table update");
                if (dec->state == A_HPACK_STATE_OP_CODE) {
                    rv = A_HPACK_COMPRESSION_ERR;
                    goto err;
                }
                dec->opcode = A_HPACK_OP_CODE_INDEXED;
                dec->state = A_HPACK_STATE_READ_TAB_SIZE_UPDATE;
                dec->prefix = 5;
            } else if (aura_hpack_bin_fmt_indexed_field(c)) {
                app_debug(true, 0, "decoding bin format indexed field:");
                dec->opcode = A_HPACK_OP_CODE_INDEXED;
                dec->state = A_HPACK_STATE_READ_INDEX;
                dec->prefix = 7;
            } else {
                if (aura_hpack_bin_fmt_new_name(c)) {
                    app_debug(true, 0, "decoding new name");
                    dec->opcode = A_HPACK_OP_CODE_NEW_NAME;
                    dec->state = A_HPACK_STATE_READ_NEW_NAME_LEN;
                    src_in++;
                } else {
                    app_debug(true, 0, "decoding indexed name");
                    dec->opcode = A_HPACK_OP_CODE_INDEXED_NAME;
                    dec->state = A_HPACK_STATE_READ_INDEX;
                }
                dec->new_tab_insert = aura_hpack_insert_new_tab_entry(c);
                dec->never_indexed = (c & 0xf0) == 0x10;
                if (dec->new_tab_insert)
                    dec->prefix = 6;
                else
                    dec->prefix = 4;
            }
            dec->len = 0;
            dec->shift = 0;
            break;

        case A_HPACK_STATE_READ_TAB_SIZE_UPDATE:
            done = false;
            rv = a_hpack_len_read(dec, src_in, end, a_min(dec->dyn_tab.max_size, dec->dyn_tab.hdr_tab_max_size), &done);
            if (rv < 0)
                goto err;

            src_in += rv;
            if (!done) {
                goto ok;
            }

            aura_hpack_dyn_tab_update_curr_size(&dec->dyn_tab, dec->len);
            // dec->dyn_tab.max_size = dec->len;

            // /* shrink table */
            // while (dec->dyn_tab.cnt != 0 && dec->dyn_tab.tab_size > dec->dyn_tab.max_size)
            //     aura_hpack_header_table_evict_one(&dec->dyn_tab);
            /**
             * RFC says update is always before first
             * header, so we can safely set state to start
             */
            dec->state = A_HPACK_STATE_DECODE_START;
            break;

        case A_HPACK_STATE_READ_INDEX:
            done = false;
            rv = a_hpack_len_read(dec, src_in, end, a_hpack_get_max_index(&dec->dyn_tab), &done);
            if (rv < 0)
                goto err;

            src_in += rv;
            if (!done)
                goto ok;

            /* invalid index */
            if (aura_hpack_tab_index_invalid(&dec->dyn_tab, dec->len)) {
                rv = A_HPACK_COMPRESSION_ERR;
                goto err;
            }

            /* Indexed header field */
            if (dec->opcode == A_HPACK_OP_CODE_INDEXED) {
                dec->index = dec->len;
                /* emit header field */
                rv = a_hpack_emit_hdr_indexed(&dec->dyn_tab, hdr, dec->index);
                if (rv < 0)
                    if (aura_hpack_hdr_err_fatal(rv))
                        goto err;
                    else {
                        aura_hpack_set_decoder_soft_err(dec, rv);
                    }

                dec->state = A_HPACK_STATE_OP_CODE;
                dec->flags |= A_HDR_FIELD_FLAG_EMIT;
                return (src_in - start);
            } else {
                /* indexed name */
                dec->index = dec->len;
                dec->state = A_HPACK_STATE_READ_VALUE_LEN;
            }
            break;

        case A_HPACK_STATE_READ_NEW_NAME_LEN:
            done = false;
            aura_hpack_decoder_reset_for_new_len(dec, *src_in);
            rv = a_hpack_len_read(dec, src_in, end, A_HPACK_MAX_HDR_NV_SZ, &done);
            if (rv < 0)
                goto err;

            src_in += rv;
            if (!done) {
                goto ok;
            }

            if (dec->huff_encoded) {
                /* init huffman decoder ctx */
                aura_hpack_init_huff_decode_ctx(dec);
                dec->state = A_HPACK_STATE_READ_NEW_NAME_HUFF;
                /**
                 * huffman 'safe and simple' estimate for actual string
                 * len is len * 2, +1 for null termination
                 */
                rv = aura_hpack_decoder_recv_buf_reserve(&dec->recv_buf, dec->len * 2 + 1, &dec->name_recv_buf);
            } else {
                dec->state = A_HPACK_STATE_READ_NEW_NAME;
                /* reserve space in sliding_buf for name */
                rv = aura_hpack_decoder_recv_buf_reserve(&dec->recv_buf, dec->len + 1, &dec->name_recv_buf);
            }

            if (rv < 0)
                goto err;
            break;

        case A_HPACK_STATE_READ_NEW_NAME_HUFF:
            rv = a_hpack_huff_read(dec, &dec->name_recv_buf, src_in, end);
            if (rv < 0)
                goto err;

            src_in += rv;

            /* still has more bytes to consume */
            if (dec->len > 0) {
                goto ok;
            }

            dec->name_recv_buf.base[dec->name_recv_buf.len] = '\0';

            dec->state = A_HPACK_STATE_READ_VALUE_LEN;
            break;

        case A_HPACK_STATE_READ_NEW_NAME:
            rv = a_hpack_normal_read(dec, &dec->name_recv_buf, src_in, end);
            src_in += rv;

            if (dec->len > 0)
                goto ok;

            dec->name_recv_buf.base[dec->name_recv_buf.len] = '\0';

            dec->state = A_HPACK_STATE_READ_VALUE_LEN;
            break;

        case A_HPACK_STATE_READ_VALUE_LEN:
            done = false;
            aura_hpack_decoder_reset_for_new_len(dec, *src_in);
            rv = a_hpack_len_read(dec, src_in, end, A_HPACK_MAX_HDR_NV_SZ, &done);
            if (rv < 0)
                goto err;

            src_in += rv;
            if (!done) {
                goto ok;
            }

            if (dec->len == 0) {
                dec->value_recv_buf.base = NULL;
                dec->value_recv_buf.len = 0;
                dec->value_recv_buf.reserved = 0;
                /* emit decoded header value */
                if (dec->opcode == A_HPACK_OP_CODE_NEW_NAME) {
                    /* emit new name */
                    rv = a_hpack_emit_new_name(dec, hdr, intern_tab);
                } else {
                    /* emit indexed name */
                    rv = a_hpack_emit_indexed_name(dec, hdr, intern_tab);
                }

                if (rv < 0)
                    if (aura_hpack_hdr_err_fatal(rv))
                        goto err;
                    else {
                        aura_hpack_set_decoder_soft_err(dec, rv);
                    }

                return (src_in - start);
            }

            if (dec->huff_encoded) {
                /* init huffman decoder ctx */
                aura_hpack_init_huff_decode_ctx(dec);
                dec->state = A_HPACK_STATE_READ_VALUE_HUFF;
                /**
                 * huffman 'safe and simple' estimate for actual string
                 * len is len * 2, +1 for null termination
                 */
                rv = aura_hpack_decoder_recv_buf_reserve(&dec->recv_buf, dec->len * 2 + 1, &dec->value_recv_buf);
            } else {
                dec->state = A_HPACK_STATE_READ_VALUE;
                /* reserve space in sliding_buf for name */
                rv = aura_hpack_decoder_recv_buf_reserve(&dec->recv_buf, dec->len + 1, &dec->value_recv_buf);
            }

            if (rv < 0)
                goto err;
            break;

        case A_HPACK_STATE_READ_VALUE_HUFF:
            rv = a_hpack_huff_read(dec, &dec->value_recv_buf, src_in, end);
            if (rv < 0)
                goto err;

            src_in += rv;

            /* still has to read more bytes */
            if (dec->len)
                goto ok;

            dec->value_recv_buf.base[dec->value_recv_buf.len] = '\0';

            /* emit decoded header value */
            if (dec->opcode == A_HPACK_OP_CODE_NEW_NAME) {
                /* emit new name */
                rv = a_hpack_emit_new_name(dec, hdr, intern_tab);
            } else {
                /* emit indexed name */
                rv = a_hpack_emit_indexed_name(dec, hdr, intern_tab);
            }

            if (rv < 0)
                if (aura_hpack_hdr_err_fatal(rv))
                    goto err;
                else {
                    aura_hpack_set_decoder_soft_err(dec, rv);
                }

            dec->state = A_HPACK_STATE_OP_CODE;
            dec->flags |= A_HDR_FIELD_FLAG_EMIT;
            return (src_in - start);

        case A_HPACK_STATE_READ_VALUE:
            rv = a_hpack_normal_read(dec, &dec->value_recv_buf, src_in, end);
            src_in += rv;

            if (dec->len > 0)
                goto ok;

            dec->value_recv_buf.base[dec->value_recv_buf.len] = '\0';

            /* emit decoded header value */
            if (dec->opcode == A_HPACK_OP_CODE_NEW_NAME) {
                /* emit new name */
                rv = a_hpack_emit_new_name(dec, hdr, intern_tab);
            } else {
                /* emit indexed name */
                rv = a_hpack_emit_indexed_name(dec, hdr, intern_tab);
            }

            if (rv < 0)
                if (aura_hpack_hdr_err_fatal(rv))
                    goto err;
                else {
                    aura_hpack_set_decoder_soft_err(dec, rv);
                }

            dec->state = A_HPACK_STATE_OP_CODE;
            dec->flags |= A_HDR_FIELD_FLAG_EMIT;
            return (src_in - start);

        default:
            /* nothing */
        }
    }
    A_BUG_ON_2(src_in != end, true);

    if (final) {
        switch (dec->state) {
        case A_HPACK_STATE_DECODE_START:
        case A_HPACK_STATE_OP_CODE:
            break;
        default:
            rv = A_HPACK_COMPRESSION_ERR;
            goto err;
        }

        /* final */
        dec->flags |= A_HDR_FIELD_FLAG_FINAL;
        return (src_in - start);
    }

ok:
    /* Failed to decode peer */
    if (final) {
        rv = A_HPACK_COMPRESSION_ERR;
        goto err;
    }
    return (src_in - start);
err:
    dec->err_state = true;
    return rv;
}

int aura_hpack_encoder_init(struct aura_hpack_encoder *enc, struct aura_mem_ctx *mc, size_t max_size) {
    memset(enc, 0, sizeof(*enc));
    a_hpack_dyn_tab_init(&enc->dyn_tab, max_size);
    enc->mc = mc;
    if (aura_sliding_buf_init(&enc->enc_buf, mc, 4096, A_SLIDING_BUF_FL_NONE) < 0)
        return -1;

    if (max_size < A_HPACK_INITIAL_SETTINGS_HDR_SZ)
        enc->send_table_size_update = true;

    return 0;
}

void aura_hpack_encoder_destroy(struct aura_hpack_encoder *enc) {
    aura_sliding_buf_destroy(&enc->enc_buf);
    aura_hpack_hdr_tab_destroy(&enc->dyn_tab);
}

static void a_hpack_search_static_table2(struct aura_header_field *nv, bool name_only,
                                         uint32_t *index, bool *exact_match) {
    const struct aura_hpack_tab_entry *e;
    size_t n;

    for (int i = 1; i < A_HPACK_DYNAMIC_TAB_HEADER_OFFSET; ++i) {
        e = &static_table.entries[i];
        if (e->header_field.token == nv->token) {
            *index = i;

            if (name_only)
                break;

            if ((nv->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)) {
                if (e->header_field.value.interned == nv->value.interned) {
                    *exact_match = true;
                    break;
                }
            } else {
                if (aura_mem_is_eq(nv->value.raw.str.base, nv->value.raw.str.len, e->header_field.value.raw.str.base, e->header_field.value.raw.str.len)) {
                    *exact_match = true;
                    break;
                }
            }
        }
    }
}

static void a_hpack_search_dyn_tab2(struct aura_hpack_dyn_tab *dyn_tab,
                                    struct aura_header_field *hdr, bool name_only,
                                    uint32_t *index, bool *exact_match) {
    struct aura_hpack_tab_entry *e;

    for (int i = 0; i < dyn_tab->cnt; ++i) {
        e = &dyn_tab->entries[i];

        if (hdr->name == e->header_field.name) {
            *index = i + A_HPACK_DYNAMIC_TAB_HEADER_OFFSET;
            if (name_only)
                break;

            if (e->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                if (hdr->value.interned == e->header_field.value.interned) {
                    *exact_match = true;
                    break;
                }
            } else {
                if (aura_mem_is_eq(hdr->value.raw.str.base, hdr->value.raw.str.len, e->header_field.value.raw.str.base, e->header_field.value.raw.str.len)) {
                    *exact_match = true;
                    break;
                }
            }
        }
    }
}

static a_hpack_indexing_mode a_hpack_get_indexing_mode(size_t name_len, size_t value_len,
                                                       int token, int flags, size_t hdr_tab_size) {
    a_hpack_indexing_mode indexing_mode;

    if (flags & A_HDR_FIELD_FLAG_NO_INDEX)
        indexing_mode = A_HPACK_HDR_FIELD_NEVER_INDEXED;
    else {
        switch (token) {
        case A_TOKEN_PATH:
        case A_TOKEN_LOCATION:
        case A_TOKEN_CONTENT_LENGTH:
        case A_TOKEN_IF_MODIFIED_SINCE:
        case A_TOKEN_ETAG:
        case A_TOKEN_AGE:
        case A_TOKEN_SET_COOKIE:
        case A_TOKEN_IF_NONE_MATCH:
        case A_TOKEN_DATE:
        case A_TOKEN_USER_AGENT:
            indexing_mode = A_HPACK_HDR_FIELD_WITHOUT_INDEXING;
            break;
        default:
            if (aura_hpack_hdr_entry_size(name_len, value_len) > hdr_tab_size * 3 / 4)
                indexing_mode = A_HPACK_HDR_FIELD_WITHOUT_INDEXING;
            else
                indexing_mode = A_HPACK_HDR_FIELD_WITH_INDEXING;
        }
    }

    return indexing_mode;
}

static a_hpack_indexing_mode a_hpack_determine_bin_fmt(struct aura_hpack_static_table *static_tab,
                                                       struct aura_hpack_dyn_tab *dyn_tab,
                                                       struct aura_header_field *hdr, int *index) {
    size_t name_len, value_len;
    bool name_only = false, is_exact_match = false;
    a_hpack_indexing_mode ind_mode;

    name_len = hdr->name->len;
    if (hdr->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
        value_len = hdr->value.interned->len;
    else
        value_len = hdr->value.raw.str.len;

    ind_mode = a_hpack_get_indexing_mode(name_len, value_len, hdr->token, hdr->flags, dyn_tab->max_size);
    name_only = ind_mode == A_HPACK_HDR_FIELD_NEVER_INDEXED;

    *index = 0;
    if (aura_hpack_is_static_table_token(hdr->token)) {
        a_hpack_search_static_table2(hdr, name_only, index, &is_exact_match);
    } else {
        a_hpack_search_dyn_tab2(dyn_tab, hdr, name_only, index, &is_exact_match);
    }

    if (is_exact_match)
        return A_HPACK_INDEXED_HDR_FIELD;

    return ind_mode;
}

static inline uint8_t a_hpack_pack_binary_fmt(a_hpack_indexing_mode ind_mode) {
    switch (ind_mode) {
    case A_HPACK_HDR_FIELD_WITH_INDEXING:
        return 0x40u;
    case A_HPACK_HDR_FIELD_WITHOUT_INDEXING:
        return 0;
    case A_HPACK_HDR_FIELD_NEVER_INDEXED:
        return 0x10u;
    default:
        return 0;
    }
}

static size_t a_hpack_encode_len(uint8_t *dest, size_t prefix, size_t n) {
    uint8_t prefix_max = (uint8_t)((1 << prefix) - 1);
    uint8_t *start = dest;

    *dest = (uint8_t)(*dest & ~prefix_max);
    /* can fit in one byte */
    if (n < prefix_max) {
        *dest = (uint8_t)(*dest | n);
        return 1;
    }

    *dest++ = (uint8_t)(*dest | prefix_max);
    n -= prefix_max;

    while (n >= 128) {
        *dest++ = (uint8_t)((1 << 7) | (n & 0x7f));
        n >>= 7;
    }
    /* add final bytes of n */
    *dest++ = (uint8_t)n;

    return (size_t)(dest - start);
}

static inline size_t a_hpack_string_encode(uint8_t *dest, const char *s, size_t len) {
    uint8_t *start = dest;
    memcpy(dest, s, len);
    dest += len;
    return dest - start;
}

static size_t a_hpack_encode_string2(uint8_t *dest, size_t dest_len, const uint8_t *str, size_t len) {
    uint8_t *start = dest;
    size_t enc_len;
    bool huffman = false;
    int rv;

    enc_len = a_hpack_huff_get_encode_len(str, len);
    if (enc_len < len) {
        huffman = true;
    } else
        enc_len = len;

    *dest = huffman ? 1 << 7 : 0;
    dest += a_hpack_encode_len(dest, 7, enc_len);

    if (huffman)
        dest += a_hpack_huffman_encode3(dest, dest_len, str, len);
    else
        dest += a_hpack_string_encode(dest, str, len);

    return dest - start;
}

static inline int a_hpack_encode_tab_size_update(struct aura_sliding_buf *buf, size_t tab_size) {
    uint8_t *dest, tab_update[] = {0x20};
    uint8_t *start;
    size_t enc_len;

    enc_len = a_hpack_count_encoded_len(5, tab_size);
    /* If enc_len > 5 bytes (arbitrary safe value) */
    if (enc_len > 5)
        return A_HPACK_COMPRESSION_ERR;

    dest = aura_sliding_buf_write_ptr(buf);
    start = dest;
    *dest = 0x20u;
    dest += a_hpack_encode_len(dest, 5, tab_size);

    aura_sliding_buf_commit(buf, dest - start);
    return A_HPACK_OK;
}

static inline size_t a_hpack_encode_indexed_block(uint8_t *dest, size_t idx) {
    *dest = 0x80u;
    return a_hpack_encode_len(dest, 7, idx);
}

static size_t a_hpack_encode_indexed_name(uint8_t *dest, size_t dest_len, size_t idx,
                                          struct aura_iovec *value, a_hpack_indexing_mode ind_mode) {
    size_t prefix;
    uint8_t *start = dest;

    if (ind_mode == A_HPACK_HDR_FIELD_WITH_INDEXING) {
        prefix = 6;
    } else
        prefix = 4;

    *dest = a_hpack_pack_binary_fmt(ind_mode);
    dest += a_hpack_encode_len(dest, prefix, idx);

    dest += a_hpack_encode_string2(dest, dest_len, value->base, value->len);

    return dest - start;
}

static size_t a_hpack_encode_new_name(uint8_t *dest, size_t dest_len, struct aura_iovec *name,
                                      struct aura_iovec *value, a_hpack_indexing_mode ind_mode) {
    uint8_t *start = dest;

    *dest++ = a_hpack_pack_binary_fmt(ind_mode);
    dest += a_hpack_encode_string2(dest, dest_len, name->base, name->len);
    dest += a_hpack_encode_string2(dest, dest_len, value->base, value->len);

    return dest - start;
}

static int a_hpack_encode_header(struct aura_hpack_encoder *enc, struct aura_header_field *hdr) {
    uint8_t *dest;
    size_t dest_len, hdr_size, rv;
    struct aura_iovec name, value;
    bool name_only = false, is_exact_match = false;
    a_hpack_indexing_mode ind_mode;
    uint32_t index;
    uint16_t token;

    index = 0;
    name.base = (char *)hdr->name->data;
    name.len = hdr->name->len;
    if (hdr->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
        value.base = (char *)hdr->value.interned->data;
        value.len = hdr->value.interned->len;
    } else {
        value.base = hdr->value.raw.str.base;
        value.len = hdr->value.raw.str.len;
    }

    ind_mode = a_hpack_get_indexing_mode(name.len, value.len, hdr->token, hdr->flags, enc->dyn_tab.max_size);
    name_only = (ind_mode == A_HPACK_HDR_FIELD_NEVER_INDEXED);

    if (aura_hpack_is_static_table_token(hdr->token)) {
        a_hpack_search_static_table2(hdr, name_only, &index, &is_exact_match);
    } else {
        a_hpack_search_dyn_tab2(&enc->dyn_tab, hdr, name_only, &index, &is_exact_match);
    }

    hdr_size = aura_hpack_hdr_entry_size(name.len, value.len);
    if (!aura_sliding_buf_ensure_cap(&enc->enc_buf, hdr_size))
        return A_HPACK_INTERNAL_ERR;

    dest = aura_sliding_buf_write_ptr(&enc->enc_buf);
    dest_len = aura_sliding_buf_write_len(&enc->enc_buf);

    if (is_exact_match) {
        rv = a_hpack_encode_indexed_block(dest, index);
        aura_sliding_buf_commit(&enc->enc_buf, rv);
        return A_HPACK_OK;
    }

    if (index != 0) {
        rv = a_hpack_encode_indexed_name(dest, dest_len, index, &value, ind_mode);
    } else {
        rv = a_hpack_encode_new_name(dest, dest_len, &name, &value, ind_mode);
    }
    aura_sliding_buf_commit(&enc->enc_buf, rv);

    if (ind_mode == A_HPACK_HDR_FIELD_WITH_INDEXING) {
        rv = a_hpack_dyn_tab_add_new_entry2(enc->mc, &enc->dyn_tab, hdr);
        if (rv < 0)
            return rv;
    }

    return A_HPACK_OK;
}

static void a_hpack_header_find_or_create2(struct aura_header_field *hdr, struct aura_intern_tab *intern_tab,
                                           uint8_t *name, size_t name_len, uint8_t *val, size_t val_len,
                                           bool should_intern_name, bool should_intern_value) {
    const struct aura_hpack_tab_entry *e;
    int token;
    bool name_match_found, value_match_found;

    token = lookup_token(name, name_len);
    name_match_found = false;
    value_match_found = false;

    memset(hdr, 0, sizeof(*hdr));
    hdr->token = token;
    /* static table entry */
    if (aura_hpack_is_static_table_token(token)) {
        hdr->name = static_table.tokens[token].name;
        hdr->flags = static_table.tokens[token].flags;
        /* check for value in static intern table first */
        hdr->value.interned = aura_interned_str_find((struct aura_intern_tab *)&static_table.intern_tab, val, val_len);
        if (hdr->value.interned) {
            hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
            return;
        }
    } else {
        /**
         * name is not in static table if no matching token found.
         * so try dynamic intern table
         */
        /* if name should be interned */
        if (should_intern_name) {
            hdr->name = aura_interned_str_find_or_add(intern_tab, name, name_len);
        } else {
            hdr->name = aura_interned_str_find(intern_tab, name, name_len);
        }
        hdr->flags = 0;

        /* fallback to raw string */
        if (!hdr->name) {
            /**/
        }
    }

    /**
     * We know here value can only be found in dynamic intern table,
     * so try getting value in dynamic intern table
     */
    if (should_intern_value)
        hdr->value.interned = aura_interned_str_find_or_add(intern_tab, val, val_len);
    else
        hdr->value.interned = aura_interned_str_find(intern_tab, val, val_len);
    if (hdr->value.interned) {
        hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
        return;
    }

    /* fallback to raw string */
    hdr->value.raw.str.base = aura_strndup(intern_tab->mc, val, val_len);
    hdr->value.raw.str.len = val_len;
}

int aura_hpack_encoder_adjust_tab_size(struct aura_hpack_encoder *enc) {
    int rv;

    if (enc->send_table_size_update) {
        enc->send_table_size_update = 0;

        rv = a_hpack_encode_tab_size_update(&enc->enc_buf, enc->dyn_tab.max_size);
        if (rv < 0) {
            return rv;
        }
    }

    return A_HPACK_OK;
}

/**
 *
 */
int aura_hpack_encode_method(struct aura_hpack_encoder *enc,
                             struct aura_intern_tab *intern_tab,
                             struct aura_iovec value) {
    uint8_t *dest;
    size_t dest_len;
    int rv;

    dest = aura_sliding_buf_read_ptr(&enc->enc_buf);
    if (aura_mem_is_eq(value.base, value.len, str_lit("GET"))) {
        /* direct static table */
        *dest = 0x82;
        aura_sliding_buf_commit(&enc->enc_buf, 1);
        return 0;
    }

    if (aura_mem_is_eq(value.base, value.len, str_lit("POST"))) {
        /* direct static table */
        *dest = 0x83;
        aura_sliding_buf_commit(&enc->enc_buf, 1);
        return 0;
    }

    struct aura_header_field header;
    a_hpack_header_find_or_create2(&header, intern_tab, str_lit(":method"), value.base, value.len, true, true);
    return a_hpack_encode_header(enc, &header);
}

int aura_hpack_encode_status(struct aura_hpack_encoder *enc,
                             int status) {
    A_BUG_ON_2(status < 100 || status > 999, true);
    uint8_t *dest, *start;
    int rv;

    dest = aura_sliding_buf_write_ptr(&enc->enc_buf);
    start = dest;
    switch (status) {
#define COMMON_CODE(code, st)  \
    case st:                   \
        *dest++ = 0x80 | code; \
        break;
        COMMON_CODE(8, 200);
        COMMON_CODE(9, 204);
        COMMON_CODE(10, 206);
        COMMON_CODE(11, 304);
        COMMON_CODE(12, 400);
        COMMON_CODE(13, 404);
        COMMON_CODE(14, 500);
#undef COMMON_CODE
    default:
        /* use literal header field without indexing - indexed name */
        *dest++ = 8;
        *dest++ = 3;
        sprintf((char *)dest, "%d", status);
        dest += 3;
        break;
    }

    aura_sliding_buf_commit(&enc->enc_buf, dest - start);
    return 0;
}

/** @todo: ensure that the enc->buf has enough space */
int aura_hpack_encode_content_length(struct aura_hpack_encoder *enc,
                                     size_t value) {
    char buf[32];
    char *p = buf + sizeof(buf);
    size_t l;
    uint8_t *dest, *start;

    do {
        *--p = '0' + value % 10;
    } while ((value /= 10) != 0);
    l = buf + sizeof(buf) - p;

    dest = aura_sliding_buf_write_ptr(&enc->enc_buf);
    start = dest;
    *dest++ = 0x0f; /* 15 */
    *dest++ = 0x0d; /* + 13 = 28(index) */
    *dest++ = (uint8_t)l;
    memcpy(dest, p, l);
    dest += l;

    aura_sliding_buf_commit(&enc->enc_buf, dest - start);
    return A_HPACK_OK;
}

int aura_hpack_encode_headers(struct aura_hpack_encoder *enc, struct aura_intern_tab *intern_tab,
                              struct aura_basic_header *hdr_field, size_t hdr_cnt) {
    bool should_intern_value;
    uint8_t *dest;
    size_t dest_len, hdr_size = 0;
    int rv;

    // aura_hpack_enc_dump(enc);
    // if (enc->err_state)
    //     return A_HPACK_COMPRESSION_ERR;

    if (enc->send_table_size_update) {
        enc->send_table_size_update = 0;

        rv = a_hpack_encode_tab_size_update(&enc->enc_buf, enc->dyn_tab.max_size);
        if (rv < 0) {
            // enc->err_state = true;
            return rv;
        }
    }

    should_intern_value = false;
    struct aura_header_field header;

    for (int i = 0; i < hdr_cnt; ++i) {
        a_hpack_header_find_or_create2(
          &header,
          intern_tab,
          hdr_field[i].name.base,
          hdr_field[i].name.len,
          hdr_field[i].value.base,
          hdr_field[i].value.len,
          true,
          should_intern_value);
        if (a_hpack_encode_header(enc, &header) < 0)
            return -1;
    }
    return 0;
}

int a_hpack_huffman_encode3(uint8_t *dest, size_t dest_len, const uint8_t *src, size_t len) {
    const nghttp2_huff_sym *sym;
    const uint8_t *end;
    uint8_t *start, *dest_end;
    uint64_t code = 0;
    int bits_left = 40;
    uint32_t n;

    end = src + len;
    start = dest;
    while (src != end) {
        sym = huff_sym_table + *src++;
        code |= (uint64_t)sym->code << (bits_left - sym->nbits);
        bits_left -= sym->nbits;

        if (likely(bits_left > 8))
            continue;

        if (dest_len >= 4) {
            n = htonl((uint32_t)(code >> 8));
            memcpy(dest, &n, 4);
            dest += 4;
            dest_len -= 4;
            code <<= 32;
            bits_left += 32;
            continue;
        }

        while (bits_left <= 32) {
            if (dest_len == 0)
                return -1;
            *dest++ = code >> 32;
            dest_len--;
            code <<= 8;
            bits_left += 8;
        }
    }

    while (bits_left <= 32) {
        if (dest_len == 0)
            return -1;
        *dest++ = code >> 32;
        dest_len--;
        code <<= 8;
        bits_left += 8;
    }

    if (bits_left != 40) {
        if (dest_len == 0)
            return -1;
        code |= ((uint64_t)1 << bits_left) - 1;
        *dest++ = code >> 32;
    }

    return dest - start;
}

void aura_hpack_tab_dump(struct aura_hpack_dyn_tab *tab) {
    app_debug(true, 0, "AURA HPACK TABLE");
    app_debug(true, 0, "    Entries: %p", tab->entries);
    app_debug(true, 0, "    Num of entries: %lu", tab->cnt);
    app_debug(true, 0, "    Capacity: %lu", tab->cap);
    app_debug(true, 0, "    Table size: %lu", tab->tab_size);
    app_debug(true, 0, "    Max Updated size: %lu", tab->max_size);
    app_debug(true, 0, "    Settings tab size: %lu", tab->hdr_tab_max_size);
}

void aura_hpack_enc_dump(struct aura_hpack_encoder *enc) {
    app_debug(true, 0, "AURA HPACK ENCODER");
    app_debug(true, 0, "-----------------------------------------");
    app_debug(true, 0, "    Send tab size update: %d", enc->send_table_size_update);
    app_debug(true, 0, "-----------------------------------------");
}

void aura_hpack_dec_dump(struct aura_hpack_decoder *dec) {
    app_debug(true, 0, "AURA HPACK DECODER");
    app_debug(true, 0, "    STATE: %d", dec->state);
    app_debug(true, 0, "    OP CODE: %d", dec->opcode);
    app_debug(true, 0, "    SHIFT: %lu", dec->shift);
    app_debug(true, 0, "    INDEX: %lu", dec->index);
    app_debug(true, 0, "    LENGTH: %lu", dec->len);
    app_debug(true, 0, "    PREFIX: %u", dec->prefix);
    app_debug(true, 0, "    HUFFMAN: %d", dec->huff_encoded);
    app_debug(true, 0, "    HUFF STATE: %u", dec->huff_state);
    app_debug(true, 0, "    FLAGS: %u", dec->flags);
    app_debug(true, 0, "    ERR STATE: %d", dec->err_state);
}

/* ========== TEST HELPERS ========== */

int aura_hpack_decoder_update_tab_size(struct aura_hpack_decoder *dec, size_t max_size) {
    switch (dec->state) {
    case A_HPACK_STATE_EXPECT_TAB_SIZE_UPDATE:
    case A_HPACK_STATE_DECODE_START:
        break;
    default:
        return A_HPACK_INVALID_STATE_ERR;
    }

    dec->dyn_tab.hdr_tab_max_size = max_size;
    if (dec->dyn_tab.max_size > dec->dyn_tab.hdr_tab_max_size) {
        dec->state = A_HPACK_STATE_EXPECT_TAB_SIZE_UPDATE;
        dec->dyn_tab.max_size = max_size;

        a_hpack_dyn_tab_shrink(&dec->dyn_tab);
    }

    /* update and shrink table */
    return 0;
}

int aura_hpack_encoder_update_tab_size(struct aura_hpack_encoder *enc, size_t max_settings_size) {
    if (enc->dyn_tab.max_size > max_settings_size) {
        enc->dyn_tab.max_size = max_settings_size;
        enc->send_table_size_update = true;

        a_hpack_dyn_tab_shrink(&enc->dyn_tab);
    }

    return A_HPACK_OK;
}

int aura_hpack_encode_header_test(struct aura_hpack_encoder *enc, struct aura_intern_tab *intern_tab,
                                  struct aura_basic_header *hdr) {
    bool should_intern_value;
    uint8_t *dest;
    size_t dest_len, hdr_size = 0;

    should_intern_value = false;
    struct aura_header_field header;

    a_hpack_header_find_or_create2(
      &header,
      intern_tab,
      hdr->name.base,
      hdr->name.len,
      hdr->value.base,
      hdr->value.len,
      true,
      should_intern_value);
    if (a_hpack_encode_header(enc, &header) < 0)
        return -1;
    return 0;
}

int aura_hpack_encode_header_indexed_name_test(struct aura_hpack_encoder *enc,
                                               struct aura_intern_tab *intern_tab,
                                               struct aura_basic_header *hdr, int index,
                                               a_hpack_indexing_mode ind_mode) {
    uint8_t *dest;
    size_t dest_len, hdr_size = 0, rv;
    struct aura_iovec name, value;
    struct aura_header_field header;
    bool should_intern_value;

    should_intern_value = false;

    a_hpack_header_find_or_create2(
      &header,
      intern_tab,
      hdr->name.base,
      hdr->name.len,
      hdr->value.base,
      hdr->value.len,
      true,
      should_intern_value);

    name.base = (char *)header.name->data;
    name.len = header.name->len;
    if (header.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
        value.base = (char *)header.value.interned->data;
        value.len = header.value.interned->len;
    } else {
        value.base = header.value.raw.str.base;
        value.len = header.value.raw.str.len;
    }

    hdr_size = aura_hpack_hdr_entry_size(name.len, value.len);
    if (!aura_sliding_buf_ensure_cap(&enc->enc_buf, hdr_size)) {
        return -1;
    }
    dest = aura_sliding_buf_write_ptr(&enc->enc_buf);
    dest_len = aura_sliding_buf_write_len(&enc->enc_buf);

    rv = a_hpack_encode_indexed_name(dest, dest_len, index, &value, ind_mode);

    if (ind_mode == A_HPACK_HDR_FIELD_WITH_INDEXING)
        if (a_hpack_dyn_tab_add_new_entry2(enc->mc, &enc->dyn_tab, &header) < 0)
            return -1;

    aura_sliding_buf_commit(&enc->enc_buf, rv);

    return 0;
}

int aura_hpack_encode_header_new_name_test(struct aura_hpack_encoder *enc,
                                           struct aura_intern_tab *intern_tab,
                                           struct aura_basic_header *hdr,
                                           a_hpack_indexing_mode ind_mode) {
    uint8_t *dest;
    size_t dest_len, hdr_size = 0, rv;
    struct aura_iovec name, value;
    struct aura_header_field header;
    bool should_intern_value;

    should_intern_value = false;

    a_hpack_header_find_or_create2(
      &header,
      intern_tab,
      hdr->name.base,
      hdr->name.len,
      hdr->value.base,
      hdr->value.len,
      true,
      should_intern_value);

    name.base = (char *)header.name->data;
    name.len = header.name->len;
    if (header.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
        value.base = (char *)header.value.interned->data;
        value.len = header.value.interned->len;
    } else {
        value.base = header.value.raw.str.base;
        value.len = header.value.raw.str.len;
    }

    hdr_size = aura_hpack_hdr_entry_size(name.len, value.len);
    if (!aura_sliding_buf_ensure_cap(&enc->enc_buf, hdr_size)) {
        return -1;
    }
    dest = aura_sliding_buf_write_ptr(&enc->enc_buf);
    dest_len = aura_sliding_buf_write_len(&enc->enc_buf);

    rv = a_hpack_encode_new_name(dest, dest_len, &name, &value, ind_mode);

    if (ind_mode == A_HPACK_HDR_FIELD_WITH_INDEXING)
        if (a_hpack_dyn_tab_add_new_entry2(enc->mc, &enc->dyn_tab, &header) < 0)
            return -1;

    aura_sliding_buf_commit(&enc->enc_buf, rv);

    return 0;
}

int aura_hpack_header_decode_test(struct aura_hpack_decoder *dec, struct aura_intern_tab *intern_tab,
                                  struct aura_header_field *dec_hdrs, uint8_t *src_in,
                                  size_t in_len, size_t *hdr_cnt, bool final) {
    struct aura_header_field hdr;
    const uint8_t *end = src_in + in_len;
    ssize_t rv;
    size_t _inlen = in_len;

    while (true) {
        rv = aura_hpack_decode(dec, src_in, end, intern_tab, &dec_hdrs[*hdr_cnt], final);
        if (rv < 0)
            return (int)rv;
        _inlen -= rv;
        src_in += rv;

        if (dec->flags & A_HDR_FIELD_FLAG_EMIT)
            (*hdr_cnt)++;

        if (dec->flags & A_HDR_FIELD_FLAG_FINAL) {
            break;
        }
    }

    /* end headers */
    dec->state = A_HPACK_STATE_DECODE_START;
    return 0;
}
