#include "header_srv.h"
#include "string_lib.h"
#include "token_srv.h"

int aura_add_header(struct aura_mem_ctx *mc, struct aura_header_vector2 *hdrs,
                    struct aura_header_field *header) {
    struct aura_basic_header *slot;

    if (hdrs->cnt >= hdrs->cap) {
        hdrs->cap = hdrs->cap == 0 ? 16 : hdrs->cap * 2;
        hdrs->entries = aura_realloc(mc, hdrs->entries, sizeof(*(hdrs->entries)) * hdrs->cap);
        if (hdrs->entries == NULL)
            return -1;
    }

    slot = &hdrs->entries[hdrs->cnt++];
    slot->name.base = aura_strndup(mc, header->name->data, header->name->len);
    slot->name.len = header->name->len;
    if (header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
        slot->value.base = aura_strndup(mc, header->value.interned->data, header->value.interned->len);
        slot->value.len = header->value.interned->len;
    } else {
        slot->value.base = aura_strndup(mc, header->value.raw.str.base, header->value.raw.str.len);
        slot->value.len = header->value.raw.str.len;
    }

    return 0;
}

bool aura_header_name_valid(const char *s) {
    for (; *s; ++s) {
        if (*s <= 32 || *s >= 127 || *s == ':')
            return false;
    }
    return true;
}

bool aura_header_value_forbidden(const char *name) {
    return strcasecmp(name, "host") == 0 ||
           strcasecmp(name, "content-length") == 0;
}

bool aura_header_value_valid(const char *v) {
    for (; *v; ++v) {
        if (*v == '\r' || *v == '\n')
            return false;
    }
    return true;
}

struct aura_header_field *aura_header_field_create(struct aura_intern_tab *tab,
                                                   char *name, size_t name_len,
                                                   char *value, size_t value_len) {
    struct aura_header_field *header_field;
    struct aura_interned_str *i_name, *i_value;

    if (name_len == 0 && value_len == 0)
        return NULL;

    header_field = aura_alloc(tab->mc, sizeof(*header_field));
    if (!header_field)
        return NULL;

    header_field->name = aura_interned_str_find_or_add(tab, name, name_len);
    if (!header_field->name)
        goto err;

    header_field->token = lookup_token(header_field->name->data, header_field->name->len);
    header_field->value.interned = NULL;
    header_field->flags |= ~A_HDR_FIELD_FLAG_VALUE_INTERNED;

    if (value_len > 0) {
        header_field->value.interned = aura_interned_str_find_or_add(tab, value, value_len);
        if (!header_field->value.interned)
            goto err;
        header_field->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
    }

    return header_field;
err:
    aura_free(header_field);
    return NULL;
}

int aura_header_field_create2(struct aura_intern_tab *tab, struct aura_header_field *hdr,
                              char *name, size_t name_len, char *value, size_t value_len) {

    if (name_len == 0 && value_len == 0)
        return -1;

    memset(hdr, 0, sizeof(*hdr));
    hdr->token = lookup_token(name, name_len);

    hdr->name = aura_interned_str_find_or_add(tab, name, name_len);
    if (!hdr->name)
        return -1;

    hdr->value.interned = NULL;
    hdr->flags |= ~A_HDR_FIELD_FLAG_VALUE_INTERNED;

    if (value_len > 0) {
        hdr->value.interned = aura_interned_str_find_or_add(tab, value, value_len);
        if (!hdr->value.interned)
            return -1;
        hdr->flags |= A_HDR_FIELD_FLAG_VALUE_INTERNED;
    }

    return 0;
}

void aura_header_field_destroy(struct aura_header_field *header) {
    if (!header)
        return;
    /* name always interned, so we destroy it when destroying intern table */

    if (!(header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)) {
        if (header->value.raw.str.base && --header->value.raw.ref_cnt == 0)
            aura_free(header->value.raw.str.base);
    }

    aura_free(header);
}

void aura_header_field_destroy2(struct aura_header_field *header) {
    if (!header)
        return;
    /* name always interned, so we destroy it when destroying intern table */

    if (!(header->flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)) {
        if (header->value.raw.str.base)
            aura_free(header->value.raw.str.base);
    }
}