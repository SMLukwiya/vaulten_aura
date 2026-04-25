#include "header_srv.h"
#include "server_srv.h"
#include "token_srv.h"

int aura_add_header(struct aura_memory_ctx *mc, struct aura_header_vector *hdrs, struct aura_header_field *header) {
    struct aura_header_field *slot;

    if (hdrs->cnt >= hdrs->cap) {
        hdrs->cap = hdrs->cap == 0 ? 16 : hdrs->cap * 2;
        hdrs->entries = aura_realloc(mc, hdrs->entries, hdrs->cap);
        if (hdrs->entries == NULL)
            return -1;
    }

    slot = &hdrs->entries[hdrs->cnt++];
    memcpy(slot, header, sizeof(*header));
    /* update ref cnt */
    if (!slot->value_interned)
        slot->value.raw.ref_cnt++;
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

struct aura_header_field *aura_header_field_create(struct aura_intern_tab *tab, char *name, size_t name_len, char *value, size_t value_len) {
    struct aura_header_field *header_field;
    struct aura_interned_str *i_name, *i_value;

    if (name_len == 0 && value_len == 0)
        return NULL;

    header_field = aura_alloc(tab->mc, sizeof(*header_field));
    if (!header_field)
        return NULL;

    header_field->name.interned = aura_interned_str_find_or_add(tab, name, name_len);
    if (!header_field->name.interned)
        goto err;
    header_field->name_interned = true;
    header_field->token = lookup_token(header_field->name.interned->data, header_field->name.interned->len);

    header_field->value.interned = NULL;
    header_field->value_interned = false;
    if (value_len > 0) {
        header_field->value.interned = aura_interned_str_find_or_add(tab, value, value_len);
        if (!header_field->value.interned)
            goto err;
        header_field->value_interned = true;
    }

    return header_field;
err:
    aura_free(header_field);
    return NULL;
}

void aura_header_field_destroy(struct aura_header_field *header) {
    if (!header)
        return;
    /* name always interned, so we destroy it when destroying intern table */

    if (!header->value_interned) {
        if (header->value.raw.str && --header->value.raw.ref_cnt == 0)
            aura_iovec_destroy(header->value.raw.str);
    }

    aura_free(header);
}