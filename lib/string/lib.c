#include "lib.h"
#include "slab.h"
#include <errno.h>

bool is_valid_utf_8_string(const unsigned char *str) {
    const unsigned char *str_ptr = str;
    int nb;

    for (str_ptr = str; *str_ptr; str_ptr += (nb + 1)) {
        if (!(*str_ptr & 0x80))
            nb = 0;
        else if ((*str_ptr & 0xc0) == 0x80)
            return 0;
        else if ((*str_ptr & 0xe0) == 0xc0)
            nb = 1;
        else if ((*str_ptr & 0xf0) == 0xe0)
            nb = 2;
        else if ((*str_ptr & 0xf8) == 0xf0)
            nb = 3;
        else if ((*str_ptr & 0xfc) == 0xf8)
            nb = 4;
        else if ((*str_ptr & 0xfe) == 0xfc)
            nb = 5;

        while (nb-- > 0)
            if ((*(str_ptr + nb) & 0xc0) != 0x80)
                return 0;
    }
    return 1;
}

char *aura_strdup(struct aura_mem_ctx *mc, const char *str) {
    char *copy;
    size_t len;

    len = strlen(str) + 1; /* +1 null-terminated */
    copy = aura_alloc(mc, len);
    strcpy(copy, str);
    return copy;
}

char *aura_strndup(struct aura_mem_ctx *mc, const char *str, size_t len) {
    char *copy, *_str = (char *)str;
    uint64_t _len;

    if (len == 0)
        return NULL;

    for (int i = 0, _len = 0; i < len && *_str++; ++i)
        _len++;

    _len = _len < len ? _len : len;
    _len += 1; /* null-terminate */
    copy = aura_alloc(mc, _len);
    memcpy(copy, str, _len - 1);
    copy[_len - 1] = '\0';
    return copy;
}

char *aura_str_touppercase(struct aura_mem_ctx *mc, const char *str, size_t len) {
    char *s;

    if (!str || len == 0)
        return NULL;

    s = aura_alloc(mc, len + 1);
    if (!s)
        return NULL;

    for (int i = 0; i < len; ++i) {
        s[i] = toupper(str[i]);
    }
    s[len] = '\0';
    return s;
}

char *aura_str_tolowercase(struct aura_mem_ctx *mc, const char *str, size_t len) {
    char *s;

    if (!str || len == 0)
        return NULL;

    s = aura_alloc(mc, len + 1);
    if (!s)
        return NULL;

    for (int i = 0; i < len; ++i) {
        s[i] = tolower(str[i]);
    }
    s[len] = '\0';
    return s;
}

void *aura_memcpy(struct aura_mem_ctx *mc, const void *data, size_t len) {
    void *dest;

    if (!data || len == 0)
        return NULL;

    dest = aura_alloc(mc, len);
    if (!dest)
        return NULL;

    memcpy(dest, data, len);
    return dest;
}

/* wrapper around strtoul */
size_t aura_strtoul(const char *nptr, size_t len) {
    size_t res;
    char *endptr = NULL;

    if (len == 0)
        goto err_out;

    res = strtoul(nptr, &endptr, 10);
    if (endptr != NULL || endptr == nptr)
        goto err_out;

    if (errno == ERANGE || errno == EINVAL)
        goto err_out;

    return res;

err_out:
    return SIZE_MAX;
}

bool aura_lc_str_is_eq(const char *target, size_t target_len, const char *other, size_t other_len) {
    if (target_len != other_len)
        return false;

    for (; other_len != 0; --other_len)
        if (tolower(*target++) != *other++)
            return false;
    return true;
}

bool aura_mem_is_eq(const void *target, size_t target_len, const void *other, size_t other_len) {
    const char *t = (const char *)target;
    const char *o = (const char *)other;

    if (target_len != other_len)
        return false;

    if (t[0] != o[0])
        return false;

    return memcmp(target + 1, other + 1, target_len - 1) == 0;
}

int aura_str_buf_init(struct aura_str_buf *buf, struct aura_mem_ctx *mc, uint64_t cap) {
    buf->data = mc ? aura_alloc(mc, cap) : malloc(cap);
    if (!buf->data)
        return -1;
    memset(buf->data, 0, cap);
    buf->len = 0;
    buf->cap = cap;
    buf->mc = mc;

    return 0;
}

void aura_str_buf_destroy(struct aura_str_buf *buf) {
    if (buf->data)
        if (buf->mc)
            aura_free(buf->data);
        else
            free(buf->data);

    buf->data = NULL;
    buf->len = 0;
}

int aura_str_buf_reserve(struct aura_str_buf *buf, uint64_t size) {
    char *old = buf->data;

    if (buf->len + size <= buf->cap)
        return 0;

    while ((buf->len + size + 1) > buf->cap)
        buf->cap *= 2;

    if (buf->mc)
        buf->data = aura_realloc(buf->mc, buf->data, buf->cap);
    else
        buf->data = realloc(buf->data, buf->cap);

    if (!buf->data) {
        buf->data = old;
        return -1;
    }

    return 0;
}

int aura_str_buf_append(struct aura_str_buf *buf, const char *s) {
    uint64_t len = strlen(s);
    int rv = aura_str_buf_reserve(buf, len);
    if (rv < 0)
        return rv;

    memcpy(buf->data + buf->len, s, len);
    buf->len += len;
    buf->data[buf->len] = '\0';

    return 0;
}

int aura_str_buf_print(struct aura_str_buf *buf, const char *fmt, ...) {
    int len, rv;
    va_list ap, ap_copy;

    va_start(ap, fmt);
    va_copy(ap_copy, ap);
    /* Determine len */
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (len < 0) {
        va_end(ap_copy);
        return -1;
    }

    rv = aura_str_buf_reserve(buf, len);
    if (rv < 0)
        return rv;

    vsnprintf(buf->data + buf->len, len + 1, fmt, ap_copy);
    va_end(ap_copy);

    buf->len += len;
    return 0;
}

int aura_str_buf_append_field(struct aura_str_buf *buf, const char *prefix, const char *key, const char *value) {
    return aura_str_buf_print(buf, "%s%-*s%s\n", prefix, A_STR_BUF_KEY_WIDTH, key, value);
}

int aura_str_buf_append_continuation(struct aura_str_buf *buf, const char *prefix, const char *value) {
    return aura_str_buf_print(buf, "%s%*s%s\n", prefix, A_STR_BUF_KEY_WIDTH, "", value);
}
