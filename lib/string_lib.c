#include "string_lib.h"
#include "slab.h"
#include <errno.h>

/**
 * Internal 'strlcpy' implementation
 * This returns the actual size of the data that would be copied
 * without truncating @src:. Users must check the value returned
 * and react accordingly, a return value >= @size: indicates data loss.
 * Note: src must be null terminated
 */
size_t _strlcpy(char *dest, const char *src, size_t size) {
    char *dest_ptr = dest;
    const char *src_ptr = src;
    size_t n_left = size;

    if (n_left && --n_left) {
        do {
            if (!(*dest_ptr++ = *src_ptr++))
                break;
        } while (--n_left);
    }

    /* we are at the end */
    if (!n_left) {
        if (size)
            *dest_ptr = '\0'; /* null terminate */
        while (src_ptr++)
            ; /* advance to end of src */
    }

    return (src_ptr - src - 1); /* return size minus null character */
}

/**
 * Internal 'strlcat' implementation
 * This returns the actual size of the data that would be concatenated
 * without truncating @src:. Users must check the value returned
 * and react accordingly, a return value >= @size: indicates data loss.
 */
size_t _strlcat(char *dest, const char *src, size_t size) {
    char *dest_ptr = dest;
    const char *src_ptr = src;
    size_t n_left = size, dest_len;

    while (n_left-- && *dest_ptr)
        dest_ptr++;

    dest_len = dest_ptr - dest;
    if (!(n_left = size - dest_len)) /* can't copy anything */
        return dest_len + strlen(src);

    while (*src_ptr) {
        if (n_left != 1) {
            *dest_ptr++ = *src_ptr++;
            n_left--;
        }
        src_ptr++;
    }
    *dest_ptr = '\0';
    return (dest_len + (src_ptr - src));
}

/**
 * Decodes url copying result to @dest:
 * It returns the actual size of decoded url
 * @size: represents size of @dest:
 * @todo: may need revision
 */
size_t decode_url(const char *url, char *dest, size_t size) {
    char *c, *dest_ptr;

    for (c = (char *)url; *c && size > 0; ++c) {
        if (*c == '%' && isxdigit(c[1]) && isxdigit(c[2])) {
            *dest_ptr++ = BASE_16_TO_10(c[1]) * 16 + BASE_16_TO_10(c[2]);
            c += 2;
        } else
            *dest_ptr++ = *c++;
    }
    *dest_ptr = '\0';
    return (dest_ptr - dest - 1); /* minus null char */
}

/** @todo: look into utf-8 encoding */
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