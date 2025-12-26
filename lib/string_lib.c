#include "string_lib.h"

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

    for (c = url; *c && size > 0; ++c) {
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
