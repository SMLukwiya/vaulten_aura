#include <arpa/inet.h>

#include "core.h"
#include "hpack_huffman_tb_srv.h"

uint64_t aura_encode_status(uint8_t *dest, int status) {
    uint8_t *start = dest;

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
    return dest - start;
}

/* Count the number of bytes taken by the length to be encoded */
static uint64_t a_hpack_count_encoded_len(uint64_t prefix, uint64_t n) {
    uint64_t prefix_max, len = 0;

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

/* Decode length from given src */
static int64_t a_hpack_decode_len(uint8_t *src, const uint8_t *end, uint64_t *out, uint64_t *shift,
                                  uint64_t initial, uint64_t start_shift, uint64_t prefix, bool *done) {
    uint64_t prefix_max = (uint8_t)((1 << prefix) - 1);
    uint64_t n = initial, add;
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
            *done = true;
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
        if (n > UINT64_MAX - add) {
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
        return (int64_t)(src - start);
    }

    *out = n;
    return (int64_t)(src - start);
}

/* Get number of bytes to encode len bytes of src using huffman encoding */
static uint64_t a_hpack_huff_get_encode_len(const uint8_t *src, uint64_t len) {
    uint64_t nbits = 0;

    for (uint64_t i = 0; i < len; ++i) {
        nbits += huff_sym_table[src[i]].nbits;
    }
    return (nbits + 7) / 8;
}

/* Decode huffman into r_buf */
static int a_hpack_huffman_decode(struct aura_hpack_recv_buf *r_buf, uint8_t *state, const uint8_t *src,
                                  uint64_t len, bool final, int *err) {
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
        return -1;

    return 0;
}

/* Get the first byte of the determined encoding pattern */
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

/* Encode given len using provided prefix */
static uint64_t a_hpack_encode_len(uint8_t *dest, uint64_t prefix, uint64_t n) {
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

    return (uint64_t)(dest - start);
}

/* Encode normal string */
static inline uint64_t a_hpack_string_encode(uint8_t *dest, const uint8_t *s, uint64_t len) {
    uint8_t *start = dest;
    memcpy(dest, s, len);
    dest += len;
    return dest - start;
}

int a_hpack_huffman_encode(uint8_t *dest, uint64_t dest_len, const uint8_t *src, uint64_t len) {
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

        if (bits_left > 8)
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

static uint64_t a_hpack_encode_string(uint8_t *dest, uint64_t dest_len, const uint8_t *str, uint64_t len) {
    uint8_t *start = dest;
    uint64_t enc_len;
    bool huffman = false;

    enc_len = a_hpack_huff_get_encode_len(str, len);
    if (enc_len < len) {
        huffman = true;
    } else
        enc_len = len;

    *dest = huffman ? 1 << 7 : 0;
    dest += a_hpack_encode_len(dest, 7, enc_len);

    if (huffman)
        dest += a_hpack_huffman_encode(dest, dest_len, str, len);
    else
        dest += a_hpack_string_encode(dest, str, len);

    return dest - start;
}

/* Encode table size update */
uint64_t aura_hpack_encode_tab_size_update(uint8_t *dest, uint64_t tab_size) {
    uint8_t *start;

    start = dest;
    *dest = 0x20u;
    dest += a_hpack_encode_len(dest, 5, tab_size);

    return dest - start;
}

/* Encode indexed block for perfect table match */
uint64_t aura_hpack_encode_indexed_block(uint8_t *dest, uint64_t idx) {
    *dest = 0x80u;
    return a_hpack_encode_len(dest, 7, idx);
}

/* Encode indexed name representation */
uint64_t aura_hpack_encode_indexed_name(uint8_t *dest, uint64_t dest_len, uint64_t idx,
                                        struct aura_iovec *value, a_hpack_indexing_mode ind_mode) {
    uint64_t prefix;
    uint8_t *start = dest;

    if (ind_mode == A_HPACK_HDR_FIELD_WITH_INDEXING) {
        prefix = 6;
    } else
        prefix = 4;

    *dest = a_hpack_pack_binary_fmt(ind_mode);
    dest += a_hpack_encode_len(dest, prefix, idx);

    dest += a_hpack_encode_string(dest, dest_len, (uint8_t *)value->base, value->len);

    return dest - start;
}

/* Encode new name representation */
uint64_t aura_hpack_encode_new_name(uint8_t *dest, uint64_t dest_len, struct aura_iovec *name,
                                    struct aura_iovec *value, a_hpack_indexing_mode ind_mode) {
    uint8_t *start = dest;

    *dest++ = a_hpack_pack_binary_fmt(ind_mode);
    dest += a_hpack_encode_string(dest, dest_len, (uint8_t *)name->base, name->len);
    dest += a_hpack_encode_string(dest, dest_len, (uint8_t *)value->base, value->len);

    return dest - start;
}

/** @todo: ensure that the enc->buf has enough space */
uint64_t aura_hpack_encode_content_length(uint8_t *dest, uint64_t value) {
    char buf[64];
    char *p = buf + sizeof(buf);
    uint64_t l;
    uint8_t *start;

    do {
        *--p = '0' + value % 10;
    } while ((value /= 10) != 0);
    l = buf + sizeof(buf) - p;

    start = dest;
    *dest++ = 0x0f; /* 15 */
    *dest++ = 0x0d; /* + 13 = 28(index) */
    *dest++ = (uint8_t)l;
    memcpy(dest, p, l);
    dest += l;

    return dest - start;
}
