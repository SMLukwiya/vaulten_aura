#include "hpack.h"
#include "utils.h"

uint8_t *aura_h2_probe_hpack_write_tab_size_update(uint8_t *dest, uint64_t tab_size) {
    *dest = 0x20;
    dest += aura_hpack_encode_len(dest, 5, tab_size);

    return dest;
}

uint8_t *aura_h2_probe_hpack_write_indexed(uint8_t *dest, int idx) {
    *dest = 0x80;
    dest += aura_hpack_encode_len(dest, 7, idx);
}

uint8_t *aura_h2_prove_write_indexed_name(uint8_t *dest, size_t dest_len, size_t idx,
                                          struct aura_iovec *value, a_hpack_indexing_mode ind_mode) {
    dest += aura_hpack_encode_indexed_name(dest, dest_len, idx, value, ind_mode);
    return dest;
}

uint8_t *aura_h2_probe_write_new_name(uint8_t *dest, size_t dest_len, struct aura_iovec *name,
                                      struct aura_iovec *value, a_hpack_indexing_mode ind_mode) {
    dest += aura_hpack_encode_new_name(dest, dest_len, name, value, ind_mode);
    return dest;
}

uint8_t *aura_h2_probe_write_status(uint8_t *dest, int status) {
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

uint8_t *aura_h2_probe_write_content_len(uint8_t *dest, uint64_t value) {
    char buf[64];
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