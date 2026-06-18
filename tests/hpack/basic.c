#include "h2/hpack.h"
#include "header_srv.h"
#include "interned.h"
#include <assert.h>

#define A_MAKE_HDR(name, value) \
    {str_lit(name), str_lit(value)}

struct aura_mem_ctx mc;
struct aura_hpack_encoder enc;
struct aura_hpack_decoder dec;
struct aura_intern_tab intern_tab;
extern struct aura_hpack_static_table static_table;

int aura_hpack_header_decode_test(struct aura_hpack_decoder *dec, struct aura_intern_tab *intern_tab,
                                  struct aura_header_field *dec_hdrs, uint8_t *src_in,
                                  size_t in_len, size_t *hdr_cnt, bool final);

int aura_hpack_encode_header_test(struct aura_hpack_encoder *enc, struct aura_intern_tab *intern_tab,
                                  struct aura_basic_header *hdr);

int aura_hpack_encode_header_indexed_name_test(struct aura_hpack_encoder *enc,
                                               struct aura_intern_tab *intern_tab,
                                               struct aura_basic_header *hdr, int index,
                                               a_hpack_indexing_mode ind_mode);

int aura_hpack_encode_header_new_name_test(struct aura_hpack_encoder *enc,
                                           struct aura_intern_tab *intern_tab,
                                           struct aura_basic_header *hdr,
                                           a_hpack_indexing_mode ind_mode);

int aura_hpack_decoder_update_tab_size(struct aura_hpack_decoder *dec, size_t max_settings_size);

int aura_hpack_encoder_update_tab_size(struct aura_hpack_encoder *enc, size_t max_settings_size);

static void a_test_resources_create(void) {
    int rv;

    aura_mem_ctx_init(&mc);
    rv = aura_create_dynamic_slab_alloc_caches(&mc);
    assert(rv == 0);

    aura_intern_tab_create2(&intern_tab, &mc, 32);
    aura_hpack_load_static_table(&mc);
}

static void a_test_resources_destroy() {
    aura_mem_ctx_destroy(&mc);
    aura_intern_tab_destroy2(&intern_tab);
}

static void a_hpack_test_destroy_headers(struct aura_header_field *hdrs, size_t cnt) {
    for (int i = 0; i < cnt; ++i)
        aura_header_field_destroy2(&hdrs[i]);

    aura_free(hdrs);
}

static void a_hpack_test_decode(void) {
    size_t hdr_cnt, len;
    uint8_t *src;
    struct aura_header_field *dec_fields;
    int rv;

    struct aura_basic_header nv_pairs1[] = {
      A_MAKE_HDR(":method", "GET"),
      A_MAKE_HDR(":path", "/example/index.html"),
      A_MAKE_HDR(":scheme", "https"),
    };

    struct aura_basic_header nv_pairs2[] = {
      A_MAKE_HDR(":status", "200"),
      A_MAKE_HDR(":path", "/index.html"),
      A_MAKE_HDR("authorization", "hippopotamus-getamus"),
    };

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    dec_fields = aura_alloc(&mc, sizeof(*dec_fields) * ARR_CNT(nv_pairs1));
    assert(dec_fields != NULL);

    /*  nc_pair1 */
    rv = aura_hpack_encode_headers(&enc, &intern_tab, nv_pairs1, ARR_CNT(nv_pairs1));
    assert(rv == 0);

    src = aura_sliding_buf_read_ptr(&enc.enc_buf);
    len = aura_sliding_buf_read_len(&enc.enc_buf);
    hdr_cnt = 0;
    rv = aura_hpack_header_decode_test(&dec, &intern_tab, dec_fields, src, len, &hdr_cnt, true);
    assert(rv == 0);
    assert(hdr_cnt == ARR_CNT(nv_pairs1));

    aura_sliding_buf_reset(&enc.enc_buf);
    a_hpack_test_destroy_headers(dec_fields, ARR_CNT(nv_pairs1));

    dec_fields = aura_alloc(&mc, sizeof(*dec_fields) * ARR_CNT(nv_pairs1));
    assert(dec_fields != NULL);

    /* nv_pair2 */
    rv = aura_hpack_encode_headers(&enc, &intern_tab, nv_pairs2, ARR_CNT(nv_pairs2));
    assert(rv == 0);

    src = aura_sliding_buf_read_ptr(&enc.enc_buf);
    len = aura_sliding_buf_read_len(&enc.enc_buf);
    hdr_cnt = 0;
    rv = aura_hpack_header_decode_test(&dec, &intern_tab, dec_fields, src, len, &hdr_cnt, true);
    assert(rv == 0);
    assert(hdr_cnt == ARR_CNT(nv_pairs2));

    a_hpack_test_destroy_headers(dec_fields, ARR_CNT(nv_pairs2));
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_encode_indexed(void) {
    int rv;
    uint8_t *dest;
    const uint8_t hdr_data[] = {0x84}, *end;
    struct aura_header_field hdr;

    struct aura_basic_header nv_pair = A_MAKE_HDR(":path", "/");

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    aura_sliding_buf_append(&enc.enc_buf, hdr_data, sizeof(hdr_data));
    dest = aura_sliding_buf_read_ptr(&enc.enc_buf);
    end = dest + 1;

    rv = aura_hpack_decode(&dec, dest, end, &intern_tab, &hdr, true);
    assert(rv == 1);
    assert(strcmp(hdr.name->data, nv_pair.name.base) == 0);
    assert(strcmp(hdr.value.interned->data, nv_pair.value.base) == 0);

    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_indexed_name_no_inc(void) {
    int rv;
    const uint8_t *dest, *end;
    size_t dest_len;
    struct aura_header_field hdr;

    struct aura_basic_header nv_pairs[] = {
      A_MAKE_HDR("user-agent", "aura"),
      A_MAKE_HDR("user-agent", "x"),
    };

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    for (int i = 0; i < ARR_CNT(nv_pairs); ++i) {
        memset(&hdr, 0, sizeof(hdr));
        rv = aura_hpack_encode_header_test(&enc, &intern_tab, &nv_pairs[i]);
        assert(rv == 0);

        dest = aura_sliding_buf_read_ptr(&enc.enc_buf);
        dest_len = aura_sliding_buf_read_len(&enc.enc_buf);
        end = dest + dest_len;

        rv = aura_hpack_decode(&dec, dest, end, &intern_tab, &hdr, true);
        assert(rv == dest_len);
        assert(strcmp(hdr.name->data, nv_pairs[i].name.base) == 0);
        if (hdr.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
            assert(strcmp(hdr.value.interned->data, nv_pairs[i].value.base) == 0);
        else
            assert(strcmp(hdr.value.raw.str.base, nv_pairs[i].value.base) == 0);
        aura_sliding_buf_consume(&enc.enc_buf, dest_len);
    }

    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_indexed_inc(void) {
    int rv;
    const uint8_t *src_in, *end;
    size_t in_len;
    struct aura_header_field hdr;
    struct aura_hpack_tab_entry *e;

    struct aura_basic_header nv_pair = A_MAKE_HDR("x-aura", "aura");

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    rv = aura_hpack_encode_header_test(&enc, &intern_tab, &nv_pair);
    assert(rv == 0);

    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    end = src_in + in_len;

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);
    assert(aura_hpack_tab_get_entry_cnt(&dec.dyn_tab) == 62);

    e = aura_hpack_dyn_header_tab_get_entry(&dec.dyn_tab, A_HPACK_STATIC_TAB_LEN + dec.dyn_tab.cnt);
    assert(e != NULL);
    assert(e->header_field.name == hdr.name);

    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_duplicate_indexed_repr(void) {
    size_t hdr_cnt, len;
    uint8_t *src;
    struct aura_header_field *dec_fields;
    int rv;

    struct aura_basic_header nv_pairs[] = {
      A_MAKE_HDR("host", "aling"),
      A_MAKE_HDR("host", "aling"),
    };

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    dec_fields = aura_alloc(&mc, sizeof(*dec_fields) * ARR_CNT(nv_pairs));
    assert(dec_fields != NULL);

    rv = aura_hpack_encode_headers(&enc, &intern_tab, nv_pairs, ARR_CNT(nv_pairs));
    assert(rv == 0);

    src = aura_sliding_buf_read_ptr(&enc.enc_buf);
    len = aura_sliding_buf_read_len(&enc.enc_buf);
    hdr_cnt = 0;
    rv = aura_hpack_header_decode_test(&dec, &intern_tab, dec_fields, src, len, &hdr_cnt, true);
    assert(rv == 0);
    assert(hdr_cnt == ARR_CNT(nv_pairs));

    a_hpack_test_destroy_headers(dec_fields, ARR_CNT(nv_pairs));
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_indexed_name_inc_evict(void) {
    uint8_t value[1025], *src_in;
    size_t in_len, hdr_cnt;
    struct aura_basic_header hdr;
    struct aura_header_field *dec_fields;
    int rv;

    memset(value, '0', sizeof(value));
    value[sizeof(value) - 1] = '\0';

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    dec_fields = aura_alloc(&mc, sizeof(*dec_fields) * 4);
    assert(dec_fields != NULL);

    hdr.value.base = value;
    hdr.value.len = sizeof(value) - 1;

    hdr.name.base = (char *)static_table.entries[17].header_field.name->data;
    hdr.name.len = static_table.entries[17].header_field.name->len;
    rv = aura_hpack_encode_header_indexed_name_test(&enc, &intern_tab, &hdr, 17, A_HPACK_HDR_FIELD_WITH_INDEXING);
    assert(rv == 0);

    hdr.name.base = (char *)static_table.entries[18].header_field.name->data;
    hdr.name.len = static_table.entries[18].header_field.name->len;
    rv = aura_hpack_encode_header_indexed_name_test(&enc, &intern_tab, &hdr, 18, A_HPACK_HDR_FIELD_WITH_INDEXING);
    assert(rv == 0);

    hdr.name.base = (char *)static_table.entries[19].header_field.name->data;
    hdr.name.len = static_table.entries[19].header_field.name->len;
    rv = aura_hpack_encode_header_indexed_name_test(&enc, &intern_tab, &hdr, 19, A_HPACK_HDR_FIELD_WITH_INDEXING);
    assert(rv == 0);

    hdr.name.base = (char *)static_table.entries[20].header_field.name->data;
    hdr.name.len = static_table.entries[20].header_field.name->len;
    rv = aura_hpack_encode_header_indexed_name_test(&enc, &intern_tab, &hdr, 20, A_HPACK_HDR_FIELD_WITH_INDEXING);
    assert(rv == 0);

    hdr_cnt = 0;
    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    rv = aura_hpack_header_decode_test(&dec, &intern_tab, dec_fields, src_in, in_len, &hdr_cnt, true);
    assert(rv == 0);
    assert(hdr_cnt == 4);
    assert(strncmp(dec_fields[0].name->data, "accept-language", dec_fields[0].name->len) == 0);
    assert(memcmp(dec_fields[0].value.raw.str.base, value, sizeof(value) - 1) == 0);

    assert(dec.dyn_tab.cnt == 3);
    assert(aura_hpack_tab_get_entry_cnt(&dec.dyn_tab) == 64);

    a_hpack_test_destroy_headers(dec_fields, 4);
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_newname_no_inc(void) {
    struct aura_header_field hdr;
    int rv;
    const uint8_t *src_in, *end;
    size_t in_len;

    struct aura_basic_header nv_pairs[] = {
      A_MAKE_HDR("x-custom-aura-content-type-long", "v-aura"),
      A_MAKE_HDR("y", "x"),
      A_MAKE_HDR("x-custom-aura-content-type-long", "v"),
      A_MAKE_HDR("x", "aura"),
    };

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    for (int i = 0; i < ARR_CNT(nv_pairs); ++i) {
        rv = aura_hpack_encode_header_new_name_test(&enc, &intern_tab, &nv_pairs[i], A_HPACK_HDR_FIELD_WITHOUT_INDEXING);
        assert(rv == 0);

        src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
        in_len = aura_sliding_buf_read_len(&enc.enc_buf);
        end = src_in + in_len;

        rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
        assert(rv == in_len);
        assert(strcmp(hdr.name->data, nv_pairs[i].name.base) == 0);
        if (hdr.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
            assert(strcmp(hdr.value.interned->data, nv_pairs[i].value.base) == 0);
        else
            assert(strcmp(hdr.value.raw.str.base, nv_pairs[i].value.base) == 0);
        aura_sliding_buf_consume(&enc.enc_buf, in_len);
    }

    assert(dec.dyn_tab.cnt == 0);

    a_hpack_test_destroy_headers(&hdr, 1);
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_newname_inc(void) {
    struct aura_header_field hdr;
    struct aura_hpack_tab_entry *e;
    int rv;
    const uint8_t *src_in, *end;
    size_t in_len;

    struct aura_basic_header nv_pair = A_MAKE_HDR("x-aura", "aura");

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    rv = aura_hpack_encode_header_new_name_test(&enc, &intern_tab, &nv_pair, A_HPACK_HDR_FIELD_WITH_INDEXING);
    assert(rv == 0);

    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    end = src_in + in_len;

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);
    assert(aura_hpack_tab_get_entry_cnt(&dec.dyn_tab) == 62);
    assert(dec.dyn_tab.cnt == 1);

    e = aura_hpack_dyn_header_tab_get_entry(&dec.dyn_tab, A_HPACK_STATIC_TAB_LEN + dec.dyn_tab.cnt);
    assert(e != NULL);
    assert(e->header_field.name == hdr.name);

    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_clearall_inc(void) {
    uint8_t value[4060];
    const uint8_t *src_in, *end;
    struct aura_basic_header nv_pair;
    size_t in_len;
    struct aura_header_field hdr;
    int rv;

    nv_pair.name.base = "x-aura";
    nv_pair.name.len = sizeof("x-aura") - 1;
    memset(value, '0', sizeof(value));
    value[sizeof(value) - 1] = '\0';
    nv_pair.value.base = value;
    nv_pair.value.len = sizeof(value) - 1;

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    rv = aura_hpack_encode_header_new_name_test(&enc, &intern_tab, &nv_pair, A_HPACK_HDR_FIELD_WITH_INDEXING);
    assert(rv == 0);

    /* First time */
    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    end = src_in + in_len;

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);
    assert(dec.dyn_tab.cnt == 0);

    /* Second time */
    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    end = src_in + in_len;

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);
    assert(dec.dyn_tab.cnt == 0);

    aura_sliding_buf_consume(&enc.enc_buf, rv);
    a_hpack_test_destroy_headers(&hdr, 1);

    /* Adjust value len and repeat */
    nv_pair.value.len -= 2;

    rv = aura_hpack_encode_header_new_name_test(&enc, &intern_tab, &nv_pair, A_HPACK_HDR_FIELD_WITH_INDEXING);
    assert(rv == 0);

    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    end = src_in + in_len;

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);
    assert(dec.dyn_tab.cnt == 1);

    a_hpack_test_destroy_headers(&hdr, 1);
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_huff_zero_len(void) {
    int rv;
    const uint8_t *src_in, *end;
    size_t in_len;
    struct aura_header_field hdr;

    /* Literal header without indexing, new name */
    uint8_t hdr_data[] = {0x40 /* bin fmt*/, 0x01 /* len */, 0x78 /* 'x' */, 0x80 /* huff empty */};

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    aura_sliding_buf_append(&enc.enc_buf, hdr_data, sizeof(hdr_data));
    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    end = src_in + in_len;

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);
    assert(hdr.name->data[0] == 'x');
    assert(hdr.value.raw.str.base == NULL);
    assert(hdr.value.raw.str.len == 0);

    a_hpack_test_destroy_headers(&hdr, 1);
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_expect_tab_size_update(void) {
    struct aura_header_field hdr;
    const uint8_t *src_in, *end;
    size_t in_len;
    uint8_t hdr_data[] = {0x82}; /* :method: GET */
    int rv;

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    aura_sliding_buf_append(&enc.enc_buf, hdr_data, sizeof(hdr_data));

    aura_hpack_decoder_update_tab_size(&dec, 4095);

    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);
    end = src_in + in_len;

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == A_HPACK_COMPRESSION_ERR);

    aura_hpack_decoder_destroy(&dec);

    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    /* Requires no table size update */
    aura_hpack_decoder_update_tab_size(&dec, 4096);

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);
    a_hpack_test_destroy_headers(&hdr, 1);
    aura_hpack_decoder_destroy(&dec);

    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    /* Update to a larger value, requires no table size update */
    aura_hpack_decoder_update_tab_size(&dec, 4097);

    rv = aura_hpack_decode(&dec, src_in, end, &intern_tab, &hdr, true);
    assert(rv == in_len);

    a_hpack_test_destroy_headers(&hdr, 1);
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_decode_unexpected_tab_size_update(void) {
    struct aura_header_field hdr;
    uint8_t hdr_data[] = {0x82, 0x20};
    uint8_t *src_in;
    size_t in_len, hdr_cnt;
    int rv;

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    aura_sliding_buf_append(&enc.enc_buf, hdr_data, sizeof(hdr_data));

    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);

    hdr_cnt = 0;
    rv = aura_hpack_header_decode_test(&dec, &intern_tab, &hdr, src_in, in_len, &hdr_cnt, true);
    assert(rv == A_HPACK_COMPRESSION_ERR);

    a_hpack_test_destroy_headers(&hdr, 1);
    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void a_hpack_test_table_size_change(void) {
    int rv;
    uint8_t *src_in;
    size_t in_len, hdr_cnt;
    struct aura_header_field *dec_fields;

    struct aura_basic_header nv_pair1[] = {
      A_MAKE_HDR("aura", "vaulten"),
      A_MAKE_HDR("charlies", "angels"),
    };

    struct aura_basic_header nv_pair2[] = {
      A_MAKE_HDR(":path", "/index.html"),
    };

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    /* initial settings */
    assert(enc.dyn_tab.max_size == A_HPACK_INITIAL_SETTINGS_HDR_SZ);
    assert(dec.dyn_tab.max_size == A_HPACK_INITIAL_SETTINGS_HDR_SZ);

    rv = aura_hpack_encode_headers(&enc, &intern_tab, nv_pair1, ARR_CNT(nv_pair1));
    assert(rv == 0);
    assert(enc.dyn_tab.cnt == 2);
    assert(aura_hpack_tab_get_entry_cnt(&enc.dyn_tab) == 63);
    assert(enc.dyn_tab.max_size == A_HPACK_INITIAL_SETTINGS_HDR_SZ);

    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);

    dec_fields = aura_alloc(&mc, sizeof(*dec_fields) * ARR_CNT(nv_pair1));
    hdr_cnt = 0;
    rv = aura_hpack_header_decode_test(&dec, &intern_tab, dec_fields, src_in, in_len, &hdr_cnt, true);
    assert(rv == 0);
    assert(dec.dyn_tab.cnt == 2);
    assert(aura_hpack_tab_get_entry_cnt(&dec.dyn_tab) == 63);
    assert(dec.dyn_tab.max_size == A_HPACK_INITIAL_SETTINGS_HDR_SZ);

    a_hpack_test_destroy_headers(dec_fields, ARR_CNT(nv_pair1));
    aura_sliding_buf_reset(&enc.enc_buf);

    /* Update table sizes */
    assert(aura_hpack_decoder_update_tab_size(&dec, 1024) == 0);
    assert(aura_hpack_encoder_update_tab_size(&enc, 1024) == 0);

    assert(dec.dyn_tab.max_size == 1024);
    assert(enc.dyn_tab.max_size == 1024);

    assert(enc.dyn_tab.cnt == 2);
    assert(aura_hpack_tab_get_entry_cnt(&enc.dyn_tab) == 63);
    assert(enc.dyn_tab.max_size == 1024);

    assert(dec.dyn_tab.cnt == 2);
    assert(aura_hpack_tab_get_entry_cnt(&dec.dyn_tab) == 63);
    assert(dec.dyn_tab.max_size == 1024);

    /* update table size to 0 */
    assert(aura_hpack_decoder_update_tab_size(&dec, 0) == 0);
    assert(aura_hpack_encoder_update_tab_size(&enc, 0) == 0);

    assert(enc.dyn_tab.cnt == 0);
    assert(aura_hpack_tab_get_entry_cnt(&enc.dyn_tab) == 61);
    assert(enc.dyn_tab.max_size == 0);

    assert(dec.dyn_tab.cnt == 0);
    assert(aura_hpack_tab_get_entry_cnt(&dec.dyn_tab) == 61);
    assert(dec.dyn_tab.max_size == 0);

    rv = aura_hpack_encode_headers(&enc, &intern_tab, nv_pair1, ARR_CNT(nv_pair1));
    assert(rv == 0);
    assert(enc.dyn_tab.cnt == 0);
    assert(aura_hpack_tab_get_entry_cnt(&enc.dyn_tab) == 61);
    assert(enc.dyn_tab.max_size == 0);

    src_in = aura_sliding_buf_read_ptr(&enc.enc_buf);
    in_len = aura_sliding_buf_read_len(&enc.enc_buf);

    dec_fields = aura_alloc(&mc, sizeof(*dec_fields) * ARR_CNT(nv_pair1));
    hdr_cnt = 0;
    rv = aura_hpack_header_decode_test(&dec, &intern_tab, dec_fields, src_in, in_len, &hdr_cnt, true);
    assert(rv == 0);
    assert(dec.dyn_tab.cnt == 0);
    assert(aura_hpack_tab_get_entry_cnt(&dec.dyn_tab) == 61);
    assert(dec.dyn_tab.max_size == 0);

    a_hpack_test_destroy_headers(dec_fields, ARR_CNT(nv_pair1));

    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

static void _a_hpack_test_encode_decode(struct aura_hpack_encoder *enc,
                                        struct aura_hpack_decoder *dec,
                                        struct aura_basic_header *hdrs, size_t hdr_cnt) {
    struct aura_header_field *dec_fields;
    uint8_t *src_in;
    size_t in_len, dec_hdr_cnt;
    int rv;

    dec_fields = aura_alloc(&mc, sizeof(*dec_fields) * hdr_cnt);
    assert(dec_fields != NULL);
    memset(dec_fields, 0, sizeof(*dec_fields) * hdr_cnt);

    rv = aura_hpack_encode_headers(enc, &intern_tab, hdrs, hdr_cnt);
    assert(rv == 0);

    src_in = aura_sliding_buf_read_ptr(&enc->enc_buf);
    in_len = aura_sliding_buf_read_len(&enc->enc_buf);
    dec_hdr_cnt = 0;
    rv = aura_hpack_header_decode_test(dec, &intern_tab, dec_fields, src_in, in_len, &dec_hdr_cnt, true);
    assert(rv == 0);
    assert(hdr_cnt == dec_hdr_cnt);

    for (int i = 0; i < hdr_cnt; ++i) {
        assert(memcmp(hdrs[i].name.base, dec_fields[i].name->data, hdrs[i].name.len) == 0);
        if (dec_fields[i].flags & A_HDR_FIELD_FLAG_VALUE_INTERNED)
            assert(memcmp(hdrs[i].value.base, dec_fields[i].value.interned->data, hdrs[i].value.len) == 0);
        else
            assert(memcmp(hdrs[i].value.base, dec_fields[i].value.raw.str.base, hdrs[i].value.len) == 0);
    }
    aura_sliding_buf_consume(&enc->enc_buf, in_len);
    a_hpack_test_destroy_headers(dec_fields, dec_hdr_cnt);
}

static void a_hpack_test_encode_decode() {
    struct aura_basic_header nv_pairs1[] = {
      A_MAKE_HDR(":status", "200 OK"),
      A_MAKE_HDR("access-control-allow-origin", "*"),
      A_MAKE_HDR("cache-control", "private, max-age=0, must-revalidate"),
      A_MAKE_HDR("content-length", "76073"),
      A_MAKE_HDR("content-type", "text/html"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("expires", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("server", "Apache"),
      A_MAKE_HDR("vary", "foobar"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "MISS from alphabravo"),
      A_MAKE_HDR("x-cache-action", "MISS"),
      A_MAKE_HDR("x-cache-age", "0"),
      A_MAKE_HDR("x-cache-lookup", "MISS from alphabravo:3128"),
      A_MAKE_HDR("x-lb-nocache", "true"),
    };
    struct aura_basic_header nv_pairs2[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=56682045"),
      A_MAKE_HDR("content-type", "text/css"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("expires", "Thu, 14 May 2015 07:22:57 GMT"),
      A_MAKE_HDR("last-modified", "Tue, 14 May 2013 07:22:15 GMT"),
      A_MAKE_HDR("vary", "Accept-Encoding"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs3[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=56682072"),
      A_MAKE_HDR("content-type", "text/css"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("expires", "Thu, 14 May 2015 07:23:24 GMT"),
      A_MAKE_HDR("last-modified", "Tue, 14 May 2013 07:22:13 GMT"),
      A_MAKE_HDR("vary", "Accept-Encoding"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs4[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=56682022"),
      A_MAKE_HDR("content-type", "text/css"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("expires", "Thu, 14 May 2015 07:22:34 GMT"),
      A_MAKE_HDR("last-modified", "Tue, 14 May 2013 07:22:14 GMT"),
      A_MAKE_HDR("vary", "Accept-Encoding"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs5[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=4461139"),
      A_MAKE_HDR("content-type", "application/x-javascript"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("expires", "Mon, 16 Sep 2013 21:34:31 GMT"),
      A_MAKE_HDR("last-modified", "Thu, 05 May 2011 09:15:59 GMT"),
      A_MAKE_HDR("vary", "Accept-Encoding"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs6[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=18645951"),
      A_MAKE_HDR("content-type", "application/x-javascript"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("expires", "Fri, 28 Feb 2014 01:48:03 GMT"),
      A_MAKE_HDR("last-modified", "Tue, 12 Jul 2011 16:02:59 GMT"),
      A_MAKE_HDR("vary", "Accept-Encoding"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs7[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=31536000"),
      A_MAKE_HDR("content-type", "application/javascript"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("etag", "\"6807-4dc5b54e0dcc0\""),
      A_MAKE_HDR("expires", "Wed, 21 May 2014 08:32:17 GMT"),
      A_MAKE_HDR("last-modified", "Fri, 10 May 2013 11:18:51 GMT"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs8[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=31536000"),
      A_MAKE_HDR("content-type", "application/javascript"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("etag", "\"41c6-4de7d28585b00\""),
      A_MAKE_HDR("expires", "Thu, 12 Jun 2014 10:00:58 GMT"),
      A_MAKE_HDR("last-modified", "Thu, 06 Jun 2013 14:30:36 GMT"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs9[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=31536000"),
      A_MAKE_HDR("content-type", "application/javascript"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("etag", "\"19d6e-4dc5b35a541c0\""),
      A_MAKE_HDR("expires", "Wed, 21 May 2014 08:32:18 GMT"),
      A_MAKE_HDR("last-modified", "Fri, 10 May 2013 11:10:07 GMT"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };
    struct aura_basic_header nv_pairs10[] = {
      A_MAKE_HDR(":status", "304 Not Modified"),
      A_MAKE_HDR("age", "0"),
      A_MAKE_HDR("cache-control", "max-age=56682045"),
      A_MAKE_HDR("content-type", "text/css"),
      A_MAKE_HDR("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      A_MAKE_HDR("expires", "Thu, 14 May 2015 07:22:57 GMT"),
      A_MAKE_HDR("last-modified", "Tue, 14 May 2013 07:21:53 GMT"),
      A_MAKE_HDR("vary", "Accept-Encoding"),
      A_MAKE_HDR("via", "1.1 alphabravo (squid/3.x.x), 1.1 aura"),
      A_MAKE_HDR("x-cache", "HIT from alphabravo"),
      A_MAKE_HDR("x-cache-lookup", "HIT from alphabravo:3128"),
    };

    assert(aura_hpack_encoder_init(&enc, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);
    assert(aura_hpacK_decoder_init(&dec, &mc, A_HPACK_INITIAL_SETTINGS_HDR_SZ) == 0);

    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs1, ARR_CNT(nv_pairs1));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs2, ARR_CNT(nv_pairs2));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs3, ARR_CNT(nv_pairs3));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs4, ARR_CNT(nv_pairs4));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs5, ARR_CNT(nv_pairs5));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs6, ARR_CNT(nv_pairs6));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs7, ARR_CNT(nv_pairs7));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs8, ARR_CNT(nv_pairs8));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs9, ARR_CNT(nv_pairs9));
    _a_hpack_test_encode_decode(&enc, &dec, nv_pairs10, ARR_CNT(nv_pairs10));

    aura_hpack_encoder_destroy(&enc);
    aura_hpack_decoder_destroy(&dec);
}

int main(int argc, char *argv[]) {
    a_test_resources_create();

    a_hpack_test_decode();
    a_hpack_test_encode_indexed();
    a_hpack_test_decode_indexed_name_no_inc();
    a_hpack_test_decode_indexed_inc();
    a_hpack_test_decode_duplicate_indexed_repr();
    a_hpack_test_decode_indexed_name_inc_evict();
    a_hpack_test_decode_newname_no_inc();
    a_hpack_test_decode_newname_inc();
    a_hpack_test_decode_clearall_inc();
    a_hpack_test_decode_huff_zero_len();
    a_hpack_test_decode_expect_tab_size_update();
    a_hpack_test_decode_unexpected_tab_size_update();
    a_hpack_test_table_size_change();
    a_hpack_test_encode_decode();

    a_test_resources_destroy();
    return 0;
}