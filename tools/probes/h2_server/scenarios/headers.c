#include "../hpack.h"
#include "../probe.h"
#include "utils_lib.h"

void headers_missing_authority(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    const uint8_t buf[1024];
    uint8_t *ptr = (uint8_t *)buf, *end = ptr + sizeof(buf);
    uint8_t headers[64], *hdr = headers; /* headers buffer */
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t settings_frame_len = sizeof(preface_settings_frame);
    uint64_t rv, header_len = 0, len;
    int read;

    /* connection preface */
    memcpy(ptr, conn_preface_valid, sizeof(conn_preface_valid));
    ptr += sizeof(conn_preface_valid);
    /* preface settings */
    memcpy(ptr, preface_settings_frame, sizeof(preface_settings_frame));
    ptr += sizeof(preface_settings_frame);

    /* method */
    rv = aura_hpack_encode_indexed_block(hdr, 2);
    /* path */
    header_len += rv;
    rv = aura_hpack_encode_indexed_block(hdr + header_len, 5);
    /* scheme */
    header_len += rv;
    rv = aura_hpack_encode_indexed_block(hdr + header_len, 7);
    header_len += rv;

    /* encode frame header */
    int flags = A_H2_FRAME_FLAG_END_HEADERS | A_H2_FRAME_FLAG_END_STREAM;
    aura_h2_encode_frame_header(ptr, header_len, A_H2_FRAME_TYPE_HDRS, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;

    memcpy(ptr, hdr, header_len);
    ptr += header_len;

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, buf, len, 0, len) == 0);
    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);
    aura_h2_probe_expect_rst_stream(buf, read, A_H2_PROTOCOL_ERR);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void pseudo_after_regular_headers(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    const uint8_t buf[1024];
    uint8_t *ptr = (uint8_t *)buf, *end = ptr + sizeof(buf);
    uint8_t headers[64], *hdr = headers;
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t settings_frame_len = sizeof(preface_settings_frame);
    uint64_t rv, header_len = 0, len;
    struct aura_iovec val;
    int read;

    /* connection preface */
    memcpy(ptr, conn_preface_valid, sizeof(conn_preface_valid));
    ptr += sizeof(conn_preface_valid);
    /* preface settings */
    memcpy(ptr, preface_settings_frame, sizeof(preface_settings_frame));
    ptr += sizeof(preface_settings_frame);

    /* method */
    rv = aura_hpack_encode_indexed_block(hdr, 2);
    /* path */
    header_len += rv;
    rv = aura_hpack_encode_indexed_block(hdr + header_len, 5);
    /* scheme */
    header_len += rv;
    rv = aura_hpack_encode_indexed_block(hdr + header_len, 7);
    header_len += rv;
    /* normal header */
    rv = aura_hpack_encode_indexed_block(hdr + header_len, 16);
    header_len += rv;
    /* authority */
    val.base = "vaultenaura";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_indexed_name(hdr + header_len, sizeof(headers) - header_len, 1, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;

    /* encode frame header */
    int flags = A_H2_FRAME_FLAG_END_HEADERS | A_H2_FRAME_FLAG_END_STREAM;
    aura_h2_encode_frame_header(ptr, header_len, A_H2_FRAME_TYPE_HDRS, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;

    memcpy(ptr, hdr, header_len);
    ptr += header_len;

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, buf, len, 0, len) == 0);
    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);
    aura_h2_probe_expect_rst_stream(buf, read, A_H2_PROTOCOL_ERR);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void uppercase_in_header_name(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    const uint8_t buf[1024];
    uint8_t *ptr = (uint8_t *)buf, *end = ptr + sizeof(buf);
    uint8_t headers[128], *hdr = headers;
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t settings_frame_len = sizeof(preface_settings_frame);
    uint64_t rv, header_len = 0, len;
    struct aura_iovec name, val;
    int read;

    /* connection preface */
    memcpy(ptr, conn_preface_valid, sizeof(conn_preface_valid));
    ptr += sizeof(conn_preface_valid);
    /* preface settings */
    memcpy(ptr, preface_settings_frame, sizeof(preface_settings_frame));
    ptr += sizeof(preface_settings_frame);

    /* method */
    rv = aura_hpack_encode_indexed_block(hdr, 2);
    /* path */
    header_len += rv;
    rv = aura_hpack_encode_indexed_block(hdr + header_len, 5);
    /* scheme */
    header_len += rv;
    rv = aura_hpack_encode_indexed_block(hdr + header_len, 7);
    header_len += rv;
    /* authority */
    val.base = "vaultenaura";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_indexed_name(hdr + header_len, sizeof(headers) - header_len, 1, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;
    /* uppercase in header name */
    name.base = "Priority";
    name.len = strlen(name.base);
    val.base = "u=5,i";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_new_name(hdr + header_len, sizeof(headers) - header_len, &name, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;

    /* encode frame header */
    int flags = A_H2_FRAME_FLAG_END_HEADERS | A_H2_FRAME_FLAG_END_STREAM;
    aura_h2_encode_frame_header(ptr, header_len, A_H2_FRAME_TYPE_HDRS, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;

    memcpy(ptr, hdr, header_len);
    ptr += header_len;

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, buf, len, 0, len) == 0);
    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);
    aura_h2_probe_expect_rst_stream(buf, read, A_H2_PROTOCOL_ERR);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

static const struct aura_h2_probe_scenarios scenarios[] = {
  {.name = "Missing authority pseudo header", .scenario_fn = headers_missing_authority},
  {.name = "Pseudo header after regular header", .scenario_fn = pseudo_after_regular_headers},
  {.name = "Uppercase in header name", .scenario_fn = uppercase_in_header_name},
};

const struct aura_h2_probe_scenario_group headers_scenarios = {
  .name = "Headers Scenarios",
  .scenarios = scenarios,
  .scenario_cnt = ARR_CNT(scenarios),
};