#include "../hpack.h"
#include "../probe.h"
#include "utils_lib.h"

void interleaved_frames(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    const uint8_t buf[1024];
    uint8_t *ptr = (uint8_t *)buf, *end = ptr + sizeof(buf);
    uint8_t headers[64], *hdr = headers; /* headers buffer */
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t settings_frame_len = sizeof(preface_settings_frame);
    uint64_t rv, header_len = 0, len;
    struct aura_iovec name, val;
    int64_t received, consumed = 0;
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
    /* priority */
    name.base = "priority";
    name.len = strlen(name.base);
    val.base = "u=5,i";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_new_name(hdr + header_len, sizeof(headers) - header_len, &name, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;
    /*  */
    name.base = "x-aura";
    name.len = strlen(name.base);
    val.base = "wizzy";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_new_name(hdr + header_len, sizeof(headers) - header_len, &name, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;

    /* encode frame header (no end_headers) */
    int flags = A_H2_FRAME_FLAG_END_STREAM;
    aura_h2_encode_frame_header(ptr, header_len / 2, A_H2_FRAME_TYPE_HDRS, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;

    memcpy(ptr, hdr, header_len / 2);
    ptr += header_len / 2;

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, buf, len, 0, len) == 0);

    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);

    /* ack */
    received = aura_h2_probe_expect_settings(buf, read);
    consumed += received;
    /* server settings */
    received = aura_h2_probe_expect_settings(buf + consumed, read - consumed);
    consumed += received;
    /* initial wind update */
    received = aura_h2_probe_expect_wind_update(buf + consumed, read - consumed, 0);

    /* Send wrong frame type */
    flags = A_H2_FRAME_FLAG_END_HEADERS;
    memset((void *)buf, 0, sizeof(buf));
    ptr = (uint8_t *)buf;
    aura_h2_encode_frame_header(ptr, header_len - header_len / 2, A_H2_FRAME_TYPE_HDRS, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;
    memcpy(ptr, hdr + (header_len / 2), header_len - header_len / 2);
    ptr += (header_len - header_len / 2);

    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, (uint8_t *)buf, len, 0, len) == 0);

    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);
    received = aura_h2_probe_expect_goaway(buf, read, A_H2_PROTOCOL_ERR);

    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void wrong_stream_id(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    const uint8_t buf[1024];
    uint8_t *ptr = (uint8_t *)buf, *end = ptr + sizeof(buf);
    uint8_t headers[64], *hdr = headers; /* headers buffer */
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t settings_frame_len = sizeof(preface_settings_frame);
    uint64_t rv, header_len = 0, len;
    struct aura_iovec name, val;
    int64_t received, consumed = 0;
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
    /* priority */
    name.base = "priority";
    name.len = strlen(name.base);
    val.base = "u=5,i";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_new_name(hdr + header_len, sizeof(headers) - header_len, &name, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;
    /*  */
    name.base = "x-aura";
    name.len = strlen(name.base);
    val.base = "wizzy";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_new_name(hdr + header_len, sizeof(headers) - header_len, &name, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;

    /* encode frame header (no end_headers) */
    int flags = A_H2_FRAME_FLAG_END_STREAM;
    aura_h2_encode_frame_header(ptr, header_len / 2, A_H2_FRAME_TYPE_HDRS, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;

    memcpy(ptr, hdr, header_len / 2);
    ptr += header_len / 2;

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, buf, len, 0, len) == 0);

    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);

    /* ack */
    received = aura_h2_probe_expect_settings(buf, read);
    consumed += received;
    /* server settings */
    received = aura_h2_probe_expect_settings(buf + consumed, read - consumed);
    consumed += received;
    /* initial wind update */
    received = aura_h2_probe_expect_wind_update(buf + consumed, read - consumed, 0);

    /**
     * Send incorrect stream id
     * Better approach could be to open 2 connections
     * to have 2 valid streams ids
     */
    flags = A_H2_FRAME_FLAG_END_HEADERS;
    memset((void *)buf, 0, sizeof(buf));
    ptr = buf;
    aura_h2_encode_frame_header(ptr, header_len - header_len / 2, A_H2_FRAME_TYPE_CONT, flags, 2);
    ptr += A_H2_FRAME_HEADER_SIZE;
    memcpy(ptr, hdr + (header_len / 2), header_len - header_len / 2);
    ptr += (header_len - header_len / 2);

    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, (uint8_t *)buf, len, 0, len) == 0);

    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);
    received = aura_h2_probe_expect_goaway(buf, read, A_H2_PROTOCOL_ERR);

    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void valid_cont(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    const uint8_t buf[1024];
    uint8_t *ptr = (uint8_t *)buf, *end = ptr + sizeof(buf);
    uint8_t headers[64], *hdr = headers; /* headers buffer */
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t settings_frame_len = sizeof(preface_settings_frame);
    uint64_t rv, header_len = 0, len;
    struct aura_iovec name, val;
    int64_t received, consumed = 0;
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
    /* priority */
    name.base = "priority";
    name.len = strlen(name.base);
    val.base = "u=5,i";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_new_name(hdr + header_len, sizeof(headers) - header_len, &name, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;
    /*  */
    name.base = "x-aura";
    name.len = strlen(name.base);
    val.base = "wizzy";
    val.len = strlen(val.base);
    rv = aura_hpack_encode_new_name(hdr + header_len, sizeof(headers) - header_len, &name, &val, A_HPACK_HDR_FIELD_NEVER_INDEXED);
    header_len += rv;

    /* encode frame header (no end_headers) */
    int flags = A_H2_FRAME_FLAG_END_STREAM;
    aura_h2_encode_frame_header(ptr, header_len / 2, A_H2_FRAME_TYPE_HDRS, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;

    memcpy(ptr, hdr, header_len / 2);
    ptr += header_len / 2;

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, buf, len, 0, len) == 0);

    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);

    /* ack */
    received = aura_h2_probe_expect_settings(buf, read);
    consumed += received;
    /* server settings */
    received = aura_h2_probe_expect_settings(buf + consumed, read - consumed);
    consumed += received;
    /* initial wind update */
    received = aura_h2_probe_expect_wind_update(buf + consumed, read - consumed, 0);

    flags = A_H2_FRAME_FLAG_END_HEADERS;
    memset((void *)buf, 0, sizeof(buf));
    ptr = buf;
    aura_h2_encode_frame_header(ptr, header_len - header_len / 2, A_H2_FRAME_TYPE_CONT, flags, 1);
    ptr += A_H2_FRAME_HEADER_SIZE;
    memcpy(ptr, hdr + (header_len / 2), header_len - header_len / 2);
    ptr += (header_len - header_len / 2);

    len = sizeof(buf) - (end - ptr);
    assert(aura_h2_probe_send(&p_ctx, (uint8_t *)buf, len, 0, len) == 0);

    memset((void *)buf, 0, sizeof(buf));
    read = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(read > 0);
    received = aura_h2_probe_expect_to_have(buf, read, A_H2_FRAME_TYPE_HDRS, 1);

    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

static const struct aura_h2_probe_scenarios scenarios[] = {
  {.name = "Interleaved continuation frame", .scenario_fn = interleaved_frames},
  {.name = "Wrong stream for continuation", .scenario_fn = wrong_stream_id},
  {.name = "Valid continuation", .scenario_fn = valid_cont},
};

const struct aura_h2_probe_scenario_group continuation_scenarios = {
  .name = "Continuation Scenarios",
  .scenarios = scenarios,
  .scenario_cnt = ARR_CNT(scenarios),
};