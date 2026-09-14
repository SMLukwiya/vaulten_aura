#include "../probe.h"
#include "utils_lib.h"

void invalid_conn_preface(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    uint64_t len = sizeof(conn_preface_invalid);
    int rv, err;
    uint8_t buf[16];

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    assert(aura_h2_probe_send(&p_ctx, conn_preface_invalid, len, 0, len) == 0);
    rv = aura_h2_probe_recv(&p_ctx, buf, sizeof(buf));
    err = SSL_get_error(p_ctx.ssl, rv);
    /* Abrupt TCP closure */
    assert(err == SSL_ERROR_SSL);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void invalid_preface_settings_sz(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t preface_settings_len = sizeof(preface_settings_frame_invalid_sz);
    int rv, err;
    const uint8_t buf[1024];

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    assert(aura_h2_probe_send(&p_ctx, conn_preface_valid, preface_len, 0, preface_len) == 0);
    assert(aura_h2_probe_send(&p_ctx, preface_settings_frame_invalid_sz, preface_settings_len, 0, preface_settings_len) == 0);
    rv = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(rv > 0);
    err = SSL_get_error(p_ctx.ssl, rv);
    aura_h2_probe_expect_goaway(buf, (uint64_t)rv, A_H2_PROTOCOL_ERR);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void invalid_preface_settings_stream_id(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t preface_settings_len = sizeof(preface_settings_invalid_stream_id);
    int rv, err;
    const uint8_t buf[1024];

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    assert(aura_h2_probe_send(&p_ctx, conn_preface_valid, preface_len, 0, preface_len) == 0);
    assert(aura_h2_probe_send(&p_ctx, preface_settings_invalid_stream_id, preface_settings_len, 0, preface_settings_len) == 0);
    rv = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(rv > 0);
    err = SSL_get_error(p_ctx.ssl, rv);
    aura_h2_probe_expect_goaway(buf, (uint64_t)rv, A_H2_PROTOCOL_ERR);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void invalid_frame_type(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t wind_update_len = sizeof(wind_update_valid);
    int rv, err;
    const uint8_t buf[1024];

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    assert(aura_h2_probe_send(&p_ctx, conn_preface_valid, preface_len, 0, preface_len) == 0);
    assert(aura_h2_probe_send(&p_ctx, wind_update_valid, wind_update_len, 0, wind_update_len) == 0);
    rv = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(rv > 0);
    err = SSL_get_error(p_ctx.ssl, rv);
    aura_h2_probe_expect_goaway(buf, (uint64_t)rv, A_H2_PROTOCOL_ERR);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

void valid_conn_preface(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    uint64_t preface_len = sizeof(conn_preface_valid);
    uint64_t settings_frame_len = sizeof(preface_settings_frame);
    int rv, err;
    const uint8_t buf[1024];

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    assert(aura_h2_probe_send(&p_ctx, conn_preface_valid, preface_len, 0, preface_len) == 0);
    assert(aura_h2_probe_send(&p_ctx, preface_settings_frame, settings_frame_len, 0, settings_frame_len) == 0);
    rv = aura_h2_probe_recv(&p_ctx, (uint8_t *)buf, sizeof(buf));
    assert(rv > 0);
    err = SSL_get_error(p_ctx.ssl, rv);
    aura_h2_probe_expect_settings(buf, (uint64_t)rv);
    aura_h2_probe_close(&p_ctx);
    app_info(false, 0, "%s", passed);
}

static const struct aura_h2_probe_scenarios scenarios[] = {
  {.name = "Invalid Connection Preface", .scenario_fn = invalid_conn_preface},
  {.name = "Invalid Preface setting size", .scenario_fn = invalid_preface_settings_sz},
  {.name = "Invalid Preface setting stream id", .scenario_fn = invalid_preface_settings_stream_id},
  {.name = "Invalid Frame Type", .scenario_fn = invalid_frame_type},
  {.name = "Valid connection preface", .scenario_fn = valid_conn_preface},
};

const struct aura_h2_probe_scenario_group preface_scenarios = {
  .name = "Connection Preface Scenarios",
  .scenarios = scenarios,
  .scenario_cnt = ARR_CNT(scenarios),
};