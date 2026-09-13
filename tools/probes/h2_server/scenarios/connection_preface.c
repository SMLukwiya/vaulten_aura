#include "../probe.h"
#include "utils_lib.h"

void scenario_invalid_conn_preface(const char *host, const char *port) {
    struct aura_h2_probe_ctx p_ctx;
    uint64_t len = sizeof(conn_preface_invalid);
    int rv;
    uint8_t buf[16];

    aura_h2_probe_connect(&p_ctx, host, port);
    assert(aura_h2_probe_tls_handshake(&p_ctx) == 0);
    assert(aura_h2_probe_send(&p_ctx, conn_preface_invalid, len, 0, len) == 0);
    rv = aura_h2_probe_recv(&p_ctx, buf, sizeof(buf));
    assert(SSL_get_error(p_ctx.ssl, rv) == SSL_ERROR_ZERO_RETURN);
}

static const struct aura_h2_probe_scenarios scenarios[] = {
  {.name = "Invalid Connection Preface", .scenario_fn = scenario_invalid_conn_preface},
};

const struct aura_h2_probe_scenario_group preface_scenarios = {
  .name = "Connection Preface Scenarios",
  .scenarios = scenarios,
  .scenario_cnt = ARR_CNT(scenarios),
};