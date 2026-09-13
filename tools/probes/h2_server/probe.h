#ifndef AURA_H2_SERVER_PROBE_H
#define AURA_H2_SERVER_PROBE_H

#include "frame.h"
#include "utils.h"

struct aura_h2_probe_ctx {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};

struct aura_h2_probe_scenarios {
    const char *name;
    void (*scenario_fn)(const char *host, const char *port);
};

struct aura_h2_probe_scenario_group {
    const char *name;
    const struct aura_h2_probe_scenarios *scenarios;
    uint32_t scenario_cnt;
};

int aura_h2_probe_connect(struct aura_h2_probe_ctx *p_ctx, const char *host, const char *port);
int aura_h2_probe_tls_handshake(struct aura_h2_probe_ctx *p_ctx);
void aura_h2_probe_close(struct aura_h2_probe_ctx *p_ctx);
int aura_h2_probe_send_preface(struct aura_h2_probe_ctx *p_ctx);
int aura_h2_probe_send_preface_settings(struct aura_h2_probe_ctx *p_ctx);
int aura_h2_probe_send(struct aura_h2_probe_ctx *p_ctx, const uint8_t *buf, uint64_t len, uint64_t start, uint64_t end);
int aura_h2_probe_recv(struct aura_h2_probe_ctx *p_ctx, uint8_t *buf, uint64_t len);

#endif