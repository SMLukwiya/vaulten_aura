#ifndef AURA_URL_H
#define AURA_URL_H

#include "types_lib.h"

struct aura_url {
    int scheme;
    struct {
        struct aura_iovec host;
        uint16_t port;
    } authority;
    struct aura_iovec path;
    struct aura_iovec query;
};

struct aura_iovec aura_url_path_normalize(struct aura_memory_ctx *mc, char *path, size_t len);

int aura_url_parse(struct aura_memory_ctx *mc, const char *url_str, size_t len, struct aura_url *url);

int aura_url_get_default_port(struct aura_url *url);

#endif