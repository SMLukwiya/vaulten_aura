#ifndef AURA_H2_CLIENT_H
#define AURA_H2_CLIENT_H

#include "http_lib.h"
#include "memory_lib.h"
#include "slab_lib.h"

struct aura_client_pending_req {
    struct aura_list_head head;
    void *user_data;
};

int aura_client_request_create(const char *url, size_t url_len, void *user_data);

#endif