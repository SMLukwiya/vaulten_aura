#ifndef AURA_DB_BROKER_H
#define AURA_DB_BROKER_H

#include "db.h"
#include "mem.h"
#include "slab.h"
#include "types_lib.h"
#include "unix/sock.h"

/* db request */
struct aura_db_brokered_request {
    struct aura_iovec key;
    struct aura_iovec data;
    ns_t namespace;        /* Record namespace */
    schema_id_t schema_id; /* Record schema */
};

int aura_db_brokered_fetch(struct aura_mem_ctx *mc, ns_t ns, schema_id_t schema_id,
                           struct aura_iovec *key, struct aura_iovec *out_data,
                           int dmn_fd);

void aura_db_request_dump(struct aura_db_brokered_request *req);

#endif