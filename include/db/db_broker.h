#ifndef AURA_DB_BROKER_H
#define AURA_DB_BROKER_H

#include "memory_lib.h"
#include "slab_lib.h"
#include "types_lib.h"

/* db request */
struct aura_db_broker_request {
    uint16_t namespace; /* Record namespace */
    uint16_t schema_id; /* Record schema */
    uint64_t job_id;
    int mode; /* Execution mode */
    struct aura_iovec key;
    struct aura_iovec data;
};

int aura_db_broker_fetch(struct aura_memory_ctx *mc, uint16_t ns, uint16_t schema_id,
                         struct aura_iovec *key, struct aura_iovec *out_data, int dmn_fd);

void aura_db_request_dump(struct aura_db_broker_request *req);

#endif