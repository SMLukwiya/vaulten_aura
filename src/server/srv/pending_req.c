#include "pending_req.h"

#include <string.h>

void aura_pending_req_coordinator_init(struct aura_req_coordinator *coord) {
    memset(coord, 0, sizeof(coord));
    pthread_mutex_init(&coord->mutex, NULL);
    aura_list_head_init(&coord->head);
}

void aura_pending_req_coordinator_destroy(struct aura_req_coordinator *coord) {
    struct aura_pending_req *p_req;

    if (!coord)
        return;

    while (!aura_list_is_empty(&coord->head)) {
        a_list_dequeue(p_req, &coord->head, p_list);

        aura_pending_req_destroy(p_req);
    }

    pthread_mutex_destroy(&coord->mutex);
}

struct aura_pending_req *aura_pending_req_create(struct aura_mem_ctx *mc, aura_pending_req_t type,
                                                 void *user_data, user_data_destructor destructor,
                                                 void *assoc_handler, const uint8_t *domain, size_t domain_len) {
    struct aura_pending_req *p_req;

    p_req = aura_alloc(mc, sizeof(*p_req));
    if (!p_req)
        return NULL;

    p_req->type = type;
    p_req->user_data = user_data;
    p_req->destructor = destructor;
    p_req->associated_handler = assoc_handler;
    memcpy(p_req->domain, domain, domain_len);

    return p_req;
}

void aura_pending_req_destroy(struct aura_pending_req *p_req) {
    if (!p_req)
        return;

    if (p_req->user_data)
        p_req->destructor(p_req->user_data);

    aura_free(p_req);
}
