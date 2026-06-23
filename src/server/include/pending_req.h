#ifndef AURA_PENDING_REQ_H
#define AURA_PENDING_REQ_H

#include "list_lib.h"
#include "mem.h"
#include "slab.h"

#include <pthread.h>

typedef enum {
    A_PENDING_REQ_H2_JS
} aura_pending_req_t;

typedef void (*user_data_destructor)(void *user_data);

/* Pending request structure */
struct aura_pending_req {
    aura_pending_req_t type;         /* request type */
    char domain[256];                /* connection domain for request */
    void *associated_handler;        /* pointer to actual handler for req */
    void *user_data;                 /* opaque user data */
    user_data_destructor destructor; /* user data destructor */
    struct aura_list_head p_list;
};

/* Pending request coordinator */
struct aura_req_coordinator {
    pthread_mutex_t mutex;
    struct aura_list_head head;
};

/**/
void aura_pending_req_coordinator_init(struct aura_req_coordinator *coord);

/**/
void aura_pending_req_coordinator_destroy(struct aura_req_coordinator *coord);

/**/
struct aura_pending_req *aura_pending_req_create(struct aura_mem_ctx *mc, aura_pending_req_t type,
                                                 void *user_data, user_data_destructor destructor,
                                                 void *assoc_handler, const uint8_t *domain, size_t domain_len);

/**/
void aura_pending_req_destroy(struct aura_pending_req *p_req);

/**/
static inline void aura_pending_req_add(struct aura_req_coordinator *coord, struct aura_pending_req *p_req) {
    pthread_mutex_lock(&coord->mutex);
    aura_list_add_tail(&coord->head, &p_req->p_list);
    pthread_mutex_unlock(&coord->mutex);
}

#endif