#ifndef AURA_SRV_RUNTIME_H
#define AURA_SRV_RUNTIME_H

#include <stdbool.h>

#include "function_lib.h"
#include "js.h"
#include "quickjs.h"
#include "server_srv.h"
#include "task_srv.h"
#include "types_lib.h"

#define A_RT_INITIALIZED 0xA0A0A0A0A0A0A0A0

typedef enum {
    A_WQ_JS = 1
} aura_wq_backend_t;

typedef enum {
    A_QJS_REQ_TYPE = 1, /* Quick js request type */
} aura_rt_req_t;

struct aura_runtime;

/* Could be much better I think */
struct aura_rt_ops {
    /* Create underlying engine */
    int (*on_create)(struct aura_runtime *, struct aura_srv_ctx *s_ctx, struct aura_fn *);
    /* Destroy underlying engine */
    void (*on_destroy)(struct aura_runtime *);
    /* Invoke underlying engine executor */
    int (*on_execute)(struct aura_runtime *, struct aura_task *);
};

/* Generic runtime structure */
struct aura_runtime {
    struct aura_rt_ops ops;
    void *rt_ctx; /* Underlying runtime engine */
    aura_wq_backend_t backend;
};

/* Initialize runtime structure */
void aura_rt_init(struct aura_runtime *rt, void *data, aura_wq_backend_t backend);

/* Destroy runtime */
void aura_rt_destroy(struct aura_runtime *rt);

#endif