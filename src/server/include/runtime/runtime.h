#ifndef AURA_SRV_RUNTIME_H
#define AURA_SRV_RUNTIME_H

#include "function_lib.h"
#include "js.h"
#include "quickjs.h"
#include "task_srv.h"
#include "types_lib.h"
#include <stdbool.h>
#include <sys/eventfd.h>

#define A_RT_INITIALIZED 0xA0A0A0A0A0A0A0A0

typedef enum {
    A_WQ_JS = 1
} aura_wq_backend_t;

struct aura_runtime;

/* Could be much better I think */
struct aura_rt_ops {
    /* Create underlying engine */
    int (*on_create)(struct aura_runtime *, struct aura_memory_ctx *mc, struct aura_fn *);
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

/* Completion queue */
struct aura_completion_queue {
    struct aura_list_head list;
    pthread_mutex_t lock;
    int efd; /* event fd for walking up */
};

/* Completion structure */
struct aura_completion {
    struct aura_task *task;
    struct aura_list_head c_list;
};

/* Initialize runtime structure */
void aura_rt_init(struct aura_runtime *rt, void *data, aura_wq_backend_t backend);

/* Destroy runtime */
void aura_rt_destroy(struct aura_runtime *rt);

/* init task completion queue */
int aura_completion_queue_init(struct aura_completion_queue *cq);

/* destroy task completion queue */
void aura_completion_queue_destroy(struct aura_completion_queue *cq);

/* Destroy a completion object */
void aura_completion_destroy(struct aura_completion *c);

static inline struct aura_completion *aura_completion_create(struct aura_memory_ctx *mc, struct aura_task *task) {
    struct aura_completion *c;

    app_debug(true, 0, "aura_completion_create <<<<");

    c = aura_alloc(mc, sizeof(*c));
    if (!c)
        return NULL;
    a_list_head_init(&c->c_list);
    c->task = task;
    aura_task_transition_state(task, A_TASK_STATE_DONE);
    return c;
}

int aura_completion_queue_push(struct aura_completion_queue *cq, struct aura_completion *c);

#endif