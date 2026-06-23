#ifndef AURA_RH_COMPLETION
#define AURA_RH_COMPLETION

#include "error_lib.h"
#include "list_lib.h"
#include "mem.h"
#include "slab.h"
#include "task_srv.h"
#include <pthread.h>

/* Completion queue */
struct aura_completion_queue {
    struct aura_list_head list;
    pthread_mutex_t lock;
    int efd;              /* event fd for walking up */
    size_t cnt;           /* active + completed count */
    size_t completed_cnt; /* completed count */
    size_t error_cnt;     /* error count */
};

/* Completion structure */
struct aura_completion {
    struct aura_task *task;
    struct aura_list_head c_list;
};

/* init task completion queue */
int aura_completion_queue_init(struct aura_completion_queue *cq);

/* destroy task completion queue */
void aura_completion_queue_destroy(struct aura_completion_queue *cq);

/* Destroy a completion object */
void aura_completion_destroy(struct aura_completion *c);

static inline struct aura_completion *aura_completion_create(struct aura_mem_ctx *mc, struct aura_task *task) {
    struct aura_completion *c;

    c = (struct aura_completion *)aura_alloc(mc, sizeof(*c));
    if (!c)
        return NULL;
    aura_list_head_init(&c->c_list);
    c->task = task;
    aura_task_transition_state(task, A_TASK_STATE_DONE);
    return c;
}

int aura_completion_queue_push(struct aura_completion_queue *cq, struct aura_completion *c);

#endif