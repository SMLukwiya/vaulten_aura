#ifndef AURA__SRV_WORKER_H
#define AURA__SRV_WORKER_H

#include "function_lib.h"
#include "list_lib.h"
#include "runtime/runtime.h"
#include "task_srv.h"

#include <pthread.h>
#include <stdint.h>

#define A_WQ_INITIALIZED 0xc5c5c5c5

/* aura work queue structure */
struct aura_work_queue {
    struct aura_srv_ctx *srv_ctx;
    uint32_t magic;
    pthread_mutex_t mutex; /* sync queue access */
    pthread_attr_t th_attr;
    pthread_cond_t cond_var;
    struct aura_runtime rt;
    struct aura_list_head task_list;
    uint32_t max_instances;
    uint32_t curr_instances;
    uint32_t idle_instances;
    bool quit;
    bool running;
};

/**
 * Initialize work queue
 */
int aura_work_queue_init(struct aura_work_queue *wq, struct aura_srv_ctx *, struct aura_fn *fn);

/**
 * Destroy work queue
 */
int aura_work_queue_destroy(struct aura_work_queue *wq);

/**
 * Add a task to the work queue
 */
int aura_work_queue_add(struct aura_work_queue *wq, struct aura_fn *fn, struct aura_task *task);

#endif