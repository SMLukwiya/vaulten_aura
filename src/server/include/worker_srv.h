#ifndef AURA_SRV_WORKER_H
#define AURA_SRV_WORKER_H

#include "fn/lib.h"
#include "list_lib.h"
#include "runtime/runtime.h"
#include "task_srv.h"

#include <pthread.h>
#include <stdint.h>

#define A_WQ_INITIALIZED 0xc5c5c5c5

struct aura_wq_thread_info {
    pthread_t thread_id; /* Thread Id */
    uint32_t thread_num; /* Application thread number */
};

struct aura_wq_thread_vec {
    struct aura_wq_thread_info *thread_info;
    size_t cnt;
    size_t cap;
};

/* aura work queue structure */
struct aura_work_queue {
    struct aura_srv_ctx *srv_ctx;
    uint32_t magic;
    pthread_mutex_t mutex;
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

/**/
int aura_work_queue_thread_vec_add(struct aura_wq_thread_vec *vec, struct aura_mem_ctx *mc,
                                   pthread_t thread_id);

#endif