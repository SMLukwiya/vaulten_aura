#ifndef AURA__SRV_WORKER_H
#define AURA__SRV_WORKER_H

#include "exec/runtime_srv.h"
#include "list_lib.h"

#include <pthread.h>
#include <stdint.h>

#define A_WQ_INITIALIZED 0xc5c5c5c5

typedef enum {
    A_WQ_JS
} aura_wq_backend_t;

struct aura_work_queue {
    pthread_mutex_t mutex; /* control access to the queue */
    pthread_attr_t th_attr;
    pthread_cond_t cond_var;
    st_aura_runtime rt;
    struct aura_list_head tasks;
    uint32_t max_instances;
    uint32_t curr_instances;
    uint32_t idle_instances;
    aura_wq_backend_t backend;
    int initialized;
    bool quit;
    bool running;
    /**
     * When set, the created instances created
     * is part of minimum instances
     */
    bool _is_part_of_min;
};

/**
 * Initialize work queue
 */
int aura_work_queue_init(struct aura_work_queue *wq, uint32_t min_instances, uint32_t max_instances, aura_wq_backend_t backend);

/**
 * Destroy work queue
 */
int aura_work_queue_destroy(struct aura_work_queue *wq);

/**
 * Add a task to the work queue
 */
int aura_work_queue_add(struct aura_work_queue *wq, struct aura_task *task);

#endif