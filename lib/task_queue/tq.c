#include "tq.h"
#include "time_lib.h"

int aura_task_queue_init(struct aura_task_queue *tq, uint32_t flags, int max_conc) {
    memset(tq, 0, sizeof(*tq));

    if (pthread_mutex_init(&tq->lock, NULL) != 0)
        return -1;

    aura_list_head_init(&tq->fn_queues);
    aura_list_head_init(&tq->pending_work);
    tq->flags = flags;
    tq->max_active = max_conc;
    tq->min_active = 0;

    return 0;
}

void aura_task_queue_destroy(struct aura_task_queue *tq) {
    pthread_mutex_destroy(&tq->lock);
}

int aura_worker_pool_init(struct aura_worker_pool *worker_pool) {
    memset(worker_pool, 0, sizeof(*worker_pool));

    if (pthread_mutex_init(&worker_pool->lock, NULL) != 0)
        return -1;

    aura_list_head_init(&worker_pool->idle_list);
    aura_list_head_init(&worker_pool->workers);

    for (int i = 0; i < 64; ++i)
        aura_list_head_init(&worker_pool->hashmap[i]);

    return 0;
}