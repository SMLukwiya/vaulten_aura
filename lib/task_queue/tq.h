#ifndef AURA_TASK_QUEUE_H
#define AURA_TASK_QUEUE_H

#include <pthread.h>
#include <stdint.h>

#include "list_lib.h"
#include "task/task.h"
#include "timer/timer.h"

enum a_worker_flags {
    A_WORKER_IDLE = 1,       /* Worker idle */
    A_WORKER_PREP = 1 << 1,  /* Worker setting up to do some work */
    A_WORKER_DYING = 1 << 2, /* So sad! */
};

struct aura_worker {
    pthread_t thread;                 /* Thread to worker is attached to */
    pthread_key_t thread_key;         /* Thread key */
    struct aura_list_head pool_node;  /* node in worker pool */
    void *runtime_ctx;                /* Worker's runtime context */
    struct aura_timer_node idle_time; /* Worker idle timeout */
    uint8_t flags;
    /* stats */
};

struct aura_fn_queue {
    struct aura_fn *fn;
    struct aura_worker_pool *glob_pool; /* Global worker pool */
    pthread_mutex_t lock;
    struct aura_list_head exec_slots; /* Execution context */
    struct aura_list_head fn_node;    /* node on tq->fn_queues */
    struct aura_list_head task_list;  /* Pending task list */
    uint32_t nr_exec_slots;           /* Execution slots count (qjs specific) */
    uint32_t nr_active;               /* Nr of active fn invocations */
    uint32_t work_started;
    uint32_t work_completed;
    bool paused; /* execution paused */
};

enum aura_tq_flags {
    A_TQ_DRAINING = 1
};

/* Worker pool structure */
struct aura_worker_pool {
    pthread_mutex_t lock;
    int nr_running;
    int nr_workers;
    int nr_idle;
    int max_workers;
    int min_workers;
    struct aura_list_head idle_list;   /* Idle workers list */
    struct aura_list_head workers;     /* active workers */
    struct aura_list_head hashmap[64]; /* Hash map of active workers */
};

/* Task queue structure */
struct aura_task_queue {
    struct aura_list_head fn_queues;    /* All function queues */
    struct aura_list_head pending_work; /* Fn queues with pending work */
    pthread_mutex_t lock;
    int max_active; /* Max active tasks */
    int min_active; /* Min active tasks */
    uint32_t work_started;
    uint32_t work_completed;
    uint32_t flags;
};

/* Initialize the task queue */
int aura_task_queue_init(struct aura_task_queue *tq, uint32_t flags, int max_conc);

/* Destroy task queue */
void aura_task_queue_destroy(struct aura_task_queue *tq);

/* Initialize worker pool */
int aura_worker_pool_init(struct aura_worker_pool *wp);

/**/
int aura_task_queue_enqueue(struct aura_task_queue *tq, struct aura_task *task);

/**/
int aura_schedule_task(struct aura_fn_queue *fn_q, struct aura_task *task);

/**/
int aura_task_queue_flush(struct aura_task_queue *tq);

#endif