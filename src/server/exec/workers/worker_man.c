#include "bug_lib.h"
#include "error_lib.h"
#include "exec/worker_srv.h"
#include "time_lib.h"

/* Quick js backend operations */
extern const st_aura_runtime_ops qjs_ops;

/** */
static inline const st_aura_runtime_ops *a_wq_get_backend(aura_wq_backend_t backend) {
    if (backend == A_WQ_JS)
        return &qjs_ops;
    else
        return NULL;
}

/**
 * Worker thread routine, runs its own quickjs runtime
 * and context
 */
void *aura_qjs_thread_routine(void *arg) {
    struct timespec timeout;
    struct aura_work_queue *wq;
    struct aura_runtime rt;
    st_aura_qjs_runtime *qjs_rt;
    struct aura_task *task;
    int res;
    bool timedout;

    wq = (struct aura_work_queue *)arg;
    rt = wq->rt;
    /* create on first task */
    qjs_rt = malloc(sizeof(*qjs_rt));
    if (!qjs_rt)
        return NULL;
    res = rt.ops->init(qjs_rt, NULL);
    if (res) {
        app_debug(true, 0, "Failed to initialize qjs runtime");
        return NULL;
    }
    qjs_rt->_is_part_of_min = wq->_is_part_of_min;

    res = pthread_mutex_lock(&wq->mutex);
    if (res)
        return NULL;

    for (;;) {
        timedout = false;
        aura_now_ts(&timeout);
        timeout.tv_sec += 5;

        while (a_list_is_empty(&wq->tasks) && !wq->quit) {
            /**
             * If instance is part of minimum instance,
             * we simply wait until explicitly told to shut
             */
            if (qjs_rt->_is_part_of_min) {
                res = pthread_cond_wait(&wq->cond_var, &wq->mutex);
            } else {
                res = pthread_cond_timedwait(&wq->cond_var, &wq->mutex, &timeout);
            }

            if (res == 0) {
                /* normal break */
                break;
            } else if (res == ETIMEDOUT) {
                timedout = true;
                break;
            } else if (res) {
                /* error break */
                wq->curr_instances--;
                /** @todo: update stats */
                pthread_mutex_unlock(&wq->mutex);
                return NULL;
            }
        }

        a_list_dequeue(task, &wq->tasks, t_list);
        if (task) {
            res = pthread_mutex_unlock(&wq->mutex);
            if (res)
                return NULL;
            res = rt.ops->execute(qjs_rt, task);
            // destroy task after
            // may perform any callback logic
            // see a way to use the return value, or package it into the res structure
        }

        if (a_list_is_empty(&wq->tasks) && wq->quit) {
            wq->curr_instances--;
            /* use the same cond var to signal the last closing thread */
            if (wq->curr_instances == 0) {
                pthread_cond_signal(&wq->cond_var);
            }
            pthread_mutex_unlock(&wq->mutex);
            return NULL;
        }

        if (a_list_is_empty(&wq->tasks) && timedout) {
            wq->curr_instances--;
            break;
        }
    }
    pthread_mutex_unlock(&wq->mutex);
    return NULL;
}

int aura_work_queue_init(struct aura_work_queue *wq, uint32_t min_instances, uint32_t max_instances, aura_wq_backend_t backend) {
    app_debug(true, 0, "aura_work_queue_init <<<<");
    pthread_t new_th_id;
    int res;

    wq->rt.ops = a_wq_get_backend(backend);
    A_BUG_ON_2(wq->rt.ops == NULL, true);
    wq->backend = backend;

    res = pthread_attr_init(&wq->th_attr);
    if (res) {
        return res;
    }

    res = pthread_attr_setdetachstate(&wq->th_attr, PTHREAD_CREATE_DETACHED);
    if (res) {
        pthread_attr_destroy(&wq->th_attr);
        return res;
    }

    res = pthread_mutex_init(&wq->mutex, NULL);
    if (res != 0) {
        pthread_attr_destroy(&wq->th_attr);
        return res;
    }

    res = pthread_cond_init(&wq->cond_var, NULL);
    if (res != 0) {
        pthread_mutex_destroy(&wq->mutex);
        pthread_attr_destroy(&wq->th_attr);
        return res;
    }

    a_list_head_init(&wq->tasks);
    wq->max_instances = max_instances;
    wq->curr_instances = 0;
    wq->idle_instances = 0;
    while (min_instances--) {
        wq->_is_part_of_min = true;
        res = pthread_create(&new_th_id, &wq->th_attr, aura_qjs_thread_routine, wq);
        if (res) {
            pthread_mutex_unlock(&wq->mutex);
            return res;
        }
        wq->curr_instances++;
        wq->idle_instances++;
    }

    wq->_is_part_of_min = false;
    wq->quit = wq->running = false;
    wq->initialized = A_WQ_INITIALIZED;
    return 0;
}

int aura_work_queue_destroy(struct aura_work_queue *wq) {
    int res;

    A_BUG_ON_2(wq->initialized != A_WQ_INITIALIZED, true);

    res = pthread_mutex_lock(&wq->mutex);
    if (res)
        return res;

    wq->initialized = 0;

    /**
     * Check for running instances and notify them via quit
     */
    if (wq->curr_instances > 0) {
        wq->quit = true;

        /* check for idling instances, wake them up */
        if (wq->idle_instances > 0) {
            res = pthread_cond_broadcast(&wq->cond_var);
            if (res) {
                pthread_mutex_unlock(&wq->mutex);
                return res;
            }
        }

        /* use the same variable to wait for current thread instances to shutdown */
        while (wq->curr_instances > 0) {
            res = pthread_cond_wait(&wq->cond_var, &wq->mutex);
            if (res) {
                pthread_mutex_unlock(&wq->mutex);
                return res;
            }
        }
    }

    res = pthread_mutex_unlock(&wq->mutex);
    if (res)
        return res;

    res = pthread_cond_destroy(&wq->cond_var);
    if (res)
        return res;

    res = pthread_mutex_destroy(&wq->mutex);
    if (res != 0)
        return res;

    res = pthread_attr_destroy(&wq->th_attr);
    if (res)
        return res;

    return 0;
}

int aura_work_queue_add(struct aura_work_queue *wq, struct aura_task *task) {
    pthread_t new_th_id;
    int res;

    A_BUG_ON_2(wq->initialized != A_WQ_INITIALIZED, true);

    res = pthread_mutex_lock(&wq->mutex);
    if (res)
        return res;

    a_list_head_init(&task->t_list);
    a_list_add_tail(&wq->tasks, &task->t_list);

    /* Wake idling instances */
    if (wq->idle_instances > 0) {
        res = pthread_cond_signal(&wq->cond_var);
        if (res) {
            pthread_mutex_unlock(&wq->mutex);
            return res;
        }
    } else if (wq->curr_instances < wq->max_instances) {
        /* We can still create more instances here */
        res = pthread_create(&new_th_id, &wq->th_attr, aura_qjs_thread_routine, wq);
        if (res) {
            pthread_mutex_unlock(&wq->mutex);
            return res;
        }
        wq->curr_instances++;
    }

    pthread_mutex_unlock(&wq->mutex);
    return 0;
}
