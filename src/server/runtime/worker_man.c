#include "bug_lib.h"
#include "error_lib.h"
#include "executors/js/quickjs/rt.h"
#include "server_srv.h"
#include "time_lib.h"
#include "worker_srv.h"

#include <sys/types.h>
#include <unistd.h>

struct aura_qjs_thread_routine_arg {
    struct aura_work_queue *wq;
    struct aura_fn *fn;
    bool is_part_of_min;
};
/**
 * Worker thread routine, runs its own quickjs runtime
 * and context
 */
void *aura_qjs_thread_routine(void *_arg) {
    struct timespec timeout;
    struct aura_qjs_thread_routine_arg *arg;
    struct aura_work_queue *wq;
    struct aura_fn *fn;
    struct aura_runtime *rt;
    struct aura_qjs_runtime *qjs_rt;
    struct _aura_task *task;
    Response *resp;
    int res;
    bool timedout, is_part_of_min;

    arg = (struct aura_qjs_thread_routine_arg *)_arg;
    wq = arg->wq;
    fn = arg->fn;
    is_part_of_min = arg->is_part_of_min;
    rt = &wq->rt;
    free(_arg);

    /* Create underlying qjs engine */
    if (wq->rt.ops.on_create(&wq->rt, wq->srv_ctx, fn) < 0) {
        return NULL;
    }
    qjs_rt = wq->rt.rt_ctx;
    qjs_rt->_is_part_of_min = is_part_of_min;
    res = pthread_mutex_lock(&wq->mutex);
    if (res)
        return NULL;

    for (;;) {
        timedout = false;
        aura_now_ts(&timeout, CLOCK_MONOTONIC);
        timeout.tv_sec += 5;

        while (aura_list_is_empty(&wq->task_list) && !wq->quit) {
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
                wq->rt.ops.on_destroy(&wq->rt);
                pthread_mutex_unlock(&wq->mutex);
                return NULL;
            }
        }

        a_list_dequeue(task, &wq->task_list, t_list);
        if (task) {
            wq->idle_instances--;
            struct aura_completion *c;

            res = pthread_mutex_unlock(&wq->mutex);
            if (res)
                return NULL;
            res = rt->ops.on_execute(rt, task);
            c = aura_completion_create(wq->srv_ctx->mc, task);
            if (!c) {
                /** @todo: handle stream connection closing */
                aura_task_destroy(task);
                wq->rt.ops.on_destroy(&wq->rt);
                return NULL;
            }
            aura_completion_queue_push(&wq->srv_ctx->completions, c);
            pthread_mutex_lock(&wq->mutex);
            wq->idle_instances++;
        }

        if (aura_list_is_empty(&wq->task_list) && wq->quit) {
            wq->curr_instances--;
            /* use the same cond var to signal the last closing thread */
            wq->rt.ops.on_destroy(&wq->rt);
            if (wq->curr_instances == 0) {
                pthread_cond_signal(&wq->cond_var);
            }
            pthread_mutex_unlock(&wq->mutex);
            return NULL;
        }

        if (aura_list_is_empty(&wq->task_list) && timedout) {
            wq->curr_instances--;
            wq->rt.ops.on_destroy(&wq->rt);
            pthread_mutex_unlock(&wq->mutex);
            break;
        }
    }

    return NULL;
}

int aura_work_queue_thread_vec_add(struct aura_wq_thread_vec *vec, struct aura_mem_ctx *mc,
                                   pthread_t thread_id) {
    struct aura_wq_thread_info *old_tinfo = vec->thread_info;
    struct aura_wq_thread_info *t_info;
    size_t old_cnt = vec->cnt, old_cap = vec->cap;

    if (vec->cnt <= vec->cap) {
        vec->cap = vec->cap == 0 ? 16 : vec->cap * 2;
        vec->thread_info = aura_realloc(mc, vec->thread_info, sizeof(*vec->thread_info) * vec->cap);
        if (!vec->thread_info) {
            vec->thread_info = old_tinfo;
            vec->cnt = old_cnt;
            vec->cap = old_cap;
            return -1;
        }
    }

    t_info = &vec->thread_info[vec->cnt++];
    t_info->thread_id = thread_id;
    t_info->thread_num = vec->cnt;

    return 0;
}

int aura_work_queue_init(struct aura_work_queue *wq, struct aura_srv_ctx *srv_ctx, struct aura_fn *fn) {
    pthread_t new_th_id;
    uint32_t min_instances;
    int rv;

    memset(wq, 0, sizeof(*wq));
    aura_rt_init(&wq->rt, fn, fn->backend);
    A_BUG_ON_2(!wq->rt.backend, true);

    rv = pthread_attr_init(&wq->th_attr);
    if (rv) {
        return rv;
    }

    rv = pthread_attr_setdetachstate(&wq->th_attr, PTHREAD_CREATE_DETACHED);
    if (rv) {
        pthread_attr_destroy(&wq->th_attr);
        return rv;
    }

    rv = pthread_mutex_init(&wq->mutex, NULL);
    if (rv != 0) {
        pthread_attr_destroy(&wq->th_attr);
        return rv;
    }

    rv = pthread_cond_init(&wq->cond_var, NULL);
    if (rv != 0) {
        pthread_mutex_destroy(&wq->mutex);
        pthread_attr_destroy(&wq->th_attr);
        return rv;
    }

    aura_list_head_init(&wq->task_list);
    wq->magic = A_WQ_INITIALIZED;
    wq->srv_ctx = srv_ctx;
    wq->max_instances = fn->config.fn_concurrency.max_instances;
    // wq->quit = wq->running = false;

    min_instances = a_max(1, fn->config.fn_concurrency.min_instances);
    struct aura_qjs_thread_routine_arg *arg = malloc(sizeof(*arg));

    arg->wq = wq;
    arg->fn = fn;
    arg->is_part_of_min = true;
    while (min_instances) {
        rv = pthread_create(&new_th_id, &wq->th_attr, aura_qjs_thread_routine, (void *)arg);
        if (rv) {
            pthread_mutex_unlock(&wq->mutex);
            return rv;
        }

        wq->curr_instances++;
        wq->idle_instances++;
        min_instances--;
    }

    return 0;
}

int aura_work_queue_destroy(struct aura_work_queue *wq) {
    int rv;

    if (!wq)
        return 0;

    A_BUG_ON_2(wq->magic != A_WQ_INITIALIZED, true);

    rv = pthread_mutex_lock(&wq->mutex);
    if (rv)
        return rv;

    wq->magic = 0;

    /**
     * Check for running instances and notify them via quit
     */
    if (wq->curr_instances > 0) {
        wq->quit = true;

        /* check for idling instances, wake them up */
        if (wq->idle_instances > 0) {
            rv = pthread_cond_broadcast(&wq->cond_var);
            if (rv) {
                pthread_mutex_unlock(&wq->mutex);
                return rv;
            }
        }

        /* use the same variable to wait for current thread instances to shutdown */
        while (wq->curr_instances > 0) {
            rv = pthread_cond_wait(&wq->cond_var, &wq->mutex);
            if (rv) {
                pthread_mutex_unlock(&wq->mutex);
                return rv;
            }
        }
    }

    rv = pthread_mutex_unlock(&wq->mutex);
    if (rv)
        return rv;

    rv = pthread_cond_destroy(&wq->cond_var);
    if (rv)
        return rv;

    rv = pthread_mutex_destroy(&wq->mutex);
    if (rv != 0)
        return rv;

    rv = pthread_attr_destroy(&wq->th_attr);
    if (rv)
        return rv;

    return 0;
}

int aura_work_queue_add(struct aura_work_queue *wq, struct aura_fn *fn, struct _aura_task *task) {
    pthread_t new_th_id;
    int rv;

    A_BUG_ON_2(wq->magic != A_WQ_INITIALIZED, true);

    rv = pthread_mutex_lock(&wq->mutex);
    if (rv)
        return rv;

    aura_list_head_init(&task->t_list);
    aura_list_add_tail(&wq->task_list, &task->t_list);

    /* Wake idling instances */
    if (wq->idle_instances > 0) {
        rv = pthread_cond_signal(&wq->cond_var);
        if (rv) {
            pthread_mutex_unlock(&wq->mutex);
            return rv;
        }
    } else if (wq->curr_instances < wq->max_instances) {
        /* We can still create more instances here */
        struct aura_qjs_thread_routine_arg *arg = malloc(sizeof(*arg));
        arg->wq = wq;
        arg->fn = fn;
        arg->is_part_of_min = false;
        rv = pthread_create(&new_th_id, &wq->th_attr, aura_qjs_thread_routine, (void *)arg);
        if (rv) {
            pthread_mutex_unlock(&wq->mutex);
            return rv;
        }
        wq->curr_instances++;
        wq->idle_instances++;
    }

    pthread_mutex_unlock(&wq->mutex);
    return 0;
}
