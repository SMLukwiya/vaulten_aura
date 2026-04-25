#include "bug_lib.h"
#include "error_lib.h"
#include "runtime/js.h"
#include "server_srv.h"
#include "time_lib.h"
#include "worker_srv.h"

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
    struct aura_task *task;
    Response *resp;
    int res;
    bool timedout, is_part_of_min;

    arg = (struct aura_qjs_thread_routine_arg *)_arg;
    wq = arg->wq;
    fn = arg->fn;
    is_part_of_min = arg->is_part_of_min;
    app_debug(true, 0, "aura_qjs_thread_routine <<<<<: %p", wq->rt.ops.on_create);
    rt = &wq->rt;
    free(_arg);

    /* Create underlying qjs engine */
    if (wq->rt.ops.on_create(&wq->rt, wq->srv_ctx->mc, fn) < 0) {
        return NULL;
    }
    qjs_rt = wq->rt.rt_ctx;
    qjs_rt->_is_part_of_min = is_part_of_min;
    res = pthread_mutex_lock(&wq->mutex);
    if (res)
        return NULL;

    for (;;) {
        timedout = false;
        aura_now_ts(&timeout, CLOCK_REALTIME);
        timeout.tv_sec += 5;

        while (a_list_is_empty(&wq->task_list) && !wq->quit) {
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

        wq->idle_instances--;
        a_list_dequeue(task, &wq->task_list, t_list);
        if (task) {
            struct aura_completion *c;

            res = pthread_mutex_unlock(&wq->mutex);
            if (res)
                return NULL;
            res = rt->ops.on_execute(rt, task);
            c = aura_completion_create(wq->srv_ctx->mc, task);
            if (!c) {
                /** @todo: handle stream connection closing */
                aura_task_destroy(task);
                return NULL;
            }
            aura_completion_queue_push(&wq->srv_ctx->completions, c);
        }

        if (a_list_is_empty(&wq->task_list) && wq->quit) {
            wq->curr_instances--;
            /* use the same cond var to signal the last closing thread */
            if (wq->curr_instances == 0) {
                pthread_cond_signal(&wq->cond_var);
            }
            pthread_mutex_unlock(&wq->mutex);
            return NULL;
        }

        if (a_list_is_empty(&wq->task_list) && timedout) {
            wq->curr_instances--;
            break;
        }
    }
    pthread_mutex_unlock(&wq->mutex);
    return NULL;
}

int aura_work_queue_init(struct aura_work_queue *wq, struct aura_srv_ctx *srv_ctx, struct aura_fn *fn) {
    pthread_t new_th_id;
    uint32_t min_instances;
    int res;
    app_debug(true, 0, "aura_work_queue_init <<<<: %p", srv_ctx);

    aura_rt_init(&wq->rt, fn, fn->backend);
    A_BUG_ON_2(!wq->rt.backend, true);

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

    a_list_head_init(&wq->task_list);
    wq->magic = A_WQ_INITIALIZED;
    wq->srv_ctx = srv_ctx;
    wq->max_instances = fn->config.fn_concurrency.max_instances;
    wq->curr_instances = 0;
    wq->idle_instances = 0;
    wq->quit = wq->running = false;

    min_instances = fn->config.fn_concurrency.min_instances;
    struct aura_qjs_thread_routine_arg *arg = malloc(sizeof(*arg));

    arg->wq = wq;
    arg->fn = fn;
    arg->is_part_of_min = true;
    while (min_instances--) {
        res = pthread_create(&new_th_id, &wq->th_attr, aura_qjs_thread_routine, (void *)arg);
        if (res) {
            pthread_mutex_unlock(&wq->mutex);
            return res;
        }
        wq->curr_instances++;
        wq->idle_instances++;
    }

    return 0;
}

int aura_work_queue_destroy(struct aura_work_queue *wq) {
    int rv;

    A_BUG_ON_2(wq->magic != A_WQ_INITIALIZED, true);

    rv = pthread_mutex_lock(&wq->mutex);
    if (rv)
        return rv;

    wq->magic = 0;
    wq->rt.ops.on_destroy(&wq->rt);

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

int aura_work_queue_add(struct aura_work_queue *wq, struct aura_fn *fn, struct aura_task *task) {
    pthread_t new_th_id;
    int res;
    app_debug(true, 0, "aura_work_queue_add <<<<");

    A_BUG_ON_2(wq->magic != A_WQ_INITIALIZED, true);

    res = pthread_mutex_lock(&wq->mutex);
    if (res)
        return res;

    a_list_head_init(&task->t_list);
    a_list_add_tail(&wq->task_list, &task->t_list);

    /* Wake idling instances */
    if (wq->idle_instances > 0) {
        res = pthread_cond_signal(&wq->cond_var);
        if (res) {
            pthread_mutex_unlock(&wq->mutex);
            return res;
        }
    } else if (wq->curr_instances < wq->max_instances) {
        /* We can still create more instances here */
        struct aura_qjs_thread_routine_arg *arg = malloc(sizeof(*arg));
        arg->wq = wq;
        arg->fn = fn;
        arg->is_part_of_min = false;
        res = pthread_create(&new_th_id, &wq->th_attr, aura_qjs_thread_routine, (void *)arg);
        if (res) {
            pthread_mutex_unlock(&wq->mutex);
            return res;
        }
        wq->curr_instances++;
        wq->idle_instances++;
    }

    pthread_mutex_unlock(&wq->mutex);
    return 0;
}
