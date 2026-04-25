#include "runtime/runtime.h"

int aura_rt_qjs_create(struct aura_runtime *rt, struct aura_memory_ctx *mc, struct aura_fn *fn) {
    struct aura_qjs_runtime *qjs;

    app_debug(true, 0, "aura_rt_qjs_create <<<");
    qjs = aura_qjs_create(mc, fn);
    if (!qjs)
        return -1;

    rt->rt_ctx = qjs;
    return 0;
}

void aura_rt_qjs_destroy(struct aura_runtime *rt) {
    struct aura_qjs_runtime *qjs;

    qjs = rt->rt_ctx;
    aura_qjs_destroy(qjs);
}

int aura_rt_qjs_execute(struct aura_runtime *rt, struct aura_task *task) {
    struct aura_qjs_runtime *qjs;

    qjs = rt->rt_ctx;
    return aura_qjs_execute(qjs, task);
}

/** */
static inline void *a_rt_attach_cbs(struct aura_runtime *rt, aura_wq_backend_t backend) {
    if (backend == A_WQ_JS) {
        rt->ops.on_create = aura_rt_qjs_create;
        rt->ops.on_destroy = aura_rt_qjs_destroy;
        rt->ops.on_execute = aura_rt_qjs_execute;
    }
    app_debug(true, 0, "a_rt_attach_cbs <<<< %p", rt->ops.on_create);
}

void aura_rt_init(struct aura_runtime *rt, void *data, aura_wq_backend_t backend) {
    memset(rt, 0, sizeof(*rt));
    rt->backend = backend;
    a_rt_attach_cbs(rt, backend);
}

void aura_rt_destroy(struct aura_runtime *rt) {
    if (!rt)
        return;

    if (rt->rt_ctx)
        rt->ops.on_destroy(rt);
}

int aura_completion_queue_init(struct aura_completion_queue *cq) {
    memset(cq, 0, sizeof(*cq));

    if (pthread_mutex_init(&cq->lock, NULL))
        return -1;

    cq->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (cq->efd < 0) {
        pthread_mutex_destroy(&cq->lock);
        return -1;
    }

    a_list_head_init(&cq->list);
    return 0;
}

void aura_completion_destroy(struct aura_completion *c) {
    if (!c)
        return;

    if (c->task)
        aura_task_destroy(c->task);
}

void aura_completion_queue_destroy(struct aura_completion_queue *cq) {
    struct aura_completion *c;

    while (!a_list_is_empty(&cq->list)) {
        a_list_dequeue(c, &cq->list, c_list);
        aura_completion_destroy(c);
    }

    pthread_mutex_destroy(&cq->lock);
    close(cq->efd);
}

int aura_completion_queue_push(struct aura_completion_queue *cq, struct aura_completion *c) {
    uint64_t one = 1;
    app_debug(true, 0, "aura_completion_queue_push <<<<");

    pthread_mutex_lock(&cq->lock);
    a_list_add_tail(&cq->list, &c->c_list);
    pthread_mutex_unlock(&cq->lock);

    /* Notify epoll @todo: there may be no need to notify */
    // write(cq->efd, &one, sizeof(one));

    // return 0;
}
