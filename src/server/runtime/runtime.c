#include "runtime/runtime.h"

int aura_rt_qjs_create(struct aura_runtime *rt, struct aura_srv_ctx *s_ctx, struct aura_fn *fn) {
    struct aura_qjs_runtime *qjs;

    qjs = aura_qjs_create(s_ctx, fn);
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
