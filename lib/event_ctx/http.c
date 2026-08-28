#include "context.h"

int aura_http_init(struct aura_evt_src *evt_src) {
    snprintf(evt_src->name, sizeof(evt_src->name), "http");

    if (aura_rax_init(&evt_src->http_src.routes) < 0)
        return -1;

    evt_src->flags |= A_EVT_SRC_INITIALIZED;
    return 0;
}

int aura_http_start(struct aura_evt_src *evt_src) {
    evt_src->flags |= A_EVT_SRC_RUNNING;
    return 0;
}

int aura_http_stop(struct aura_evt_src *evt_src) {
    evt_src->flags &= ~A_EVT_SRC_RUNNING;
    evt_src->flags |= A_EVT_SRC_STOPPED;
    return 0;
}

void aura_http_destroy(struct aura_evt_src *evt_src) {
    aura_rax_free(&evt_src->http_src.routes);
    evt_src->flags = 0;
}

int aura_http_bind(struct aura_evt_src *evt_src, struct aura_fn_registry_ent *fn_ent, int trigger_idx) {
    if (aura_rax_insert(&evt_src->http_src.routes,
                        fn_ent->fn->meta.triggers.entries[trigger_idx].http.path.base,
                        fn_ent->fn->meta.triggers.entries[trigger_idx].http.path.len,
                        A_RAX_NODE_TYPE_SPARSE,
                        a_rax_data_init_ptr(fn_ent)) == false)
        return -1;

    return 0;
}

int aura_http_unbind(struct aura_evt_src *evt_src, struct aura_fn_registry_ent *fn_ent, int trigger_idx) {
    if (aura_rax_remove(&evt_src->http_src.routes,
                        fn_ent->fn->meta.triggers.entries[trigger_idx].http.path.base,
                        fn_ent->fn->meta.triggers.entries[trigger_idx].http.path.len,
                        NULL) == false)
        return -1;
}

/* HTTP event source */
struct aura_evt_src_ops http_src_ops = {
  .init = aura_http_init,
  .start = aura_http_start,
  .stop = aura_http_stop,
  .destroy = aura_http_destroy,
  .bind = aura_http_bind,
  .unbind = aura_http_unbind,
};