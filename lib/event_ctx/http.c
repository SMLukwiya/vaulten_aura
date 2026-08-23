#include "context.h"

int init(struct aura_evt_src *evt_src) {
    memset(evt_src, 0, sizeof(*evt_src));
    snprintf(evt_src->name, sizeof(evt_src->name), "http");

    if (aura_rax_init(&evt_src->http_src.routes) < 0)
        return -1;

    evt_src->flags = A_EVT_SRC_INITIALIZED;
    return 0;
}

int start(struct aura_evt_src *evt_src) {
    evt_src->flags |= A_EVT_SRC_RUNNING;
    return 0;
}

int stop(struct aura_evt_src *evt_src) {
    evt_src->flags &= ~A_EVT_SRC_RUNNING;
    evt_src->flags |= A_EVT_SRC_STOPPED;
    return 0;
}

void destroy(struct aura_evt_src *evt_src) {
    aura_rax_free(&evt_src->http_src.routes);
    evt_src->flags = 0;
}

int bind(struct aura_evt_src *evt_src, struct aura_fn_registry_ent *trigger) {
    if (aura_rax_insert(&evt_src->http_src.routes,
                        trigger->fn_tag.triggers->http_trigger.path,
                        strlen(trigger->fn_tag.triggers->http_trigger.path),
                        A_RAX_NODE_TYPE_SPARSE,
                        a_rax_data_init_ptr(trigger)) == false)
        return -1;

    return 0;
}

int unbind(struct aura_evt_src *evt_src, struct aura_fn_registry_ent *trigger) {
    if (aura_rax_remove(&evt_src->http_src.routes,
                        trigger->fn_tag.triggers->http_trigger.path,
                        strlen(trigger->fn_tag.triggers->http_trigger.path),
                        NULL) == false)
        return -1;
}

/* HTTP event source */
struct aura_evt_src_ops http_src_ops = {
  .init = init,
  .start = start,
  .stop = stop,
  .destroy = destroy,
  .bind = bind,
  .unbind = unbind,
};