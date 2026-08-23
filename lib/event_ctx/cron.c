#include "context.h"
#include "cron/ccronexpr.h"
#include "fn/lib.h"

int cron_src_init(struct aura_evt_src *evt_src) {
    memset(evt_src, 0, sizeof(*evt_src));
    snprintf(evt_src->name, sizeof(evt_src->name), "cron");

    aura_timer_wheel_init(&evt_src->cron_src.wheel);

    evt_src->flags = A_EVT_SRC_INITIALIZED;
    return 0;
}

int cron_src_start(struct aura_evt_src *evt_src) {
    evt_src->flags |= A_EVT_SRC_RUNNING;
    return 0;
}

int cron_src_stop(struct aura_evt_src *evt_src) {
    evt_src->flags &= ~A_EVT_SRC_RUNNING;
    evt_src->flags |= A_EVT_SRC_STOPPED;
    return 0;
}

void cron_src_destroy(struct aura_evt_src *evt_src) {
    evt_src->flags = 0;
}

int cron_src_bind(struct aura_evt_src *evt_src, struct aura_fn_registry_ent *trigger) {
    /**/
}

int cron_src_unbind(struct aura_evt_src *evt_src, struct aura_fn_registry_ent *trigger) {
    /**/
}

/* cron event source */
struct aura_evt_src_ops cron_src_ops = {
  .init = cron_src_init,
  .start = cron_src_start,
  .stop = cron_src_stop,
  .destroy = cron_src_destroy,
  .bind = cron_src_bind,
  .unbind = cron_src_unbind,
};