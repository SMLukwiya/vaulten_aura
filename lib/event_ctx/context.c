#include "context.h"

extern struct aura_evt_src_ops http_src_ops;
extern struct aura_evt_src_ops cron_src_ops;

int aura_event_registry_add(struct aura_evt_src_registry *reg, aura_evt_src_t type, int flags) {
    struct aura_evt_src *evt_src;

    if (reg->cnt >= A_EVT_SRC_MAX_CNT)
        return -1;

    evt_src = &reg->sources[reg->cnt++];
    memset(evt_src, 0, sizeof(*evt_src));
    snprintf(evt_src->name, A_EVT_SRC_NAME_MAX_LEN, "%s", aura_evt_src_str_name[type]);
    evt_src->flags = flags;
    evt_src->type = type;

    switch (type) {
    case A_EVT_SRC_HTTP:
        evt_src->ops = &http_src_ops;
        break;

    case A_EVT_SRC_CRON:
        evt_src->ops = &cron_src_ops;
        break;

    default:
        app_debug(true, 0, "Unknown event source type: %d", type);
        --reg->cnt;
        return -1;
    }

    /* Initialize the event source immediately */
    if (evt_src->ops->init(evt_src) < 0) {
        --reg->cnt;
        return -1;
    }

    return 0;
}

struct aura_evt_src *aura_evt_src_get(struct aura_evt_src_registry *reg, aura_evt_src_t type) {
    struct aura_evt_src *src;

    for (int i = 0; i < reg->cnt; ++i) {
        src = &reg->sources[i];
        if (src->type == type)
            return src;
    }

    return NULL;
}

void aura_evt_registry_destroy(struct aura_evt_src_registry *reg) {
    struct aura_evt_src *evt_src;

    for (int i = 0; i < reg->cnt; ++i) {
        evt_src = &reg->sources[i];
        evt_src->ops->destroy(evt_src);
    }
}