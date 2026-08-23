#ifndef AURA_EVT_CONTEXT_H
#define AURA_EVT_CONTEXT_H

#include <stdint.h>

#include "fn/lib.h"
#include "radix/tree.h"
#include "request/req.h"
#include "timer/timer.h"

#define A_EVT_SRC_MAX_CNT 16

enum aura_msg_data_kind {
    A_ROUTING_INFO
};

/* Function execution context event */
struct aura_exec_ctx_evt {
    const char source_name[64]; /* http, cron, queue... */
    Request *request;
};

/* Function execution context */
struct aura_exec_ctx {
    struct aura_exec_ctx_evt event;
    void *fs;
    void *os;
    void *db;
    bool is_test; /* If context is being run inside test */
};

struct aura_http_evt_src {
    aura_rax_tree_t routes;
};

struct aura_cron_evt_src {
    struct aura_timer_wheel wheel;
};

struct aura_evt_trigger {
    uint64_t fn_id;
    int trigger_type;
    union {
        struct {
            char *path;
            int method;
        } http_config;
        struct {
            char *schedule;
        } cron_config;
    };
};

/* Event source structure */
struct aura_evt_src {
    char name[64];
    struct aura_evt_src_ops *ops;
    union {
        struct aura_http_evt_src http_src;
        struct aura_cron_evt_src cron_src;
    };
    uint8_t flags;
};

struct aura_evt_src_ops {
    int (*init)(struct aura_evt_src *);
    int (*start)(struct aura_evt_src *);
    int (*stop)(struct aura_evt_src *);
    void (*destroy)(struct aura_evt_src *);

    int (*bind)(struct aura_evt_src *, struct aura_fn_registry_ent *trigger);
    int (*unbind)(struct aura_evt_src *, struct aura_fn_registry_ent *trigger);
};

enum {
    A_EVT_SRC_INITIALIZED = 1,
    A_EVT_SRC_RUNNING = 1 << 1,
    A_EVT_SRC_STOPPED = 1 << 2,
};

struct aura_evt_src_registry {
    struct aura_evt_src sources[A_EVT_SRC_MAX_CNT];
    uint8_t cnt;
};

static inline struct aura_evt_src *aura_evt_src_get(struct aura_evt_src_registry *registry, const char *name) {
    struct aura_evt_src *src;

    for (int i = 0; i < registry->cnt; ++i) {
        src = registry[i].sources;
        if (strcmp(src->name, name) == 0)
            return src;
    }

    return NULL;
}

#endif