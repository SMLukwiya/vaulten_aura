#ifndef AURA_DATA_PATH_H
#define AURA_DATA_PATH_H

#include "sliding_buf.h"
#include <stdint.h>

typedef enum {
    A_DP_HOOK_CONT,
    A_DP_HOOK_WAIT,
    A_DP_HOOK_DONE,
    A_DP_HOOK_ERR,
} aura_dp_hook_rv;

struct aura_dp_msg;

/* Data path result structure */
struct aura_dp_result {
    aura_dp_hook_rv rv;
    uint8_t target_idx;
};

typedef struct aura_dp_result (*aura_dp_hook_fn)(struct aura_dp_msg *);

/* Data path hook structure */
struct aura_dp_pipeline_hook {
    uint8_t *fn_name;
    aura_dp_hook_fn fn;
};

/* Data path message structure */
struct aura_dp_msg {
    struct aura_sliding_buf buf;
    uint64_t req_id;
    uint32_t flags;

    uint8_t scratch[64];                 /* Private pipe line data */
    struct aura_dp_pipeline_hook *hooks; /* Array of assigned hooks */
    uint8_t hook_cnt;                    /* Count of hooks array entries*/
    uint8_t active_idx;                  /* Current active index in hook */

    void *owner; /* current context that gets to work on buf */
};

/* Attach the data path msg owner */
static inline void aura_dp_msg_attach_owner(struct aura_dp_msg *msg, void *owner) {
    msg->owner = owner;
}

/* Attach inbound hooks */
static inline void aura_dp_msg_attach_inbound_hook(struct aura_dp_msg *msg,
                                                   struct aura_dp_pipeline_hook *hooks,
                                                   uint8_t hooks_cnt) {
    msg->hooks = hooks;
    msg->hook_cnt = hooks_cnt;
}

/**
 * Initialize a msg structure,
 * The msg->buf is initialized on its own
 * since we do not yet know its x-tics
 */
void aura_dp_msg_init(struct aura_dp_msg *msg);

void aura_dp_msg_destroy(struct aura_dp_msg *msg);
/**
 * Trigger pipeline execution
 */
int aura_dp_pipeline_execute(struct aura_dp_msg *msg);

#endif