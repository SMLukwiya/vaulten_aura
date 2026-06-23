#ifndef AURA_SRV_TASK_H
#define AURA_SRV_TASK_H

#include "error_lib.h"
#include "h2/stream.h"
#include "header_srv.h"
#include "list_lib.h"
#include "mem.h"
#include "time_lib.h"

typedef enum {
    A_TASK_STATE_QUEUED,
    A_TASK_STATE_RUNNING,
    A_TASK_STATE_DONE,
} a_task_state_t;

typedef enum {
    A_TASK_PROTOCOL_H2,
    A_TASK_PROTOCOL_H3
} a_task_protocol_t;

/* Generic Task structure */
struct aura_task {
    uint64_t id;
    a_task_state_t state;
    a_task_protocol_t protocol;
    void *req_data;
    void *res_data;
    uint32_t stream_id;
    uint32_t conn_idx;
    uint32_t conn_id;
    struct aura_list_head t_list;
    uint64_t started_at;
    uint64_t completed_at;
};

/* init task */
struct aura_task *aura_task_create(struct aura_h2_stream *stream, struct aura_mem_ctx *mc,
                                   uint8_t *url, uint64_t next_id, uint32_t conn_id,
                                   uint32_t conn_idx, a_task_protocol_t prot);

/* destroy task */
void aura_task_destroy(struct aura_task *task);

void aura_task_dump(struct aura_task *task);

static inline void aura_task_start(struct aura_task *task) {
    task->started_at = aura_now_ms(CLOCK_MONOTONIC);
}

static inline void aura_task_complete(struct aura_task *task) {
    task->completed_at = aura_now_ms(CLOCK_MONOTONIC);
}

static inline void aura_task_transition_state(struct aura_task *task, a_task_state_t new_state) {
    if (task->state = new_state)
        task->state = new_state;
}

#endif