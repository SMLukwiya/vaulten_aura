#ifndef AURA_TASK_H
#define AURA_TASK_H

#include <stdint.h>

#include "list_lib.h"
#include "time_lib.h"
#include "types_lib.h"
#include "url/lib.h"

enum aura_task_flags {
    A_TASK_PENDING = 1,
};

struct aura_task {
    uint64_t id;
    uint64_t fn_id;
    uint8_t *payload;
    uint64_t payload_len;
    uint64_t queued_at;
    uint64_t started_at;
    uint64_t completed_at;
    void *invoker_data; /* Some data on the invoker for completion (req...etc) */
    struct aura_list_head entry;
    uint8_t state;
    uint8_t flags;
};

static inline void aura_task_start_time(struct aura_task *task) {
    task->started_at = aura_now_ms(CLOCK_MONOTONIC);
}

static inline void aura_task_complete2(struct aura_task *task) {
    task->completed_at = aura_now_ms(CLOCK_MONOTONIC);
}

#endif