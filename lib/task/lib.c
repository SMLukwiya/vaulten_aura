#include "lib.h"

struct aura_task *aura_task_create(struct aura_mem_ctx *mc, uint64_t fn_id, uint8_t *payload,
                                   uint64_t p_len, void *opaque, uint32_t flags) {
    struct aura_task *task;

    task = aura_alloc(mc, sizeof(*task));
    if (!task)
        return NULL;
    memset(task, 0, sizeof(*task));

    // task->id = aura_get_next_id();
    task->fn_id = fn_id;
    task->payload = payload;
    task->payload_len = p_len;
    task->invoker_data = opaque;
    task->flags = flags;
    task->state = A_TASK_STATE_QUEUED;
    aura_list_head_init(&task->entry);

    return task;
}

void aura_task_destroy(struct aura_task *task) {
    if (!task)
        return;

    /* Figure out best strategy */
}