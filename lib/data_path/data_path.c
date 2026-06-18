#include "data_path.h"

void aura_dp_msg_init(struct aura_dp_msg *msg) {
    memset(msg, 0, sizeof(*msg));
}

void aura_dp_msg_destroy(struct aura_dp_msg *msg) {
    aura_sliding_buf_destroy(&msg->buf);
}

int aura_dp_pipeline_execute(struct aura_dp_msg *msg) {
    struct aura_dp_pipeline_hook *hook;
    struct aura_dp_result result;
    int rv = 0;

    while (msg->active_idx < msg->hook_cnt) {
        hook = &msg->hooks[msg->active_idx];
        result = hook->fn(msg);

        switch (result.rv) {
        case A_DP_HOOK_CONT:
            msg->active_idx = result.target_idx;
            break;

        case A_DP_HOOK_WAIT:
        case A_DP_HOOK_DONE:
            /* Early exit */
            return rv;

        case A_DP_HOOK_ERR:
            return -1;

        default:
            break;
        }
    }
}
