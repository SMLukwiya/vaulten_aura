#include "data_path.h"
#include "error_lib.h"

void aura_dp_msg_init(struct aura_dp_msg *msg) {
    memset(msg, 0, sizeof(*msg));
}

void aura_dp_msg_destroy(struct aura_dp_msg *msg) {
    aura_sliding_buf_destroy(&msg->buf);
}

int aura_dp_pipeline_execute(struct aura_dp_msg *msg) {
    struct aura_dp_pipeline_hook *hook;
    struct aura_dp_result result;
    int rv = A_DP_HOOK_DONE;

    while (msg->active_idx < msg->hook_cnt) {
        hook = &msg->hooks[msg->active_idx];
        result = hook->fn(msg);
        rv = result.rv;

        switch (rv) {
        case A_DP_HOOK_CONT:
        case A_DP_HOOK_DONE:
        case A_DP_HOOK_WAIT:
            msg->active_idx = result.target_idx;
            break;

        case A_DP_HOOK_ERR:
            /* Early exit */
            return rv;

        default:
            break;
        }
    }

    return rv;
}
