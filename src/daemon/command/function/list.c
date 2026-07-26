#include "command/function.h"
#include "dmn.h"
#include "fn/lib.h"
#include "unix/sock.h"

void aura_dmn_fn_list(struct iovec *key, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    AURA_DBHANDLE db = gc->db_handle;
    struct aura_fn_list *fn_list, *fn_list_ptr;
    struct aura_fn_evt evt, *evt_ptr;
    const char *fn_state;
    int error;
    size_t len;

    fn_state = key->iov_base;

    fn_list = aura_fn_list_fetch(db, &error);
    if (!fn_list) {
        if (error < 0) {
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_resp_send(cli_fd, (void *)&evt, sizeof(evt));
            goto out;
        }
    }

    if (!fn_list || fn_list->func_cnt == 0) {
        /* No available functions */
        len = sizeof(evt) + sizeof(struct aura_fn_list);
        char buf[len];

        evt_ptr = (struct aura_fn_evt *)buf;

        evt_ptr->error_code = A_FN_ERROR_NONE;
        evt_ptr->state = A_FN_OP_STATE_DONE;
        evt_ptr->msg_len = sizeof(struct aura_fn_list);
        evt_ptr->_msg = buf + sizeof(evt);

        fn_list_ptr = (struct aura_fn_list *)evt_ptr->_msg;
        fn_list_ptr->func_cnt = 0;
        fn_list_ptr->func_tags = NULL;

        aura_resp_send(cli_fd, (void *)buf, len);
    } else {
        size_t fn_cnt;

        if (strncmp(fn_state, "all", key->iov_len) == 0) {
            size_t len = sizeof(evt) +
                         sizeof(struct aura_fn_list) + (fn_list->func_cnt * sizeof(struct aura_fn_tag));
            char buf[len];
            memset(buf, 0, sizeof(buf));
            struct aura_fn_evt *evt_p = (struct aura_fn_evt *)buf;

            evt_p->error_code = A_FN_ERROR_NONE;
            evt_p->state = A_FN_OP_STATE_DONE;
            evt_p->msg_len = (fn_list->func_cnt * sizeof(struct aura_fn_tag));
            evt_p->_msg = buf + sizeof(evt);
            fn_list_ptr = (struct aura_fn_list *)evt_p->_msg;
            memcpy(fn_list_ptr, fn_list, len - sizeof(evt));

            aura_resp_send(cli_fd, (void *)buf, len);
        }
    }

out:
    if (fn_state)
        free((void *)fn_state);
    if (fn_list)
        aura_free((void *)fn_list);
    close(cli_fd);
}