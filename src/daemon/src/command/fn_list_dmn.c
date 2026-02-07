#include "command/function_dmn.h"
#include "function_lib.h"
#include "unix_socket_lib.h"

void aura_dmn_function_list(AURA_DBHANDLE db, struct iovec *key, int cli_fd) {
    struct aura_functions *fns;
    struct aura_fn_list fn_list, *fn_list_ptr;
    struct aura_fn_evt evt, *evt_ptr;
    struct aura_iovec state_key, state_data;
    const char *fn_state;
    int res, error;
    size_t len;

    fn_state = key->iov_base;

    fns = aura_fn_list_fetch(db, &error);
    if (!fns) {
        if (error < 0) {
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_send_resp(cli_fd, (void *)&evt, sizeof(evt));
            goto out;
        }
    }

    if (!fns || fns->func_cnt == 0) {

        len = sizeof(evt) + sizeof(struct aura_fn_list);
        char buf[len];

        evt_ptr = (struct aura_fn_evt *)buf;

        evt_ptr->error_code = A_FN_ERROR_NONE;
        evt_ptr->state = A_FN_OP_STATE_DONE;
        evt_ptr->msg_len = sizeof(struct aura_fn_list);
        evt_ptr->_msg = buf + sizeof(evt);

        fn_list_ptr = (struct aura_fn_list *)evt_ptr->_msg;
        fn_list_ptr->cnt = 0;
        fn_list_ptr->fns = NULL;

        struct aura_fn_list *fl = (struct aura_fn_list *)evt_ptr->_msg;

        aura_send_resp(cli_fd, (void *)buf, len);
    } else {
        size_t fn_cnt;

        if (strncmp(fn_state, "all", key->iov_len) == 0) {
            size_t len = sizeof(evt) + sizeof(struct aura_fn_list) + (fns->func_cnt * sizeof(struct aura_fn_rep));
            char buf[len];
            struct aura_fn_evt *evt_p = (struct aura_fn_evt *)buf;

            evt_p->error_code = A_FN_ERROR_NONE;
            evt_p->state = A_FN_OP_STATE_DONE;
            evt_p->msg_len = (fn_list.cnt * sizeof(struct aura_fn_rep));
            evt_p->_msg = buf + sizeof(evt);
            struct aura_fn_list *fn_list = (struct aura_fn_list *)evt_p->_msg;
            fn_list->cnt = fns->func_cnt;
            fn_list->fns = (struct aura_fn_rep *)((char *)fn_list + sizeof(*fn_list));

            for (int i = 0; i < fn_list->cnt; ++i) {
                memcpy(fn_list->fns[i].fn_name, fns->funcs[i].fn_name, strlen(fns->funcs[i].fn_name));
                fn_list->fns[i].fn_version = fns->funcs[i].fn_version;
            }

            aura_send_resp(cli_fd, (void *)buf, len);
        }
    }

out:
    if (fn_state)
        free((void *)fn_state);
    close(cli_fd);
}