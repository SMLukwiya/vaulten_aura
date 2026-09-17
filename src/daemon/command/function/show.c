#include "dmn.h"
#include "fn/lib.h"

void aura_dmn_fn_show(struct iovec *key, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    AURA_DBHANDLE db = gc->db_handle;
    struct aura_fn fn;
    struct aura_fn_evt evt;
    char fn_name[A_FN_NAME_MAX_LEN];
    char fn_version[A_FN_VERSION_MAX_LEN];
    struct aura_str_buf buf;
    int rv, err, state;

    aura_fn_get_name_and_version(key, fn_name, sizeof(fn_name), fn_version, sizeof(fn_version));

    /**
     * @todo: check function registry first
     */
    rv = aura_fn_meta_load(&fn, &gc->mc, fn_name, fn_version, db, -1);
    if (rv < 0 || rv == A_DB_REC_NOT_FOUND) {
        err = rv < 0 ? A_FN_ERROR_GENERIC : A_FN_ERROR_NOT_EXIST;
        state = A_FN_OP_STATE_FAILED;
        goto err;
    }

    if (aura_str_buf_init(&buf, NULL, 4096) < 0) {
        err = A_FN_ERROR_GENERIC;
        state = A_FN_OP_STATE_FAILED;
        goto err;
    }

    if (aura_fn_meta_construct(&buf, &fn.meta) < 0) {
        aura_str_buf_destroy(&buf);
        err = A_FN_ERROR_GENERIC;
        state = A_FN_OP_STATE_FAILED;
        goto err;
    }

    evt.error_code = A_FN_ERROR_NONE;
    evt.state = A_FN_OP_STATE_DONE;
    memcpy(evt.msg, buf.data, buf.len);
    evt.msg_len = buf.len;

    aura_resp_send(cli_fd, &evt, sizeof(evt));
    aura_str_buf_destroy(&buf);
    goto out;

err:
    evt.error_code = err;
    evt.state = state;
    evt.msg_len = 0;

    aura_resp_send(cli_fd, &evt, sizeof(evt));

out:
    if (key->iov_base)
        free(key->iov_base);
    close(cli_fd);
}