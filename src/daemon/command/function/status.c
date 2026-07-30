#include "command/function.h"
#include "dmn.h"
#include "fn/lib.h"
#include "unix/sock.h"

const char fn_status_active[] = "\x1B[1;32mFunction active\x1B[0m";
const char fn_status_inactive[] = "\x1B[1;32mFunction Inactive\x1B[0m";

static void a_fn_get_name_and_version(struct iovec *fn, char *fn_name,
                                      uint64_t func_len, char *fn_version,
                                      uint64_t func_vlen) {
    memset(fn_name, 0, func_len);
    memset(fn_version, 0, func_vlen);

    /* assume no version was provided */
    func_len = fn->iov_len;

    char *sep = strchr(fn->iov_base, ':');
    if (sep) {
        /**
         * Function key provided as <fn_name>:<fn_version>
         * We therefore copy the function version
         * found after the sep(:).
         */
        *sep = '\0';
        func_vlen = ((char *)fn->iov_base + fn->iov_len) - sep;
        memcpy(fn_version, sep + 1, func_vlen);

        /* account for version and separator */
        func_len -= func_vlen - 1;
    }

    memcpy(fn_name, fn->iov_base, func_len);
}

void aura_dmn_fn_status(struct iovec *fn, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    AURA_DBHANDLE db = gc->db_handle;
    struct aura_fn_state *fn_state;
    struct aura_fn_tag *fn_tag;
    struct aura_fn_evt evt;
    struct aura_iovec state_key;
    struct aura_db_rec rec;
    char fn_name[A_FN_NAME_MAX_LEN];
    char fn_version[A_FN_VERSION_MAX_LEN];
    char buf[2000];
    int error, rv;

    a_fn_get_name_and_version(fn, fn_name, sizeof(fn_name), fn_version, sizeof(fn_version));
    fn_tag = aura_fn_tag_fetch(db, &gc->mc, fn_name, fn_version, &error);
    if (!fn_tag) {
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;

        if (error == A_DB_REC_NOT_FOUND || error == 0) {
            evt.error_code = A_FN_ERROR_NOT_EXIST;
        } else if (error < 0) {
            evt.error_code = A_FN_ERROR_GENERIC;
        }

        aura_resp_send(cli_fd, &evt, sizeof(evt));
        goto out;
    }

    memcpy(fn_version, fn_tag->fn_version, A_FN_VERSION_MAX_LEN);
    aura_free(fn_tag);

    snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_STATE_SUFFIX);
    state_key.base = buf;
    state_key.len = strlen(buf);

    rv = aura_db_fetch(db, A_NS_FN, A_FN_STATE_SCHEMA_ID, &state_key, &rec);
    if (rv < 0 || rv == A_DB_REC_NOT_FOUND) {
        evt.error_code = rv < 0 ? A_FN_ERROR_GENERIC : A_FN_ERROR_NOT_EXIST;
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;

        aura_resp_send(cli_fd, &evt, sizeof(evt));
        goto out;
    }

    fn_state = (struct aura_fn_state *)rec.data.base;

    evt.error_code = A_FN_ERROR_NONE;
    evt.state = A_FN_OP_STATE_DONE;
    evt.msg_len = fn_state->is_active ? sizeof(fn_status_active) : sizeof(fn_status_inactive);
    memcpy(evt.msg, fn_state->is_active ? fn_status_active : fn_status_inactive, evt.msg_len);

    aura_resp_send(cli_fd, &evt, sizeof(evt));

    aura_free(fn_state);

out:
    if (fn->iov_base)
        free(fn->iov_base);
    close(cli_fd);
}

void aura_dmn_start_fn(struct iovec *fn, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    AURA_DBHANDLE db = gc->db_handle;
    struct aura_fn_state fn_state;
    struct aura_fn_tag *fn_tag;
    struct aura_fn_evt evt;
    struct aura_iovec key;
    char fn_name[A_FN_NAME_MAX_LEN];
    char fn_version[A_FN_VERSION_MAX_LEN];
    struct aura_iovec state_key, state_data;
    char key_buf[2000];
    int error;

    a_fn_get_name_and_version(fn, fn_name, sizeof(fn_name), fn_version, sizeof(fn_version));
    fn_tag = aura_fn_tag_fetch(db, &gc->mc, fn_name, fn_version, &error);
    if (!fn_tag) {
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;

        if (error == A_DB_REC_NOT_FOUND || error == 0) {
            evt.error_code = A_FN_ERROR_NOT_EXIST;
        } else if (error < 0) {
            evt.error_code = A_FN_ERROR_GENERIC;
        }

        aura_resp_send(cli_fd, &evt, sizeof(evt));
        goto out;
    }

    memcpy(fn_version, fn_tag->fn_version, A_FN_VERSION_MAX_LEN);
    aura_free(fn_tag);

    memset(key_buf, 0, sizeof(key_buf));
    snprintf(key_buf, sizeof(key_buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_STATE_SUFFIX);

    state_key.base = key_buf;
    state_key.len = strlen(key_buf);

    state_data.base = (char *)&fn_state;
    state_data.len = sizeof(fn_state);

    ((struct aura_fn_state *)state_data.base)->is_active = true;

    if (aura_db_insert(
          db,
          A_NS_FN,
          A_FN_STATE_SCHEMA_ID,
          0,
          A_DB_INSERT_OP,
          &state_key,
          &state_data) < 0) {
        goto out;
    }

    evt.error_code = A_FN_ERROR_NONE;
    evt.state = A_FN_OP_STATE_DONE;
    evt.msg_len = 0;
    aura_resp_send(cli_fd, &evt, sizeof(evt));

out:
    if (fn->iov_base)
        free(fn->iov_base);
    close(cli_fd);
}

void aura_dmn_stop_fn(struct iovec *fn, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    AURA_DBHANDLE db = gc->db_handle;
    struct aura_fn_state fn_state;
    struct aura_fn_tag *fn_tag;
    struct aura_fn_evt evt;
    struct aura_iovec key;
    char fn_name[A_FN_NAME_MAX_LEN];
    char fn_version[A_FN_VERSION_MAX_LEN];
    char key_buf[2000];
    int error;

    a_fn_get_name_and_version(fn, fn_name, sizeof(fn_name), fn_version, sizeof(fn_version));
    fn_tag = aura_fn_tag_fetch(db, &gc->mc, fn_name, fn_version, &error);
    if (!fn_tag) {
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;

        if (error == A_DB_REC_NOT_FOUND || error == 0) {
            evt.error_code = A_FN_ERROR_NOT_EXIST;
        } else if (error < 0) {
            evt.error_code = A_FN_ERROR_GENERIC;
        }

        aura_resp_send(cli_fd, &evt, sizeof(evt));
        goto out;
    }

    memcpy(fn_version, fn_tag->fn_version, A_FN_VERSION_MAX_LEN);
    aura_free(fn_tag);

    struct aura_iovec state_key, state_data;

    memset(key_buf, 0, sizeof(key_buf));
    snprintf(key_buf, sizeof(key_buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_STATE_SUFFIX);

    state_key.base = key_buf;
    state_key.len = strlen(key_buf);

    state_data.base = (char *)&fn_state;
    state_data.len = sizeof(fn_state);

    ((struct aura_fn_state *)state_data.base)->is_active = false;

    if (aura_db_insert(
          db,
          A_NS_FN,
          A_FN_STATE_SCHEMA_ID,
          0,
          A_DB_INSERT_OP,
          &state_key,
          &state_data) < 0) {
        goto out;
    }

    evt.error_code = A_FN_ERROR_NONE;
    evt.state = A_FN_OP_STATE_DONE;
    evt.msg_len = 0;
    aura_resp_send(cli_fd, &evt, sizeof(evt));

out:
    if (fn->iov_base)
        free(fn->iov_base);
    close(cli_fd);
}