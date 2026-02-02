#include "command/function_dmn.h"
#include "function_lib.h"
#include "unix_socket_lib.h"

const char fn_status_active[] = "\x1B[1;32mFunction active\x1B[0m";
const char fn_status_inactive[] = "\x1B[1;32mFunction Inactive\x1B[0m";

void aura_dmn_function_status(AURA_DBHANDLE db, struct iovec *key, int cli_fd) {
    struct aura_fn_state *fn_state;
    struct aura_fn_petite *fn_petite;
    struct aura_fn_evt evt;
    struct aura_iovec state_key, state_data;
    const char *fn_name;
    uint32_t fn_version;
    char buf[2000];

    fn_name = key->iov_base;
    fn_version = UINT32_MAX;
    char *sep = strchr(key->iov_base, ':');
    if (sep) {
        aura_scan_str(sep + 1, "%d" SCNu32, &fn_version);
        *sep = '\0';
    }

    /* Version not provided, get latest */
    if (fn_version == UINT32_MAX) {
        fn_petite = aura_fn_petite_fetch(db, fn_name);
        if (!fn_petite) {
            evt.error_code = A_FN_ERROR_NOT_EXIST;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_send_resp(cli_fd, &evt, sizeof(evt));
            goto out;
        }
        fn_version = fn_petite->fn_version;
        free(fn_petite);
    }

    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STATE);
    state_key.base = buf;
    state_key.len = strlen(buf);
    if (aura_db_record_fetch(db, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1, &state_key, &state_data) < 0) {
        evt.error_code = A_FN_ERROR_NOT_EXIST;
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;

        aura_send_resp(cli_fd, &evt, sizeof(evt));
        goto out;
    }

    fn_state = (struct aura_fn_state *)state_data.base;

    evt.error_code = A_FN_ERROR_NONE;
    evt.state = A_FN_OP_STATE_DONE;
    evt.msg_len = fn_state->is_active ? sizeof(fn_status_active) : sizeof(fn_status_inactive);
    memcpy(evt.msg, fn_state->is_active ? fn_status_active : fn_status_inactive, evt.msg_len);

    aura_send_resp(cli_fd, &evt, sizeof(evt));

out:
    close(cli_fd);
}

void aura_fn_start_cb(struct aura_db_completion *comp, ssize_t result) {
    struct aura_fn_evt evt;

    if (result < 0) {
        evt.error_code = A_FN_ERROR_GENERIC;
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;
        aura_send_resp(comp->client_fd, &evt, sizeof(evt));
        comp->proceed = true;
        comp->status = result;
        return;
    }
    comp->status = 0;
    comp->proceed = true;
}

void aura_dmn_function_start(AURA_DBHANDLE db, struct aura_memory_ctx *mc, struct iovec *fn, int cli_fd) {
    struct aura_fn_state *fn_state;
    struct aura_fn_petite *fn_petite;
    struct aura_fn_evt evt;
    struct aura_iovec key;
    const char *fn_name;
    uint32_t fn_version;
    struct aura_db_completion comp;
    char buf[2000];
    int res;

    comp.client_fd = cli_fd;
    comp.on_complete = aura_fn_start_cb;

    fn_name = fn->iov_base;
    fn_version = UINT32_MAX;
    char *sep = strchr(fn->iov_base, ':');
    if (sep) {
        aura_scan_str(sep + 1, "%d" SCNu32, &fn_version);
        *sep = '\0';
    }

    /* Version not provided, get latest */
    if (fn_version == UINT32_MAX) {
        fn_petite = aura_fn_petite_fetch(db, fn_name);
        if (!fn_petite) {
            evt.error_code = A_FN_ERROR_NOT_EXIST;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_send_resp(cli_fd, &evt, sizeof(evt));
            goto out;
        }
        fn_version = fn_petite->fn_version;
        free(fn_petite);
    }

    snprintf(buf, sizeof(buf), "%s:%s:v%u", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);
    if (!aura_db_record_exists(db, A_DB_NS_FN, A_FN_DEPLOY, A_DB_SCHEMA_FN_META_V1, &key, true)) {
        evt.error_code = A_FN_ERROR_NOT_EXIST;
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;

        aura_send_resp(cli_fd, &evt, sizeof(evt));
        goto out;
    }

    struct aura_iovec *state_key, *state_data;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STATE);

    state_key = aura_iovec_init(mc, strlen(buf), NULL);
    if (!state_key)
        goto out;

    state_data = aura_iovec_init(mc, sizeof(*fn_state), NULL);
    if (!state_data) {
        aura_iovec_destroy(state_key);
        goto out;
    }

    memcpy(state_key->base, buf, state_key->len);
    fn_state = (struct aura_fn_state *)state_data->base;
    fn_state->is_active = true;

    res = aura_db_record_insert(db, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1, 0, 0, A_DB_OP_INSERT, state_key, state_data, A_DB_EXEC_ASYNC, &comp);
    if (res != 0) {
        aura_iovec_destroy(state_key);
        aura_iovec_destroy(state_data);
        goto out;
    }
    aura_fn_async_op_wait(comp.proceed);

    if (comp.status != 0)
        goto out;

    evt.error_code = A_FN_ERROR_NONE;
    evt.state = A_FN_OP_STATE_DONE;
    evt.msg_len = 0;
    aura_send_resp(cli_fd, &evt, sizeof(evt));

out:
    close(cli_fd);
}

void aura_dmn_function_stop(AURA_DBHANDLE db, struct aura_memory_ctx *mc, struct iovec *fn, int cli_fd) {
    struct aura_fn_state *fn_state;
    struct aura_fn_petite *fn_petite;
    struct aura_fn_evt evt;
    struct aura_iovec key;
    const char *fn_name;
    uint32_t fn_version;
    struct aura_db_completion comp;
    char buf[2000];
    int res;

    comp.client_fd = cli_fd;
    comp.on_complete = aura_fn_start_cb;

    fn_name = fn->iov_base;
    fn_version = UINT32_MAX;
    char *sep = strchr(fn->iov_base, ':');
    if (sep) {
        aura_scan_str(sep + 1, "%d" SCNu32, &fn_version);
        *sep = '\0';
    }

    /* Version not provided, get latest */
    if (fn_version == UINT32_MAX) {
        fn_petite = aura_fn_petite_fetch(db, fn_name);
        if (!fn_petite) {
            evt.error_code = A_FN_ERROR_NOT_EXIST;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_send_resp(cli_fd, &evt, sizeof(evt));
            goto out;
        }
        fn_version = fn_petite->fn_version;
        free(fn_petite);
    }

    snprintf(buf, sizeof(buf), "%s:%s:v%u", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version);
    key.base = buf;
    key.len = strlen(buf);
    if (!aura_db_record_exists(db, A_DB_NS_FN, A_FN_DEPLOY, A_DB_SCHEMA_FN_META_V1, &key, true)) {
        evt.error_code = A_FN_ERROR_NOT_EXIST;
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;

        aura_send_resp(cli_fd, &evt, sizeof(evt));
        goto out;
    }

    struct aura_iovec *state_key, *state_data;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STATE);

    state_key = aura_iovec_init(mc, strlen(buf), NULL);
    if (!state_key)
        goto out;

    state_data = aura_iovec_init(mc, sizeof(*fn_state), NULL);
    if (!state_data) {
        aura_iovec_destroy(state_key);
        goto out;
    }

    memcpy(state_key->base, buf, state_key->len);
    fn_state = (struct aura_fn_state *)state_data->base;
    fn_state->is_active = false;

    res = aura_db_record_insert(db, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1, 0, 0, A_DB_OP_INSERT, state_key, state_data, A_DB_EXEC_ASYNC, &comp);
    if (res != 0) {
        aura_iovec_destroy(state_key);
        aura_iovec_destroy(state_data);
        goto out;
    }
    aura_fn_async_op_wait(comp.proceed);

    if (comp.status != 0)
        goto out;

    evt.error_code = A_FN_ERROR_NONE;
    evt.state = A_FN_OP_STATE_DONE;
    evt.msg_len = 0;
    aura_send_resp(cli_fd, &evt, sizeof(evt));

out:
    close(cli_fd);
}