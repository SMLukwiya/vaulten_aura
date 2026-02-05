#include "aura_dmn.h"
#include "db/db.h"
#include "function_lib.h"
#include "types_lib.h"
#include "unix_socket_lib.h"

#include <unistd.h>

const char fn_deleted_msg[] = "\x1B[1;32mFunction successfully deleted\x1B[0m";

/** @todo: is it better to pass conf via parameters instead? */
extern struct aura_daemon_glob_conf glob_conf;

void aura_fn_delete_cb(struct aura_db_completion *comp, ssize_t result) {
    struct aura_fn_evt evt;
    struct aura_fn_cb_data *user_data;
    int res;

    if (result < 0) {
        aura_db_job_update(glob_conf.db_handle, user_data->job_id, A_DB_JOB_FAILED, A_FN_ERROR_GENERIC, 0, A_DB_EXEC_ASYNC, NULL);
        evt.error_code = A_FN_ERROR_GENERIC;
        evt.state = A_FN_OP_STATE_FAILED;
        evt.msg_len = 0;
        evt.msg[0] = '\0';
        aura_send_resp(comp->client_fd, &evt, sizeof(evt));
        comp->status = result;
        comp->proceed = true;
        return;
    }

    user_data = (struct aura_fn_cb_data *)comp->user_data;

    /* Insert job step */
    char buf[2000];

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "%s:%s:v%u", A_DB_KEY_PREFIX_FUNC, user_data->fn_name, user_data->fn_version);
    struct aura_iovec target = {.base = buf, .len = strlen(buf)};

    switch (comp->state) {
    case A_FN_OP_STATE_START:
        res = 0;
        comp->state = A_FN_OP_STATE_RUNNING;
        break;

    case A_FN_OP_STATE_RUNNING:
        res = 0;
        comp->state = A_FN_OP_STATE_META;
        break;

    case A_FN_OP_STATE_META:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DELETE,
                                      A_FN_OP_STATE_META, &target, A_DB_EXEC_ASYNC, NULL);
        comp->state == A_FN_OP_STATE_CONFIG;
        break;

    case A_FN_OP_STATE_CONFIG:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DELETE,
                                      A_FN_OP_STATE_CONFIG, &target, A_DB_EXEC_ASYNC, NULL);
        comp->state == A_FN_OP_STATE_CODE;
        break;

    case A_FN_OP_STATE_CODE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DELETE,
                                      A_FN_OP_STATE_CODE, &target, A_DB_EXEC_ASYNC, NULL);
        comp->state = A_FN_OP_STATE_STAT;
        break;

    case A_FN_OP_STATE_STAT:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DELETE,
                                      A_FN_OP_STATE_STAT, &target, A_DB_EXEC_ASYNC, NULL);
        comp->state == A_FN_OP_STATE_FN_STATE;
        break;

    case A_FN_OP_STATE_FN_STATE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DELETE,
                                      A_FN_OP_STATE_FN_STATE, &target, A_DB_EXEC_ASYNC, NULL);
        comp->state == A_FN_OP_STATE_FN_LIST_UPDATE;
        break;

    case A_FN_OP_STATE_FN_LIST_UPDATE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DELETE,
                                      A_FN_OP_STATE_FN_LIST_UPDATE, &target, A_DB_EXEC_ASYNC, NULL);
        comp->state == A_FN_OP_STATE_DONE;
        break;

    case A_FN_OP_STATE_DONE:

    default:
        break;
    }

    if (res != 0) {
        aura_db_job_update(glob_conf.db_handle, user_data->job_id, A_DB_JOB_FAILED, 0,
                           A_FN_ERROR_GENERIC, A_DB_EXEC_ASYNC, NULL);
        evt.state = A_FN_OP_STATE_FAILED;
        evt.error_code = A_FN_ERROR_GENERIC;
        evt.msg_len = 0;
        aura_send_resp(comp->client_fd, (void *)&evt, sizeof(evt));
        comp->status = res;
        comp->proceed = true;
        return;
    }

    comp->status = 0;
    comp->proceed = true;
}

void aura_dmn_function_delete(AURA_DBHANDLE db, struct iovec *key, int cli_fd) {
    char *data, *fn_name;
    uint32_t fn_version;
    struct aura_iovec db_key, db_data;
    struct aura_db_completion comp;
    struct aura_fn_evt evt;
    struct aura_fn_cb_data user_data;
    uint64_t job_id;
    ssize_t res;
    char buf[2000];

    /* Mark function as deleted */
    /* Delete from cache */
    /* Gradually move all new function invocations to new ones */

    comp.client_fd = cli_fd;
    comp.state = A_FN_OP_STATE_START;
    comp.proceed = false;
    comp.user_data = &user_data;
    comp.on_complete = aura_fn_delete_cb;
    fn_name = NULL;

    switch (comp.state) {
    case A_FN_OP_STATE_START:
        job_id = aura_db_job_insert(db, A_FN_DELETE, A_DB_JOB_START, 0, A_FN_ERROR_NONE, A_DB_EXEC_ASYNC, &comp);
        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            return;
        }
        user_data.job_id = job_id;
        /* Fall through */

    case A_FN_OP_STATE_RUNNING:
        struct aura_fn_petite *fn_petite;
        int error;

        /**
         * Extract fn name and version
         * format: fn_name:fn_version or just fn_name
         */
        fn_name = key->iov_base;
        fn_version = UINT32_MAX;
        char *sep = strchr(key->iov_base, ':');
        if (sep) {
            aura_scan_str(sep + 1, "%d" SCNu32, &fn_version);
            *sep = '\0';
        }

        fn_petite = aura_fn_petite_fetch(db, fn_name, fn_version, &error);
        if (!fn_petite) {
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            if (error == A_DB_REC_NOT_FOUND || error == 0) {
                evt.error_code = A_FN_ERROR_NOT_EXIST;
            } else if (error < 0) {
                evt.error_code = A_FN_ERROR_GENERIC;
            }

            aura_db_job_update(db, job_id, A_DB_JOB_FAILED, evt.error_code, 0, A_DB_EXEC_ASYNC, NULL);
            aura_send_resp(cli_fd, &evt, sizeof(evt));
            goto out;
        }

        fn_version = fn_petite->fn_version;
        free(fn_petite);

        user_data.fn_name = fn_name;
        user_data.fn_version = fn_version;
        comp.state = A_FN_OP_STATE_META;
        /* Fall through */

    case A_FN_OP_STATE_META:
        struct aura_iovec meta_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_META);

        meta_key.base = buf;
        meta_key.len = strlen(buf);

        comp.proceed = false;
        res = aura_db_record_delete(glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1, job_id, &meta_key, A_DB_EXEC_ASYNC, &comp);
        if (res != 0) {
            goto out;
        }

        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            goto out;
        }
        /* Fall through */

    case A_FN_OP_STATE_CONFIG:
        struct aura_iovec config_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CONFIG);

        config_key.base = buf;
        config_key.len = strlen(buf);

        comp.proceed = false;
        res = aura_db_record_delete(glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1, job_id, &config_key, A_DB_EXEC_ASYNC, &comp);
        if (res != 0) {
            goto out;
        }

        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            goto out;
        }
        /* Fall through */

    case A_FN_OP_STATE_CODE:
        struct aura_iovec code_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CODE);

        code_key.base = buf;
        code_key.len = strlen(buf);

        comp.proceed = false;
        res = aura_db_record_delete(glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1, job_id, &code_key, A_DB_EXEC_ASYNC, &comp);
        if (res != 0) {
            goto out;
        }

        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            goto out;
        }
        /* Fall through */

    case A_FN_OP_STATE_STAT:
        struct aura_iovec stat_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STAT);

        stat_key.base = buf;
        stat_key.len = strlen(buf);

        comp.proceed = false;
        res = aura_db_record_delete(glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1, job_id, &stat_key, A_DB_EXEC_ASYNC, &comp);
        if (res != 0) {
            goto out;
        }

        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            goto out;
        }
        /* Fall through */

    case A_FN_OP_STATE_FN_STATE:
        struct aura_iovec state_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STATE);

        state_key.base = buf;
        state_key.len = strlen(buf);

        comp.proceed = false;
        res = aura_db_record_delete(glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1, job_id, &state_key, A_DB_EXEC_ASYNC, &comp);
        if (res != 0) {
            goto out;
        }

        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            goto out;
        }
        /* Fall through */

    case A_FN_OP_STATE_FN_LIST_UPDATE:
        comp.proceed = false;
        res = aura_fn_list_delete(glob_conf.db_handle, &glob_conf.mc, fn_name, fn_version, &comp);
        if (res != 0) {
            aura_db_job_update(db, job_id, A_DB_JOB_FAILED, A_FN_ERROR_NOT_EXIST, 0, A_DB_EXEC_ASYNC, NULL);
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_send_resp(cli_fd, &evt, sizeof(evt));
            goto out;
        }

        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            goto out;
        }
        /* Fall through */

    case A_FN_OP_STATE_DONE:
        res = aura_db_job_update(db, job_id, A_DB_JOB_DONE, A_FN_ERROR_NONE, 0, A_DB_EXEC_ASYNC, &comp);
        if (res != 0)
            goto out;

        aura_fn_async_op_wait(comp.proceed);
        if (comp.status != 0) {
            goto out;
        }

        evt.error_code = A_FN_ERROR_NONE;
        evt.state = A_FN_OP_STATE_DONE;
        evt.msg_len = 0;

        res = aura_send_resp(cli_fd, &evt, sizeof(evt));
        if (res < 0) {
            sys_debug(true, errno, "aura_dmn_function_delete: aura_send_resp error:");
        }

    default:
        break;
    }

out:
    if (fn_name)
        free(fn_name);
    close(cli_fd);
}