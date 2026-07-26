#include "db/db.h"
#include "dmn.h"
#include "fn/lib.h"
#include "types_lib.h"
#include "unix/sock.h"

#include <unistd.h>

const char fn_deleted_msg[] = "\x1B[1;32mFunction successfully deleted\x1B[0m";

void aura_dmn_delete_fn(struct iovec *key, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    AURA_DBHANDLE db = gc->db_handle;
    char *fn_name;
    uint32_t fn_version;
    struct aura_fn_evt evt;
    char buf[2000];
    int state;

    /* Mark function as deleted */
    /* Delete from cache */
    /* Gradually move all new function invocations to new ones */

    fn_name = NULL;
    state = A_FN_OP_STATE_RUNNING;

    switch (state) {
    case A_FN_OP_STATE_RUNNING:
        struct aura_fn_tag *fn_tag;
        int error;

        /**
         * Extract fn name and version
         * format: fn_name:fn_version or just fn_name
         */
        fn_name = key->iov_base;
        fn_version = UINT32_MAX;
        char *sep = strchr(key->iov_base, ':');
        if (sep) {
            if (aura_scan_str(sep + 1, "%d" SCNu32, &fn_version) < 0) {
                evt.state = A_FN_OP_STATE_FAILED;
                evt.msg_len = 0;
                evt.error_code = A_FN_ERROR_GENERIC;
                aura_resp_send(cli_fd, &evt, sizeof(evt));
                goto out;
            }
            *sep = '\0';
        }

        fn_tag = aura_fn_tag_fetch(db, &gc->mc, fn_name, fn_version, &error);
        if (!fn_tag) {
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            if (error == A_DB_REC_NOT_FOUND || error == 0) {
                evt.error_code = A_FN_ERROR_NOT_EXIST;
            } else if (error < 0) {
                evt.error_code = A_FN_ERROR_GENERIC;
            }

            aura_resp_send(cli_fd, (void *)&evt, sizeof(evt));
            goto out;
        }

        fn_version = fn_tag->fn_version;
        aura_free(fn_tag);

        if (aura_db_transaction_begin(gc->db_handle, A_FN_DEPLOY, 0) < 0) {
            evt.state = A_FN_OP_STATE_FAILED;
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.msg_len = 0;
            aura_resp_send(cli_fd, (void *)&evt, sizeof(evt));
            return;
        }

        state = A_FN_OP_STATE_META;
        /* Fall through */

    case A_FN_OP_STATE_META:
        /**
         * set error state so we don not
         * have to repeat the code in subsequent
         * steps
         */
        evt.state = A_FN_OP_STATE_FAILED;
        evt.error_code = A_FN_ERROR_GENERIC;
        evt.msg_len = 0;
        evt.msg[0] = '\0';

        struct aura_iovec meta_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_META_SUFFIX);

        meta_key.base = buf;
        meta_key.len = strlen(buf);

        if (aura_db_delete(db, A_DB_NS_FN, A_DB_FN_META_SCHEMA_ID, &meta_key) < 0)
            goto out;

        state = A_FN_OP_STATE_CONFIG;
        /* Fall through */

    case A_FN_OP_STATE_CONFIG:
        struct aura_iovec config_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_CONF_SUFFIX);

        config_key.base = buf;
        config_key.len = strlen(buf);

        if (aura_db_delete(db, A_DB_NS_FN, A_DB_FN_CONF_SCHEMA_ID, &config_key) < 0)
            goto out;

        state = A_FN_OP_STATE_CODE;
        /* Fall through */

    case A_FN_OP_STATE_CODE:
        struct aura_iovec code_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_CODE_SUFFIX);

        code_key.base = buf;
        code_key.len = strlen(buf);

        if (aura_db_delete(db, A_DB_NS_FN, A_DB_FN_CODE_SCHEMA_ID, &code_key) < 0)
            goto out;

        state = A_FN_OP_STATE_STAT;
        /* Fall through */

    case A_FN_OP_STATE_STAT:
        struct aura_iovec stat_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_STAT_SUFFIX);

        stat_key.base = buf;
        stat_key.len = strlen(buf);

        if (aura_db_delete(db, A_DB_NS_FN, A_DB_FN_STAT_DELTA_SCHEMA_ID, &stat_key) < 0)
            goto out;

        state = A_FN_OP_STATE_FN_STATE;
        /* Fall through */

    case A_FN_OP_STATE_FN_STATE:
        struct aura_iovec state_key;

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_STATE_SUFFIX);

        state_key.base = buf;
        state_key.len = strlen(buf);

        if (aura_db_delete(db, A_DB_NS_FN, A_DB_FN_STATE_SCHEMA_ID, &state_key) < 0)
            goto out;

        state = A_FN_OP_STATE_FN_LIST_UPDATE;
        /* Fall through */

    case A_FN_OP_STATE_FN_LIST_UPDATE:
        if (aura_fn_list_delete(db, &gc->mc, fn_name, fn_version) < 0) {
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_resp_send(cli_fd, &evt, sizeof(evt));
            goto out;
        }

        state = A_FN_OP_STATE_DONE;
        /* Fall through */

    case A_FN_OP_STATE_DONE:
        if (aura_db_transaction_commit(db) < 0) {
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.state = A_FN_OP_STATE_FAILED;
            evt.msg_len = 0;

            aura_resp_send(cli_fd, &evt, sizeof(evt));
            goto out;
        }

        evt.error_code = A_FN_ERROR_NONE;
        evt.state = A_FN_OP_STATE_DONE;
        evt.msg_len = 0;

        aura_resp_send(cli_fd, &evt, sizeof(evt));

    default:
        break;
    }

out:
    if (fn_name)
        free(fn_name);
    close(cli_fd);
}