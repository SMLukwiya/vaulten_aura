#include "db/broker.h"
#include "fn/lib.h"

int aura_dmn_db_req(struct iovec *data, int cli_fd, AURA_DBHANDLE db) {
    struct aura_db_broker_request *request;
    struct aura_msg_hdr msg_hdr;
    size_t len;
    int error, res;
    char *end;
    char fn_name[A_FN_NAME_MAX_LEN];
    char fn_version[A_FN_VERSION_MAX_LEN];
    uint32_t version_len;
    char fn_version_str[64];
    struct iovec fn;

    memset(fn_name, 0, sizeof(fn_name));
    memset(fn_version, 0, sizeof(fn_version));
    request = data->iov_base;
    request->key.base = (char *)request + sizeof(*request);
    request->data.base = NULL;
    if (request->data.len > 0)
        request->data.base = (char *)request + sizeof(*request) + request->key.len;

    if (request->schema_id != A_DB_FN_LIST_SCHEMA_ID) {
        fn.iov_base = request->key.base;
        fn.iov_len = request->key.len;
        aura_fn_get_name_and_version(&fn, fn_name, sizeof(fn_name), fn_version, sizeof(fn_version));
    }

    if (request->namespace == A_DB_NS_FN) {
        switch (request->schema_id) {
        case A_DB_FN_CODE_SCHEMA_ID:
            struct aura_iovec code = aura_fn_code_fetch(db, fn_name, fn_version);
            if (!code.base) {
                res = aura_resp_send(cli_fd, NULL, 0);
                return res;
            }

            res = aura_resp_send(cli_fd, code.base, code.len);
            aura_free(code.base);
            break;

        case A_DB_FN_META_SCHEMA_ID:
            struct aura_iovec meta = aura_fn_meta_fetch(db, fn_name, fn_version);
            if (!meta.base) {
                res = aura_resp_send(cli_fd, NULL, 0);
                return res;
            }

            res = aura_resp_send(cli_fd, meta.base, meta.len);
            aura_free(meta.base);
            break;

        case A_DB_FN_CONF_SCHEMA_ID:
            struct aura_iovec config = aura_fn_config_fetch(db, fn_name, fn_version);
            if (!config.base) {
                res = aura_resp_send(cli_fd, NULL, 0);
                return res;
            }

            res = aura_resp_send(cli_fd, config.base, config.len);
            aura_free(config.base);
            break;

        case A_DB_FN_STAT_DELTA_SCHEMA_ID:
            struct aura_fn_stat *stat = aura_fn_stat_fetch(db, fn_name, fn_version);
            if (!stat) {
                res = aura_resp_send(cli_fd, NULL, 0);
                return res;
            }

            res = aura_resp_send(cli_fd, stat, sizeof(*stat));
            aura_free(stat);
            break;

        case A_DB_FN_TAG_SCHEMA_ID:
            struct aura_iovec state = aura_fn_state_fetch(db, fn_name, fn_version);
            if (!state.base) {
                res = aura_resp_send(cli_fd, NULL, 0);
                return res;
            }

            res = aura_resp_send(cli_fd, state.base, sizeof(state.len));
            aura_free(state.base);
            break;

        case A_DB_FN_LIST_SCHEMA_ID:
            struct aura_fn_list *fns;

            error = 0;
            fns = aura_fn_list_fetch(db, &error);
            if (error < 0 || error == A_DB_REC_NOT_FOUND) {
                res = aura_resp_send(cli_fd, NULL, 0);
                return res;
            }

            len = sizeof(*fns) + (fns->func_cnt * sizeof(struct aura_fn_tag));
            res = aura_resp_send(cli_fd, fns, len);
            aura_free(fns);
            break;

        default:
            break;
        }
    }

    return 0;
}