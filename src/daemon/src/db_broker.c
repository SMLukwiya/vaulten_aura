#include "db_broker.h"
#include "function_lib.h"

struct name_version {
    char name[1024];
    uint32_t version;
};

/** @todo: unused yet */
static inline struct name_version a_extract_fn_name_version(const char *str) {
    struct name_version nv;
    char *end;
    int res;

    end = strchr(str, ':');
    *end = '\0';
    memcpy(nv.name, str, end - str);
    res = aura_scan_str(end + 1, "%u", &nv.version);
    if (res == 0)
        nv.version = UINT32_MAX;

    return nv;
}

int aura_dmn_fetch_request(AURA_DBHANDLE db, struct iovec *data, int cli_fd) {
    struct aura_db_broker_request *request;
    struct aura_msg_hdr msg_hdr;
    size_t len;
    int error, res;
    char *fn_name, *end;
    uint32_t fn_version, version_len;
    char fn_version_str[64];

    request = data->iov_base;
    request->key.base = (char *)request + sizeof(*request);
    request->data.base = NULL;
    if (request->data.len > 0)
        request->data.base = (char *)request + sizeof(*request) + request->key.len;

    if (request->schema_id != A_DB_SCHEMA_FNS) {
        end = strchr(request->key.base, ':');
        *end = '\0';
        fn_name = request->key.base;
        version_len = request->key.len - (end - fn_name);
        snprintf(fn_version_str, version_len, "%s", end + 1);
        res = aura_scan_str(fn_version_str, "%u", &fn_version);
        if (!fn_name || res == 0) {
            res = aura_resp_send(cli_fd, NULL, 0);
            return res;
        }
    }

    switch (request->schema_id) {
    case A_DB_SCHEMA_FN_CODE_V1:
        struct aura_iovec code = aura_fn_code_fetch(db, fn_name, fn_version);
        if (!code.base) {
            res = aura_resp_send(cli_fd, NULL, 0);
            return res;
        }

        res = aura_resp_send(cli_fd, code.base, code.len);
        aura_free(code.base);
        break;

    case A_DB_SCHEMA_FN_META_V1:
        struct aura_iovec meta = aura_fn_meta_fetch(db, fn_name, fn_version);
        if (!meta.base) {
            res = aura_resp_send(cli_fd, NULL, 0);
            return res;
        }

        res = aura_resp_send(cli_fd, meta.base, meta.len);
        aura_free(meta.base);
        break;

    case A_DB_SCHEMA_FN_CONFIG_V1:
        struct aura_iovec config = aura_fn_config_fetch(db, fn_name, fn_version);
        if (!config.base) {
            res = aura_resp_send(cli_fd, NULL, 0);
            return res;
        }

        res = aura_resp_send(cli_fd, config.base, config.len);
        aura_free(config.base);
        break;

    case A_DB_SCHEMA_FN_STAT_DELTA:
        struct aura_fn_stat *stat = aura_fn_stat_fetch(db, fn_name, fn_version);
        if (!stat) {
            res = aura_resp_send(cli_fd, NULL, 0);
            return res;
        }

        res = aura_resp_send(cli_fd, stat, sizeof(*stat));
        aura_free(stat);
        break;

    case A_DB_SCHEMA_FN_STATE_V1:
        struct aura_iovec state = aura_fn_state_fetch(db, fn_name, fn_version);
        if (!state.base) {
            res = aura_resp_send(cli_fd, NULL, 0);
            return res;
        }

        res = aura_resp_send(cli_fd, state.base, sizeof(state.len));
        aura_free(state.base);
        break;

    case A_DB_SCHEMA_FNS:
        struct aura_functions *fns;

        error = 0;
        fns = aura_fn_list_fetch(db, &error);
        if (error < 0 || error == A_DB_REC_NOT_FOUND) {
            res = aura_resp_send(cli_fd, NULL, 0);
            return res;
        }

        len = sizeof(*fns) + (fns->func_cnt * sizeof(fns->funcs[0]));
        res = aura_resp_send(cli_fd, fns, len);
        aura_free(fns);
        break;

    default:
        break;
    }

    return 0;
}