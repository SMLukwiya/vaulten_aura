#include "aura_dmn.h"
#include "bug_lib.h"
#include "common_dmn.h"
#include "db/db.h"
#include "file_lib.h"
#include "function_lib.h"
#include "ipc_lib.h"
#include "quickjs/quickjs.h"
#include "runtime_lib.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

struct statistical_baseline {
    double mean;
    double standard_deviation;
    int sample_count;
};

/** @todo: is it better to pass conf via parameters instead? */
extern struct aura_daemon_glob_conf glob_conf;

extern struct aura_yml_validator aura_function_validator[];
extern int aura_function_validator_len;
extern char *fn_config_valid;
extern void a_fn_init_user_data_ctx(struct aura_yml_fn_data_ctx *usr_data, bool extract, int fn_dir_fd);
extern void a_fn_free_user_data_ctx(struct aura_yml_fn_data_ctx *usr_data);

const char fn_deploy_success[] = "\x1B[1;32mDeployment complete\x1B[0m";
const char fn_deployment_failed[] = "\x1B[1;31mDeployment Failed\x1B[0m";
const char entry_file_error[] = "\x1B[1;31mFailed to load entry file\x1B[0m";
const char file_aready_exists[] = "\x1B[1;31mDeployment failed. Function with same name and version already exists\x1B[0m";

struct aura_builder_stack fn_stack;

extern int _fn_conf_tab[];
extern size_t _fn_conf_tab_size;

/** Build a blob of the funtion metadata */
static void *a_build_fn_meta(struct aura_yml_fn_data_ctx *usr_data) {
    uint32_t root_off, func_off, triggers_off, resources_off, networking_off;
    void *fn_meta;
    st_aura_b_builder b;

    aura_blob_builder_init(&b);

    root_off = aura_blob_b_add_map(&b);
    /* Function */
    func_off = aura_build_blob_from_rax(usr_data->parse_tree, &b, usr_data->node_arr, "function", sizeof("function") - 1, &fn_stack, _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "function", func_off);

    /* Triggers */
    triggers_off = aura_build_blob_from_rax(usr_data->parse_tree, &b, usr_data->node_arr, "triggers", sizeof("triggers") - 1, &fn_stack, _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "triggers", triggers_off);

    /* Resources */
    resources_off = aura_build_blob_from_rax(usr_data->parse_tree, &b, usr_data->node_arr, "resources", sizeof("resources") - 1, &fn_stack, _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "resources", resources_off);

    fn_meta = aura_serialize_blob(&b, _fn_conf_tab, _fn_conf_tab_size, NULL, 0);
    aura_blob_free(&b);
    return fn_meta;
}

/** Build a blob of the function config */
static void *a_build_fn_config(struct aura_yml_fn_data_ctx *usr_data) {
    uint32_t root_off, env_off, concurrency_off, observability_off;
    void *fn_config;
    st_aura_b_builder b;

    aura_blob_builder_init(&b);

    root_off = aura_blob_b_add_map(&b);
    /* Environment vars */
    env_off = aura_build_blob_from_rax(usr_data->parse_tree, &b, usr_data->node_arr, "env", sizeof("env") - 1, &fn_stack, _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "env", env_off);

    /* Concurrency */
    concurrency_off = aura_build_blob_from_rax(usr_data->parse_tree, &b, usr_data->node_arr, "concurrency", sizeof("concurrency") - 1, &fn_stack, _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "concurrency", concurrency_off);

    /* Observability */

    fn_config = aura_serialize_blob(&b, _fn_conf_tab, _fn_conf_tab_size, NULL, 0);
    aura_blob_free(&b);
    return fn_config;
}

static const char *a_get_entry_file(void *fn_meta) {
    const st_aura_blob_node *nodes, *node;
    const char *strtab, *file;
    const int *fn_tab;

    nodes = aura_blob_get_nodes(fn_meta);
    strtab = aura_blob_get_strtab(fn_meta);
    fn_tab = aura_blob_get_tab(fn_meta);
    /* Entry */
    if (fn_tab[A_IDX_FN_ENTRY_POINT] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_ENTRY_POINT]];
        file = strtab + node->str_offset;
        return file;
    }
    return NULL;
}

static const char *a_fn_name_get(void *fn_meta) {
    const st_aura_blob_node *nodes, *node;
    const char *strtab, *name;
    const int *fn_tab;

    nodes = aura_blob_get_nodes(fn_meta);
    strtab = aura_blob_get_strtab(fn_meta);
    fn_tab = aura_blob_get_tab(fn_meta);

    if (fn_tab[A_IDX_FN_NAME] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_NAME]];
        name = strdup(strtab + node->str_offset);
        return name;
    }
    return NULL;
}

static int64_t a_fn_version_get(void *fn_meta) {
    const st_aura_blob_node *nodes, *node;
    const char *strtab;
    uint32_t version;
    const int *fn_tab;

    nodes = aura_blob_get_nodes(fn_meta);
    strtab = aura_blob_get_strtab(fn_meta);
    fn_tab = aura_blob_get_tab(fn_meta);
    /* Entry */
    if (fn_tab[A_IDX_FN_VERSION] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_VERSION]];
        aura_scan_str(strtab + node->str_offset, "%d" SCNu32, &version);
        return version;
    }
    return -1;
}

void aura_fn_deploy_start_cb(struct aura_db_completion *comp, ssize_t result) {
    struct aura_fn_evt evt;
    struct aura_fn_cb_data *user_data;
    int rv;

    user_data = comp->user_data;

    if (result < 0) {
        evt.state = A_FN_OP_STATE_FAILED;
        evt.error_code = A_FN_ERROR_GENERIC;
        evt.msg_len = 0;

        /* update job as failed, don't wait */
        aura_db_job_update(glob_conf.db_handle, user_data->job_id, A_DB_JOB_FAILED, evt.error_code, 0, A_DB_EXEC_ASYNC, NULL);

        /* Send response */
        aura_send_resp(comp->client_fd, (void *)&evt, sizeof(evt));
    }

    /* Store result and proceed to next step */
    comp->status = 0;
    comp->state = A_FN_OP_STATE_RUNNING;
    /* Proceed to next step */
    comp->proceed = true;
}

/**
 * Save function byte/compiled code and related job event
 * @result contains the offset of the newly inserted record
 */
void aura_fn_deploy_artifacts_insert_cb(struct aura_db_completion *comp, ssize_t result) {
    struct aura_fn_evt evt;
    struct aura_fn_cb_data *user_data;
    int res;

    user_data = comp->user_data;

    if (result < 0) {
        evt.state = A_FN_OP_STATE_FAILED;
        evt.error_code = A_FN_ERROR_CONFIG;
        evt.msg_len = 0;

        /* Update job failed */
        aura_db_job_update(glob_conf.db_handle, user_data->job_id, A_DB_JOB_FAILED, evt.error_code, 0, A_DB_EXEC_ASYNC, NULL);

        aura_send_resp(comp->client_fd, (void *)&evt, sizeof(evt));

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
    case A_FN_OP_STATE_PETITE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_PETITE, &target, A_DB_EXEC_ASYNC, NULL);
        /* We can safely advance the step here since we will halt if we get any error */
        comp->state = A_FN_OP_STATE_META;
        break;

    case A_FN_OP_STATE_META:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_META, &target, A_DB_EXEC_ASYNC, NULL);
        /* We can safely advance the step here since we will halt if we get any error */
        comp->state = A_FN_OP_STATE_CONFIG;
        break;

    case A_FN_OP_STATE_CONFIG:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_CONFIG, &target, A_DB_EXEC_ASYNC, NULL);

        comp->state = A_FN_OP_STATE_CODE;
        break;

    case A_FN_OP_STATE_CODE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_CODE, &target, A_DB_EXEC_ASYNC, NULL);

        comp->state = A_FN_OP_STATE_STAT;
        break;

    case A_FN_OP_STATE_STAT:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_STAT, &target, A_DB_EXEC_ASYNC, NULL);

        comp->state = A_FN_OP_STATE_FN_STATE;
        break;

    case A_FN_OP_STATE_FN_STATE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_FN_STATE, &target, A_DB_EXEC_ASYNC, NULL);

        comp->state = A_FN_OP_STATE_FN_LIST_UPDATE;
        break;

    case A_FN_OP_STATE_FN_LIST_UPDATE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_FN_LIST_UPDATE, &target, A_DB_EXEC_ASYNC, NULL);

        comp->state = A_FN_OP_STATE_DONE;
        break;

    case A_FN_OP_STATE_DONE:
        res = aura_db_job_step_insert(glob_conf.db_handle, user_data->job_id, A_FN_DEPLOY,
                                      A_FN_OP_STATE_DONE, &target, A_DB_EXEC_ASYNC, NULL);
        break;
    default:
        break;
    }

    if (res != 0) {
        evt.state = A_FN_OP_STATE_FAILED;
        evt.error_code = A_FN_ERROR_CONFIG;
        evt.msg_len = 0;

        /* Update job failed */
        aura_db_job_update(glob_conf.db_handle, user_data->job_id, A_DB_JOB_FAILED, evt.error_code, 0, A_DB_EXEC_ASYNC, NULL);

        /* Send response */
        aura_send_resp(comp->client_fd, (void *)&evt, sizeof(evt));
        comp->status = res;
        comp->proceed = true;
        return;
    }

    /* Store result and proceed */
    comp->status = 0;
    comp->proceed = true;
}

/** */
void aura_dmn_function_deploy(int dir_fd, int srv_fd, int cli_fd) {
    struct aura_yml_fn_data_ctx usr_data;
    struct aura_yml_err_ctx *parser_err;
    JSRuntime *rt;
    JSContext *ctx;
    bool fail_fast = true, extract = true;
    int config_fd, entry_file_fd;
    uint64_t entry_file_len;
    const uint8_t *entry_file, *entry_script;
    uint32_t root_off, func_root, triggers_root;
    struct aura_db_completion completion;
    struct aura_fn_cb_data user_data;
    struct aura_msg_hdr hdr;
    struct aura_fn_evt evt;
    int64_t job_id;
    const char *first_err;
    char buf[2000];
    int res;

    void *bytecode, *fn_meta, *fn_config;
    uint64_t bytecode_len, fn_meta_size, fn_config_size;
    struct aura_iovec key, data;

    const char *fn_name;
    uint32_t fn_version;

    rt = NULL;  /* Runtime */
    ctx = NULL; /* Runtime context */
    bytecode = NULL;
    fn_meta = NULL;
    fn_config = NULL;
    entry_script = NULL;

    completion.on_complete = aura_fn_deploy_start_cb;
    completion.client_fd = cli_fd;
    completion.state = A_FN_OP_STATE_START;
    completion.proceed = false;
    completion.user_data = (void *)&user_data;

    switch (completion.state) {
    case A_FN_OP_STATE_START:
        job_id = aura_db_job_insert(
          glob_conf.db_handle, A_FN_DEPLOY, A_DB_JOB_START, 0,
          A_FN_ERROR_NONE, A_DB_EXEC_ASYNC, &completion);

        if (job_id < 0) {
            sys_debug(true, errno, "aura_dmn_function_deploy: aura_db_job_insert deploy start error:");
            return;
        }
        /* Wait to proceed and Fall through */
        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0)
            return;
        /* Store job Id and fall through */
        user_data.job_id = job_id;

    case A_FN_OP_STATE_RUNNING:
        int error;
        size_t msg_len;
        char *msg;

        /* Parse config */
        first_err = NULL;
        config_fd = openat(dir_fd, "function.yaml", O_RDONLY);
        if (config_fd < 0) {
            config_fd = openat(dir_fd, "function.yml", O_RDONLY);
            /* Missing fn config file */
            A_BUG_ON_2(config_fd < 0, true);
        }

        parser_err = aura_create_yml_error_ctx(fail_fast);
        a_fn_init_user_data_ctx(&usr_data, extract, dir_fd);

        res = aura_load_config_fd(config_fd, aura_function_validator, aura_function_validator_len, parser_err, (void *)&usr_data);
        close(config_fd); /* No longer needed */
        if (res != 0) {
            error = A_FN_ERROR_CONFIG;
            msg_len = 0;
            msg == NULL;
            goto err;
        }

        if (res == 0 && parser_err->err_cnt > 0) {
            msg = parser_err->errors[0].message;
            msg_len = strlen(msg);
            error = A_FN_ERROR_CONFIG;
            goto err;
        }

        struct aura_fn_meta _fn_meta;
        struct aura_fn_config _fn_config;

        fn_meta = a_build_fn_meta(&usr_data);
        fn_meta_size = aura_blob_get_size(fn_meta);
        /**
         * Check if we can parse the meta upfront
         */
        if (aura_fn_meta_parse(fn_meta, &_fn_meta) != 0) {
            error = A_FN_ERROR_CONFIG;
            msg_len = 0;
            msg == NULL;
            goto err;
        }
        aura_fn_meta_destroy(&_fn_meta);

        fn_config = a_build_fn_config(&usr_data);
        fn_config_size = aura_blob_get_size(fn_config);
        /**
         * Check if we can parse the config upfront
         */
        if (aura_fn_config_parse(fn_config, &_fn_config) != 0) {
            error = A_FN_ERROR_CONFIG;
            msg_len = 0;
            msg == NULL;
            goto err;
        }
        aura_fn_config_destroy(&_fn_config);

        entry_file = a_get_entry_file(fn_meta);
        /* Missing entry file */
        A_BUG_ON_2(!entry_file, true);

        entry_file_fd = openat(dir_fd, entry_file, O_RDONLY);
        /* Can't open entry file */
        A_BUG_ON_2(entry_file_fd < 0, true);

        rt = JS_NewRuntime();
        if (!rt) {
            error = A_FN_ERROR_CONFIG;
            msg_len = 0;
            msg == NULL;
            goto err;
        }
        ctx = JS_NewContext(rt);
        if (!ctx) {
            error = A_FN_ERROR_CONFIG;
            msg_len = 0;
            msg == NULL;
            goto err;
        }

        entry_script = aura_load_file(entry_file_fd, &entry_file_len);
        /* close fd, no longer useful */
        close(entry_file_fd);
        if (!entry_script) {
            error = A_FN_ERROR_CONFIG;
            msg_len = sizeof(entry_file_error) - 1;
            msg = (char *)entry_file_error;
            goto err;
        }

        bytecode = aura_qjs_create_bytecode(ctx, entry_script, entry_file_len, entry_file, &bytecode_len);
        if (!bytecode) {
            error = A_FN_ERROR_CONFIG;
            msg_len = 0;
            msg == NULL;
            goto err;
        }

        goto proceed;

    err:
        evt.state = A_FN_OP_STATE_FAILED;
        evt.error_code = error;
        evt.msg_len = msg_len;
        memset(evt.msg, 0, sizeof(evt.msg));
        if (msg_len > 0)
            memcpy(evt.msg, msg, sizeof(evt.msg));

        /* We don't wait for confirmation of job update, we should probably wait!! */
        aura_db_job_update(glob_conf.db_handle, user_data.job_id, A_DB_JOB_FAILED, error, 0, A_DB_EXEC_ASYNC, NULL);
        aura_send_resp(cli_fd, (void *)&evt, sizeof(evt));
        goto out;

        /* Move to next step */
    proceed:
        completion.state = A_FN_OP_STATE_PETITE;
        /* Fall through */

    case A_FN_OP_STATE_PETITE:
        struct aura_fn_petite *fn_petite;

        fn_name = a_fn_name_get(fn_meta);
        fn_version = a_fn_version_get(fn_meta);
        user_data.fn_name = fn_name;
        user_data.fn_version = fn_version;

        /* Check if we have duplicate */
        fn_petite = aura_fn_petite_fetch(glob_conf.db_handle, &glob_conf.mc, fn_name, fn_version, &error);
        if (!fn_petite) {
            if (error < 0) {
                evt.state = A_FN_OP_STATE_FAILED;
                evt.error_code = A_FN_ERROR_GENERIC;
                evt.msg_len = 0;

                aura_db_job_update(glob_conf.db_handle, job_id, A_DB_JOB_FAILED, evt.error_code, 0, A_DB_EXEC_ASYNC, NULL);
                aura_send_resp(cli_fd, &evt, sizeof(evt));
                goto out;
            }
        }

        if (fn_petite) {
            /* Record no longer needed */
            aura_free(fn_petite);
            evt.state = A_FN_OP_STATE_FAILED;
            evt.error_code = A_FN_ERROR_DUPLICATE;
            evt.msg_len = 0;
            evt.msg[0] = '\0';

            /* Don't wait for async op */
            aura_db_job_update(glob_conf.db_handle, job_id, A_DB_JOB_FAILED, evt.error_code, 0, A_DB_EXEC_ASYNC, NULL);
            aura_send_resp(cli_fd, (void *)&evt, sizeof(evt));
            goto out;
        }

        completion.state = A_FN_OP_STATE_META;
        /* Fall through */

    case A_FN_OP_STATE_META:
        /* format: fn:<name>:<version>:<schema> */
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_META);
        struct aura_iovec *meta_key, *meta_data;

        meta_key = aura_iovec_init(&glob_conf.mc, strlen(buf), NULL);
        if (!meta_key) {
            /* @todo: report failure */
            goto out;
        }
        meta_data = aura_iovec_init(&glob_conf.mc, fn_meta_size, NULL);
        if (!meta_data) {
            aura_iovec_destroy(meta_key);
            goto out;
        }

        /* make a copy of key and data for now */
        memcpy(meta_key->base, buf, meta_key->len);
        memcpy(meta_data->base, fn_meta, meta_data->len);

        /* Update completion to write fn code */
        completion.proceed = false;
        completion.on_complete = aura_fn_deploy_artifacts_insert_cb;
        res = aura_db_record_insert(
          glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_META_V1,
          user_data.job_id, 0, A_DB_OP_INSERT,
          meta_key, meta_data, A_DB_EXEC_ASYNC, &completion);

        if (res != 0) {
            aura_iovec_destroy(meta_key);
            aura_iovec_destroy(meta_data);
            goto out;
        }

        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0)
            goto out;
        /* Fall through */

    case A_FN_OP_STATE_CONFIG:
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CONFIG);

        struct aura_iovec *config_key, *config_data;

        config_key = aura_iovec_init(&glob_conf.mc, strlen(buf), NULL);
        if (!config_key) {
            /* @todo: report failure */
            goto out;
        }
        config_data = aura_iovec_init(&glob_conf.mc, fn_config_size, NULL);
        if (!config_data) {
            aura_iovec_destroy(config_key);
            goto out;
        }

        memcpy(config_key->base, buf, config_key->len);
        memcpy(config_data->base, fn_config, config_data->len);

        completion.proceed = false;
        res = aura_db_record_insert(
          glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_CONFIG_V1,
          user_data.job_id, 0, A_DB_OP_INSERT,
          config_key, config_data, A_DB_EXEC_ASYNC, &completion);

        if (res != 0) {
            aura_iovec_destroy(config_key);
            aura_iovec_destroy(config_data);
            goto out;
        }

        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0)
            goto out;
        /* Fall through */

    case A_FN_OP_STATE_CODE:
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_CODE);

        struct aura_iovec *code_key, *code_data;

        code_key = aura_iovec_init(&glob_conf.mc, strlen(buf), NULL);
        if (!code_key) {
            /* @todo: report failure */
            goto out;
        }
        code_data = aura_iovec_init(&glob_conf.mc, bytecode_len, NULL);
        if (!code_data) {
            aura_iovec_destroy(code_key);
            goto out;
        }

        memcpy(code_key->base, buf, code_key->len);
        memcpy(code_data->base, bytecode, code_data->len);

        completion.proceed = false;
        res = aura_db_record_insert(
          glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_CODE_V1,
          user_data.job_id, 0, A_DB_OP_INSERT,
          code_key, code_data, A_DB_EXEC_ASYNC, &completion);

        if (res != 0) {
            aura_iovec_destroy(code_key);
            aura_iovec_destroy(code_data);
            goto out;
        }

        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0)
            goto out;
        /* Fall through */

    case A_FN_OP_STATE_STAT:
        struct aura_fn_stat stats;

        /* stats */
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STAT);

        struct aura_iovec *stats_key, *stats_data;

        stats_key = aura_iovec_init(&glob_conf.mc, strlen(buf), NULL);
        if (!stats_key) {
            /* @todo: report failure */
            goto out;
        }
        stats_data = aura_iovec_init(&glob_conf.mc, sizeof(stats), NULL);
        if (!stats_data) {
            aura_iovec_destroy(stats_key);
            goto out;
        }

        memset(&stats, 0, sizeof(stats));
        memcpy(stats_key->base, buf, stats_key->len);
        memcpy(stats_data->base, &stats, stats_data->len);

        completion.proceed = false;
        res = aura_db_record_insert(
          glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_STAT_DELTA,
          user_data.job_id, 0, A_DB_OP_INSERT,
          stats_key, stats_data, A_DB_EXEC_ASYNC, &completion);

        if (res != 0) {
            aura_iovec_destroy(stats_key);
            aura_iovec_destroy(stats_data);
            goto out;
        }

        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0)
            goto out;
        /* Fall through */

    case A_FN_OP_STATE_FN_STATE:
        struct aura_fn_state fn_state;

        /* state */
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:v%u:%s", A_DB_KEY_PREFIX_FUNC, fn_name, fn_version, A_DB_SCHEMA_SUFFIX_STATE);

        struct aura_iovec *state_key, *state_data;

        state_key = aura_iovec_init(&glob_conf.mc, strlen(buf), NULL);
        if (!state_key) {
            goto out;
        }
        state_data = aura_iovec_init(&glob_conf.mc, sizeof(fn_state), NULL);
        if (!state_data) {
            aura_iovec_destroy(state_key);
            goto out;
        }

        fn_state.is_active = false;
        memcpy(state_key->base, buf, state_key->len);
        memcpy(state_data->base, &fn_state, state_data->len);

        completion.proceed = false;
        res = aura_db_record_insert(
          glob_conf.db_handle, A_DB_NS_FN, A_DB_SCHEMA_FN_STATE_V1,
          user_data.job_id, 0, A_DB_OP_INSERT,
          state_key, state_data, A_DB_EXEC_ASYNC, &completion);

        if (res != 0) {
            aura_iovec_destroy(state_key);
            aura_iovec_destroy(state_data);
            goto out;
        }

        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0)
            goto out;
        /* Fall through */

    case A_FN_OP_STATE_FN_LIST_UPDATE:
        completion.proceed = false;

        /* Insert function into function list */
        res = aura_fn_list_add(glob_conf.db_handle, &glob_conf.mc, fn_name, fn_version, job_id, &completion);
        if (res < 0) {
            evt.state = A_FN_OP_STATE_FAILED;
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.msg_len = 0;
            evt.msg[0] = '\0';

            /* Don't wait for async op */
            aura_db_job_update(glob_conf.db_handle, user_data.job_id, A_DB_JOB_FAILED, evt.error_code, 0, A_DB_EXEC_ASYNC, NULL);
            aura_send_resp(cli_fd, (void *)&evt, sizeof(evt));
            goto out;
        }

        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0) {
            goto out;
        }

    case A_FN_OP_STATE_DONE:
        completion.proceed = false;
        res = aura_db_job_update(glob_conf.db_handle, user_data.job_id, A_DB_JOB_DONE,
                                 A_FN_ERROR_NONE, 0, A_DB_EXEC_ASYNC, &completion);
        if (res != 0) {
            goto out;
        }

        aura_fn_async_op_wait(completion.proceed);
        if (completion.status != 0) {
            goto out;
        }

        evt.state = A_FN_OP_STATE_DONE;
        evt.error_code = A_FN_ERROR_NONE;
        evt.msg_len = 0;
        evt.msg[0] = '\0';
        aura_send_resp(cli_fd, (void *)&evt, sizeof(evt));
        break;
    default:
        break;
    }

    /* @todo: change the message sent, let server read new function from db */
    /* try and send to server, we ignore if server is down for now */
    a_init_msg_hdr(hdr, fn_config_size, A_MSG_CMD_EXECUTE, A_CMD_FN_DEPLOY);
    res = aura_msg_send(srv_fd, &hdr, (void *)fn_config, fn_config_size, -1);
    if (res != 0) {
        sys_debug(true, errno, "aura_dmn_function_deploy: aura_msg_send to server error");
    }

out:
    close(cli_fd);
    close(dir_fd);

    if (bytecode)
        js_free(ctx, (void *)bytecode);
    if (ctx)
        JS_FreeContext(ctx);
    if (rt)
        JS_FreeRuntime(rt);

    if (entry_script)
        free((void *)entry_script);

    if (fn_meta)
        free(fn_meta);
    if (fn_config)
        free(fn_config);

    aura_free_yml_error_ctx(parser_err);
    a_fn_free_user_data_ctx(&usr_data);
}

static int a_detect_anomaly(struct statistical_baseline *baseline, double current_value, double threshold_sigma) {
    /**/
    return 0;
}

/**
 * Most of this values will be received from the server
 * And I would be watching several functions
 */
void aura_rollback_detector_evaluate(struct aura_rollback_detector *detector) {
    int num_of_deployments = 10;
    struct aura_fn_deployment *curr;
    /**/
}