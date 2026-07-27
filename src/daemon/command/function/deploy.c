#include "bug_lib.h"
#include "common_dmn.h"
#include "db/db.h"
#include "dmn.h"
#include "file/lib.h"
#include "fn/lib.h"
#include "quickjs.h"
#include "unix/sock.h"
#include "utils_lib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

JSValue aura_js_std_await(JSContext *ctx, JSValue obj) {
    JSValue rv;
    int state;
    char *result;

    for (;;) {
        state = JS_PromiseState(ctx, obj);
        if (state == JS_PROMISE_FULFILLED) {
            rv = JS_PromiseResult(ctx, obj);
            JS_FreeValue(ctx, obj);
            result = "PROMISE DONE";
            break;
        } else if (state == JS_PROMISE_REJECTED) {
            result = "PROMISE REJECTED";
            rv = JS_Throw(ctx, JS_PromiseResult(ctx, obj));
            JS_FreeValue(ctx, obj);
            break;
        } else if (state == JS_PROMISE_PENDING) {
            int err;
            err = JS_ExecutePendingJob(JS_GetRuntime(ctx), NULL);
            if (err < 0) {
                result = "PENDING DUMP";
            } else if (err == 0) {
                result = "NOTHING DUMP";
            }
        } else {
            result = "NOT A PROMISE";
            rv = obj;
            break;
        }
    }
    app_debug(true, 0, "%s", result);
    return rv;
}

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
    func_off = aura_build_blob_from_rax(
      usr_data->parse_tree,
      &b,
      usr_data->node_vec.entries,
      "function",
      sizeof("function") - 1,
      &fn_stack,
      _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "function", func_off);

    /* Triggers */
    triggers_off = aura_build_blob_from_rax(
      usr_data->parse_tree,
      &b,
      usr_data->node_vec.entries,
      "triggers",
      sizeof("triggers") - 1,
      &fn_stack,
      _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "triggers", triggers_off);

    /* Resources */
    resources_off = aura_build_blob_from_rax(
      usr_data->parse_tree,
      &b,
      usr_data->node_vec.entries,
      "resources",
      sizeof("resources") - 1,
      &fn_stack,
      _fn_conf_tab);
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
    env_off = aura_build_blob_from_rax(
      usr_data->parse_tree,
      &b,
      usr_data->node_vec.entries,
      "env",
      sizeof("env") - 1,
      &fn_stack,
      _fn_conf_tab);
    aura_blob_b_map_add_kv(&b, root_off, "env", env_off);

    /* Concurrency */
    concurrency_off = aura_build_blob_from_rax(
      usr_data->parse_tree,
      &b,
      usr_data->node_vec.entries,
      "concurrency",
      sizeof("concurrency") - 1,
      &fn_stack,
      _fn_conf_tab);
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

static void a_fn_name_get(void *fn_meta, char *fn_name) {
    const st_aura_blob_node *nodes, *node;
    const char *strtab, *name;
    const int *fn_tab;

    nodes = aura_blob_get_nodes(fn_meta);
    strtab = aura_blob_get_strtab(fn_meta);
    fn_tab = aura_blob_get_tab(fn_meta);

    if (fn_tab[A_IDX_FN_NAME] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_NAME]];
        memcpy(fn_name, strtab + node->str_offset, strlen(strtab + node->str_offset));
    }
}

static void a_fn_version_get(void *fn_meta, char *fn_version) {
    const st_aura_blob_node *nodes, *node;
    const char *strtab;
    const int *fn_tab;

    nodes = aura_blob_get_nodes(fn_meta);
    strtab = aura_blob_get_strtab(fn_meta);
    fn_tab = aura_blob_get_tab(fn_meta);

    if (fn_tab[A_IDX_FN_VERSION] != 0) {
        node = &nodes[fn_tab[A_IDX_FN_VERSION]];
        memcpy(fn_version, strtab + node->str_offset, strlen(strtab + node->str_offset));
    }
}

/** */
void aura_dmn_deploy_fn(int dir_fd, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    struct aura_yml_fn_data_ctx usr_data;
    struct aura_yml_err_ctx *parser_err;
    JSRuntime *rt;
    JSContext *ctx;
    bool fail_fast = true, extract = true;
    int config_fd, entry_file_fd;
    uint64_t entry_file_len;
    const uint8_t *entry_file, *entry_script;
    uint32_t root_off, func_root, triggers_root;
    struct aura_msg_hdr hdr;
    struct aura_fn_evt evt;
    char buf[2000];
    int res, srv_fd = gc->server_fd;
    int state;

    void *bytecode, *fn_meta, *fn_config;
    uint64_t bytecode_len, fn_meta_size, fn_config_size;
    struct aura_iovec key, data;

    char fn_name[A_FN_NAME_MAX_LEN], fn_version[A_FN_VERSION_MAX_LEN];

    rt = NULL;  /* Runtime */
    ctx = NULL; /* Runtime context */
    bytecode = NULL;
    fn_meta = NULL;
    fn_config = NULL;
    entry_script = NULL;
    memset(fn_name, 0, sizeof(fn_name));
    memset(fn_version, 0, sizeof(fn_version));

    state = A_FN_OP_STATE_RUNNING;
    switch (state) {
    case A_FN_OP_STATE_RUNNING:
        size_t msg_len;
        const char *msg;
        int error;

        /* Parse config */
        config_fd = openat(dir_fd, "function.yaml", O_RDONLY);
        if (config_fd < 0) {
            config_fd = openat(dir_fd, "function.yml", O_RDONLY);
            /**
             * Missing fn config file
             * Config validation must have caught this by now.
             */
            A_BUG_ON_2(config_fd < 0, true);
        }

        /* Initialize config parser error context and user data */
        parser_err = aura_create_yml_error_ctx(fail_fast);
        a_fn_init_user_data_ctx(&usr_data, extract, dir_fd);

        /* Run config parsing */
        res = aura_load_config_fd(
          config_fd,
          aura_function_validator,
          aura_function_validator_len,
          parser_err,
          (void *)&usr_data);

        /* No longer needed */
        close(config_fd);
        msg_len = 0;
        msg = NULL;
        if (res != 0) {
            error = A_FN_ERROR_CONFIG;
            goto err;
        }

        /**
         * If we got validation error due to incorrect
         * config values, report that error back to the
         * caller.
         */
        if (res == 0 && parser_err->err_cnt > 0) {
            msg = parser_err->errors[0].message;
            msg_len = strlen(msg);
            error = A_FN_ERROR_CONFIG;
            goto err;
        }

        struct aura_fn_meta _fn_meta;
        struct aura_fn_config _fn_config;

        /* Build function metadata and verify it's correctness */
        fn_meta = a_build_fn_meta(&usr_data);
        fn_meta_size = aura_blob_get_size(fn_meta);
        if (aura_fn_meta_parse(fn_meta, &_fn_meta) != 0) {
            error = A_FN_ERROR_CONFIG;
            goto err;
        }
        aura_fn_meta_destroy(&_fn_meta);

        /* Build function config data and verify it's correctness */
        fn_config = a_build_fn_config(&usr_data);
        fn_config_size = aura_blob_get_size(fn_config);
        if (aura_fn_config_parse(fn_config, &_fn_config) != 0) {
            error = A_FN_ERROR_CONFIG;
            goto err;
        }
        aura_fn_config_destroy(&_fn_config);

        entry_file = a_get_entry_file(fn_meta);
        /* Validation must have caught this earlier */
        A_BUG_ON_2(!entry_file, true);

        entry_file_fd = openat(dir_fd, entry_file, O_RDONLY);
        /* Validation must have caught this earlier */
        A_BUG_ON_2(entry_file_fd < 0, true);

        /**
         * Create quickjs environment.
         * This is used to verify function syntax
         * and structure.
         */
        rt = JS_NewRuntime();
        if (!rt) {
            error = A_FN_ERROR_CONFIG;
            goto err;
        }
        ctx = JS_NewContext(rt);
        if (!ctx) {
            error = A_FN_ERROR_CONFIG;
            goto err;
        }

        /* Load function script */
        entry_script = aura_load_file(entry_file_fd, &entry_file_len);
        /* close fd, no longer useful */
        close(entry_file_fd);
        if (!entry_script) {
            error = A_FN_ERROR_CONFIG;
            msg_len = sizeof(entry_file_error) - 1;
            msg = (char *)entry_file_error;
            goto err;
        }

        JSValue obj = JS_Eval(
          ctx,
          entry_script,
          entry_file_len,
          entry_file,
          JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        JSValue exception, js_msg;
        const char *js_msg_str;
        if (JS_IsException(obj)) {
            JS_FreeValue(ctx, obj);
            exception = JS_GetException(ctx);
            js_msg = JS_GetPropertyStr(ctx, exception, "message");
            js_msg_str = JS_ToCString(ctx, js_msg);
            app_debug(true, 0, "aura_dmn_deploy_fn: JS_Eval error %s", js_msg_str);
            error = A_FN_ERROR_FN_CODE;
            goto err;
        }

        bytecode = JS_WriteObject(ctx, &bytecode_len, obj, JS_WRITE_OBJ_BYTECODE);
        JS_FreeValue(ctx, obj);
        if (!bytecode) {
            sys_debug(true, errno, "aura_dmn_deploy_fn: JS_WriteObject error:");
            error = A_FN_ERROR_GENERIC;
            goto err;
        }

        obj = JS_ReadObject(ctx, bytecode, bytecode_len, JS_READ_OBJ_BYTECODE);
        if (JS_IsException(obj)) {
            exception = JS_GetException(ctx);
            js_msg = JS_GetPropertyStr(ctx, exception, "message");
            js_msg_str = JS_ToCString(ctx, js_msg);
            app_debug(true, 0, "aura_dmn_deploy_fn: JS_ReadObject error %s", js_msg_str);
            error = A_FN_ERROR_GENERIC;
            goto err;
        }

        if (JS_VALUE_GET_TAG(obj) == JS_TAG_MODULE)
            if (JS_ResolveModule(ctx, obj) < 0) {
                JS_FreeValue(ctx, obj);
                app_debug(true, 0, "aura_dmn_deploy_fn: JS_ResolveModule error");
                error = A_FN_ERROR_GENERIC;
                goto err;
            }

        /* Verify we have a valid function structure */
        JSValue module = JS_EvalFunction(ctx, obj);
        if (JS_IsException(module)) {
            JS_FreeValue(ctx, obj);
            exception = JS_GetException(ctx);
            js_msg = JS_GetPropertyStr(ctx, exception, "message");
            js_msg_str = JS_ToCString(ctx, js_msg);
            app_debug(true, 0, "aura_dmn_deploy_fn: JS_EvalFunction error: %s", js_msg_str);
            error = A_FN_ERROR_GENERIC;
            goto err;
        }

        module = aura_js_std_await(ctx, module);
        if (JS_IsException(module)) {
            JS_FreeValue(ctx, obj);
            exception = JS_GetException(ctx);
            js_msg = JS_GetPropertyStr(ctx, exception, "message");
            js_msg_str = JS_ToCString(ctx, js_msg);
            app_debug(true, 0, "aura_dmn_deploy_fn: aura_js_std_await error: %s", js_msg_str);
            error = A_FN_ERROR_GENERIC;
            goto err;
        }
        JS_FreeValue(ctx, module);

        JSModuleDef *m = JS_VALUE_GET_PTR(obj);
        JSValue val = JS_GetModuleNamespace(ctx, m);
        JSValue handler = JS_GetPropertyStr(ctx, val, "default");
        JS_FreeValue(ctx, obj);
        JS_FreeValue(ctx, val);

        if (!JS_IsFunction(ctx, handler)) {
            JS_FreeValue(ctx, handler);
            error = A_FN_ERROR_GENERIC;
            js_msg_str = "export default must be of type function";
            msg = js_msg_str;
            msg_len = strlen(js_msg_str);
            goto err;
        }
        JS_FreeValue(ctx, handler);

        app_debug(true, 0, "Proceeding to deploy bytecode: %p -> %lu", bytecode, bytecode_len);
        goto proceed;

    err:
        evt.state = A_FN_OP_STATE_FAILED;
        evt.error_code = error;
        evt.msg_len = msg_len;
        memset(evt.msg, 0, sizeof(evt.msg));
        if (msg_len > 0)
            memcpy(evt.msg, msg, sizeof(evt.msg));

        aura_resp_send(cli_fd, (void *)&evt, sizeof(evt));
        goto out;

    proceed:
        state = A_FN_OP_STATE_TAG;
        /* Fall through */

    case A_FN_OP_STATE_TAG:
        struct aura_fn_tag *fn_tag;

        a_fn_name_get(fn_meta, fn_name);
        a_fn_version_get(fn_meta, fn_version);

        /* Check if we have duplicate */
        fn_tag = aura_fn_tag_fetch(gc->db_handle, &gc->mc, fn_name, fn_version, &error);
        if (fn_tag) {
            /* Record no longer needed */
            aura_free(fn_tag);
            evt.state = A_FN_OP_STATE_FAILED;
            evt.error_code = A_FN_ERROR_DUPLICATE;
            evt.msg_len = 0;
            evt.msg[0] = '\0';

            aura_resp_send(cli_fd, (void *)&evt, sizeof(evt));
            goto out;
        }

        if (!fn_tag) {
            if (error < 0) {
                evt.state = A_FN_OP_STATE_FAILED;
                evt.error_code = A_FN_ERROR_GENERIC;
                evt.msg_len = 0;

                aura_resp_send(cli_fd, &evt, sizeof(evt));
                goto out;
            }
        }

        /* Start transaction to create function */
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

        /* format: fn:<name>:<version>:<schema_suffix> */
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_META_SUFFIX);
        struct aura_iovec meta_key, meta_data;

        meta_key.base = buf;
        meta_key.len = strlen(buf);
        meta_data.base = fn_meta;
        meta_data.len = fn_meta_size;

        if (aura_db_insert(
              gc->db_handle,
              A_DB_NS_FN,
              A_DB_FN_META_SCHEMA_ID,
              0,
              A_DB_INSERT_OP,
              &meta_key,
              &meta_data) < 0)
            goto err_out;

        state = A_FN_OP_STATE_CONFIG;
        /* Fall through */

    case A_FN_OP_STATE_CONFIG:
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_CONF_SUFFIX);

        struct aura_iovec conf_key, conf_data;
        conf_key.base = buf;
        conf_key.len = strlen(buf);
        conf_data.base = fn_config;
        conf_data.len = fn_config_size;

        if (aura_db_insert(
              gc->db_handle,
              A_DB_NS_FN,
              A_DB_FN_CONF_SCHEMA_ID,
              0,
              A_DB_INSERT_OP,
              &conf_key,
              &conf_data) != 0)
            goto err_out;

        state = A_FN_OP_STATE_CODE;
        /* Fall through */

    case A_FN_OP_STATE_CODE:
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_CODE_SUFFIX);

        struct aura_iovec code_key, code_data;
        code_key.base = buf;
        code_key.len = strlen(buf);
        code_data.base = bytecode;
        code_data.len = bytecode_len;

        if (aura_db_insert(
              gc->db_handle,
              A_DB_NS_FN,
              A_DB_FN_CODE_SCHEMA_ID,
              0,
              A_DB_INSERT_OP,
              &code_key,
              &code_data) < 0)
            goto err_out;

        state = A_FN_OP_STATE_STAT;
        /* Fall through */

    case A_FN_OP_STATE_STAT:
        struct aura_fn_stat stat;

        /* stats */
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_STAT_SUFFIX);

        struct aura_iovec stat_key, stat_data;

        stat_key.base = buf;
        stat_key.len = strlen(buf);
        memset(&stat, 0, sizeof(stat));
        stat_data.base = (char *)&stat;
        stat_data.len = sizeof(stat);

        if (aura_db_insert(
              gc->db_handle,
              A_DB_NS_FN,
              A_DB_FN_STAT_DELTA_SCHEMA_ID,
              0,
              A_DB_INSERT_OP,
              &stat_key,
              &stat_data) != 0)
            goto err_out;

        state = A_FN_OP_STATE_FN_STATE;
        /* Fall through */

    case A_FN_OP_STATE_FN_STATE:
        struct aura_fn_state fn_state;

        /* state */
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s", A_DB_FN_KEY_PREFIX, fn_name, fn_version, A_DB_FN_STATE_SUFFIX);

        struct aura_iovec fn_state_key, fn_state_data;

        fn_state.is_active = false;
        fn_state_key.base = buf;
        fn_state_key.len = strlen(buf);
        fn_state_data.base = (char *)&fn_state;
        fn_state_data.len = sizeof(fn_state);

        if (aura_db_insert(
              gc->db_handle,
              A_DB_NS_FN,
              A_DB_FN_STATE_SCHEMA_ID,
              0,
              A_DB_INSERT_OP,
              &fn_state_key,
              &fn_state_data) != 0)
            goto err_out;

        state = A_FN_OP_STATE_FN_LIST_UPDATE;
        /* Fall through */

    case A_FN_OP_STATE_FN_LIST_UPDATE:
        /* Insert function into function list */
        if (aura_fn_list_add_fn(gc->db_handle, &gc->mc, fn_name, fn_version) < 0) {
            evt.state = A_FN_OP_STATE_FAILED;
            evt.error_code = A_FN_ERROR_GENERIC;
            evt.msg_len = 0;
            evt.msg[0] = '\0';

            goto err_out;
        }

        state = A_FN_OP_STATE_DONE;
        /* Fall through */

    case A_FN_OP_STATE_DONE:
        if (aura_db_transaction_commit(gc->db_handle) < 0)
            goto err_out;

        evt.state = A_FN_OP_STATE_DONE;
        evt.error_code = A_FN_ERROR_NONE;
        evt.msg_len = 0;
        evt.msg[0] = '\0';
        aura_resp_send(cli_fd, (void *)&evt, sizeof(evt));
        goto out;

        break;

    default:
        break;
    }

err_out:
    aura_db_transaction_cancel(gc->db_handle);
    aura_resp_send(cli_fd, (void *)&evt, sizeof(evt));

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
