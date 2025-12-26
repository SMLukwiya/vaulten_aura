#include "aura_dmn.h"
#include "bug_lib.h"
#include "common_dmn.h"
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

int fn_conf_tab[] = {
  [A_IDX_FN_NONE] = 0,
  [A_IDX_FN_NAME] = 0,
  [A_IDX_FN_DESCRIPTION] = 0,
  [A_IDX_FN_VERSION] = 0,
  [A_IDX_FN_HOST] = 0,
  [A_IDX_FN_ENTRY_POINT] = 0,
  [A_IDX_FN_ENV] = 0,
  [A_IDX_FN_TRIGGERS] = 0,
  [A_IDX_FN_HTTP_TRIGGER] = 0,
};

/** */
static inline void *a_build_fn_config(struct aura_yml_fn_data_ctx *usr_data, void *byte_code, uint64_t bytecode_len) {
    uint32_t root_off, func_root, triggers_root;
    void *fn_config;

    /** Build function config */
    root_off = aura_blob_b_add_map(&usr_data->builder);
    /* Function */
    func_root = aura_build_blob_from_rax(usr_data->parse_tree, &usr_data->builder, usr_data->node_arr, "function", sizeof("function") - 1, &fn_stack, fn_conf_tab);
    aura_blob_b_map_add_kv(&usr_data->builder, root_off, "function", func_root);
    /* Triggers */
    triggers_root = aura_build_blob_from_rax(usr_data->parse_tree, &usr_data->builder, usr_data->node_arr, "triggers", sizeof("triggers") - 1, &fn_stack, fn_conf_tab);
    aura_blob_b_map_add_kv(&usr_data->builder, root_off, "triggers", triggers_root);

    fn_config = aura_serialize_blob(&usr_data->builder, fn_conf_tab, ARRAY_SIZE(fn_conf_tab), (void *)byte_code, bytecode_len);
    return fn_config;
}

/**
 * Create symlink to current active funtion
 */
// static int a_create_sym

/**
 * Save function with particular version
 */
int aura_save_fn(const char *fn_name, uint32_t fn_version, void *fn_config, size_t fn_config_size, int cli_fd) {
    int fd, len;
    struct aura_iovec fn_dir;
    char dir[2048];
    char fn_path[2056];
    char fn_version_str[64];
    ssize_t write_size;
    bool res;

    snprintf(fn_version_str, sizeof(fn_version_str), "v%d", fn_version);
    len = glob_conf.fn_data_path.len + strlen(fn_name) + strlen(fn_version_str) + 3;
    snprintf(dir, len, "%s/%s/%s", glob_conf.fn_data_path.base, fn_name, fn_version_str);
    fn_dir.base = dir;
    fn_dir.len = len - 1;

    res = aura_ensure_app_path(&fn_dir, S_IRWXU);
    if (res == false) {
        goto exception;
    }

    len = strlen(dir) + 4 /* strlen("main")=4 */ + 2;
    /* store function under filename=main */
    snprintf(fn_path, len, "%s/%s", dir, "main");
    app_debug(true, 0, "aura_save_fn <<<<: path value: %s", fn_path);

    fd = open(fn_path, O_WRONLY | O_SYNC | O_CREAT | O_EXCL, S_IRWXU);
    if (fd == -1) {
        if (errno == EEXIST) {
            aura_send_resp(cli_fd, (void *)file_aready_exists, sizeof(file_aready_exists) - 1);
            return -1;
        }
        return -1;
    }

    write_size = write(fd, fn_config, fn_config_size);
    if (write_size != fn_config_size) {
        unlink(fn_path);
        goto exception;
    }

    return 0;

exception:
    aura_send_resp(cli_fd, (void *)fn_deployment_failed, sizeof(fn_deployment_failed) - 1);
    return -1;
}

/** */
void aura_dmn_function_deploy(int dir_fd, int srv_fd, int cli_fd) {
    struct aura_yml_fn_data_ctx usr_data;
    struct aura_yml_err_ctx *parser_err;
    JSRuntime *rt;
    JSContext *ctx;
    bool fail_fast = true, extract = true;
    int config_fd, entry_file_fd, fn_version;
    uint64_t entry_file_len, bytecode_len, fn_config_size;
    const uint8_t *fn_name, *entry_file, *entry_script, *bytecode;
    uint32_t entry_file_node_off;
    uint32_t root_off, func_root, triggers_root;
    struct aura_msg_hdr hdr;
    const char *first_err;
    int res;

    rt = NULL;
    ctx = NULL;
    bytecode = NULL;
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
    if (res != 0) {
        /** @todo: report this error, also in server start as well */
        goto out;
    }

    if (res == 0 && parser_err->err_cnt > 0) {
        first_err = parser_err->errors[0].message;
        aura_send_resp(cli_fd, (void *)first_err, strlen(first_err));
        goto out;
    }

    entry_file_node_off = A_IDX_FN_ENTRY_POINT;
    entry_file = usr_data.node_arr[entry_file_node_off].str_val;
    /* Missing entry file */
    A_BUG_ON_2(!entry_file, true);

    entry_file_fd = openat(dir_fd, entry_file, O_RDONLY);
    /* Can't open entry file */
    A_BUG_ON_2(entry_file_fd < 0, true);

    rt = JS_NewRuntime();
    if (!rt) {
        aura_send_resp(cli_fd, (void *)fn_deployment_failed, sizeof(fn_deployment_failed) - 1);
        goto out;
    }
    ctx = JS_NewContext(rt);
    if (!ctx) {
        aura_send_resp(cli_fd, (void *)fn_deployment_failed, sizeof(fn_deployment_failed) - 1);
        goto out;
    }

    entry_script = aura_load_file(entry_file_fd, &entry_file_len);
    if (!entry_script) {
        aura_send_resp(cli_fd, (void *)entry_file_error, sizeof(entry_file_error) - 1);
        goto out;
    }

    bytecode = aura_qjs_create_bytecode(ctx, entry_script, entry_file_len, entry_file, &bytecode_len);
    app_debug(true, 0, ">>>> BYTECODE len %d", bytecode_len);
    app_debug(true, 0, "%s", bytecode);

    void *fn_config = a_build_fn_config(&usr_data, (void *)bytecode, bytecode_len);
    fn_config_size = aura_blob_get_size(fn_config);
    fn_name = usr_data.node_arr[A_IDX_FN_NAME].str_val;
    fn_version = usr_data.node_arr[A_IDX_FN_VERSION].int_val;

    res = aura_save_fn(fn_name, fn_version, fn_config, fn_config_size, cli_fd);
    if (res != 0) {
        // aura_send_resp(cli_fd, (void *)fn_deployment_failed, sizeof(fn_deployment_failed) - 1);
        goto out;
    }

    /* try and send to server, we ignore if server is down for now */
    a_init_msg_hdr(hdr, fn_config_size, A_MSG_CMD_EXECUTE, A_CMD_FN_DEPLOY);
    res = aura_msg_send(srv_fd, &hdr, (void *)fn_config, fn_config_size, -1);
    if (res != 0) {
        app_debug(true, 0, "> Failed to deploy to server");
    }
    aura_send_resp(cli_fd, (void *)fn_deploy_success, sizeof(fn_deploy_success) - 1);

out:
    close(cli_fd);
    close(dir_fd);

    if (bytecode)
        js_free(ctx, (void *)bytecode);
    if (ctx)
        JS_FreeContext(ctx);
    if (rt)
        JS_FreeRuntime(rt);

    aura_free_yml_error_ctx(parser_err);
    a_fn_free_user_data_ctx(&usr_data);
}

static int detect_anomaly(struct statistical_baseline *baseline, double current_value, double threshold_sigma) {
    /**/
    return 0;
}

/**
 * Most of this values will be received from the server
 * And I would be watching several functions
 */
void rollback_detector_evaluate(struct aura_rollback_detector *detector) {
    int num_of_deployments = 10;
    struct aura_fn_deployment *curr;
    /**/
}