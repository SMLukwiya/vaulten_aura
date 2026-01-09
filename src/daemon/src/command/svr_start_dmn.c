#include "command/server_dmn.h"
#include "common_dmn.h"
#include "error_lib.h"
#include "utils_lib.h"

#include <sys/wait.h>

/*********************** */
char server_started[] = "\x1B[1;32mServer started\x1B[0m";
char server_stopped[] = "\x1B[1;32mServer stopped\x1B[0m";
char server_stopped_failed[] = "\x1B[1;32mServer stop failed\x1B[0m";
char server_up[] = "\x1B[1;32mServer up\x1B[0m";
char server_down[] = "\x1B[1;31mServer down\x1B[0m";

/**
 * Defined in validator c file
 */
extern struct aura_yml_validator aura_server_validator[];
extern void a_srv_init_user_data_ctx(struct aura_yml_usr_data_ctx *usr_data, bool extract);
extern void a_srv_free_user_data_ctx(struct aura_yml_usr_data_ctx *usr_data);
extern int aura_server_validator_len;

/**
 * table for O(1) access when reading configs.
 * Using  0 is safe because node at index 0
 * is the root node.
 */
int srv_conf_tab[] = {
  [A_IDX_SERVER_NAME] = 0,
  [A_IDX_SERVER_PORT] = 0,
  [A_IDX_SERVER_ADDR] = 0,
  [A_IDX_SERVER_TO_READ] = 0,
  [A_IDX_SERVER_TO_WRITE] = 0,
  [A_IDX_TLS_IDEN] = 0,
  [A_IDX_TLS_CIPHERS] = 0,
  [A_IDX_HOSTS] = 0,
};

struct aura_builder_stack srv_stack;

/**
 *
 */
int aura_dmn_start_server(struct aura_msg *msg, int cli_fd, struct srv_start_arg *p) {
    struct aura_yml_err_ctx *parser_err;
    struct aura_yml_usr_data_ctx usr_data;
    char *first_err = NULL;
    struct aura_msg_hdr hdr;
    bool fail_fast = true, extract = true;
    uint32_t root_off, server_root, tls_root, host_root, config_size;
    pid_t pid;
    void *blob;
    int res, sock_fds[2];

    parser_err = aura_create_yml_error_ctx(fail_fast);

    a_srv_init_user_data_ctx(&usr_data, extract);

    res = aura_load_config_fd(msg->fd, aura_server_validator, aura_server_validator_len, parser_err, (void *)&usr_data);
    if (res != 0) {
        goto out;
    }

    if (res == 0 && parser_err->err_cnt > 0) {
        first_err = parser_err->errors[0].message;
        aura_send_resp(cli_fd, (void *)first_err, strlen(first_err));
        goto out;
    }

    /**
     * Build config blob
     */
    root_off = aura_blob_b_add_map(&usr_data.builder);
    /* Server */
    server_root = aura_build_blob_from_rax(usr_data.parse_tree, &usr_data.builder, usr_data.node_arr, "server", sizeof("server") - 1, &srv_stack, srv_conf_tab);
    /* Tls */
    tls_root = aura_build_blob_from_rax(usr_data.parse_tree, &usr_data.builder, usr_data.node_arr, "tls", sizeof("tls") - 1, &srv_stack, srv_conf_tab);
    /* Host */
    host_root = aura_build_blob_from_rax(usr_data.parse_tree, &usr_data.builder, usr_data.node_arr, "hosts", sizeof("hosts") - 1, &srv_stack, srv_conf_tab);

    aura_blob_b_map_add_kv(&usr_data.builder, root_off, "server", server_root);
    aura_blob_b_map_add_kv(&usr_data.builder, root_off, "tls", tls_root);
    aura_blob_b_map_add_kv(&usr_data.builder, root_off, "hosts", host_root);

    void *config = aura_serialize_blob(&usr_data.builder, srv_conf_tab, ARRAY_SIZE(srv_conf_tab), NULL, 0);
    config_size = aura_blob_get_size(config);

    /**
     * Setup wait par_ch pipe
     */
    res = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds);
    if (res < 0)
        sys_exit(true, errno, "Failed to setup server socket");

    aura_clear_fd_flag(sock_fds[0], SOCK_CLOEXEC);
    aura_clear_fd_flag(sock_fds[1], SOCK_CLOEXEC);

    res = aura_setup_wait();
    // check if server already running using its pid
    pid = fork();
    if (pid < 0) {
        sys_alert(true, errno, "Error starting server");
        goto out;
    }

    if (pid == 0) {
        char fd_str[16];
        close(sock_fds[0]);

        snprintf(fd_str, sizeof(fd_str), "%d", sock_fds[1]);
        /* wait for daemon to set things up */
        res = aura_child_wait();
        if (res == -1)
            sys_exit(true, errno, "Server start failed");
        execlp("aura_server", "aura_server", fd_str, (char *)0);
        sys_alert(true, errno, "Error starting server");
    } else {
        /* callback to register fds[0] with poll */
        close(sock_fds[1]);
        p->cb(sock_fds[0], pid);

        a_init_msg_hdr(hdr, config_size, A_MSG_CONF_DATA, 0);
        res = aura_msg_send(sock_fds[0], &hdr, config, config_size, -1);
        /* alert server things are set */
        res = aura_child_proceed(pid);
        if (res == -1)
            app_alert(true, errno, "Server start failed");

        struct aura_msg res_msg;
        res = aura_recv_msg(sock_fds[0], &res_msg);
        if (res_msg.hdr.type != A_MSG_PING) {
            app_debug(true, 0, "Incorrect message format, something weird going on");
            goto out;
        }

        res = aura_send_resp(cli_fd, (void *)server_started, sizeof(server_started) - 1);
        return 0;
    }
out:
    close(cli_fd);
    close(sock_fds[0]);
    close(sock_fds[1]);
    close(msg->fd);
    aura_free_yml_error_ctx(parser_err);
    a_srv_free_user_data_ctx(&usr_data);
    return 1;
}

/**
 *
 */
int aura_dmn_stop_server(struct aura_msg *msg, int sock_fd, int cli_fd, pid_t srv_pid) {
    struct aura_msg_hdr hdr;
    int res, status;
    pid_t pid;
    void *data;

    if (srv_pid == 0) {
        /** @todo: create correct message to return */
        res = aura_send_resp(cli_fd, (void *)server_stopped, sizeof(server_stopped) - 1);
        close(cli_fd);
        return 0;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STOP);
    res = aura_msg_send(sock_fd, &hdr, NULL, 0, -1);
    if (res != 0) {
        app_debug(true, 0, "aura_dmn_stop_server: aura_msg_send error");
        res = aura_send_resp(cli_fd, (void *)server_stopped_failed, sizeof(server_stopped_failed) - 1);
        return 1;
    }

    pid = waitpid(srv_pid, &status, 0);
    if (pid < 0) {
        sys_debug(true, errno, "aura_dmn_stop_server: waitpid error:");
        res = aura_send_resp(cli_fd, (void *)server_stopped_failed, sizeof(server_stopped_failed) - 1);
        return 1;
    }

    res = aura_send_resp(cli_fd, (void *)server_stopped, sizeof(server_stopped) - 1);
    return 0;
}

/**
 *
 */
int aura_dmn_server_status(int srv_fd, int cli_fd) {
    int res;
    struct aura_msg_hdr hdr;
    struct aura_msg res_msg;

    a_init_msg_hdr(hdr, 0, A_MSG_PING, 0);
    res = aura_msg_send(srv_fd, &hdr, NULL, 0, -1);
    if (res != 0) {
        sys_debug(true, errno, "server down");
        goto out;
    }

    res = aura_recv_msg(srv_fd, &res_msg);
    if (res != 1) {
        app_debug(true, errno, "aura_dmn_server_status() failed");
        goto out;
    }

    hdr = res_msg.hdr;
    if (hdr.type != A_MSG_PING) {
        app_debug(true, 0, "Incorrect status format, some weird ass stuff going on!");
        goto out;
    }

    aura_send_resp(cli_fd, server_up, sizeof(server_up) - 1);
    close(cli_fd);
    return 0;
out:
    aura_send_resp(cli_fd, server_down, sizeof(server_down) - 1);
    close(cli_fd);
    return 1;
}