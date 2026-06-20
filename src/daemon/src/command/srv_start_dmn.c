#include "aura_dmn.h"
#include "command/server_dmn.h"
#include "common_dmn.h"
#include "error_lib.h"
#include "utils_lib.h"

#include <sys/wait.h>

/*********************** */
char server_started[] = "\x1B[1;32mServer started\x1B[0m";
char server_start_failed[] = "\x1B[1;32mFailed to start server\x1B[0m";
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
  [A_IDX_SERVER_NONE] = 0,
  [A_IDX_SERVER_NAME] = 0,
  [A_IDX_SERVER_READ_TO] = 0,     // read timeout
  [A_IDX_SERVER_WRITE_TO] = 0,    // write timeout
  [A_IDX_SERVER_LISTENERS] = 0,   // socket listeners
  [A_IDX_SERVER_TLS_IDEN] = 0,    // tls identities
  [A_IDX_SERVER_TLS_CIPHERS] = 0, // tls ciphers
  [A_IDX_SERVER_HOSTS] = 0,       // hosts
};

struct aura_builder_stack srv_stack;

/**
 *
 */
int aura_dmn_server_start(struct aura_msg *msg, int cli_fd, void *_conf) {
    struct aura_dmn_glob_conf *conf = _conf;
    struct aura_yml_err_ctx *parser_err;
    struct aura_yml_usr_data_ctx usr_data;
    char *first_err = NULL;
    struct aura_msg_hdr hdr;
    bool fail_fast = true, extract = true;
    uint32_t root_off, server_root, listener_root, tls_root, host_root, config_size;
    pid_t pid;
    void *blob;
    int res, ret_val, sock_fds[2];

    parser_err = aura_create_yml_error_ctx(fail_fast);

    a_srv_init_user_data_ctx(&usr_data, extract);

    res = aura_load_config_fd(
      msg->fd,
      aura_server_validator,
      aura_server_validator_len,
      parser_err,
      (void *)&usr_data);
    close(msg->fd);
    if (res != 0) {
        goto err;
    }

    if (res == 0 && parser_err->err_cnt > 0) {
        first_err = parser_err->errors[0].message;
        aura_resp_send(cli_fd, (void *)first_err, strlen(first_err));
        ret_val = -1;
        goto out;
    }

    /**
     * Build config blob
     */
    root_off = aura_blob_b_add_map(&usr_data.builder);
    /* Server */
    server_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_arr,
      "server",
      sizeof("server") - 1,
      &srv_stack,
      srv_conf_tab);

    /* listeners */
    listener_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_arr,
      "listeners",
      sizeof("listeners") - 1,
      &srv_stack,
      srv_conf_tab);

    /* tls */
    tls_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_arr,
      "tls",
      sizeof("tls") - 1,
      &srv_stack,
      srv_conf_tab);

    /* Host */
    host_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_arr,
      "hosts",
      sizeof("hosts") - 1,
      &srv_stack,
      srv_conf_tab);

    aura_blob_b_map_add_kv(&usr_data.builder, root_off, "server", server_root);
    aura_blob_b_map_add_kv(&usr_data.builder, root_off, "listeners", listener_root);
    aura_blob_b_map_add_kv(&usr_data.builder, root_off, "tls", tls_root);
    aura_blob_b_map_add_kv(&usr_data.builder, root_off, "hosts", host_root);

    void *config = aura_serialize_blob(&usr_data.builder, srv_conf_tab, ARRAY_SIZE(srv_conf_tab), NULL, 0);
    config_size = aura_blob_get_size(config);

    /**
     * Setup wait par_ch pipe
     */
    res = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds);
    if (res < 0)
        sys_exit(true, errno, "aura_dmn_server_start: socketpair error;");

    aura_clear_fd_flag(sock_fds[0], SOCK_CLOEXEC);
    aura_clear_fd_flag(sock_fds[1], SOCK_CLOEXEC);

    res = aura_setup_wait();
    // check if server already running using its pid
    pid = fork();
    if (pid < 0) {
        close(sock_fds[0]);
        close(sock_fds[1]);
        sys_alert(true, errno, "aura_dmn_server_start: fork error:");
        goto err;
    }

    if (pid == 0) {
        char fd_str[16];
        close(sock_fds[0]);

        snprintf(fd_str, sizeof(fd_str), "%d", sock_fds[1]);
        /* wait for daemon to set things up */
        res = aura_child_wait();
        if (res == -1)
            sys_exit(true, errno, "aura_dmn_server_start: aura_child_wait error:");
        execlp("aura_server", "aura_server", fd_str, (char *)0);
        sys_alert(true, errno, "aura_dmn_server_start: Error starting server");
        close(sock_fds[1]);
        goto err;
    } else {
        /* callback to register fds[0] with poll */
        close(sock_fds[1]);
        conf->poll_fds[A_SOCK_PAIR_FD_IDX].fd = sock_fds[0];
        conf->poll_fds[A_SOCK_PAIR_FD_IDX].events = POLLIN;
        conf->poll_fds[A_SOCK_PAIR_FD_IDX].revents = 0;
        conf->server_pid = pid;

        // p->cb(sock_fds[0], pid);

        a_init_msg_hdr(hdr, config_size, A_MSG_CONF_DATA, 0);
        res = aura_msg_send(sock_fds[0], &hdr, config, config_size, -1);
        if (res != 0) {
            close(sock_fds[0]);
            sys_debug(true, errno, "aura_dmn_server_start: send config error:");
            goto err;
        }
        /* tell server things are set */
        res = aura_child_proceed(pid);
        if (res == -1) {
            sys_debug(true, errno, "aura_dmn_server_start: aura_child_proceed error:");
            close(sock_fds[0]);
            goto err;
        }

        struct aura_msg res_msg;
        if (aura_msg_recv(sock_fds[0], &res_msg) <= 0) {
            close(sock_fds[0]);
            goto err;
        }
        if (res_msg.hdr.type != A_MSG_PING) {
            app_debug(true, 0, "aura_dmn_server_start: Incorrect msg hdr type: %d", res_msg.hdr.type);
            close(sock_fds[0]);
            goto err;
        }

        res = aura_resp_send(cli_fd, (void *)server_started, sizeof(server_started) - 1);
        ret_val = 0;
        goto out;
    }
err:
    res = aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
    ret_val = -1;
out:
    close(cli_fd);
    aura_free_yml_error_ctx(parser_err);
    a_srv_free_user_data_ctx(&usr_data);
    return ret_val;
}

/**
 *
 */
int aura_dmn_server_stop(struct aura_msg *msg, int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    struct aura_msg_hdr hdr;
    int rv;

    if (gc->server_pid == 0) {
        rv = aura_resp_send(cli_fd, (void *)server_down, sizeof(server_down) - 1);
        close(cli_fd);
        return 0;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SERVER_STOP);
    int srv_fd = gc->poll_fds[A_SOCK_PAIR_FD_IDX].fd;
    if (aura_msg_send(srv_fd, &hdr, NULL, 0, -1) != 0) {
        rv = aura_resp_send(cli_fd, (void *)server_stopped_failed, sizeof(server_stopped_failed) - 1);
        close(cli_fd);
        return -1;
    }

    /* close and reset server socket */
    close(srv_fd);
    gc->poll_fds[A_SOCK_PAIR_FD_IDX].fd = -1;
    gc->server_pid = 0;

    /* respond to cli */
    rv = aura_resp_send(cli_fd, (void *)server_stopped, sizeof(server_stopped) - 1);
    close(cli_fd);
    return 0;
}

/**
 *
 */
int aura_dmn_server_status(int cli_fd, void *arg) {
    struct aura_dmn_glob_conf *gc = arg;
    struct aura_msg_hdr hdr;
    struct aura_msg res_msg;
    int rv, srv_fd;

    srv_fd = gc->poll_fds[A_SOCK_PAIR_FD_IDX].fd;
    a_init_msg_hdr(hdr, 0, A_MSG_PING, 0);

    if (aura_msg_send(srv_fd, &hdr, NULL, 0, -1) < 0) {
        sys_debug(true, errno, "aura_dmn_server_status: aura_msg_send error:");
        goto out;
    }

    if (aura_msg_recv(srv_fd, &res_msg) < 0) {
        sys_debug(true, errno, "aura_dmn_server_status: aura_msg_recv error:");
        goto out;
    }

    hdr = res_msg.hdr;
    if (hdr.type != A_MSG_PING) {
        app_debug(true, 0, "aura_dmn_server_status: Incorrect msg hdr type: %d!", hdr.type);
        goto out;
    }

    rv = aura_resp_send(cli_fd, server_up, sizeof(server_up) - 1);
    close(cli_fd);
    return 0;
out:
    rv = aura_resp_send(cli_fd, server_down, sizeof(server_down) - 1);
    close(cli_fd);
    return -1;
}