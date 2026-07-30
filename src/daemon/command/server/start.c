#include "command/server.h"
#include "common_dmn.h"
#include "db_broker.h"
#include "dmn.h"
#include "error_lib.h"
#include "ipc/wait.h"
#include "utils_lib.h"

/**
 * Defined in validator c file
 */
extern struct aura_yml_validator aura_server_validator[];
extern void aura_srv_init_user_data_ctx(struct aura_yml_usr_data_ctx *usr_data, bool extract);
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

int aura_dmn_start_server(struct aura_msg *msg, int cli_fd, void *_conf) {
    struct aura_dmn_glob_conf *gc = _conf;
    struct aura_yml_err_ctx *parser_err;
    struct aura_yml_usr_data_ctx usr_data;
    char *first_err = NULL;
    struct aura_msg_hdr hdr;
    bool fail_fast = true, extract = true;
    bool parent_sock_closed = false;
    uint32_t root_off, server_root, listener_root, tls_root, host_root, config_size;
    int res, ret_val, sock_fds[2];
    pid_t pid;
    void *blob;

    parser_err = aura_create_yml_error_ctx(fail_fast);

    aura_srv_init_user_data_ctx(&usr_data, extract);

    /* Load server config */
    res = aura_load_config_fd(
      msg->fd,
      aura_server_validator,
      aura_server_validator_len,
      parser_err,
      (void *)&usr_data);

    close(msg->fd);
    if (res != 0) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);

        ret_val = -1;
        goto out;
    }

    /* Check for config errors */
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
    if (root_off == UINT32_MAX) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    /* Server */
    server_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_vec.entries,
      "server",
      sizeof("server") - 1,
      &srv_stack,
      srv_conf_tab);
    if (server_root == A_RAX_NIL_OFFSET) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    /* listeners */
    listener_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_vec.entries,
      "listeners",
      sizeof("listeners") - 1,
      &srv_stack,
      srv_conf_tab);
    if (listener_root == A_RAX_NIL_OFFSET) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    /* tls */
    tls_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_vec.entries,
      "tls",
      sizeof("tls") - 1,
      &srv_stack,
      srv_conf_tab);
    if (tls_root == A_RAX_NIL_OFFSET) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    /* Host */
    host_root = aura_build_blob_from_rax(
      usr_data.parse_tree,
      &usr_data.builder,
      usr_data.node_vec.entries,
      "hosts",
      sizeof("hosts") - 1,
      &srv_stack,
      srv_conf_tab);
    if (host_root == A_RAX_NIL_OFFSET) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    if (aura_blob_b_map_add_kv(&usr_data.builder, root_off, "server", server_root) == UINT32_MAX) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    if (aura_blob_b_map_add_kv(&usr_data.builder, root_off, "listeners", listener_root) == UINT32_MAX) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    if (aura_blob_b_map_add_kv(&usr_data.builder, root_off, "tls", tls_root) == UINT32_MAX) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    if (aura_blob_b_map_add_kv(&usr_data.builder, root_off, "hosts", host_root) == UINT32_MAX) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    void *config = aura_serialize_blob(&usr_data.builder, srv_conf_tab, ARRAY_SIZE(srv_conf_tab), NULL, 0);
    if (!config) {
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);
        ret_val = -1;
        goto out;
    }

    config_size = aura_blob_get_size(config);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) < 0) {
        sys_debug(true, errno, "aura_dmn_start_server: socketpair error;");
        aura_resp_send(cli_fd, (void *)server_start_failed, sizeof(server_start_failed) - 1);

        free(config);
        ret_val = -1;
        goto out;
    }

    aura_clear_fd_flag(sock_fds[0], SOCK_CLOEXEC);
    aura_clear_fd_flag(sock_fds[1], SOCK_CLOEXEC);

    /**
     * Setup interprocess wait
     */
    if (aura_setup_ipc_wait() < 0) {
        sys_debug(true, errno, "aura_dmn_start_server: ipc wait");
        ret_val = -1;
        goto err_socket_pair;
    }

    pid = fork();
    if (pid < 0) {
        sys_debug(true, errno, "aura_dmn_start_server: fork error:");
        ret_val = -1;
        goto err_ipc_wait;
    }

    if (pid == 0) {
        /* server */
        char fd_str[16];
        close(sock_fds[0]);

        snprintf(fd_str, sizeof(fd_str), "%d", sock_fds[1]);
        /* wait for daemon to set things up */
        if (aura_child_ipc_wait() == -1)
            sys_exit(true, errno, "aura_dmn_start_server: aura_child_ipc_wait error:");

        execlp("aura_server", "aura_server", fd_str, (char *)0);
        sys_alert(true, errno, "aura_dmn_start_server: Error starting server");
        close(sock_fds[1]);
    } else {
        /* daemon */
        close(sock_fds[1]);
        parent_sock_closed = true;

        a_init_msg_hdr(hdr, config_size, A_MSG_CONF_DATA, 0);
        if (aura_msg_send(sock_fds[0], &hdr, config, config_size, -1) != 0) {
            sys_debug(true, errno, "aura_dmn_start_server: send config error:");
            ret_val = -1;
            goto err_ipc_wait;
        }

        /* tell server things are set */
        if (aura_child_ipc_proceed(pid) == -1) {
            sys_debug(true, errno, "aura_dmn_start_server: aura_child_ipc_proceed error:");
            ret_val = -1;
            goto err_ipc_wait;
        }

        struct aura_msg res_msg;

        /**
         * On startup, the server runs a series of steps,
         * some of which send requests to the daemon. These
         * steps end with a PING message to indicate a successful
         * completion. This is done before we add the server socketpair
         * fd to poll. So we suffer less!
         */
        while (true) {
            if (aura_msg_recv(sock_fds[0], &res_msg) <= 0) {
                app_debug(true, 0, "aura_dmn_start_server: setup loop");
                ret_val = -1;
                goto err_ipc_wait;
            }

            switch (res_msg.hdr.type) {
            case A_MSG_PING:
                /**
                 * PING is the last msg sent by the server
                 * upon its successful setup completion.
                 */
                goto done;

            case A_MSG_CMD_EXECUTE:
                /* server db request */
                if (res_msg.hdr.cmd_type == A_CMD_DB_FETCH_REQUEST) {
                    if (aura_dmn_db_req(&res_msg.data, sock_fds[0], gc->db_handle) < 0) {
                        ret_val = -1;
                        goto err_ipc_wait;
                    }
                } else {
                    app_debug(true, 0, "aura_dmn_start_server: Incorrect cmd type: %d", res_msg.hdr.cmd_type);
                    ret_val = -1;
                    goto err_ipc_wait;
                }
                break;

            default:
                app_debug(true, 0, "aura_dmn_start_server: Incorrect msg hdr type: %d", res_msg.hdr.type);
                ret_val = -1;
                goto err_ipc_wait;
            }
        }
    }

/**
 * We do not send the final cli response of
 * successful server start or failure here.
 * See explanation in main "a_dmn_finalize_server_start" fn;
 */
done:
    gc->server_fd = sock_fds[0];
    gc->server_running = true;
    gc->server_pid = pid;
    gc->server_fd_idx = aura_add_pollfd_entry(&gc->pollfd_pool, gc->server_fd);

    aura_destroy_ipc_wait();
    free(config);
    ret_val = 0;

    aura_resp_send(cli_fd, (void *)server_started, sizeof(server_started) - 1);
    goto out;

err_ipc_wait:
    aura_destroy_ipc_wait();

err_socket_pair:
    free(config);
    close(sock_fds[0]);
    if (!parent_sock_closed)
        close(sock_fds[1]);

out:
    aura_free_yml_error_ctx(parser_err);
    a_srv_free_user_data_ctx(&usr_data);
    return ret_val;
}