#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "aura_dmn.h"
#include "command/function_dmn.h"
#include "command/server_dmn.h"
#include "command/sys_dmn.h"
#include "db_broker.h"
#include "ipc_lib.h"
#include "unix/sock.h"
#include "utils_lib.h"

#include <limits.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>

static long A_MAX_FILE = 256;

const char cli_auth_error[] = "\x1B[1;32mClient Not Authenticated\x1B[0m";

#ifdef AURA_DEV_BUILD
const char *passphrase = "dev_default_password";
#else
/* read passphrase */
#endif

typedef int (*dmn_cb)(void *);

/**
 * Handle requests from server and cli
 * @msg is the message as received over the socket
 * @cli is the socket associated with the message
 * @arg is an opaque pointer to data passed according
 * to whatever contexts
 */
static int a_handle_client_request(struct aura_msg *msg, int cli_fd, void *arg) {

    switch (msg->hdr.type) {
    case A_MSG_PING:
        aura_resp_send(cli_fd, NULL, 0);
        close(cli_fd);
        return 0;

    case A_MSG_CMD_EXECUTE:
        switch (msg->hdr.cmd_type) {
        case A_CMD_SYSTEM_STOP:
            aura_dmn_system_stop(cli_fd, arg);
            return 0;

        case A_CMD_SERVER_VALIDATE_CONF:
            aura_dmn_server_config_validate(msg->fd, cli_fd);
            return 0;

        case A_CMD_SERVER_START:
            aura_dmn_server_start(msg, cli_fd, arg);
            return 0;

        case A_CMD_SERVER_STOP:
            aura_dmn_server_stop(msg, cli_fd, arg);
            return 0;

        case A_CMD_SERVER_STATUS:
            aura_dmn_server_status(cli_fd, arg);
            return 0;

        case A_CMD_FN_VALIDATE_CONF:
            aura_dmn_fn_conf_validate(msg->fd, cli_fd);
            return 0;

        case A_CMD_FN_DEPLOY:
            aura_dmn_fn_deploy(msg->fd, cli_fd, arg);
            return 0;

        case A_CMD_FN_DELETE:
            aura_dmn_fn_del(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_STATUS:
            aura_dmn_fn_status(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_START:
            aura_dmn_fn_start(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_STOP:
            aura_dmn_fn_stop(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_LIST:
            aura_dmn_fn_list(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_DB_FETCH_REQUEST:
            aura_dmn_fetch_request(&msg->data, cli_fd, ((struct aura_dmn_glob_conf *)arg)->db_handle);
            return 0;

        case A_CMD_DB_INSERT_REQUEST:
            return 0;

        default:
            app_debug(true, 0, "unknown cmd line %u", msg->hdr.cmd_type);
            aura_resp_send(cli_fd, NULL, 0);
            return 0;
        }
        return 0;
    default:
        app_info(true, 0, "unknown message %u", msg->hdr.type);
    }
    return 1;
}

/**
 * Clean up server connection
 */
static void a_sig_ch_handler(int signo) {
    // if (waitpid(glob_conf.server_pid, NULL, 0) != glob_conf.server_pid) {
    //     sys_debug(true, errno, "a_sig_ch_handler: waitpid error: %d", glob_conf.server_pid);
    // }
    // glob_conf.server_pid = 0;
    // if (glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd == -1)
    //     return;
    // close(glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd);
    // glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd = -1;
}

static int a_setup_database(struct aura_dmn_glob_conf *glob_conf) {
    int res;

    res = aura_setup_database_file_path(&glob_conf->aura_app_path, &glob_conf->aura_db_path);
    if (res == -1) {
        sys_debug(true, errno, "a_setup_database: aura_setup_database_file_path error");
        return -1;
    }

    glob_conf->db_handle = aura_db_open(
      &glob_conf->mc,
      glob_conf->aura_app_path.base,
      glob_conf->aura_db_path.base,
      O_RDWR | O_CREAT | O_EXCL | O_TRUNC,
      A_DB_FILE_MODE);
    if (!glob_conf->db_handle) {
        sys_debug(true, errno, "a_setup_database: aura_db_open error");
        return -1;
    }

    res = aura_db_start_bg_tasks(glob_conf->db_handle);
    if (res != 0) {
        sys_debug(true, errno, "a_setup_database: aura_db_start_bg_tasks");
        return -1;
    }

    return 0;
}

static bool a_authenticate_cli(struct aura_dmn_glob_conf *gc, int cli_fd, struct aura_msg *msg) {
    if (gc->user.user_id != msg->cred.uid) {
        aura_resp_send(cli_fd, (void *)cli_auth_error, sizeof(cli_auth_error) - 1);
        close(cli_fd);
        return false;
    }
    return true;
}

int aura_daemon() {
    struct aura_dmn_glob_conf glob_conf;
    struct aura_unix_sock d_sock;
    int rv, cli_fd;
    size_t n_read, num_fd;
    struct aura_msg aura_msg;
    struct rlimit rlimit;

    // if (getrlimit(RLIMIT_NOFILE, &rlimit) < 0)
    //     sys_exit(true, errno, "main: get resource limit err");

    // if (rlimit.rlim_max != RLIM_INFINITY)
    //     A_MAX_FILE = rlimit.rlim_max;

    memset(&glob_conf, 0, sizeof(glob_conf));
    if (aura_now_ts(&glob_conf.boot_time, CLOCK_MONOTONIC) < 0)
        sys_exit(true, 0, "Daemon config error:");

    if (aura_usr_get_rec(&glob_conf.user) < 0)
        sys_exit(true, 0, "Daemon config error:");

    glob_conf.poll_fds = alloca(sizeof(struct pollfd) * A_MAX_FILE);
    if (!glob_conf.poll_fds)
        sys_exit(false, 0, "Daemon config error");

    /* Set up unix socket */
    if (aura_unix_server_listen(&d_sock, A_UNIX_SOCK_FILE) < 0)
        sys_exit(false, errno, "aura_daemon: aura_unix_server_listen error: %s", A_UNIX_SOCK_FILE);

    for (int i = 0; i < A_MAX_FILE; ++i) {
        glob_conf.poll_fds[i].fd = -1;
        glob_conf.poll_fds[i].events = POLLIN;
        glob_conf.poll_fds[i].revents = 0;
    }

    /* Add unix IPC socket to poll */
    glob_conf.poll_fds[A_SOCK_FILE_FD_IDX].fd = d_sock.fd;
    num_fd = 1;

    aura_install_signal_handler(SIGCHLD, a_sig_ch_handler);

    /* set up memory context */
    aura_mem_ctx_init(&glob_conf.mc);
    if (aura_create_dynamic_slab_alloc_caches(&glob_conf.mc) < 0)
        sys_exit(true, errno, "aura_daemon: aura_create_dynamic_slab_alloc_caches error:");

    /* check app paths */
    if (aura_setup_app_paths(&glob_conf.aura_app_path) < 0)
        sys_exit(true, errno, "aura_daemon: a_setup_app_paths error:");

    /* Setup database */
    if (a_setup_database(&glob_conf) < 0)
        sys_exit(true, 0, "DB error");

    for (;;) {
        if (poll(glob_conf.poll_fds, num_fd, -1) < 0 && errno != EINTR) {
            sys_debug(true, errno, "aura_daemon: poll error:");
            break;
        }

        if (glob_conf.poll_fds[0].revents & POLLIN) {
            cli_fd = aura_unix_server_accept(d_sock.fd);
            if (cli_fd < 0) {
                sys_debug(true, errno, "aura_daemon: aura_unix_server_accept error:");
                break;
            }

            glob_conf.poll_fds[num_fd].fd = cli_fd;
            glob_conf.poll_fds[num_fd].events = POLLIN;
            glob_conf.poll_fds[num_fd].revents = 0;
            num_fd++;
        }

        for (int i = 1; i < num_fd; ++i) {
            if (glob_conf.poll_fds[i].revents & POLLIN) {
                rv = aura_msg_recv(glob_conf.poll_fds[i].fd, &aura_msg);
                if (rv <= 0)
                    goto err_out;

                if (i == A_SOCK_PAIR_FD_IDX) {
                    /* server request */
                    a_handle_client_request(&aura_msg, glob_conf.poll_fds[i].fd, NULL);
                } else {
                    /* cli request */
                    if (a_authenticate_cli(&glob_conf, glob_conf.poll_fds[i].fd, &aura_msg) == false)
                        continue;
                    a_handle_client_request(&aura_msg, glob_conf.poll_fds[i].fd, (void *)&glob_conf);
                }

            } else if (glob_conf.poll_fds[i].revents & (POLLHUP | POLLERR | POLLNVAL | POLLOUT)) {
            err_out:
                close(glob_conf.poll_fds[i].fd);
                glob_conf.poll_fds[i].fd = -1;
            }
        }
    }

    exit(1);
}
