#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "aura_dmn.h"
#include "command/function_dmn.h"
#include "command/server_dmn.h"
#include "command/sys_dmn.h"
#include "daemon_lib.h"
#include "db_broker.h"
#include "ipc_lib.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <signal.h>
#include <sys/wait.h>

struct aura_daemon_glob_conf glob_conf;

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
            aura_dmn_system_stop(cli_fd, &glob_conf);
            return 0;

        case A_CMD_SERVER_VALIDATE_CONF:
            aura_dmn_server_config_validate(msg->fd, cli_fd);
            return 0;

        case A_CMD_SERVER_START:
            aura_dmn_start_server(msg, cli_fd, (struct srv_start_arg *)arg);
            return 0;

        case A_CMD_SERVER_STOP:
            aura_dmn_server_stop(msg, &glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd, cli_fd, glob_conf.server_pid);
            return 0;

        case A_CMD_SERVER_STATUS:
            aura_dmn_server_status(glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd, cli_fd);
            return 0;

        case A_CMD_FN_VALIDATE_CONF:
            aura_dmn_function_config_validate(msg->fd, cli_fd);
            return 0;

        case A_CMD_FN_DEPLOY:
            aura_dmn_function_deploy(msg->fd, glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd, cli_fd);
            return 0;

        case A_CMD_FN_DELETE:
            aura_dmn_function_delete(glob_conf.db_handle, &msg->data, cli_fd);
            return 0;

        case A_CMD_FN_STATUS:
            aura_dmn_function_status(glob_conf.db_handle, &glob_conf.mc, &msg->data, cli_fd);
            return 0;

        case A_CMD_FN_START:
            aura_dmn_function_start(glob_conf.db_handle, &glob_conf.mc, &msg->data, cli_fd);
            return 0;

        case A_CMD_FN_STOP:
            aura_dmn_function_stop(glob_conf.db_handle, &glob_conf.mc, &msg->data, cli_fd);
            return 0;

        case A_CMD_FN_LIST:
            aura_dmn_function_list(glob_conf.db_handle, &msg->data, cli_fd);
            return 0;

        case A_CMD_DB_FETCH_REQUEST:
            aura_dmn_fetch_request(glob_conf.db_handle, &msg->data, cli_fd);
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
    if (waitpid(glob_conf.server_pid, NULL, 0) != glob_conf.server_pid) {
        sys_debug(true, errno, "a_sig_ch_handler: waitpid error: %d", glob_conf.server_pid);
    }
    glob_conf.server_pid = 0;
    if (glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd == -1)
        return;
    close(glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd);
    glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd = -1;
}

/**
 * callback called assuming server shall
 * start successfully, it registers the
 * created socket pair for polling
 */
static inline void a_setup_sockfd(int fd, pid_t srv_pid) {
    glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].fd = fd;
    glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].events = POLLIN;
    glob_conf.poll_fds[A_SOCKET_PAIR_FD_INDEX].revents = 0;
    glob_conf.server_pid = srv_pid;
}

static void a_setup_database(struct aura_daemon_glob_conf *glob_conf) {
    int res;

    res = aura_setup_database_file_path(&glob_conf->aura_app_path, &glob_conf->aura_db_path);
    if (res == -1)
        sys_exit(true, errno, "a_setup_database: aura_setup_database_file_path error");

    glob_conf->db_handle = aura_db_open(
      &glob_conf->mc,
      glob_conf->aura_app_path.base,
      glob_conf->aura_db_path.base,
      O_RDWR | O_CREAT | O_EXCL | O_TRUNC,
      A_DB_FILE_MODE);
    if (!glob_conf->db_handle)
        sys_exit(true, errno, "a_setup_database: aura_db_open error");

    res = aura_db_start_bg_tasks(glob_conf->db_handle);
    if (res != 0)
        sys_exit(true, errno, "a_setup_database: aura_db_start_bg_tasks");
}

int aura_daemon() {
    struct aura_unix_socket d_sock;
    struct sockaddr_un d_addr;
    uid_t uid, aura_cli_pid;
    int res, i;
    int cli_fd, lock_file_fd, num_fd;
    size_t n_read;
    time_t t;
    struct msghdr msg;
    struct cmsghdr cmsg;
    struct iovec iov[1];
    struct aura_msg aura_msg;
    struct srv_start_arg srv_arg = {
      .cb = a_setup_sockfd,
    };

    memset(&glob_conf, 0, sizeof(glob_conf));
    lock_file_fd = open(AURA_PID, O_RDWR | O_CREAT, LOCKMODE);
    if (lock_file_fd < 0)
        sys_exit(false, errno, "aura_daemon: lock_file error");

    if (already_running(lock_file_fd))
        sys_exit(false, 0, "aura_daemon: already_running error");

    app_debug(false, 0, "Daemon tests"); /* probably after setting socket */

    /**
     * Set up named socket
     */
    res = aura_unix_server_listen(&d_sock, AURA_SOCKET);
    if (res < 0)
        sys_exit(false, 0, "aura_daemon: aura_unix_server_listen error");

    for (i = 0; i < MAX_CONN; ++i) {
        glob_conf.poll_fds[i].fd = -1;
        glob_conf.poll_fds[i].events = POLLIN;
        glob_conf.poll_fds[i].revents = 0;
    }

    glob_conf.poll_fds[0].fd = d_sock.sock_fd;

    int keep_fd[] = {
      d_sock.sock_fd,
      lock_file_fd,
    };
    /* starting number of fds to watch */
    num_fd = ARRAY_SIZE(keep_fd);

    aura_install_signal_handler(SIGCHLD, a_sig_ch_handler);

    /* Daemonize */
    daemonize("aurad", keep_fd, ARRAY_SIZE(keep_fd));

    res = set_pid_lock(lock_file_fd);
    if (res < 0)
        sys_exit(true, errno, "aura_daemon: set_pid_lock error");

    /* set up memory context */
    aura_memory_ctx_init(&glob_conf.mc);
    if (aura_create_dynamic_slab_alloc_caches(&glob_conf.mc) < 0)
        sys_exit(true, errno, "aura_daemon: aura_create_dynamic_slab_alloc_caches error:");

    /* check app paths */
    res = aura_setup_app_paths(&glob_conf.aura_app_path);
    if (res == -1)
        sys_exit(true, errno, "aura_daemon: a_setup_app_paths error:");
    /* Setup database */
    a_setup_database(&glob_conf);

    for (;;) {
        if (poll(glob_conf.poll_fds, num_fd, -1) < 0 && errno != EINTR)
            sys_exit(true, errno, "aura_daemon: poll error:");

        if (glob_conf.poll_fds[0].revents & POLLIN) {
            cli_fd = aura_unix_server_accept(d_sock.sock_fd, &uid);
            if (cli_fd < 0)
                sys_exit(true, errno, "aura_daemon: aura_unix_server_accept error:");

            glob_conf.poll_fds[num_fd].fd = cli_fd;
            glob_conf.poll_fds[num_fd].events = POLLIN;
            glob_conf.poll_fds[num_fd].revents = 0;
            num_fd++;
        }

        for (i = 1; i < num_fd; ++i) {
            if (glob_conf.poll_fds[i].revents & POLLIN) {
                switch (i) {
                case A_SOCKET_PAIR_FD_INDEX:
                // fallthrough
                default:
                    res = aura_msg_recv(glob_conf.poll_fds[i].fd, &aura_msg);
                    if (res > 0) {
                        if (i == A_SOCKET_PAIR_FD_INDEX) {
                            /* aura_server request */
                            a_handle_client_request(&aura_msg, glob_conf.poll_fds[i].fd, NULL);
                        } else {
                            /* aura_cli request */
                            a_handle_client_request(&aura_msg, glob_conf.poll_fds[i].fd, (void *)&srv_arg);
                            break;
                        }
                    } else
                        goto err_out;
                }
            } else if (glob_conf.poll_fds[i].revents & (POLLHUP | POLLERR | POLLNVAL | POLLOUT)) {
            err_out:
                close(glob_conf.poll_fds[i].fd);
                glob_conf.poll_fds[i].fd = -1;
            }
        }
    }

    unlink(AURA_PID);
    sys_exit(true, errno, "aura_daemon: Exiting daemon"); // @todo Do clean up
}
