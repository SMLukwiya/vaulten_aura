#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "aura_dmn.h"
#include "command/command_dmn.h"
#include "command/function_dmn.h"
#include "command/server_dmn.h"
#include "daemon_lib.h"
#include "ipc_lib.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_CONN 100
#define A_SOCKET_PAIR_FD_INDEX 1

struct aura_daemon_glob_conf glob_conf;
struct pollfd poll_fds[MAX_CONN];
int server_pid = 0;

/**
 * Handle requests from server and cli
 * @msg is the message as received over the socket
 * @cli is the socket associated with the message
 * @arg is an opaque pointer to data passed according
 * to whatever contexts
 */
static int a_handle_client_request(struct aura_msg *msg, int cli_fd, void *arg) {
    aura_dump_msg(msg, true);

    switch (msg->hdr.type) {
    case A_MSG_PING:
        aura_send_resp(cli_fd, NULL, 0);
        close(cli_fd);
        return 0;
    case A_MSG_CMD_EXECUTE:
        switch (msg->hdr.cmd_type) {
        case A_CMD_SYSTEM_STOP:
            if (server_pid == 0) {
                close(cli_fd);
                return 0;
            }

        case A_CMD_SERVER_START:
            aura_dmn_start_server(msg, cli_fd, (struct srv_start_arg *)arg);
            return 0;

        case A_CMD_SERVER_STOP:
            aura_dmn_stop_server(msg, poll_fds[A_SOCKET_PAIR_FD_INDEX].fd, cli_fd, server_pid);
            server_pid = 0;
            return 0;

        case A_CMD_SERVER_STATUS:
            aura_dmn_server_status(poll_fds[A_SOCKET_PAIR_FD_INDEX].fd, cli_fd);
            return 0;

        case A_CMD_FN_DEPLOY:
            aura_dmn_function_deploy(msg->fd, poll_fds[A_SOCKET_PAIR_FD_INDEX].fd, cli_fd);
            return 0;

        case A_CMD_FN_VALIDATE_CONF:
            aura_dmn_function_config_validate(msg->fd, cli_fd);
            return 0;

        case A_CMD_SERVER_VALIDATE_CONF:
            aura_dmn_server_config_validate(msg->fd, cli_fd);
            return 0;

        default:
            app_debug(true, 0, "unknown cmd line %s", msg->hdr.cmd_type);
            aura_send_resp(cli_fd, NULL, 0);
            return 0;
        }
        return 0;
    default:
        app_info(true, 0, "unknown message %s", msg->hdr.type);
    }
    return 1;
}

/**
 *
 */
static void a_sig_ch_handler(int signo) {
    /* kill the registered socket pair */
    if (waitpid(server_pid, NULL, 0) < 0) {
        sys_debug(true, errno, "a_sig_ch_handler: waitpid server: %d", server_pid);
    }
    server_pid = 0;
    if (poll_fds[A_SOCKET_PAIR_FD_INDEX].fd == -1)
        return;
    close(poll_fds[A_SOCKET_PAIR_FD_INDEX].fd);
    poll_fds[A_SOCKET_PAIR_FD_INDEX].fd = -1;
}

/**
 * callback called assuming server shall
 * start successfully, it registers the
 * created socket pair for polling
 */
static inline void a_setup_sockfd(int fd, pid_t srv_pid) {
    poll_fds[A_SOCKET_PAIR_FD_INDEX].fd = fd;
    poll_fds[A_SOCKET_PAIR_FD_INDEX].events = POLLIN;
    poll_fds[A_SOCKET_PAIR_FD_INDEX].revents = 0;
    server_pid = srv_pid;
}

static void a_setup_database(struct aura_daemon_glob_conf *glob_conf) {
    int res;

    res = aura_setup_database_file_path(&glob_conf->aura_db_path);
    if (res == -1)
        sys_exit(true, errno, "a_setup_database: aura_setup_database_file_path error");

    glob_conf->db_handle = aura_db_open(glob_conf->aura_db_path.base, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, A_DB_FILE_MODE);
    if (!glob_conf->db_handle)
        sys_exit(true, errno, "a_setup_database: aura_db_open error");
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
        poll_fds[i].fd = -1;
        poll_fds[i].events = POLLIN;
        poll_fds[i].revents = 0;
    }

    poll_fds[0].fd = d_sock.sock_fd;

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

    /* check app paths */
    res = aura_setup_app_paths(&glob_conf.aura_db_path);
    if (res == -1)
        sys_exit(true, errno, "aura_daemon: a_setup_app_paths");
    /* Setup database */
    a_setup_database(&glob_conf);

    for (;;) {
        if (poll(poll_fds, num_fd, -1) < 0 && errno != EINTR)
            sys_exit(true, errno, "aura_daemon: poll error");

        if (poll_fds[0].revents & POLLIN) {
            cli_fd = aura_unix_server_accept(d_sock.sock_fd, &uid);
            if (cli_fd < 0)
                sys_exit(true, errno, "aura_daemon: aura_unix_server_accept");

            poll_fds[num_fd].fd = cli_fd;
            poll_fds[num_fd].events = POLLIN;
            poll_fds[num_fd].revents = 0;
            num_fd++;
        }

        for (i = 1; i < num_fd; ++i) {
            if (poll_fds[i].revents & POLLIN) {
                switch (i) {
                case A_SOCKET_PAIR_FD_INDEX:
                // fallthrough
                default:
                    res = aura_recv_msg(poll_fds[i].fd, &aura_msg);
                    if (res > 0) {
                        if (i == A_SOCKET_PAIR_FD_INDEX) {
                            /* aura_server request */
                            aura_dump_msg(&aura_msg, true);
                        } else {
                            /* aura_cli request */
                            a_handle_client_request(&aura_msg, poll_fds[i].fd, (void *)&srv_arg);
                            break;
                        }
                    } else
                        goto err_out;
                }
            } else if (poll_fds[i].revents & (POLLHUP | POLLERR | POLLNVAL | POLLOUT)) {
            err_out:
                close(poll_fds[i].fd);
                poll_fds[i].fd = -1;
            }
        }
    }

    unlink(AURA_PID);
    sys_exit(true, errno, "aura_daemon: Exiting daemon"); // @todo Do clean up
}
