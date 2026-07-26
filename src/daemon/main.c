#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "command/function.h"
#include "command/server.h"
#include "command/system.h"
#include "db_broker.h"
#include "dmn.h"
#include "ipc/ipc.h"
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

static int a_ensure_db_path(const char *path, int mode) {
    char temp[1024];
    char *p;
    size_t path_len = strlen(path);

    snprintf(temp, sizeof(temp), "%s", path);
    /* remove trailing slash */
    if (temp[path_len - 1] == '/')
        temp[path_len - 1] = '\0';

    /* Traverse and create directory */
    for (p = temp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp, mode) != 0 && (errno != EEXIST))
                return -1;
            *p = '/';
        }
    }

    if (mkdir(temp, mode) != 0 && errno != EEXIST)
        return -1;

    return 0;
}

// int aura_path_get_db_file_path(char *path, size_t len, const char *db_file_name) {
int aura_path_get_db_file_path(char *path, size_t len) {
    bool dev_mode;
    char *base;

#ifdef AURA_DEV_BUILD
    dev_mode = true;
#else
    dev_mode = false;
#endif

    memset(path, 0, len);
    if (dev_mode) {
        char *xdg_home = getenv("XDG_DATA_HOME");
        if (xdg_home) {
            base = xdg_home;
        } else {
            char *home = getenv("HOME");
            if (!home)
                home = "~";
            snprintf(path, len, "%s/.local/share/", home);
        }
        strncat(path, "v_aura/", len - strlen(path));

        if (a_ensure_db_path(path, S_IRWXU | S_IRGRP | S_IROTH) < 0)
            return -1;
    } else {
        /* Created by systemd.exec */
        base = getenv("STATE_DIRECTORY");
        snprintf(path, len, "%s/", base);
    }

    // strncat(path, db_file_name, len - strlen(path));
    return 0;
}

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
            aura_dmn_validate_server_conf(msg->fd, cli_fd);
            return 0;

        case A_CMD_SERVER_START:
            aura_dmn_start_server(msg, cli_fd, arg);
            return 0;

        case A_CMD_SERVER_STOP:
            aura_dmn_stop_server(msg, cli_fd, arg);
            return 0;

        case A_CMD_SERVER_STATUS:
            aura_dmn_get_server_status(cli_fd, arg);
            return 0;

        case A_CMD_FN_VALIDATE_CONF:
            aura_dmn_validate_fn_conf(msg->fd, cli_fd);
            return 0;

        case A_CMD_FN_DEPLOY:
            aura_dmn_deploy_fn(msg->fd, cli_fd, arg);
            return 0;

        case A_CMD_FN_DELETE:
            aura_dmn_delete_fn(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_STATUS:
            aura_dmn_fn_status(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_START:
            aura_dmn_start_fn(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_STOP:
            aura_dmn_stop_fn(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_FN_LIST:
            aura_dmn_fn_list(&msg->data, cli_fd, arg);
            return 0;

        case A_CMD_DB_FETCH_REQUEST:
            aura_dmn_db_req(&msg->data, cli_fd, ((struct aura_dmn_glob_conf *)arg)->db_handle);
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

static int a_setup_database(struct aura_dmn_glob_conf *gc) {
    int res;
    char db_path[A_DB_MAX_FILE_PATH_LEN];
    // char ctrl_file[A_DB_MAX_FILE_PATH_LEN];
    // char data_file[A_DB_MAX_FILE_PATH_LEN];
    // char wal_file[A_DB_MAX_FILE_PATH_LEN];

    if (aura_path_get_db_file_path(db_path, A_DB_MAX_FILE_PATH_LEN) < 0)
        return -1;

    // if (aura_path_get_db_file_path(data_file, sizeof(ctrl_file), AURA_DB_CONTROL_FILE) < 0)
    //     return -1;

    // if (aura_path_get_db_file_path(data_file, sizeof(data_file), AURA_DB_DATA_FILE) < 0)
    //     return -1;

    // if (aura_path_get_db_file_path(wal_file, sizeof(wal_file), AURA_DB_WAL_FILE) < 0)
    //     return -1;

    // gc->db_file.len = strlen(data_file);
    // gc->db_file.base = strndup(data_file, gc->db_file.len);

    // gc->db_handle = aura_db_open(
    //   &gc->mc,
    //   db_path,
    //   ctrl_file,
    //   data_file,
    //   wal_file,
    //   O_RDWR | O_CREAT | O_EXCL | O_TRUNC,
    //   A_DB_FILE_MODE);
    gc->db_handle = aura_db_open(&gc->mc, db_path);
    if (!gc->db_handle) {
        sys_debug(true, errno, "a_setup_database: aura_db_open error");
        return -1;
    }

    return 0;
}

static bool a_authenticate_cli(struct aura_dmn_glob_conf *gc, int cli_fd, struct aura_msg *msg) {
    if (gc->user.user_id != msg->cred.uid) {
        aura_resp_send(cli_fd, (void *)cli_auth_error, sizeof(cli_auth_error) - 1);
        return false;
    }
    return true;
}

int main(int argc, char *argv[]) {
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
    glob_conf.server_fd = A_DMN_DEFAULT_SERVER_FD;
    if (aura_now_ts(&glob_conf.boot_time, CLOCK_MONOTONIC) < 0)
        sys_exit(true, 0, "Daemon config error:");

    if (aura_usr_get_rec(&glob_conf.user) < 0)
        sys_exit(true, 0, "Daemon config error:");

    /* Set up unix socket */
    char sock_path[256];
    bool dev_mode = false;

#ifdef AURA_DEV_BUILD
    dev_mode = true;
#endif

    aura_ipc_get_unix_sock_path(dev_mode, sock_path, sizeof(sock_path));
    if (aura_unix_server_listen(&d_sock, sock_path) < 0)
        sys_exit(false, errno, "aura_daemon: aura_unix_server_listen error: %s", sock_path);

    aura_pollfd_dense_pool_init(&glob_conf.pollfd_pool);
    for (int i = 0; i < A_DMN_POLLFD_POOL_SZ; ++i) {
        struct pollfd *pfd = aura_pollfd_dense_pool_get_slot(&glob_conf.pollfd_pool, i);
        pfd->fd = -1;
        pfd->events = POLLIN;
        pfd->revents = 0;
    }

    /* Add unix IPC socket to poll */
    aura_add_pollfd_entry(&glob_conf.pollfd_pool, d_sock.fd);
    glob_conf.unix_sock_fd = d_sock.fd;

    aura_install_signal_handler(SIGCHLD, a_sig_ch_handler);

    /* set up memory context */
    aura_mem_ctx_init(&glob_conf.mc);
    if (aura_create_dynamic_slab_alloc_caches(&glob_conf.mc) < 0)
        sys_exit(true, errno, "aura_daemon: aura_create_dynamic_slab_alloc_caches error:");

    /* Setup database */
    if (a_setup_database(&glob_conf) < 0)
        sys_exit(true, errno, "DB error");

    for (;;) {
        if (poll(aura_pollfd_dense_pool_get_entries(&glob_conf.pollfd_pool), A_DMN_POLLFD_POOL_SZ, -1) < 0 && errno != EINTR) {
            sys_debug(true, errno, "aura_daemon: poll error:");
            break;
        }

        for (int i = 0; i < A_DMN_POLLFD_POOL_SZ; ++i) {
            struct pollfd *pfd = aura_pollfd_dense_pool_get_slot(&glob_conf.pollfd_pool, i);
            if (pfd->revents & POLLIN) {
                if (pfd->fd == d_sock.fd) {
                    cli_fd = aura_unix_server_accept(d_sock.fd);
                    if (cli_fd < 0) {
                        sys_debug(true, errno, "aura_daemon: aura_unix_server_accept error:");
                        break;
                    }

                    if (aura_add_pollfd_entry(&glob_conf.pollfd_pool, cli_fd) < 0) {
                        close(cli_fd);
                    }
                    continue;
                }

                rv = aura_msg_recv(pfd->fd, &aura_msg);
                if (rv <= 0)
                    goto err_out;

                if (pfd->fd == glob_conf.server_fd) {
                    /* server request */
                    a_handle_client_request(&aura_msg, pfd->fd, NULL);
                } else {
                    /* cli request */
                    if (a_authenticate_cli(&glob_conf, pfd->fd, &aura_msg) == false)
                        goto err_out;

                    a_handle_client_request(&aura_msg, pfd->fd, (void *)&glob_conf);
                }

                aura_release_pollfd_entry(&glob_conf.pollfd_pool, i);
            } else if (pfd->revents & (POLLHUP | POLLERR | POLLNVAL | POLLOUT)) {
            err_out:
                close(pfd->fd);
                aura_release_pollfd_entry(&glob_conf.pollfd_pool, i);
            }
        }
    }

    exit(1);
}
