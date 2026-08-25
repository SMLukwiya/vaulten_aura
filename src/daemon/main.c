#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <limits.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "command/function.h"
#include "command/server.h"
#include "command/system.h"
#include "db_broker.h"
#include "dmn.h"
#include "event_ctx/context.h"
#include "ipc/ipc.h"
#include "unix/sock.h"
#include "utils_lib.h"

static long A_MAX_FILE = 256;

const char cli_auth_error[] = "\x1B[1;32mClient Not Authenticated\x1B[0m";

#ifdef AURA_DEV_BUILD
const char *passphrase = "dev_default_password";

/**
 * Create database path during testing
 */
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
#else
/* read passphrase */
#endif

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

static struct aura_dmn_glob_conf *conf;

/**
 * Run when server dies
 */
static void aura_dmn_server_killed() {
    if (conf->server_pid != 0) {
        if (waitpid(conf->server_pid, NULL, 0) != conf->server_pid) {
            sys_debug(true, errno, "a_sig_ch_handler: waitpid error: %d", conf->server_pid);
        }
    }

    if (conf->server_fd != A_DMN_DEFAULT_SERVER_FD)
        close(conf->server_fd);

    conf->server_pid = 0;
    conf->server_fd = A_DMN_DEFAULT_SERVER_FD;
    conf->server_running = false;
    conf->server_fd_idx = -1;
}

/**
 * The path the server takes when it dies is unclear.
 * Sometimes the sig child is delivered, other times
 * the poll fd entry hungs (see the main polling loop).
 * Either way, which ever path executes the server died
 * function.
 */
static void a_sig_ch_handler(int signo) {
    app_debug(true, 0, "aura server dead");
    aura_dmn_server_killed();
}

static int a_dmn_initialize_pollfd_slot(struct pollfd *p) {
    p->fd = -1;
    p->events = POLLIN;
    p->revents = 0;
    return 0;
}

static int a_dmn_setup_database(struct aura_dmn_glob_conf *gc) {
    int res;
    char db_path[A_DB_MAX_FILE_PATH_LEN];

    if (aura_path_get_db_file_path(db_path, A_DB_MAX_FILE_PATH_LEN) < 0)
        return -1;

    gc->db_handle = aura_db_open(&gc->mc, db_path);
    if (!gc->db_handle) {
        sys_debug(true, errno, "a_dmn_setup_database: aura_db_open error");
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

static int a_dmn_load_native_evt_sources(struct aura_evt_src_registry *r) {
    /* HTTP source */
    if (aura_event_registry_add(r, A_EVT_SRC_HTTP, 0) < 0)
        return -1;

    /* CRON source */
    if (aura_event_registry_add(r, A_EVT_SRC_CRON, 0) < 0)
        return -1;

    return 0;
}

/**
 * Load function registry.
 * Fetch function list and attach fn triggers
 * from function meta.
 * For each function trigger, bind the functions to
 * their respective trigger sources. HTTP triggers are invoked
 * via the server but binding them here helps us know
 * which functions are available.
 */
static int a_dmn_load_fn_registry(struct aura_dmn_glob_conf *gc) {
    struct aura_fn_list *fn_list;
    struct aura_fn_registry_ent *ent;
    struct aura_evt_src *evt_src;
    struct aura_fn_tag *fn_tag;
    int error;

    fn_list = aura_fn_list_fetch(gc->db_handle, &error);
    if (!fn_list) {
        if (error < 0)
            return -1;
        return 0;
    }

    for (int i = 0; i < fn_list->func_cnt && i < A_FN_MAX_REGISTRY_CNT; ++i) {
        fn_tag = &fn_list->func_tags[i];
        if (aura_fn_fetch_trigger(gc->db_handle, &fn_tag->fn_triggers, fn_tag->fn_name, fn_tag->fn_version, &error) < 0) {
            aura_fn_tag_destroy(fn_tag);
            aura_free(fn_list);
            return -1;
        }

        ent = aura_fn_load_fn_registry_entry(&gc->fn_registry, fn_tag);
        /* Function registry is full, abandon effort */
        if (!ent) {
            aura_fn_tag_destroy(fn_tag);
            aura_free(fn_list);
            return 0;
        }

        for (int j = 0; j < fn_tag->fn_triggers.cnt; ++j) {
            switch (ent->fn_tag.fn_triggers.entries[j].trigger) {
            case A_FN_TRIGGER_HTTP:
                evt_src = aura_evt_src_get(&gc->evt_src_registry, A_EVT_SRC_HTTP);
                if (evt_src->ops->bind(evt_src, ent, j) < 0) {
                    return -1;
                }
                break;

            case A_FN_TRIGGER_CRON:
                evt_src = aura_evt_src_get(&gc->evt_src_registry, A_EVT_SRC_CRON);
                if (evt_src->ops->bind(evt_src, ent, j) < 0) {
                    /* Nothing yet */
                }

            default:
                break;
            }
        }

        aura_fn_tag_destroy(fn_tag);
    }

    aura_free(fn_list);

    return 0;
}

static int a_dmn_get_next_poll_timeout(struct aura_dmn_glob_conf *gc) {
    /** @todo */
    return -1;
}

int main(int argc, char *argv[]) {
    struct aura_dmn_glob_conf *gc;
    struct aura_unix_sock d_sock;
    int rv, cli_fd;
    size_t n_read, num_fd;
    struct aura_msg aura_msg;
    struct rlimit rlimit;
    /* Set up unix socket */
    char sock_path[256];
    bool dev_mode = false;

#ifdef AURA_DEV_BUILD
    dev_mode = true;
#endif

    // if (getrlimit(RLIMIT_NOFILE, &rlimit) < 0)
    //     sys_exit(true, errno, "main: get resource limit err");

    // if (rlimit.rlim_max != RLIM_INFINITY)
    //     A_MAX_FILE = rlimit.rlim_max;

    gc = alloca(sizeof(*gc));
    if (!gc)
        sys_exit(true, errno, "aura_daemon: gc alloca");
    memset(gc, 0, sizeof(*gc));

    /* init memory context */
    aura_mem_ctx_init(&gc->mc);
    if (aura_create_dynamic_slab_alloc_caches(&gc->mc) < 0)
        sys_exit(true, errno, "aura_daemon: aura_create_dynamic_slab_alloc_caches error:");

    /* Setup database connection */
    if (a_dmn_setup_database(gc) < 0)
        sys_exit(true, errno, "DB error");

    /* Load native event sources */
    if (a_dmn_load_native_evt_sources(&gc->evt_src_registry) < 0)
        sys_exit(true, errno, "aura_daemon: a_dmn_load_native_evt_sources error:");

    /* init function registry */
    if (aura_fn_registry_init(&gc->fn_registry, &gc->mc, A_FN_MAX_REGISTRY_CNT) < 0)
        sys_exit(true, errno, "aura_daemon: aura_fn_registry_init");

    if (a_dmn_load_fn_registry(gc) < 0)
        sys_exit(true, errno, "aura_daemon: a_dmn_load_fn_registry error:");

    gc->server_fd = A_DMN_DEFAULT_SERVER_FD;

    aura_install_signal_handler(SIGCHLD, a_sig_ch_handler);

    if (aura_usr_get_rec(&gc->user) < 0)
        sys_exit(true, 0, "Daemon config error:");

    /* init unix socket */
    aura_ipc_get_unix_sock_path(dev_mode, sock_path, sizeof(sock_path));
    if (aura_unix_server_listen(&d_sock, sock_path) < 0)
        sys_exit(false, errno, "aura_daemon: aura_unix_server_listen error: %s", sock_path);

    /* poll fd */
    aura_pollfd_dense_pool_init(&gc->pollfd_pool);
    aura_pollfd_dense_pool_for_each(&gc->pollfd_pool, a_dmn_initialize_pollfd_slot);

    /* Add unix IPC socket to poll */
    aura_add_pollfd_entry(&gc->pollfd_pool, d_sock.fd);
    gc->unix_sock_fd = d_sock.fd;

    if (aura_now_ts(&gc->boot_time, CLOCK_MONOTONIC) < 0)
        sys_exit(true, 0, "Daemon config error:");

    /* Make visible to signal handler */
    conf = gc;

    for (;;) {
        int timeout = a_dmn_get_next_poll_timeout(gc);

        if (poll(
              aura_pollfd_dense_pool_get_entries(&gc->pollfd_pool),
              A_DMN_POLLFD_POOL_SZ,
              timeout) < 0 &&
            errno != EINTR) {
            sys_debug(true, errno, "aura_daemon: poll error:");
            break;
        }

        for (int i = 0; i < A_DMN_POLLFD_POOL_SZ; ++i) {
            struct pollfd *pfd = aura_pollfd_dense_pool_get_slot(&gc->pollfd_pool, i);
            if (pfd->revents & (POLLHUP | POLLERR | POLLNVAL | POLLOUT)) {
            err:
                aura_release_pollfd_entry(&gc->pollfd_pool, i);

            } else if (pfd->revents & POLLIN) {
                if (pfd->fd == d_sock.fd) {
                    cli_fd = aura_unix_server_accept(d_sock.fd);
                    if (cli_fd < 0) {
                        sys_debug(true, errno, "aura_daemon: aura_unix_server_accept error:");
                        break;
                    }

                    if (aura_add_pollfd_entry(&gc->pollfd_pool, cli_fd) < 0) {
                        close(cli_fd);
                    }
                    continue;
                }

                rv = aura_msg_recv(pfd->fd, &aura_msg);
                if (rv <= 0)
                    goto err;

                if (pfd->fd == gc->server_fd) {
                    /* server request */
                    a_handle_client_request(&aura_msg, pfd->fd, (void *)gc);

                } else {
                    /* cli request */
                    if (a_authenticate_cli(gc, pfd->fd, &aura_msg) == false)
                        goto err;

                    a_handle_client_request(&aura_msg, pfd->fd, (void *)gc);
                }

                aura_release_pollfd_entry(&gc->pollfd_pool, i);
            }
        }
    }

    exit(1);
}
