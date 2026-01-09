#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>

struct aura_cli_sys_start_opts {
    char *system_config_path;
};

static void *a_system_start_option_allocator(void) {
    return malloc(sizeof(struct aura_cli_sys_start_opts));
}

static void a_system_start_option_destructor(void *opts_ptr) {
    struct aura_cli_sys_start_opts *opts = (struct aura_cli_sys_start_opts *)opts_ptr;
    if (!opts_ptr)
        return;

    if (opts->system_config_path)
        free(opts->system_config_path);

    free(opts);
}

struct aura_cli_flag path_flag = {
  .name = "path",
  .short_name = 'p',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = true,
  .is_set = false,
  .type = A_CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct aura_cli_sys_start_opts, system_config_path),
  .description = "Path flag description",
};

struct aura_cli_flag *system_start_flags[] = {
  &path_flag,
};

/* Start aura system up */
int aura_cli_system_start(void *opts_ptr, void *glob_opts) {
    pid_t pid;
    int pipe_fd[2], n;
    char startup_report[1024];
    struct aura_cli_sys_start_opts *opts = (struct aura_cli_sys_start_opts *)opts_ptr;

    if (pipe(pipe_fd) < 0) {
        sys_exit(false, errno, "aura_cli_system_start: pipe error:");
    }

    pid = fork();
    if (pid < 0) {
        sys_exit(false, errno, "aura_cli_system_start: fork error:");
    }

    if (pid == 0) {
        /* close child read */
        close(pipe_fd[0]);

        if (pipe_fd[1] != STDOUT_FILENO) {
            if (dup2(pipe_fd[1], STDOUT_FILENO) != STDOUT_FILENO)
                // report
                return 1;
        }

        if (pipe_fd[1] != STDERR_FILENO) {
            if (dup2(pipe_fd[1], STDERR_FILENO) != STDERR_FILENO)
                // report
                return 1;
        }

        if (execlp("aura_daemon", "aura_daemon", (char *)0) < 0)
            sys_exit(false, errno, "execlp error starting server");
    } else {
        /* close parent write */
        close(pipe_fd[1]);
        n = read(pipe_fd[0], startup_report, sizeof(startup_report));
        write(STDOUT_FILENO, startup_report, n);
        return 0;
    }
}

/* aura system start cmd */
struct aura_cli_cmd system_start = {
  .version = "to be filled later",
  .name = "start",
  .description = "start description",
  .usage = "start (describe usage)",
  .deprecated = NULL,
  .flags = system_start_flags,
  .flag_count = ARRAY_SIZE(system_start_flags),
  .args = NULL,
  .args_cnt = 0,
  .sub_cmds = NULL,
  .sub_cmd_cnt = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 1,
  .handler = aura_cli_system_start,
  .opt_allocator = a_system_start_option_allocator,
  .opt_destructor = a_system_start_option_destructor,
};

/* Stop aura system */
int aura_cli_system_stop(void *opts_ptr, void *glob_opts) {
    struct aura_msg_hdr hdr;
    FILE *pid_file;
    char buf[64];
    pid_t pid;
    int res, sock_fd;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1)
        app_exit(false, 0, "Failed to connect to daemon, use 'aura system start' to start aura daemon");

    pid_file = fopen(AURA_PID, "r");
    if (!pid_file) {
        fprintf(stderr, "failed to open pid file: %s\n", strerror(errno));
        return 1;
    }

    fread(buf, sizeof(buf), 1, pid_file);
    if (ferror(pid_file)) {
        fprintf(stderr, "could not read pid file: %s\n", strerror(errno));
        return 1;
    }

    errno = 0;
    pid = strtol(buf, NULL, 10);

    if (errno != 0) {
        fprintf(stderr, "invalid pid: %s\n", strerror(errno));
        return 1;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SYSTEM_STOP);

    if (aura_msg_send(sock_fd, &hdr, NULL, 0, -1) < 0) {
        app_debug(false, errno, "system stop, failed");
        return 1;
    }

    printf("PID: %lu\n", (long unsigned)pid);
    res = unlink(AURA_PID);
    return kill(pid, SIGTERM);
}

struct aura_cli_cmd system_stop = {
  .version = "to be filled later",
  .name = "stop",
  .description = "stop description",
  .usage = "stop (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .args = NULL,
  .args_cnt = 0,
  .sub_cmds = NULL,
  .sub_cmd_cnt = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 0,
  .handler = aura_cli_system_stop,
};

/* Check if system is alive */
int aura_cli_system_status(void *opts, void *glob_opts) {
    int res, sock_fd;
    struct aura_msg_hdr hdr;
    struct aura_msg msg;

    aura_try_connect_or_error(&sock_fd);
    if (sock_fd == -1) {
        app_exit(false, 0, "Server down");
        return 0;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_PING, 0);
    if (aura_msg_send(sock_fd, &hdr, NULL, 0, -1) < 0) {
        app_debug(false, errno, "system status, failed");
        return 1;
    }

    res = aura_recv_msg(sock_fd, &msg);
    if (msg.hdr.type == A_MSG_RESPONSE) {
        printf("System up");
    } else {
        printf("System down!");
    }

    return 0;
}

static void a_system_status_help() {
    printf("Server status help\n");
}

struct aura_cli_cmd system_status = {
  .version = "to be filled later",
  .name = "status",
  .description = "status description",
  .usage = "status (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .args = NULL,
  .args_cnt = 0,
  .sub_cmds = NULL,
  .sub_cmd_cnt = 0,
  .min_args = 0,
  .max_args = 0,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .handler = aura_cli_system_status,
  .opt_help = a_system_status_help,
};

struct aura_cli_cmd *system_subs[] = {
  &system_start,
  &system_stop,
  &system_status,
};

static int a_run_system_base_handle() {
    printf("Manage system\n");
    return 0;
}

static void a_run_help_system() {
    printf("Manage system\n");
}

struct aura_cli_cmd system_base_cmd = {
  .version = "to be filled later",
  .name = "system",
  .description = "Manage systems",
  .usage = "system (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .args = NULL,
  .args_cnt = 0,
  .sub_cmds = system_subs,
  .sub_cmd_cnt = 3,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .handler = a_run_system_base_handle,
  .opt_help = a_run_help_system,
};
