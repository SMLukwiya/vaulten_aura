#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>

struct start_options {
    char *system_config_path;
};

void *start_option_allocator(void) {
    return malloc(sizeof(struct start_options));
}

void start_option_destructor(void *opts_ptr) {
    struct start_options *opts = (struct start_options *)opts_ptr;
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
  .type = CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct start_options, system_config_path),
  .description = "path flag description",
};

struct aura_cli_flag *system_start_flags[] = {
  &path_flag,
};

void run_system_start(void *opts_ptr, int argc, char *argv[], void *glob_opts) {
    pid_t pid;
    int pipe_fd[2], n;
    char startup_report[1024];
    struct start_options *opts = (struct start_options *)opts_ptr;

    if (pipe(pipe_fd) < 0) {
        fprintf(stderr, "failed to create system pipe: %s\n", strerror(errno));
        exit(1);
    }

    if ((pid = fork()) < 0) {
        fprintf(stderr, "error starting daemon: %s\n", strerror(errno));
        exit(1);
    }

    if (pid == 0) {
        /* close child read */
        close(pipe_fd[0]);

        if (pipe_fd[1] != STDOUT_FILENO) {
            if (dup2(pipe_fd[1], STDOUT_FILENO) != STDOUT_FILENO)
                // report
                exit(1);
        }

        if (pipe_fd[1] != STDERR_FILENO) {
            if (dup2(pipe_fd[1], STDERR_FILENO) != STDERR_FILENO)
                // report
                exit(1);
        }

        if (execlp("aura_daemon", "aura_daemon", (char *)0) < 0)
            sys_exit(false, errno, "execlp error starting server");
    } else {
        /* close parent write */
        close(pipe_fd[1]);
        n = read(pipe_fd[0], startup_report, sizeof(startup_report));
        write(STDOUT_FILENO, startup_report, n);
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
  .flag_count = 1,
  .arguments = NULL,
  .sub_commands = NULL,
  .sub_command_count = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 1,
  .handler = run_system_start,
  .opt_allocator = start_option_allocator,
  .opt_destructor = start_option_destructor,
};

void run_system_stop(void *opts_ptr, int argc, char *argv[], void *glob_opts) {
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
        exit(1);
    }

    fread(buf, sizeof(buf), 1, pid_file);
    if (ferror(pid_file)) {
        fprintf(stderr, "could not read pid file: %s\n", strerror(errno));
        exit(1);
    }

    errno = 0;
    pid = strtol(buf, NULL, 10);

    if (errno != 0) {
        fprintf(stderr, "invalid pid: %s\n", strerror(errno));
        exit(1);
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SYSTEM_STOP);

    res = aura_msg_send(sock_fd, &hdr, NULL, 0, -1);
    if (res < 0) {
        app_debug(false, errno, "system stop, failed");
    }

    printf("PID: %lu\n", (long unsigned)pid);
    kill(pid, SIGTERM);
}

struct aura_cli_cmd system_stop = {
  .version = "to be filled later",
  .name = "stop",
  .description = "stop description",
  .usage = "stop (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .arguments = NULL,
  .sub_commands = NULL,
  .sub_command_count = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 0,
  .handler = run_system_stop,
  //   .opt_allocator = start_option_allocator,
  //   .opt_destructor = start_option_destructor,
};

void run_system_status() {
    int sock_fd;
    struct msghdr msg;
    struct iovec data[1];
    struct aura_unix_socket cli_socket;
    int res;
    struct aura_msg_hdr header = {
      .type = A_MSG_PING,
      .len = 0,
      .version = "1.0.0",
    };

    res = aura_unix_cli_connect(&cli_socket, AURA_SOCKET, AURA_SOCKET_CLI, CLI_FILE_PERM);
    if (res != 0) {
        fprintf(stderr, "status: down\n");
        exit(1);
    }

    data[0].iov_base = &header;
    data[0].iov_len = sizeof(struct aura_msg_hdr);

    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_iov = data;
    msg.msg_iovlen = 1;

    if (sendmsg(cli_socket.sock_fd, &msg, 0) < 0) {
        fprintf(stderr, "Error sending ping: %s\n", strerror(errno));
    }
}

void run_help_system() {
    printf("Manage system\n");
}

struct aura_cli_cmd system_status = {
  .version = "to be filled later",
  .name = "status",
  .description = "status description",
  .usage = "status (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .arguments = NULL,
  .sub_commands = NULL,
  .sub_command_count = 0,
  .min_args = 0,
  .max_args = 0,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .handler = run_system_status,
};

struct aura_cli_cmd *system_subs[] = {
  &system_start,
  &system_stop,
  &system_status,
};

struct aura_cli_cmd system_cmd = {
  .version = "to be filled later",
  .name = "system",
  .description = "Manage systems",
  .usage = "system (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .arguments = NULL,
  .sub_commands = system_subs,
  .sub_command_count = 3,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .handler = run_help_system // aura_cli_cmd show_help function
};
