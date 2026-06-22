#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "ipc/ipc.h"
#include "unix/sock.h"
#include "utils_lib.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>

// struct aura_cli_sys_start_opts {
//     char *system_config_path;
// };

// static void *a_system_start_option_allocator(void) {
//     return malloc(sizeof(struct aura_cli_sys_start_opts));
// }

// static void a_system_start_option_destructor(void *opts_ptr) {
//     struct aura_cli_sys_start_opts *opts = (struct aura_cli_sys_start_opts *)opts_ptr;
//     if (!opts_ptr)
//         return;

//     if (opts->system_config_path)
//         free(opts->system_config_path);

//     free(opts);
// }

// struct aura_cli_flag path_flag = {
//   .name = "path",
//   .short_name = 'p',
//   .default_value = NULL,
//   .is_hidden = false,
//   .deprecated = NULL,
//   .is_required = true,
//   .is_set = false,
//   .type = A_CLI_FLAG_STRING,
//   .offset_in_option = OPT_OFFSET(struct aura_cli_sys_start_opts, system_config_path),
//   .description = "Path flag description",
// };

// struct aura_cli_flag *system_start_flags[] = {
//   &path_flag,
// };

#ifdef AURA_DEV_BUILD
/**/
#else
/**/
#endif

/* Start aura system up */
#ifdef AURA_DEV_BUILD
#else
int aura_cli_system_start(void *opts_ptr, void *glob_opts) {
    return 0;
}

int aura_cli_system_stop(void *opts_ptr, void *glob_opts) {
    return 0;
}

int aura_cli_system_status(void *opts, void *glob_opts) {
    return 0;
}
#endif

int aura_cli_system_start(void *opts_ptr, void *glob_opts) {
    struct aura_cli_sys_start_opts *opts = (struct aura_cli_sys_start_opts *)opts_ptr;
    pid_t pid;
    int sock_fd;
    char sock_file[A_MAX_SOCK_FILE_LEN];

    aura_ipc_get_unix_sock_path(true, sock_file, sizeof(sock_file));
    sock_fd = aura_try_connect_or_error(sock_file);
    if (sock_fd != -1) {
        app_info(false, 0, system_up);
        return 0;
    }

    pid = fork();
    if (pid < 0) {
        sys_info(false, errno, "aura_cli_system_start: fork error:");
        return -1;
    }

    if (pid == 0) {
        execlp("aura_daemon", "aura_daemon", (char *)0);
        sys_debug(false, errno, "execlp error starting server");
    } else {
        app_info(false, 0, "System started!");
    }
    return 0;
}

/* aura system start cmd */
struct aura_cli_cmd system_start_cmd = {
  .version = "to be filled later",
  .name = "start",
  .description = "start description",
  .usage = "start (describe usage)",
  .deprecated = NULL,
  //   .flags = system_start_flags,
  //   .flag_cnt = ARRAY_SIZE(system_start_flags),
  .flags = NULL,
  .flag_cnt = 0,
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
  //   .options_size = ARRAY_SIZE(system_start_flags),
  .options_size = 0,
  .handler = aura_cli_system_start,
  //   .opt_allocator = a_system_start_option_allocator,
  //   .opt_destructor = a_system_start_option_destructor,
};

/* Stop aura system */
int aura_cli_system_stop(void *opts_ptr, void *glob_opts) {
    struct aura_msg_hdr hdr;
    int rv, sock_fd;
    struct aura_iovec data;
    char sock_file[A_MAX_SOCK_FILE_LEN];

    aura_ipc_get_unix_sock_path(true, sock_file, sizeof(sock_file));
    sock_fd = aura_try_connect_or_error(sock_file);
    if (sock_fd == -1) {
        app_info(false, 0, system_down);
        app_info(false, 0, system_start);
        return -1;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_CMD_EXECUTE, A_CMD_SYSTEM_STOP);

    if (aura_msg_send(sock_fd, &hdr, NULL, 0, -1) != 0) {
        sys_info(false, errno, cmd_send_failed);
        return -1;
    }

    while (true) {
        rv = aura_recv_resp(&data, sock_fd, NULL);
        if (rv < 0 || data.base == NULL)
            break;
    }

    app_info(false, errno, "system_stopped");

    return 0;
}

struct aura_cli_cmd system_stop_cmd = {
  .version = "to be filled later",
  .name = "stop",
  .description = "stop description",
  .usage = "stop (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_cnt = 0,
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
    int sock_fd;
    struct aura_msg_hdr hdr;
    struct aura_msg msg;
    char sock_file[A_MAX_SOCK_FILE_LEN];

    aura_ipc_get_unix_sock_path(true, sock_file, sizeof(sock_file));
    sock_fd = aura_try_connect_or_error(sock_file);
    if (sock_fd == -1) {
        app_info(false, 0, system_down);
        app_info(false, 0, system_start);
        return -1;
    }

    a_init_msg_hdr(hdr, 0, A_MSG_PING, 0);
    if (aura_msg_send(sock_fd, &hdr, NULL, 0, -1) != 0) {
        sys_info(false, errno, cmd_send_failed);
        return -1;
    }

    if (aura_msg_recv(sock_fd, &msg) <= 0)
        return -1;

    if (msg.hdr.type == A_MSG_RESPONSE) {
        app_info(false, 0, "%s", system_up);
    } else {
        app_info(false, 0, "%s", system_down);
    }

    return 0;
}

static void a_system_status_help() {
    printf("Server status help\n");
}

struct aura_cli_cmd system_status_cmd = {
  .version = "to be filled later",
  .name = "status",
  .description = "status description",
  .usage = "status (describe usage)",
  .deprecated = NULL,
  .flags = NULL,
  .flag_cnt = 0,
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
  &system_start_cmd,
  &system_stop_cmd,
  &system_status_cmd,
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
  .flag_cnt = 0,
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
