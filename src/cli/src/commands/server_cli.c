#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

extern struct aura_cli_cmd server_start_cli;
extern struct aura_cli_cmd server_config_validate_cli;
extern struct aura_cli_cmd server_stop_cli;
extern struct aura_cli_cmd server_status_cli;

int aura_cli_server_handler() {
    app_info(false, 0, "Manage server, lists command");
    return 0;
}

static void a_server_help() {
    app_info(false, 0, "Manage server, lists command");
}

/**
 * server sub commands
 */
struct aura_cli_cmd *server_subs[] = {
  &server_start_cli,
  &server_config_validate_cli,
  &server_stop_cli,
  &server_status_cli,
};

struct aura_cli_cmd server_base_cmd = {
  .version = "1.0.0",
  .name = "server",
  .description = "Manage server, e.g, deploy, delete...etc",
  .usage = "Manage aura server, run with help to see options",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .args = NULL,
  .args_cnt = 0,
  .sub_cmds = server_subs,
  .sub_cmd_cnt = ARRAY_SIZE(server_subs),
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 0,
  .opt_allocator = NULL,
  .opt_destructor = NULL,
  .handler = aura_cli_server_handler,
  .opt_help = a_server_help,
};