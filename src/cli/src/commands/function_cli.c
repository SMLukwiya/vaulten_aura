#include "cmdline_cli.h"
#include "utils_lib.h"

extern struct aura_cli_cmd fn_deploy_cli;
extern struct aura_cli_cmd fn_delete_cli;
extern struct aura_cli_cmd fn_config_validate_cli;

struct aura_cli_cmd *function_subs[] = {
  &fn_deploy_cli,
  &fn_delete_cli,
  &fn_config_validate_cli,
};

void run_help_func() {
    printf("Manage functions\n");
}

struct aura_cli_cmd function_cmd = {
  .version = "1.0.0",
  .name = "function",
  .description = "Manage functions, e.g, deploy, delete...etc",
  .usage = "Manage aura functions, run with help to see options",
  .deprecated = NULL,
  .flags = NULL,
  .flag_count = 0,
  .arguments = NULL,
  .sub_commands = function_subs,
  .sub_command_count = ARRAY_SIZE(function_subs),
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = 0,
  .opt_allocator = NULL,
  .opt_destructor = NULL,
  .handler = NULL,
  .opt_help = run_help_func,
};
