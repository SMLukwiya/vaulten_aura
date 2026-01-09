#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

extern struct aura_cli_cmd server_base_cmd;
extern struct aura_cli_cmd system_base_cmd;
extern struct aura_cli_cmd function_base_cmd;

struct aura_cli_flag *root_flags[] = {
  &version_flag,
  &help_flag,
};

void aura_cli_root_handler(void *opt, int argc, char *args[], void *glob_opt) {
    char c;
    if (argc == 0 || strcmp(args[0], "-h") == 0 || strcmp(args[0], "--help") == 0) {
        aura_cli_help_fn();
    } else if (strcmp(args[0], "-v") == 0 || strcmp(args[0], "--version") == 0) {
        aura_cli_version_fn();
    } else
        app_info(false, 0, "unknown aura cli command: aura %s\n\nRun 'aura --help' for more information\n", args[0]);
}

/**
 * Aura Root commanf subs
 */
struct aura_cli_cmd *root_subs[] = {
  &server_base_cmd,
  &system_base_cmd,
  &function_base_cmd,
};

struct aura_cli_cmd root_cmd = {
  .version = "1.0.0",
  .name = "aura",
  .description = "Vaulten aura, high performance edge runtime",
  .usage = "Some slick usage description",
  .deprecated = NULL,
  .flags = root_flags,
  .flag_count = ARRAY_SIZE(root_flags),
  .args = NULL,
  .args_cnt = 0,
  .sub_cmds = root_subs,
  .sub_cmd_cnt = ARRAY_SIZE(root_subs),
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
  .opt_help = aura_cli_help_fn,
};