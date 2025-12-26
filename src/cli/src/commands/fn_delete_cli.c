#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "file_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

// #include <fcntl.h>
// #include <stdlib.h>
// #include <sys/types.h>
// #include <unistd.h>

struct fn_delete_config {
    char *fn_name;
};

/* Allocator fn */
void *fn_delete_option_allocator(void) {
    return malloc(sizeof(struct fn_delete_config));
}

/* Deallocator fn */
void fn_delete_option_deallocator(void *opts_ptr) {
    struct fn_delete_config *opts = (struct fn_delete_config *)opts_ptr;
    if (!opts_ptr)
        return;

    if (opts->fn_name)
        free(opts->fn_name);

    free(opts);
}

struct aura_cli_flag fn_delete_flag = {
  .name = "function",
  .short_name = 'f',
  .default_value = NULL,
  .is_hidden = false,
  .deprecated = NULL,
  .is_required = true,
  .is_set = false,
  .type = CLI_FLAG_STRING,
  .offset_in_option = OPT_OFFSET(struct fn_delete_config, fn_name),
  .description = "name of the function to delete",
};

void run_fn_delete(void *opts_ptr, int argc, char *argv[], void *glob_opts) {
    printf("Function Delete\n");
}

/* HELP CMD */
void fn_delete_help() {
    app_info(false, 0, "aura function delete -f <name of function to delete>");
}

struct aura_cli_flag *fn_delete_flags[] = {
  &fn_delete_flag,
};

struct aura_cli_cmd fn_delete_cli = {
  .version = "1.0.0",
  .name = "delete",
  .description = "delete a function specified by the file name",
  .usage = "aura function delete -f <function name>",
  .deprecated = NULL,
  .flags = fn_delete_flags,
  .flag_count = ARRAY_SIZE(fn_delete_flags),
  .arguments = NULL,
  .sub_commands = NULL,
  .sub_command_count = 0,
  .min_args = 1,
  .max_args = 1,
  .is_top_level = false,
  .is_hidden = false,
  .is_experimental = false,
  .options = NULL,
  .options_size = sizeof(struct fn_delete_config),
  .opt_allocator = fn_delete_option_allocator,
  .opt_destructor = fn_delete_option_deallocator,
  .handler = run_fn_delete,
  .opt_help = fn_delete_help,
};
