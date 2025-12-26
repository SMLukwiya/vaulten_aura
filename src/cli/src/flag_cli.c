#include "command_cli.h"

struct aura_cli_flag version_flag = {
  .name = "version",
  .short_name = 'v',
  .description = "version command",
  .default_value = NULL,
  .deprecated = NULL,
  .is_hidden = false,
};

struct aura_cli_flag help_flag = {
  .name = "help",
  .short_name = 'h',
  .description = "help command",
  .default_value = NULL,
  .deprecated = NULL,
  .is_hidden = false,
};
