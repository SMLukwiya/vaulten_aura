#ifndef AURA_CMDLINE_H
#define AURA_CMDLINE_H

#include "command_cli.h"
#include "error_lib.h"
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct aura_cli_cxt {
    struct aura_cli_cmd *root_cmd;
    struct aura_cli_cmd *current_cmd;
    char **argv_vec;
    int args_count;
};

void parse_cli_command(int argc, char *argv[]);

#endif