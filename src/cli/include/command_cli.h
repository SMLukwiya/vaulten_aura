#ifndef AURA_CLI_COMMAND_H
#define AURA_CLI_COMMAND_H

#include "flag_cli.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define OPT_OFFSET(struct_type, field) (offsetof(struct_type, field))

typedef int (*aura_cli_cmd_handler)(void *opts, void *global_opts);
typedef void *(*option_allocator)(void);
typedef void (*option_destructor)(void *opt);
typedef void (*show_command_help)(void *arg);

/* structure of aura aura_cli_cmd */
struct aura_cli_cmd {
    char *version;
    char *name;
    char *description;
    char *usage;
    char *deprecated;
    struct aura_cli_flag **flags;
    int flag_count;
    char **args;
    uint32_t args_cnt;
    struct aura_cli_cmd **sub_cmds;
    struct aura_cli_cmd *parent;
    int sub_cmd_cnt;
    uint32_t min_args;
    uint32_t max_args;
    bool is_top_level;
    bool is_hidden;
    bool is_experimental;
    void *options;
    size_t options_size;
    aura_cli_cmd_handler handler;
    option_allocator opt_allocator;
    option_destructor opt_destructor;
    show_command_help opt_help;
    /** @todo: add grouping */
};

#endif