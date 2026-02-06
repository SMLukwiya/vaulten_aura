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
typedef void (*show_command_help)(void);

/* structure of aura aura_cli_cmd */
struct aura_cli_cmd {
    char *version;                    /* CLI command verison */
    char *name;                       /* CLI command name */
    char *description;                /* CLI command description */
    char *usage;                      /* CLI command usage description */
    char *deprecated;                 /* CLI command deprecated text */
    struct aura_cli_flag **flags;     /* CLI command flags array */
    int flag_cnt;                     /* CLI commmand flags count */
    char **args;                      /* CLI command arguments provided by user */
    uint32_t args_cnt;                /* CLI command arguments count */
    int matched;                      /* Number of cli Arguments matched */
    struct aura_cli_cmd **sub_cmds;   /* Sub commands array for the CLI command */
    int sub_cmd_cnt;                  /* Number of sub commands for the CLI command */
    struct aura_cli_cmd *parent;      /* Parent for this CLI command */
    uint32_t min_args;                /* Minimum number of flags accepted */
    uint32_t max_args;                /* Maximum number of flags accepted */
    bool is_top_level;                /* Is the CLI command a top level command when parsing */
    bool is_hidden;                   /* CLI command hidden, probably for internal or ...! */
    bool is_experimental;             /* CLI command is experimental */
    void *options;                    /* CLI command options for the different flag values */
    size_t options_size;              /* CLI command option size */
    aura_cli_cmd_handler handler;     /* Function called to execute the logic for this command */
    option_allocator opt_allocator;   /* Memory allocator function for the command's option */
    option_destructor opt_destructor; /* Memory deallocator function for the command's option */
    show_command_help opt_help;       /* Function called when command is specified with h/help flag */
    /** @todo: add grouping */
};

#endif