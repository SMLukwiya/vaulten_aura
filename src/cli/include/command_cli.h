#ifndef AURA_CLI_COMMAND_H
#define AURA_CLI_COMMAND_H

#include "flag_cli.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define OPT_OFFSET(struct_type, field) (offsetof(struct_type, field))

typedef void (*aura_cli_cmd_handler)(void *opts, int argc, char *args[], void *global_opts);
typedef void *(*option_allocator)(void);
typedef void (*option_destructor)(void *opt);
typedef void (*show_command_help)(void);

/* structure of aura aura_cli_cmd */
struct aura_cli_cmd {
    char *version;
    char *name;
    char *description;
    char *usage;
    char *deprecated;
    struct aura_cli_flag **flags;
    int flag_count;
    char **arguments;
    struct aura_cli_cmd **sub_commands;
    struct aura_cli_cmd *parent;
    int sub_command_count;
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

extern struct aura_cli_cmd system_cmd;
extern struct aura_cli_cmd function_cmd;
extern struct aura_cli_cmd server_cmd;

void *allocate_mem(void *pointer, size_t prev_count, size_t new_count);

#define RESIZE_ARRAY(type, pointer, prev_count, new_count) \
    (type *)allocate_mem((pointer), (sizeof(type) * (prev_count)), (sizeof(type) * (new_count)))

#define FREE_ARRAY(type, pointer, count) \
    allocate_mem((pointer), (sizeof(type) * (count)), 0)

#endif