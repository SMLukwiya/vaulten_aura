#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <string.h>

#define ERROR_INVALID_ARG 1
#define ERROR_INVALID_COMMAND 2

struct aura_cli_cxt cli_ctx;

struct aura_cli_cmd root_cmd;

struct aura_cli_flag *root_flags[] = {
  &version_flag,
  &help_flag,
};

struct aura_cli_cmd *root_subs[] = {
  &system_cmd,
  &server_cmd,
  &function_cmd,
};

void root_handler(void *opt, int argc, char *args[], void *glob_opt) {
    app_info(false, 0, "root handler");
    char c;
    if (argc == 0 || strcmp(args[0], "-h") == 0 || strcmp(args[0], "--help") == 0) {
        // return root_cmd.show_help();
        app_info(false, 0, "Help command");
    } else if (strcmp(args[0], "-v") == 0 || strcmp(args[0], "--version") == 0) {
        app_info(false, 0, "Vaulten aura version %s", "1.0.0");
    } else
        app_info(false, 0, "unknown aura cli command: aura %s\n\nRun 'aura --help' for more information\n", args[0]);
}

/** @todo: could also be separated */
void *allocate_mem(void *pointer, size_t prev_size, size_t new_size) {
    void *res;

    if (new_size == 0) {
        free(pointer);
        return NULL;
    }

    if ((res = realloc(pointer, new_size)) == NULL) {
        // report error
        exit(1);
    }
    return res;
}

/**
 *
 */
void *allocate_args_array(int count, char *args[], size_t *size) {
    int i, len;
    char *arg_array = NULL, *arg_ptr_pos, *arg_pos;
    size_t array_size = 0;

    for (i = 0; i < count; ++i)
        array_size += strlen(args[i] + 1); /* null terminated */

    array_size += (sizeof(char *) * count);

    arg_array = RESIZE_ARRAY(char, arg_array, 0, array_size);
    *size = array_size;
    arg_ptr_pos = arg_array;
    arg_pos = arg_array + (sizeof(char *) * count);

    for (i = 0; i < count; i++) {
        len = strlen(args[i]);
        arg_ptr_pos + sizeof(char *) * i;
        arg_ptr_pos = strncpy(arg_pos, args[i], len);
        *(arg_pos + len) = '\0';
        arg_pos + len + 1;
    }
    return arg_array;
}

/**/
bool is_long_flag(char *flag) {
    return (strlen(flag) > 2 && *flag == '-' && *(flag + 1) == '-');
}

/**/
bool is_short_flag(char *flag) {
    return strlen(flag) == 2 && *flag == '-' && *(flag + 1) != '-';
}

/**
 *
 */
void set_flag_value(struct aura_cli_flag *flag, void *opt, char *value) {
    void *target = (char *)opt + flag->offset_in_option;

    switch (flag->type) {
    case CLI_FLAG_BOOL:
        *(bool *)target = true;
        break;
    case CLI_FLAG_STRING:
        /* we may not need this */
        if (*(char **)target)
            free(*(char **)target);
        *(char **)target = strdup(value);
        break;
    default:
        // report error
    }
}

/**
 *
 */
struct aura_cli_flag *find_flag(struct aura_cli_flag *cmd_flags[], int flag_count, char *name, bool short_name) {
    int i;

    for (i = 0; i < flag_count; ++i) {
        if (strcmp(cmd_flags[i]->name, name) == 0)
            return cmd_flags[i];
    }

    return NULL;
}

/**
 *
 */
struct aura_cli_flag *find_short_flag(struct aura_cli_flag *cmd_flags[], int flag_count, char name) {
    int i;

    for (i = 0; i < flag_count; ++i) {
        if (cmd_flags[i]->short_name == name)
            return cmd_flags[i];
    }

    return NULL;
}

/**
 * We try to get the value from a long flag
 */
int parse_long_arg(struct aura_cli_flag *cmd_flags[], int flag_count, void *opt, char *arg, int argc, char *args[]) {
    char *name = arg + 2, *value = NULL;
    char *equal_sign;
    struct aura_cli_flag *flag;

    if (strlen(name) == 0 || *name == '-' || *name == '=') {
        // report error bad flag syntax
        app_info(false, 0, "Bad syntax\n");
        return 1;
    }

    if ((equal_sign = strchr(name, '=')) != NULL) {
        value = equal_sign + 1;
        *equal_sign = '\0';
    }

    flag = find_flag(cmd_flags, flag_count, name, false);

    if (!flag)
        if (strcmp(name, "help") == 0) {
            // call flag usage helper
            return 0;
        } else {
            app_info(false, 0, "unknown flag\n");
            return 1;
        }

    /**
     * Always end early when help or version,
     * this works even for invalid commands as long we end with help or version
     * which doesn't quite seem right, but it's helpful
     */
    if (flag) {
        if (flag->short_name == 'h') {
            app_info(false, 0, "Aura help command");
            exit(0);
        } else if (flag->short_name == 'v') {
            app_info(false, 0, "Aura version command");
            exit(0);
        }
    }

    if (value) { /* format would be --flag=value */
        set_flag_value(flag, opt, value);
        flag->is_set = true;
    } else if (argc > 1) { /* format would be --flag value */
        value = args[0];
        set_flag_value(flag, opt, value);
        flag->is_set = true;
    } else {
        app_info(false, 0, "flag needs an argument\n");
        return 1;
    }

    return 0;
}

/**
 * We try to get the value from a short flag
 */
int parse_short_arg(struct aura_cli_flag *cmd_flags[], int flag_count, void *opt, char *arg, int argc, char *args[]) {
    char c, *equal_sign, *value = NULL, *name = arg + 1;
    struct aura_cli_flag *flag;

    c = *name;
    flag = find_short_flag(cmd_flags, flag_count, c);
    if (!flag) {
        if (c == 'h') {
            // print usage aura_cli_cmd
            return 0;
        } else {
            // report unknown shorthand flag
            app_info(false, 0, "unknown shorthand: %s\n", arg);
            return 1;
        }
    }

    /**
     * Always end early when help or version,
     * this works even for invalid commands as long we end with help or version
     * which doesn't quite seem right, but it's helpful
     */
    if (flag) {
        if (flag->short_name == 'h') {
            app_info(false, 0, "Aura help command");
            exit(0);
        } else if (flag->short_name == 'v') {
            app_info(false, 0, "Aura version command");
            exit(0);
        }
    }

    if (strlen(name) > 2 && *(name + 1) == '=') {
        value = name + 2;
    } else if (argc > 0) {
        value = args[1];
        // update args position perhaps
    } else {
        // report need an argument
        app_info(false, 0, "need argument short\n");
        return 1;
    }

    // if (opt != NULL)
    set_flag_value(flag, opt, value);
    flag->is_set = true;
    return 0;
}

int parse_flags(struct aura_cli_cmd *cmd, int argc, char *args[]) {
    int i, res;
    char *curr_arg;

    /**
     * only allocate if cmd really works with options.
     * NOTE: make sure the underlying allocator is setup properly
     * and returns valid memory, otherwise you are a danger to society!!
     */
    if (cmd->options == NULL && cmd->opt_allocator && cmd->options_size > 0)
        cmd->options = cmd->opt_allocator();

    for (i = 0; i < argc; ++i) {
        curr_arg = args[i];
        if (is_long_flag(curr_arg))
            res = parse_long_arg(cmd->flags, cmd->flag_count, cmd->options, curr_arg, argc, args);
        else if (is_short_flag(curr_arg))
            res = parse_short_arg(cmd->flags, cmd->flag_count, cmd->options, curr_arg, argc, args);

        if (res != 0) {
            // break and return
            return 1;
        }
    }
    return 0;
}

struct aura_cli_cmd *find_command(struct aura_cli_cmd *sub_cmds[], int sub_cmd_count, char *name) {
    int i;

    for (i = 0; i < sub_cmd_count; ++i) {
        if (strcmp(sub_cmds[i]->name, name) == 0)
            return sub_cmds[i];
    }
    return NULL;
}

/**
 * We are trying to be a little futuristic here
 * as we could run into use cases with parent commands
 * having their own flags. Right now, flags are only on
 * leaf commands. We currently error on any parent flags
 */
int parse_command_args(struct aura_cli_cxt *ctx) {
    char *curr_arg;
    int i, pos = 0;
    bool in_flag = false;
    struct aura_cli_cmd *cmd = ctx->current_cmd;
    struct aura_cli_cmd *sub = NULL;
    char *flags[ctx->args_count];
    size_t flag_size;

    for (i = 0; i < ctx->args_count; ++i) {
        /* we pretend to collect flags until we encounter what may be a subcommand */
        curr_arg = ctx->argv_vec[i];

        if (*curr_arg == '-' && *(curr_arg + 1) == '-' && strchr(curr_arg, '=') == NULL) { /* -- (long) */
            in_flag = true;
            flags[pos++] = curr_arg;
            continue;
        } else if (*curr_arg == '-' && strchr(curr_arg, '=') == NULL && strlen(curr_arg) == 2) { /* - (short) */
            in_flag = true;
            flags[pos++] = curr_arg;
            continue;
        } else if (in_flag) { /* value */
            in_flag = false;
            flags[pos++] = curr_arg;
            continue;
        }

        sub = find_command(cmd->sub_commands, cmd->sub_command_count, curr_arg);
        if (!sub) {
            return 0;
        }

        /**
         * we could try and validate the current command with its collected flags
         * at this point, and report early errors if we were in our futuristic scenario
         */

        ctx->args_count = ctx->args_count - pos - 1;
        ctx->argv_vec = ctx->argv_vec + pos + 1;
        ctx->current_cmd = sub;
        return parse_command_args(ctx);
    }
    return 0;
}

/**
 * run over the passed aura_cli_cmd flags and report missing flags
 * that must be specified by user. Flag values are filled
 * by parse_flags(). This is a little hackish!
 */
int validate_required_flags(struct aura_cli_cmd *cmd) {
    int i;
    struct aura_cli_flag *fl;
    char *missing_flags[cmd->flag_count];
    int missing_flag_count = 0, missing_flags_str_len = 0;

    for (i = 0; i < cmd->flag_count; ++i) {
        fl = cmd->flags[i];
        if (fl->is_required && !fl->is_set && fl->default_value == NULL) {
            missing_flags[missing_flag_count++] = fl->name;
            missing_flags_str_len += strlen(fl->name) + 2; /* +2 for separator, see below */
        }
    }

    if (missing_flag_count == 0)
        return 0;
    else {
        char str[missing_flags_str_len + 1];
        int flag_offset = 0;
        for (i = 0; i < missing_flag_count; ++i) {
            /* join missing flags using separator (", ") */
            snprintf(str + flag_offset, missing_flags_str_len, "%s%s", missing_flags[i], i < missing_flag_count - 1 ? ", " : "");
            flag_offset += strlen(missing_flags[i]);
        }
        str[missing_flags_str_len] = '\0';
        return 1;
    }
}

/**
 *
 */
int execute(struct aura_cli_cmd *cmd, int argc, char *args[]) {
    int res;

    if (!cmd) {
        app_alert(false, 0, "Trying to run execute() without aura_cli_cmd, you ain't slick");
        return 1;
    }

    if (cmd->deprecated) {
        app_warn(false, 0, "aura_cli_cmd %s is deprecated: %s", cmd->name, cmd->deprecated);
        return 1;
    }

    res = parse_flags(cmd, argc, args);
    if (res != 0) /* somebody already likely reported it!! */
        return 1;

    res = validate_required_flags(cmd);
    if (res != 0) /* somebody already likely reported it!! */
        return 1;

    cmd->handler(cmd->options, argc, args, NULL); /* run aura_cli_cmd */
    if (cmd->options && cmd->opt_destructor)
        cmd->opt_destructor(cmd->options);
    return 0;
}

/**
 *
 */
int parse_and_execute(struct aura_cli_cxt *ctx) {
    struct aura_cli_cmd *cmd = ctx->root_cmd;
    struct aura_cli_cmd *sub = NULL;
    int res = 0;

    if (cmd->flag_count > 0) {
        res = parse_command_args(ctx);
        if (res != 0) {
            if (ctx->current_cmd) {
                // maybe report error in the sub aura_cli_cmd context
                return 1;
            }
        }
        sub = ctx->current_cmd ? ctx->current_cmd : cmd;
    } else {
        sub = find_command(cmd->sub_commands, cmd->sub_command_count, ctx->argv_vec[0]);
    }

    execute(sub, ctx->args_count, ctx->argv_vec);
}

/**
 *
 */
static inline void init_cli_context(int argc, char *args[]) {
    root_cmd.name = "aura";
    root_cmd.description = "Aura cli";
    root_cmd.handler = root_handler;
    root_cmd.flags = root_flags;
    root_cmd.flag_count = ARRAY_SIZE(root_flags);
    root_cmd.sub_commands = root_subs;
    root_cmd.sub_command_count = ARRAY_SIZE(root_subs);
    root_cmd.arguments = args;
    cli_ctx.root_cmd = &root_cmd;
    cli_ctx.current_cmd = &root_cmd;
    cli_ctx.args_count = argc;
    cli_ctx.argv_vec = args;
}

void parse_cli_command(int argc, char *argv[]) {
    init_cli_context(argc, argv);
    parse_and_execute(&cli_ctx);
    return;
}

/**
 * @todo: move to separate file
 */
int no_args(struct aura_cli_cmd *cmd, int argc, char **argv) { /** @todo: use parser context */
    if (argc > 0) {
        app_info(false, 0, "unknown aura_cli_cmd %s used with %s\n", argv[0], cmd->name);
        return -1;
    }
    return 0;
}

/** @todo: use parser context */
int exact_args(int argc, int accepted_argc) {
    if (argc != accepted_argc) {
        app_info(false, 0, "accepts %d arg(s) but received %d args(s)\n", accepted_argc, argc);
        return -1;
    }
    return 0;
}

/** @todo: use parser context */
int range_args(int argc, int max, int min) {
    if (argc > max || argc < min) {
        app_info(false, 0, "accepts between %d and %d arg(s) but received %d args(s)\n", min, max, argc);
        return -1;
    }
    return 0;
}