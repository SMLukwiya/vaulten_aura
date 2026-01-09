#include "cmdline_cli.h"
#include "command_cli.h"
#include "error_lib.h"
#include "flag_cli.h"
#include "unix_socket_lib.h"
#include "utils_lib.h"

#include <string.h>

#define ERROR_INVALID_ARG 1
#define ERROR_INVALID_COMMAND 2

struct aura_cli_ctx cli_ctx;

extern struct aura_cli_cmd root_cmd;

/** Long flag of --flag format */
static inline bool a_is_long_flag(char *flag) {
    return strlen(flag) > 2 && *flag == '-' && (flag + 1) && *(flag + 1) == '-';
}

/** Short flag of -flag format */
static inline bool a_is_short_flag(char *flag) {
    return strlen(flag) == 2 && *flag == '-' && (flag + 1) && *(flag + 1) != '-';
}

/**
 *
 */
void a_set_flag_value(struct aura_cli_flag *flag, void *opt, char *value) {
    void *target = (char *)opt + flag->offset_in_option;

    switch (flag->type) {
    case A_CLI_FLAG_BOOL:
        *(bool *)target = true;
        break;
    case A_CLI_FLAG_STRING:
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
int a_parse_long_arg(struct aura_cli_flag *cmd_flags[], int flag_count,
                     void *opt, char *arg, int argc, char *args[]) {
    char *name, *value;
    char *equal_sign;
    struct aura_cli_flag *flag;

    name = arg + 2;
    value = NULL;
    if (strlen(name) == 0 || *name == '-' || *name == '=') {
        app_info(false, 0, "Bad syntax\n");
        return A_CLI_CMD_ERR;
    }

    if ((equal_sign = strchr(name, '=')) != NULL) {
        value = equal_sign + 1;
        *equal_sign = '\0';
    }

    flag = find_flag(cmd_flags, flag_count, name, false);

    if (!flag)
        if (strcmp(name, "help") == 0) {
            return A_CLI_CMD_HELP;
        } else {
            app_info(false, 0, "unknown flag\n");
            return A_CLI_CMD_HELP;
        }

    /**
     * Always end early when help or version,
     * this works even for invalid commands as long we end with help or version
     * which doesn't quite seem right, but it's helpful
     */
    if (flag) {
        if (flag->short_name == 'h') {
            return A_CLI_CMD_HELP;
        } else if (flag->short_name == 'v') {
            return A_CLI_CMD_VERSION;
        }
    }

    if (value) {
        /* format would be --flag=value */
        a_set_flag_value(flag, opt, value);
        flag->is_set = true;
    } else if (argc > 1) {
        /* format would be --flag value */
        value = args[0];
        a_set_flag_value(flag, opt, value);
        flag->is_set = true;
    } else {
        app_info(false, 0, "flag needs an argument\n");
        return A_CLI_CMD_ERR;
    }

    return A_CLI_CMD_OK;
}

/**
 * We try to get the value from a short flag
 */
static int a_parse_short_arg(struct aura_cli_flag *cmd_flags[], int flag_count,
                             void *opt, char *arg, int argc, char *args[]) {
    char c;
    char *equal_sign, *value, *name;
    struct aura_cli_flag *flag;

    value = NULL;
    name = arg + 1;
    c = *name;
    flag = find_short_flag(cmd_flags, flag_count, c);
    if (!flag) {
        if (c == 'h') {
            return A_CLI_CMD_HELP;
        } else {
            app_info(false, 0, "unknown shorthand: %s\n", arg);
            return A_CLI_CMD_HELP;
        }
    }

    /**
     * Always end early when help or version,
     * this works even for invalid commands as long we end with help or version
     * which doesn't quite seem right, but it's helpful
     */
    if (flag) {
        if (flag->short_name == 'h') {
            return A_CLI_CMD_HELP;
        } else if (flag->short_name == 'v') {
            return A_CLI_CMD_VERSION;
        }
    }

    if (strlen(name) > 2 && *(name + 1) == '=') {
        value = name + 2;
    } else if (argc > 0) {
        value = args[1];
    } else {
        app_info(false, 0, "need argument short\n");
        return A_CLI_CMD_ERR;
    }

    a_set_flag_value(flag, opt, value);
    flag->is_set = true;
    return A_CLI_CMD_OK;
}

static int a_parse_flags(struct aura_cli_cmd *cmd) {
    int i, res;
    char *curr_arg;

    /**
     * only allocate if cmd really works with options.
     * NOTE: make sure the underlying allocator is setup properly
     * and returns valid memory, otherwise you are a danger to society!!
     */
    if (cmd->options == NULL && cmd->options_size > 0 && cmd->opt_allocator)
        cmd->options = cmd->opt_allocator();

    for (i = 0; i < cmd->args_cnt; ++i) {
        curr_arg = cmd->args[i];
        if (a_is_long_flag(curr_arg))
            res = a_parse_long_arg(cmd->flags, cmd->flag_count, cmd->options, curr_arg, cmd->args_cnt, cmd->args);
        else if (a_is_short_flag(curr_arg))
            res = a_parse_short_arg(cmd->flags, cmd->flag_count, cmd->options, curr_arg, cmd->args_cnt, cmd->args);

        switch (res) {
        case A_CLI_CMD_VERSION:
            aura_cli_version_fn();
            exit(0);

        case A_CLI_CMD_HELP:
            aura_cli_cmd_help_fn(cmd);
            exit(0);

        case A_CLI_CMD_ERR:
            exit(0);

        default:
            break;
        }
    }
    return A_CLI_CMD_OK;
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
static int a_parse_command_args(struct aura_cli_ctx *ctx) {
    char *curr_arg;
    int i, pos = 0;
    bool in_flag = false;
    struct aura_cli_cmd *cmd;
    struct aura_cli_cmd *sub;
    size_t flag_size;
    char *flags[ctx->args_count];

    cmd = ctx->current_cmd;
    sub = NULL;
    for (i = 0; i < cmd->args_cnt; ++i) {
        /* we pretend to collect flags until we encounter what may be a subcommand */
        curr_arg = cmd->args[i];

        if (!curr_arg || !*(curr_arg + 1)) {
            app_info(false, 0, "Bad syntax\n");
            return A_CLI_CMD_ERR;
        }

        if (*curr_arg == '-' && *(curr_arg + 1) == '-' && strchr(curr_arg, '=') == NULL) { /* -- (long) */
            in_flag = true;
            flags[pos++] = curr_arg;
            ctx->pos++;
            continue;
        } else if (*curr_arg == '-' && strchr(curr_arg, '=') == NULL && strlen(curr_arg) == 2) { /* - (short) */
            in_flag = true;
            flags[pos++] = curr_arg;
            ctx->pos++;
            continue;
        } else if (in_flag) { /* value */
            in_flag = false;
            flags[pos++] = curr_arg;
            ctx->pos++;
            continue;
        }

        sub = find_command(cmd->sub_cmds, cmd->sub_cmd_cnt, curr_arg);
        if (!sub) {
            return A_CLI_CMD_UNKNOWN;
        }

        /**
         * we could try and validate the current command with its collected flags
         * at this point, and report early errors if we were in our futuristic scenario
         */

        ctx->pos++;
        sub->args = ctx->argv_vec + ctx->pos;
        sub->args_cnt = ctx->args_count - ctx->pos;
        ctx->current_cmd = sub;
        return a_parse_command_args(ctx);
    }
    return A_CLI_CMD_OK;
}

/**
 * run over the passed aura_cli_cmd flags and report missing flags
 * that must be specified by user. Flag values are filled
 * by a_parse_flags(). This is a little hackish!
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
        app_info(false, 0, "Missing required flag(s) %s", str);
        return 1;
    }
}

/**
 *
 */
int a_execute(struct aura_cli_cmd *cmd) {
    int res;

    if (!cmd) {
        app_debug(false, 0, "Trying to execute a NULL command, FIX ASAP!");
        return 1;
    }

    if (cmd->deprecated) {
        app_warn(false, 0, "Aura cli command %s is deprecated: %s", cmd->name, cmd->deprecated);
        return 1;
    }

    res = a_parse_flags(cmd);
    if (res != 0) /* somebody already likely reported it!! */
        return 1;
    ;
    res = validate_required_flags(cmd);
    /* somebody already likely reported it!! */
    if (res != 0) {
        return 1;
    }

    /* run command handler */
    cmd->handler(cmd->options, NULL);
    if (cmd->options && cmd->opt_destructor)
        cmd->opt_destructor(cmd->options);
    app_debug(false, 0, "EXECUTED <<");
    return 0;
}

/**
 *
 */
static int a_parse_and_execute(struct aura_cli_ctx *ctx) {
    struct aura_cli_cmd *cmd, *sub;
    int res = 0;

    cmd = ctx->current_cmd;
    sub = NULL;
    if (cmd->flag_count > 0) {
        res = a_parse_command_args(ctx);
        if (res == A_CLI_CMD_UNKNOWN) {
            aura_cli_command_unknown(ctx);
            return 1;
        }

        if (res != 0) {
            return 1;
        }
        sub = ctx->current_cmd ? ctx->current_cmd : cmd;
    } else {
        sub = find_command(cmd->sub_cmds, cmd->sub_cmd_cnt, ctx->argv_vec[0]);
    }

    return a_execute(sub);
}

/**
 *
 */
static inline void init_cli_context(int argc, char *args[]) {
    root_cmd.args = args;
    root_cmd.args_cnt = argc;

    cli_ctx.current_cmd = &root_cmd;
    cli_ctx.args_count = argc;
    cli_ctx.argv_vec = args;
}

void parse_cli_command(int argc, char *argv[]) {
    init_cli_context(argc, argv);
    a_parse_and_execute(&cli_ctx);
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

int a_validate_cmd_argument_cnt(struct aura_cli_cmd *cmd) {
    /**/
}

void aura_cli_cmd_flag_dump(struct aura_cli_flag *flag) {
    app_debug(false, 0, "AURA CLI CMD FLAG");
    app_debug(false, 0, "   Type: %u", flag->type);
    app_debug(false, 0, "   Name: %s", flag->name);
    app_debug(false, 0, "   Short name: %c", flag->short_name);
    app_debug(false, 0, "   Description: %s", flag->description);
    app_debug(false, 0, "   Default Value: %s", flag->default_value);
    app_debug(false, 0, "   Deprecated: %s", flag->deprecated ? flag->deprecated : "No");
    app_debug(false, 0, "   Hidden: %s", flag->is_hidden ? "Yes" : "No");
    app_debug(false, 0, "   Option required: %s", flag->is_required ? "Yes" : "No");
    app_debug(false, 0, "   Set: %s", flag->is_set ? "Yes" : "No");
}

void aura_cli_command_dump(struct aura_cli_cmd *cmd) {
    app_debug(false, 0, "AURA CLI CMD");
    app_debug(false, 0, "   version: %x", cmd->version);
    app_debug(false, 0, "   name: %s", cmd->name);
    app_debug(false, 0, "   Description: %s", cmd->description);
    app_debug(false, 0, "   Usage: %s", cmd->usage);
    app_debug(false, 0, "   Deprecated:  %s", cmd->deprecated ? cmd->deprecated : "No");
    app_debug(false, 0, "   Min args: %zu", cmd->min_args);
    app_debug(false, 0, "   Max args: %zu", cmd->max_args);
    app_debug(false, 0, "   Top level: %s", cmd->is_top_level ? "Yes" : "No");
    app_debug(false, 0, "   Hidden: %s", cmd->is_hidden ? "Yes" : "No");
    app_debug(false, 0, "   Experimental: %s", cmd->is_experimental ? "Yes" : "No");
    app_debug(false, 0, "   Flag cnt: %zu", cmd->flag_count);
    app_debug(false, 0, "   Sub cmd cnt: %zu", cmd->sub_cmd_cnt);

    for (int i = 0; i < cmd->flag_count; ++i)
        aura_cli_cmd_flag_dump(cmd->flags[i]);

    app_debug(false, 0, "   SUB COMMANDS");
    for (int i = 0; i < cmd->sub_cmd_cnt; ++i) {
        app_debug(false, 0, "    Sub name: %s", cmd->sub_cmds[i]->name);
    }
}