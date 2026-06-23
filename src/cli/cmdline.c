#include "cmdline.h"
#include "command.h"
#include "error_lib.h"
#include "flag.h"
#include "unix/sock.h"
#include "utils_lib.h"

#include <string.h>

#define ERROR_INVALID_ARG 1
#define ERROR_INVALID_COMMAND 2

void aura_cli_cmd_flag_dump(struct aura_cli_flag *flag);

/** Long flag of --flag format */
static inline bool a_arg_is_long_flag(char *flag) {
    return strlen(flag) > 2 && *flag == '-' && (flag + 1) && *(flag + 1) == '-';
}

/** Short flag of -flag format */
static inline bool a_arg_is_short_flag(char *flag) {
    if (strlen(flag) == 2 && *flag == '-' && (flag + 1) && isalpha(*(flag + 1)))
        return true;

    if (strlen(flag) > 2 && *flag == '-' && isalpha(*(flag + 1)) && *(flag + 2) == '=')
        return true;
}

/**
 *
 */
int a_set_flag_value(struct aura_cli_flag *flag, void *opt, char *value) {
    void *target;
    int rv;

    target = (char *)opt + flag->offset_in_option;
    rv = A_CLI_CMD_OK;
    switch (flag->type) {
    case A_CLI_FLAG_BOOL:
        if (!value || *value == '\0')
            *(bool *)target = true;
        /* parse value to get bool */
        break;
    case A_CLI_FLAG_STRING:
        if (!value || *value == '\0') {
            if (flag->is_required) {
                rv = A_CLI_CMD_VALUE_MISSING;
                break;
            }
        }
        if (!flag->is_required) {
            rv = A_CLI_CMD_BAD_SYNTAX;
            break;
        }
        /** @todo: how do handle duplicate flags */
        if (flag->is_set) {
            // if (*(char **)target)
            // free(*(char **)target);
        } else {
            *(char **)target = strdup(value);
            flag->is_set = true;
        }
        break;
    default:
        // report error
        break;
    }

    return rv;
}

/**
 *
 */
static inline struct aura_cli_flag *find_flag(struct aura_cli_flag *cmd_flags[], int flag_count, char *name, bool short_name) {

    for (int i = 0; i < flag_count; ++i) {
        if (strcmp(cmd_flags[i]->name, name) == 0)
            return cmd_flags[i];
    }

    return NULL;
}

/**
 *
 */
static inline struct aura_cli_flag *find_short_flag(struct aura_cli_flag *cmd_flags[], int flag_count, char name) {

    for (int i = 0; i < flag_count; ++i) {
        if (cmd_flags[i]->short_name == name)
            return cmd_flags[i];
    }

    return NULL;
}

/**
 * We try to get the value from a long flag
 */
int a_parse_long_flag(struct aura_cli_cmd *cmd, char *arg) {
    char *name, *value;
    char *equal_sign;
    struct aura_cli_flag *flag;

    name = arg + 2;
    value = NULL;
    if (strlen(name) == 0 || *name == '-' || *name == '=') {
        return A_CLI_CMD_BAD_SYNTAX;
    }

    equal_sign = strchr(name, '=');
    if (equal_sign) {
        value = equal_sign + 1;
        *equal_sign = '\0';
    }

    flag = find_flag(cmd->flags, cmd->flag_cnt, name, false);
    if (!flag) {
        return A_CLI_CMD_UNKNOWN_FLAG;
    }

    /**
     * We end early when help or version,
     * Even for invalid commands, as long it ends with help or version
     * which might be more helpful than complete rejection
     */
    if (flag->short_name == 'h') {
        return A_CLI_CMD_HELP;
    } else if (flag->short_name == 'v') {
        return A_CLI_CMD_VERSION;
    }

    if (value) {
        /* format would be --flag=value */
        cmd->matched++;
    } else if (cmd->args_cnt - cmd->matched > 1) {
        /* format would be --flag value */
        cmd->matched += 2;
        value = cmd->args[cmd->matched - 1]; /* -1 for zero indexed */
    }

    return a_set_flag_value(flag, cmd->options, value);
}

/**
 * We try to get the value from a short flag
 */
static int a_parse_short_flag(struct aura_cli_cmd *cmd, char *arg) {
    char *name, *value;
    char c;
    struct aura_cli_flag *flag;

    value = NULL;
    name = arg + 1;
    c = *name;
    flag = find_short_flag(cmd->flags, cmd->flag_cnt, c);
    if (!flag) {
        if (c == 'h') {
            return A_CLI_CMD_HELP;
        } else {
            return A_CLI_CMD_UNKNOWN_FLAG;
        }
    }

    /**
     * We end early when help or version,
     * Even for invalid commands, as long it ends with help or version
     * which might be more helpful than complete rejection
     */
    if (flag->short_name == 'h') {
        return A_CLI_CMD_HELP;
    } else if (flag->short_name == 'v') {
        return A_CLI_CMD_VERSION;
    }

    if (strlen(name) > 2 && *(name + 1) == '=') {
        /* format would be -f=value */
        value = name + 2;
        cmd->matched++;
    } else if (cmd->args_cnt - cmd->matched > 1) {
        /* format would be -f value */
        cmd->matched += 2;
        value = cmd->args[cmd->matched - 1]; /* -1 for zero indexed */
    }

    return a_set_flag_value(flag, cmd->options, value);
}

static int a_parse_flags(struct aura_cli_cmd *cmd, struct aura_cli_ctx *ctx) {
    int i, res;
    char *curr_arg;

    /**
     * For the case where a command is specified without
     * arguments, but said command expects arguments.
     * Run the help function of the command!
     */
    if (cmd->args_cnt == 1 && cmd->flag_cnt == 0) {
        cmd->opt_help();
        return -1;
    }

    /**
     * only allocate if cmd really works with options.
     * NOTE: make sure the underlying allocator is setup properly
     * and returns valid memory, otherwise you are a danger to society!!
     */
    /** @todo: should all commands get options allocator and deallocator */
    if (cmd->options == NULL && cmd->options_size > 0 && cmd->opt_allocator)
        cmd->options = cmd->opt_allocator();

    cmd->matched = 0;
    for (i = 0; i < cmd->args_cnt;) {
        curr_arg = cmd->args[i];
        if (a_arg_is_long_flag(curr_arg)) {
            res = a_parse_long_flag(cmd, curr_arg);
            i += cmd->matched;
        } else if (a_arg_is_short_flag(curr_arg)) {
            res = a_parse_short_flag(cmd, curr_arg);
            i += cmd->matched;
        } else {
            res = A_CLI_CMD_UNKNOWN;
        }

        switch (res) {
        case A_CLI_CMD_VERSION:
            aura_cli_version_fn();
            exit(0);

        case A_CLI_CMD_HELP:
            aura_cli_cmd_help_fn(cmd);
            exit(0);

        case A_CLI_CMD_BAD_SYNTAX:
            aura_cli_cmd_bad_syntax(cmd);
            exit(0);

        case A_CLI_CMD_UNKNOWN_FLAG:
            aura_cli_unknown_flag(cmd);
            exit(0);

        case A_CLI_CMD_UNKNOWN:
            aura_cli_command_unknown(ctx);
            exit(0);

        case A_CLI_CMD_VALUE_MISSING:
            aura_cli_cmd_value_missing(cmd);
            exit(0);

        case A_CLI_CMD_ERR:
            exit(0);

        default:
            break;
        }
    }

    return 0;
}

struct aura_cli_cmd *find_command(struct aura_cli_cmd *sub_cmds[], int sub_cmd_count, char *name) {

    for (int i = 0; i < sub_cmd_count; ++i) {
        if (strcmp(sub_cmds[i]->name, name) == 0)
            return sub_cmds[i];
    }
    return NULL;
}

/**
 * Parent commands can have their own flags.
 * Right now however, flags are only on
 * leaf commands.
 */
static int a_parse_command_args(struct aura_cli_ctx *ctx) {
    char *curr_arg;
    int i, pos = 0;
    bool in_flag;
    struct aura_cli_cmd *cmd;
    struct aura_cli_cmd *sub;
    size_t flag_size;
    char *flags[ctx->args_cnt];

    cmd = ctx->current_cmd;
    sub = NULL;
    in_flag = false;

    /**
     *
     */
    for (i = 0; i < cmd->args_cnt; ++i) {
        curr_arg = cmd->args[i];

        if (*curr_arg == '-' && !strchr(curr_arg, '=')) {
            in_flag = true;
            ctx->pos++;
            continue;
        } else if (*curr_arg == '-') {
            ctx->pos++;
            continue;
        }

        if (in_flag) {
            in_flag = false;
            continue;
        }

        sub = find_command(cmd->sub_cmds, cmd->sub_cmd_cnt, curr_arg);
        if (!sub) {
            aura_cli_command_unknown(ctx);
            return A_CLI_CMD_UNKNOWN;
        }

        /**
         * we could try and validate the current command with its collected flags
         * at this point, and report early errors if we were in our futuristic scenario
         */

        ctx->pos++;
        sub->args = ctx->argv_vec + ctx->pos;
        sub->args_cnt = ctx->args_cnt - ctx->pos;
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
    char *missing_flags[cmd->flag_cnt];
    int missing_flag_count = 0, missing_flags_str_len = 0;

    for (i = 0; i < cmd->flag_cnt; ++i) {
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
int a_execute(struct aura_cli_cmd *cmd, struct aura_cli_ctx *ctx) {
    int res;

    if (!cmd) {
        app_debug(false, 0, "Trying to execute a NULL command, FIX ASAP!");
        return 1;
    }

    if (cmd->deprecated) {
        app_info(false, 0, "Aura cli command %s is deprecated: %s", cmd->name, cmd->deprecated);
        return 1;
    }

    res = a_parse_flags(cmd, ctx);
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
    return 0;
}

/**
 *
 */
int aura_parse_and_execute(struct aura_cli_ctx *ctx) {
    struct aura_cli_cmd *cmd, *sub;
    int res = 0;

    cmd = ctx->current_cmd;
    sub = NULL;

    /**
     * Here we are sure that the first cmd (aura) always
     * has a flag count greater than 0, since we define it as
     * such!
     */
    if (cmd->flag_cnt > 0) {
        res = a_parse_command_args(ctx);

        if (res != 0) {
            return 1;
        }
        sub = ctx->current_cmd ? ctx->current_cmd : cmd;
    }

    return a_execute(sub, ctx);
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
    app_debug(false, 0, "   Flag cnt: %zu", cmd->flag_cnt);
    app_debug(false, 0, "   Sub cmd cnt: %zu", cmd->sub_cmd_cnt);

    for (int i = 0; i < cmd->flag_cnt; ++i)
        aura_cli_cmd_flag_dump(cmd->flags[i]);

    app_debug(false, 0, "   SUB COMMANDS");
    for (int i = 0; i < cmd->sub_cmd_cnt; ++i) {
        app_debug(false, 0, "    Sub name: %s", cmd->sub_cmds[i]->name);
    }
}