#include "cmdline_cli.h"

static char **cmd_argv;
struct aura_cli_ctx cli_ctx;

extern struct aura_cli_cmd root_cmd;

static char **a_cli_cmd_replicate(int argc, char **argv) {
    char **argv_replica;

    argv_replica = malloc(sizeof(char *) * argc);
    for (int i = 0; i < argc && argv[i]; ++i) {
        argv_replica[i] = strdup(argv[i]);
    }

    return argv_replica;
}

/**
 *
 */
static inline void init_cli_context(int argc, char *args[]) {
    root_cmd.args = args;
    root_cmd.args_cnt = argc;

    cli_ctx.current_cmd = &root_cmd;
    cli_ctx.args_cnt = argc;
    cli_ctx.argv_vec = args;
    cli_ctx.pos = 0;
}

int main(int argc, char *argv[]) {
    cmd_argv = a_cli_cmd_replicate(argc, argv);

    if (argc < 2) {
        aura_cli_help_fn();
        return 1;
    }

    /* Parse cmdline args */
    init_cli_context(--argc, ++argv);
    aura_parse_and_execute(&cli_ctx);

    return 0;
}