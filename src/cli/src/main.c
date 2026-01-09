#include "cmdline_cli.h"

static char **cmd_argv;

int main(int argc, char *argv[]) {
    int ch;
    const char *cmd = argv[0], *opt_config_file;
    cmd_argv = argv;

    if (argc < 2) {
        aura_cli_help_fn();
        return 1;
    }

    /* Parse cmdline args */
    parse_cli_command(--argc, ++argv);

    return 0;
}