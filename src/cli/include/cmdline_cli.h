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

struct aura_cli_ctx {
    struct aura_cli_cmd *root_cmd;
    struct aura_cli_cmd *current_cmd;
    char **argv_vec;
    int args_count;
    uint32_t pos;
};

typedef enum {
    A_CLI_CMD_OK,
    A_CLI_CMD_ERR,
    A_CLI_CMD_HELP,
    A_CLI_CMD_VERSION,
    A_CLI_CMD_UNKNOWN,
} aura_cli_cmd_return_t;

void parse_cli_command(int argc, char *argv[]);

static inline void aura_cli_version_fn() {
    app_info(false, 0, "Vaulten aura version %s", "1.0.0");
}

/* Per command help function */
static inline void aura_cli_cmd_help_fn(struct aura_cli_cmd *cmd) {
    printf(
      "Command: %s\n"
      "%s\n"
      "%s\n",
      cmd->name,
      cmd->description,
      cmd->usage);
}

/* generic help function */
static void aura_cli_help_fn() {
    printf(
      "Usage:  aura [OPTIONS | COMMAND]\n\n"

      "Commands:\n"
      "\tstart        Start an app entity\n"
      "\tstop         Stop an app entity\n"
      "\trestart      Restart the applicaton\n"
      "\tupdate       Update an app entity\n" /** @todo: could be confusing with version update */
      "\tstatus       Show application status information\n"
      "\tversion      Show version infomation\n"
      "\tget          Get application configuration\n"
      "\tset          Set application configurations\n"
      "\tlist         List application configurations\n" /** @todo: this is a little shady */
      "\tfunction     Manage functions\n"
      "\tdeploy       Deploy function\n"
      "\tremove       Remove function\n"
      "\thealth       Probe application internals\n"
      "\trace         Enable Tracing\n\n"

      "Global Options:\n"
      "\t--config string      Location of config files (default \"/home/lukwiya/.docker\")\n"
      "\t--tlscacert string   Trust certs signed only by this CA (default \"/home/lukwiya/.docker/ca.pem\")\n"
      "\t--tlscert string     Path to TLS certificate file (default \"/home/lukwiya/.docker/cert.pem\")\n"
      "\t--tlskey string      Path to TLS key file (default \"/home/lukwiya/.docker/key.pem\")\n");
}

static inline void aura_cli_command_unknown(struct aura_cli_ctx *ctx) {
    int cmd_len, i, len;

    cmd_len = 0;
    for (i = 0; i < ctx->args_count && ctx->argv_vec[i]; ++i) {
        cmd_len += strlen(ctx->argv_vec[i]) + 1; /* space */
    }

    char str_buf[cmd_len];

    str_buf[0] = '\0';
    for (i = 0; i < ctx->args_count; ++i) {
        snprintf(str_buf + strlen(str_buf), len + 1, "%s ", ctx->argv_vec[i]);
    }

    app_info(false, 0, "unknown aura cli command: aura %s\n\nRun 'aura --help' for more information\n", str_buf);
}

void aura_cli_command_dump(struct aura_cli_cmd *cmd);

#endif