#ifndef AURA_DMN_COMMAND_H
#define AURA_DMN_COMMAND_H

#include <signal.h>

/* validate function config */
void aura_dmn_function_config_validate(int fd, int cli_fd);

/* validate server config */
void aura_dmn_server_config_validate(int fd, int cli_fd);

/**
 * Deploy a function receiving the directory fd and cli fd
 */
void aura_dmn_function_deploy(int dir_fd, int srv_fd, int cli_fd);

/** Delete Function */
void aura_dmn_function_delete(AURA_DBHANDLE db, struct iovec *key, int cli_fd);

#endif