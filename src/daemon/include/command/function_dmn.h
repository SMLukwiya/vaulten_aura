#ifndef AURA_DMN_FUNCTION_H
#define AURA_DMN_FUNCTION_H

#include "db/db.h"

/* validate function config */
void aura_dmn_function_config_validate(int fd, int cli_fd);

/**
 * Deploy a function receiving the directory fd and cli fd
 */
void aura_dmn_function_deploy(int dir_fd, int srv_fd, int cli_fd);

/** Delete Function */
void aura_dmn_function_delete(AURA_DBHANDLE db, struct iovec *fn, int cli_fd);

/* Function status */
void aura_dmn_function_status(AURA_DBHANDLE db, struct aura_memory_ctx *, struct iovec *fn, int cli_fd);

/* Function start */
void aura_dmn_function_start(AURA_DBHANDLE db, struct aura_memory_ctx *mc, struct iovec *fn, int cli_fd);

/* Function stop */
void aura_dmn_function_stop(AURA_DBHANDLE db, struct aura_memory_ctx *mc, struct iovec *fn, int cli_fd);

/** List functions */
void aura_dmn_function_list(AURA_DBHANDLE db, struct iovec *state, int cli_fd);

#endif