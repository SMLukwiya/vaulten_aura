#ifndef AURA_DMN_FUNCTION_H
#define AURA_DMN_FUNCTION_H

#include "db/db.h"

/* validate function config */
void aura_dmn_fn_conf_validate(int fd, int cli_fd);

/**
 * Deploy a function receiving the directory fd and cli fd
 */
void aura_dmn_fn_deploy(int dir_fd, int cli_fd, void *arg);

/** Delete Function */
void aura_dmn_fn_del(struct iovec *fn, int cli_fd, void *arg);

/** Function status */
void aura_dmn_fn_status(struct iovec *fn, int cli_fd, void *arg);

/** Function start */
void aura_dmn_fn_start(struct iovec *fn, int cli_fd, void *arg);

/** Function stop */
void aura_dmn_fn_stop(struct iovec *fn, int cli_fd, void *arg);

/** List functions */
void aura_dmn_fn_list(struct iovec *state, int cli_fd, void *arg);

#endif