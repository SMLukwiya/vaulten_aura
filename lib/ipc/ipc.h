#ifndef AURA_APP_PATH_H
#define AURA_APP_PATH_H

#include <stdbool.h>
#include <stddef.h>

static char system_up[] = "\x1B[1;32mSystem up\x1B[0m";
static char system_down[] = "\x1B[1;31mSystem down\x1B[0m";
static char system_start[] = "\x1B[1;33muse 'aura system start' to start aura daemon\x1B[0m";
static char cmd_send_failed[] = "\x1B[1;31mFailed to send cli command\x1B[0m";
static char file_error[] = "\x1B[1;31mFile error\x1B[0m";
static char dir_error[] = "\x1B[1;31mDirectory error\x1B[0m";

/* Get sock file path */
void aura_ipc_get_unix_sock_path(bool dev_mode, char *path, size_t len);

#endif