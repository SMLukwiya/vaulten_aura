#ifndef AURA_DAEMON_H
#define AURA_DAEMON_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <signal.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>

#define DAEMON_FILE_MODES (S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)

void aura_daemonize(const char *command, int keep_fds[], int keep_fd_count);
bool aura_dmn_running(int fd);
int aura_dmn_set_pid_lock(int fd);

#endif