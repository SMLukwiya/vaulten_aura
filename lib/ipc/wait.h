#ifndef AURA_IPC_WAIT_H
#define AURA_IPC_WAIT_H

#include <fcntl.h>
#include <unistd.h>

#define A_PARENT_SYNC_CHAR "w"
#define A_CHILD_SYNC_CHAR "z"

int aura_setup_ipc_wait(void);
int aura_parent_ipc_wait(void);
int aura_child_ipc_wait(void);
int aura_parent_ipc_proceed(pid_t pid);
int aura_child_ipc_proceed(pid_t pid);
void aura_destroy_ipc_wait(void);

#endif