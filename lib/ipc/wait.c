#include "wait.h"

/**
 *
 */
static int wait_fd1[2], wait_fd2[2];

int aura_setup_ipc_wait(void) {
    if (pipe(wait_fd1) < 0 || pipe(wait_fd2) < 0)
        return -1;
    return 0;
}

void aura_destroy_ipc_wait(void) {
    close(wait_fd1[0]);
    close(wait_fd1[1]);
    close(wait_fd2[0]);
    close(wait_fd2[1]);
}

int aura_parent_ipc_wait(void) {
    char a;
    int res;

    res = read(wait_fd1[0], &a, 1);
    if (res != 1)
        return -1;

    if (a != *A_PARENT_SYNC_CHAR)
        return -1;

    return 0;
}

int aura_child_ipc_wait(void) {
    char a;
    int res;

    res = read(wait_fd2[0], &a, 1);
    if (res != 1)
        return -1;

    if (a != *A_CHILD_SYNC_CHAR)
        return -1;

    return 0;
}

int aura_parent_ipc_proceed(pid_t pid) {
    int res;

    res = write(wait_fd1[1], A_PARENT_SYNC_CHAR, 1);
    if (res != 1)
        return -1;
    return 0;
}

int aura_child_ipc_proceed(pid_t pid) {
    int res;

    res = write(wait_fd2[1], A_CHILD_SYNC_CHAR, 1);
    if (res != 1)
        return -1;
    return 0;
}