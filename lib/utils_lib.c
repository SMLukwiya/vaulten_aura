#if defined(SOLARIS) /* Solaris 10 */
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 700
#endif
#include "utils_lib.h"

int aura_set_fd_flag(int fd, int flag) {
    int val;

    val = fcntl(fd, F_GETFL, 0);
    if (val < 0)
        return -1;

    val |= flag;
    return fcntl(fd, F_SETFL, val);
}

int aura_clear_fd_flag(int fd, int flag) {
    int val;

    val = fcntl(fd, F_GETFL, 0);
    if (val < 0)
        return -1;

    val &= ~flag;
    return fcntl(fd, F_SETFL, val);
}

int aura_read_n(int fd, char *buf, size_t size) {
    int n_left;
    int n_read = 0;
    char *ptr = buf;

    n_left = size;
    while (n_left > 0) {
        if ((n_read = read(fd, buf, n_left)) < 0) {
            if (errno == EINTR) {
                n_read = 0;
                continue; /* try again */
            } else
                return -1;
        } else if (n_read == 0)
            break; /* EOF */

        n_left -= n_read;
        ptr += n_read;
    }

    return (size - n_left); /* return how much was read */
}

int aura_write_n(int fd, char *buf, size_t size) {
    int n_left;
    int n_written = 0;
    char *ptr = buf;

    n_left = size;
    while (n_left > 0) {
        if ((n_written = write(fd, buf, n_left)) < 0) {
            if (errno = EINTR) {
                n_written = 0;
                continue; /* try again */
            } else
                return -1;
        } else if (n_written == 0)
            break; /* EOF */

        n_left -= n_written;
        ptr += n_written;
    }

    return (size - n_left); /* return how much was written */
}

/**
 * Scan
 */
int aura_scan_str(const char *value, const char *fmt, ...) {
    va_list vp;
    int res, err;

    err = errno;
    errno = 0;
    va_start(vp, fmt);
    res = vsscanf(value, fmt, vp);
    va_end(vp);

    if (errno != 0)
        return -1;
    errno = err;
    return res;
}

/**
 *
 */
static int wait_fd1[2], wait_fd2[2];

int aura_setup_wait(void) {
    if (pipe(wait_fd1) < 0 || pipe(wait_fd2) < 0)
        return -1;
    return 0;
}

int aura_parent_wait(void) {
    char a;
    int res;

    res = read(wait_fd1[0], &a, 1);
    if (res != 1)
        return -1;

    if (a != *A_PARENT_SYNC_CHAR)
        return -1;

    return 0;
}

int aura_child_wait(void) {
    char a;
    int res;

    res = read(wait_fd2[0], &a, 1);
    if (res != 1)
        return -1;

    if (a != *A_CHILD_SYNC_CHAR)
        return -1;

    return 0;
}

int aura_parent_proceed(pid_t pid) {
    int res;

    res = write(wait_fd1[1], A_PARENT_SYNC_CHAR, 1);
    if (res != 1)
        return -1;
    return 0;
}

int aura_child_proceed(pid_t pid) {
    int res;

    res = write(wait_fd2[1], A_CHILD_SYNC_CHAR, 1);
    if (res != 1)
        return -1;
    return 0;
}

/**
 *
 */
int aura_install_signal_handler(int signo, void (*handler)(int signo)) {
    struct sigaction action;

    action.sa_handler = handler;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    return sigaction(signo, &action, NULL);
}
