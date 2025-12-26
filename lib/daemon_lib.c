#include "daemon_lib.h"
#include "error_lib.h"
#include "file_lib.h"
#include "unix_socket_lib.h"
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/signal.h>

void re_read_config() {}

static inline int do_cleanup(char *pid_file) {
    unlink(pid_file);
}

void aura_terminate(int signo) {
    do_cleanup(AURA_PID);
    exit(0);
}

void sighup(int signo) {
    re_read_config();
}

void daemonize(const char *command, int keep_fds[], int keep_fd_count) {
    int i, fd, null_fd;
    pid_t pid;
    bool keep_fd;
    struct rlimit f_limit;
    struct sigaction term_sa;

    /* clear and set file creation mask */
    umask(0);

    if (getrlimit(RLIMIT_NOFILE, &f_limit) < 0) {
        fprintf(stderr, "getrlimit() aura daemon init failed: %s\n", strerror(errno));
        exit(1);
    }

    if ((pid = fork()) < 0) {
        fprintf(stderr, "fork() aura daemon init failed: %s\n", strerror(errno));
        exit(1);
    } else if (pid != 0)
        exit(0);

    setsid();

    /* Initialize log file */
    openlog(command, LOG_CONS, LOG_DAEMON);

    /* change root dir to avoid mounted roots */
    if (chdir("/") < 0)
        exit(1);

    /* try to handle shutdown request gracefully */
    sigemptyset(&term_sa.sa_mask);
    term_sa.sa_flags = 0;
    term_sa.sa_handler = aura_terminate;

    if (sigaction(SIGTERM, &term_sa, NULL) < 0)
        exit(1);

    pid = fork();
    if (pid < 0) {
        exit(1);
    } else if (pid != 0)
        exit(0);

    /* close all open files leaving the needed ones */
    if (f_limit.rlim_cur == RLIM_INFINITY)
        f_limit.rlim_max = 1024;

    for (fd = 0; fd < f_limit.rlim_max; ++fd) {
        keep_fd = false;
        for (i = 0; i < keep_fd_count; ++i)
            if (keep_fds[i] == fd) {
                keep_fd = true;
                break;
            }
        if (keep_fd == false)
            close(fd);
    }

    /* attach std fds to /dev/null */
    null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        if (dup2(null_fd, STDIN_FILENO) < 0 || dup2(null_fd, STDOUT_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0) {
            exit(1);
        }
    }
}

/**
 * check if daemon already has an instance running
 */
pid_t already_running(int fd) {
    return a_is_write_lockable(fd, 0, SEEK_SET, 0) != 1;
}

/* try and lock pid file */
int set_pid_lock(int fd) {
    char buf[16];

    if (a_lockfile(fd) < 0) {
        if (errno == EACCES || errno == EAGAIN)
            close(fd);
        return -1;
    }

    ftruncate(fd, 0);
    sprintf(buf, "%ld", (long)getpid());
    write(fd, buf, strlen(buf) + 1);
    return 0;
}