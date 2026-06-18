#ifndef AURA_UTILS_H
#define AURA_UTILS_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ARRAY_SIZE(s) (sizeof(s) / sizeof(s[0]))
#define ARR_CNT(s) (sizeof(s) / sizeof(s[0]))

#ifndef a_min
#define a_min(x, y) ((x) > (y) ? (y) : (x))
#endif

#ifndef a_max
#define a_max(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef a_clamp
#define a_clamp(val, min, max) ((val) < (min) ? (min) : (val) > (max) ? (max) \
                                                                      : (val))
#endif

#define a_ceil(x) (((x) % 2) ? (((x) / 2) + 1) : (x) / 2)

#define a_is_power_of_two(x) ((x) != 0 && (((x) & ((x) - 1)) == 0))

/* WARNING: only use for static character, and character arrays, not character pointers */
#define a_str_lit_static(str) (str), sizeof(str) - 1

/* Read size bytes from fd to buf */
int aura_read_n(int fd, char *buf, size_t size);

/* Write size bytes from buf to fd */
int aura_write_n(int fd, char *buf, size_t size);

/**
 * Returns 0 when num is 0, so one might want to explicitly handle 0 edge case
 * When the power is already two, the correct power is returned
 */
static inline uint64_t a_next_power_of_two(uint32_t num) {
    num--;
    num |= num >> 1;
    num |= num >> 2;
    num |= num >> 4;
    num |= num >> 8;
    num |= num >> 16;
    num++;
    return num;
}

int aura_set_fd_flag(int fd, int flag);
int aura_clear_fd_flag(int fd, int flag);
int aura_scan_str(const char *value, const char *fmt, ...);

int aura_install_signal_handler(int signo, void (*handler)(int signo));

/*------------------------------------------------------- */

#define A_PARENT_SYNC_CHAR "w"
#define A_CHILD_SYNC_CHAR "z"

int aura_setup_wait(void);
int aura_parent_wait(void);
int aura_child_wait(void);
int aura_parent_proceed(pid_t pid);
int aura_child_proceed(pid_t pid);

#endif