#ifndef AURA_UTILS_H
#define AURA_UTILS_H

/**
 * @todo: some of this stuff are surely best placed in
 * other places.......
 */

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
#define a_min(x, y) ((x) > (y) ? (y) : (x))
#define a_max(x, y) ((x) > (y) ? (x) : (y))

#define a_ceil(x) ((x % 2) ? ((x / 2) + 1) : x / 2)

#define a_is_power_of_two(x) ((x) != 0 && (((x) & ((x) - 1)) == 0))

#define a_str_lit_static(str) (str), sizeof(str) - 1

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

/* wrapper around strtoul */
static inline size_t aura_strtoul(const char *nptr, size_t len) {
    size_t res;
    char *endptr = NULL;

    if (len == 0)
        goto err_out;

    res = strtoul(nptr, &endptr, 10);
    if (endptr != NULL || endptr == nptr)
        goto err_out;

    if (errno == ERANGE || errno == EINVAL)
        goto err_out;

    return res;

err_out:
    return SIZE_MAX;
}

/* compare two strings converting the first one to lower case */
static inline bool aura_lc_str_is_eq(const char *target, size_t target_len, const char *other, size_t other_len) {
    if (target_len != other_len)
        return false;

    for (; other_len != 0; --other_len)
        if (tolower(*target++) != *other++)
            return false;
    return true;
}

/* wrapper around memcmp */
static inline bool aura_mem_is_eq(const void *target, size_t target_len, const void *other, size_t other_len) {
    const char *t = (const char *)target;
    const char *o = (const char *)other;

    if (target_len != other_len)
        return false;

    if (t[0] != o[0])
        return false;

    return memcmp(target + 1, other + 1, target_len - 1) == 0;
}

int aura_set_fd_flag(int fd, int flag);
int aura_clear_fd_flag(int fd, int flag);
int aura_scan_str(const char *value, const char *fmt, ...);

int aura_install_signal_handler(int signo, void (*handler)(int signo));

/*------------------------------------------------------- */
/**
 * Some Lousy parent child sync stuff
 */

#define A_PARENT_SYNC_CHAR "w"
#define A_CHILD_SYNC_CHAR "z"

int aura_setup_wait(void);
int aura_parent_wait(void);
int aura_child_wait(void);
int aura_parent_proceed(pid_t pid);
int aura_child_proceed(pid_t pid);

/**
 * Some Lousy ass vector impl
 */
/**@todo: remove the base from the name */
typedef struct aura_vector {
    void *data;
    size_t cnt;
    size_t cap;
    size_t elem_size;
} aura_vec_base_st;

void aura_vec_base_init(aura_vec_base_st *v, size_t es);
int aura_vec_base_push(aura_vec_base_st *v, void *el, size_t ec);
void aura_vec_base_free(aura_vec_base_st *v);

/* Macro wrapper *@todo: remove if not used */
#define A_VEC_DEFINE(type)                                                                            \
    typedef struct {                                                                                  \
        aura_vec_base_st base;                                                                        \
    } aura_vec_##type##_st;                                                                           \
                                                                                                      \
    static inline void aura_vec_##type##_init(aura_vec_##type##_st *v) {                              \
        aura_vec_base_init(&v->base, sizeof(type));                                                   \
    }                                                                                                 \
                                                                                                      \
    static inline void aura_vec_##type##_free(aura_vec_##type##_st *v) {                              \
        aura_vec_base_free(&v->base);                                                                 \
    }                                                                                                 \
                                                                                                      \
    static inline int aura_vec_##type##_push(aura_vec_##type##_st *v, const type *value, size_t ec) { \
        aura_vec_base_push(&v->base, value, ec);                                                      \
    }

#endif