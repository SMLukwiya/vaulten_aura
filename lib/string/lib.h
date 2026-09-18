#ifndef AURA_STRING_H
#define AURA_STRING_H

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"

#define BASE_16_TO_10(x) (((x) >= '0' && (x) <= '9') ? ((x) - '0') : (toupper((x)) - 'A' + 10))
#define A_STR_BUF_KEY_WIDTH 16

/* string buffer */
struct aura_str_buf {
    struct aura_mem_ctx *mc;
    char *data;
    uint64_t len;
    uint64_t cap;
};

/**
 * trim whitespace in the front
 * and back of a string.
 * Returns the str without whitespaces, with
 * it's new length
 */
static inline char *aura_str_trim(char *str, uint64_t *len) {
    uint64_t _len = *len;
    while (_len > 0 && isspace(*str)) {
        ++str;
        --_len;
    }

    while (_len > 0 && isspace(*(str + _len - 1)))
        --_len;

    *len = _len;
    return str;
}

/* Duplicate string pointed to by str */
char *aura_strdup(struct aura_mem_ctx *mc, const char *str);

/* Duplicate exactly len bytes of string pointed to by str */
char *aura_strndup(struct aura_mem_ctx *mc, const char *str, size_t len);

/* Returns a new copy of the str in uppercase letters */
char *aura_str_touppercase(struct aura_mem_ctx *mc, const char *str, size_t len);

/* Returns a new copy of the str in lowercase letter */
char *aura_str_tolowercase(struct aura_mem_ctx *mc, const char *str, size_t len);

/* Copy len bytes from data and return new destination */
void *aura_memcpy(struct aura_mem_ctx *mc, const void *data, size_t len);

/* compare two strings converting the first one to lower case */
bool aura_lc_str_is_eq(const char *target, size_t target_len, const char *other, size_t other_len);

/* wrapper around memcmp */
bool aura_mem_is_eq(const void *target, size_t target_len, const void *other, size_t other_len);

/* wrapper around strtoul */
size_t aura_strtoul(const char *nptr, size_t len);

/**
 * Initialize string buffer
 */
int aura_str_buf_init(struct aura_str_buf *buf, struct aura_mem_ctx *mc, uint64_t cap);

/**
 * Destroy string buffer
 */
void aura_str_buf_destroy(struct aura_str_buf *buf);

/**
 * Add formatted string into the string buffer
 */
int aura_str_buf_print(struct aura_str_buf *buf, const char *fmt, ...);

/**
 * Append key value pair into string buffer.
 */
int aura_str_buf_append_field(struct aura_str_buf *buf, const char *prefix, const char *key, const char *value);

/**
 * Append a single string into string buffer
 */
int aura_str_buf_append(struct aura_str_buf *buf, const char *s);

/**
 * Append continuation to an already structured field
 */
int aura_str_buf_append_continuation(struct aura_str_buf *buf, const char *prefix, const char *value);

#endif