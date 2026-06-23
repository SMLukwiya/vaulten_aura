#ifndef AURA_STRING_H
#define AURA_STRING_H

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"

#define BASE_16_TO_10(x) (((x) >= '0' && (x) <= '9') ? ((x) - '0') : (toupper((x)) - 'A' + 10))

size_t _strlcpy(char *dest, const char *src, size_t size);
size_t _strlcat(char *dest, const char *src, size_t size);

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

#endif