#ifndef AURA_STRING_H
#define AURA_STRING_H

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_16_TO_10(x) (((x) >= '0' && (x) <= '9') ? ((x) - '0') : (toupper((x)) - 'A' + 10))

size_t _strlcpy(char *dest, const char *src, size_t size);
size_t _strlcat(char *dest, const char *src, size_t size);

#endif