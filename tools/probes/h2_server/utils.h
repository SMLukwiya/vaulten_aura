#ifndef AURA_SERVER_TOOLS_UTILS_H
#define AURA_SERVER_TOOLS_UTILS_H

#include <assert.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "error_lib.h"

#define A_MAKE_NV(name, value) {(uint8_t *)name, (uint8_t *)value, strlen(name), strlen(value), 0}

int aura_server_tool_connect(const char *host, const char *service);
void aura_server_tool_close_conn(int fd);

uint8_t *aura_pack_8u(uint8_t *dest, uint8_t val);
uint8_t *aura_pack_16u(uint8_t *dest, uint16_t val);
uint8_t *aura_pack_24u(uint8_t *dest, uint32_t val);
uint8_t *aura_pack_32u(uint8_t *dest, uint32_t val);

uint8_t aura_unpack_8u(uint8_t *dest);
uint16_t aura_unpack_16u(uint8_t *dest);
uint32_t aura_unpack_24u(uint8_t *dest);
uint32_t aura_unpack_32u(uint8_t *dest);

#endif