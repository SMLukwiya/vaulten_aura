#ifndef AURA_SERVER_TOOLS_UTILS_H
#define AURA_SERVER_TOOLS_UTILS_H

#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>
#include <unistd.h>

#include "error_lib.h"

#define A_MAKE_NV(name, value) {(uint8_t *)name, (uint8_t *)value, strlen(name), strlen(value), 0}

int aura_server_tool_connect_to_server(const char *host, const char *service);

#endif