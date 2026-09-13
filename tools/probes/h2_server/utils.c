#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "utils.h"
#include "error_lib.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int aura_server_tool_connect(const char *host, const char *service) {
    struct addrinfo hints, *res, *_res;
    struct sockaddr_in addr;
    int sock_fd, rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo(host, service, &hints, &res);
    if (rv != 0)
        return -1;

    _res = res;

    do {
        sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock_fd < 0)
            continue;

        if (connect(sock_fd, res->ai_addr, res->ai_addrlen) == 0)
            break;
        close(sock_fd);
    } while ((res = res->ai_next));

    if (!res)
        return -1;

    freeaddrinfo(_res);
    return sock_fd;
}

uint8_t *aura_pack_8u(uint8_t *dest, uint8_t val) {
    *dest++ = val;
    return dest;
}

uint8_t *aura_pack_16u(uint8_t *dest, uint16_t val) {
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
}

uint8_t *aura_pack_24u(uint8_t *dest, uint32_t val) {
    *dest++ = val >> 16;
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
}

uint8_t *aura_pack_32u(uint8_t *dest, uint32_t val) {
    *dest++ = val >> 24;
    *dest++ = val >> 16;
    *dest++ = val >> 8;
    *dest++ = val;
    return dest;
}

uint8_t aura_unpack_8u(uint8_t *src) {
    return (uint8_t)src[0];
}

uint16_t aura_unpack_16u(uint8_t *src) {
    return (uint16_t)(src[0] << 8 | src[1]);
}

uint32_t aura_unpack_24u(uint8_t *src) {
    return (uint32_t)(src[0] << 16 | src[1] << 8 | src[2]);
}

uint32_t aura_unpack_32u(uint8_t *src) {
    return (uint32_t)(src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
}