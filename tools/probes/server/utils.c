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

int aura_server_tool_connect_to_server(const char *host, const char *service) {
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
    return 0;
}