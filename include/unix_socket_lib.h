#ifndef AURA_UNIX_SOCKET_H
#define AURA_UNIX_SOCKET_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define UNIX_SOCK_ERR_NAMETOOLONG -1
#define UNIX_SOCK_ERR_CREATE -2

#define AURA_SOCKET "/tmp/aurad.sock"
#define AURA_PID "/tmp/aurad.pid"
#define AURA_SOCKET_CLI "/tmp/aura"
#define CLI_FILE_PERM S_IRWXU /* user rwx */

#define INVALID_UNIX_SOCKET -1

#if defined(SCM_CREDS) /* BSD */
#define sock_cred cmsgcred
#define SCM_CRED_TYPE SCM_CREDS
#elif defined(SCM_CREDENTIALS) /* Linux */
#define sock_cred ucred
#define SCM_CRED_TYPE SCM_CREDENTIALS
#define CREDOPT SO_PASSCRED
#endif

#ifdef linux
#define peer_uid(x) ((x)->uid)
#define peer_gid(x) ((x)->gid)
#else
/**/
#endif

typedef enum {
    A_MSG_PING = 1,
    A_MSG_CMD_EXECUTE,
    A_MSG_RESPONSE,
    A_MSG_CONF_DATA
} aura_msg_t;

typedef enum {
    A_CMD_SYSTEM_STOP = 1,
    A_CMD_SERVER_START,
    A_CMD_SERVER_STOP,
    A_CMD_SERVER_STATUS,
    A_CMD_SERVER_VALIDATE_CONF,
    A_CMD_FN_DEPLOY,
    A_CMD_FN_VALIDATE_CONF,
} aura_cmd_t;

struct aura_msg_hdr {
    uint32_t len;
    aura_msg_t type;
    aura_cmd_t cmd_type;
    char version[6];
};

/* custom defined credentials because C is being shady with that 'struct ucred'!! */
struct aura_socket_cred {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

struct aura_msg {
    struct aura_msg_hdr hdr;
    struct aura_socket_cred cred;
    int fd;
    struct iovec data;
};

#define a_init_msg_hdr(hdr, len_, type_, cmd_type_) \
    hdr.len = len_;                                 \
    hdr.type = type_;                               \
    hdr.cmd_type = cmd_type_;                       \
    strcpy(hdr.version, "1.0.0");

#define control_len(x) CMSG_LEN(sizeof(x))
#define control_space(x) CMSG_SPACE(sizeof(x))

/* Unix socket structure */
struct aura_unix_socket {
    int sock_fd;
    int domain;
    struct sockaddr_un addr;
    socklen_t sock_len;
    int flags;
};

int aura_unix_server_listen(struct aura_unix_socket *st, const char *name);
int aura_unix_server_accept(int fd, uid_t *uid_p);
int aura_unix_cli_connect(struct aura_unix_socket *cli, const char *serv_name, const char *cli_name, int cli_perm);
void aura_unix_sock_close(int fd);
int aura_msg_send(int sock_fd, struct aura_msg_hdr *aura_hdr, void *data, size_t data_len, int fd);
int aura_recv_msg(int sock_fd, struct aura_msg *aura_msg);
int aura_send_resp(int sock_fd, void *data, size_t len);
void *aura_recv_resp(int sock_fd);
void aura_dump_msg(struct aura_msg *msg, bool daemon);
void aura_try_connect_or_error(int *fd);

#endif