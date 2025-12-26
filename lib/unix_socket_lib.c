#include "unix_socket_lib.h"
#include "error_lib.h"
#include "string_lib.h"

void a_dump_msghdr(struct msghdr *msg, bool daemon) {
    app_debug(daemon, 0, "msghdr dump:");
    app_debug(daemon, 0, " msg_name: %p", msg->msg_name);
    app_debug(daemon, 0, " msg_namelen: %d", msg->msg_namelen);
    app_debug(daemon, 0, " msg_iov: %p", msg->msg_iov);
    app_debug(daemon, 0, " msg_iovlen: %ld", msg->msg_iovlen);
    app_debug(daemon, 0, " msg_control: %p", msg->msg_control);
    app_debug(daemon, 0, " msg_controllen: %zu", msg->msg_controllen);
    app_debug(daemon, 0, " msg_flags: %d", msg->msg_flags);

    if (msg->msg_iov && msg->msg_iovlen > 0) {
        for (size_t i = 0; i < msg->msg_iovlen; ++i) {
            app_debug(daemon, 0, "  iov[%zu]: base = %p, len = %zu", i, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        }
    }

    if (msg->msg_control && msg->msg_controllen > 0) {
        struct cmsghdr *cmsg;
        struct sock_cred *credp;

        for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            app_debug(daemon, 0, "cmsg -> %ld", cmsg->cmsg_len);
            switch (cmsg->cmsg_type) {
            case SCM_RIGHTS:
                app_debug(daemon, 0, "File descriptor");
                app_debug(daemon, 0, "FD: %d", *(int *)CMSG_DATA(cmsg));
                break;
            case SCM_CRED_TYPE:
                app_debug(daemon, 0, "Credentials");
                credp = (struct sock_cred *)CMSG_DATA(cmsg);
                app_debug(daemon, 0, "uid: %d", credp->uid);
                app_debug(daemon, 0, "gid: %d", credp->gid);
                app_debug(daemon, 0, "pid: %d", credp->pid);
                break;
            default:
                app_debug(daemon, 0, "Unknown control type");
            }
        }
    }
}

void aura_dump_msg(struct aura_msg *msg, bool daemon) {
    app_debug(daemon, 0, "aura message:");
    app_debug(daemon, 0, "   message header:");
    app_debug(daemon, 0, "       header length: %d", msg->hdr.len);
    app_debug(daemon, 0, "       message type: %d", msg->hdr.type);
    app_debug(daemon, 0, "       cmd type: %d", msg->hdr.cmd_type);
    app_debug(daemon, 0, "       message version: %s", msg->hdr.version);
    app_debug(daemon, 0, "   message credentials:");
    app_debug(daemon, 0, "       uid: %d", msg->cred.uid);
    app_debug(daemon, 0, "       gid: %d", msg->cred.gid);
    app_debug(daemon, 0, "       pid: %d", msg->cred.pid);
    app_debug(daemon, 0, "   message credentials:");
    app_debug(daemon, 0, "   file desc: %d", msg->fd);
    app_debug(daemon, 0, "   data: %p", msg->data.iov_base);
    app_debug(daemon, 0, "   data len: %u", msg->data.iov_len);
}

/* Adds file descriptor as part of the message */
static inline void a_add_integer(struct cmsghdr *cmsg, int value) {
    cmsg->cmsg_len = control_len(int);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = value;
}

/* Adds user credentials as part of the message */
static inline void a_add_credentials(struct cmsghdr *cmsg) {
    struct sock_cred *cred;
    cmsg->cmsg_len = control_len(struct sock_cred);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_CRED_TYPE;
    cred = (struct sock_cred *)CMSG_DATA(cmsg);
#if defined(SCM_CREDENTIALS)
    /* initilize for linux */
    cred->uid = getuid();
    cred->gid = getgid();
    cred->pid = getpid();
#endif
}

/** send */
/** @todo: it could be better to initialize the header here when sending */
int aura_msg_send(int sock_fd, struct aura_msg_hdr *aura_hdr, void *data, size_t data_len, int fd) {
    struct msghdr msg;
    struct cmsghdr *cmsg_ptr;
    bool send_fd = fd > -1;
    struct iovec iov_data[2];
    size_t iov_len = 2, res;
    size_t buf_len = control_space(struct sock_cred);
    if (send_fd) {
        buf_len += control_space(int);
    }
    struct cmsghdr *cmsg;
    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov_data, 0, (2 * sizeof(struct iovec)));

    cmsg = malloc(buf_len);
    if (!cmsg)
        return 1;

    iov_data[0].iov_base = aura_hdr;
    iov_data[0].iov_len = sizeof(struct aura_msg_hdr);
    if (data) {
        iov_data[1].iov_base = data;
        iov_data[1].iov_len = data_len;
    }

    msg.msg_iov = iov_data;
    msg.msg_iovlen = iov_len;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = cmsg;
    msg.msg_controllen = buf_len;

    cmsg_ptr = cmsg;
    a_add_credentials(cmsg_ptr);
    if (send_fd) {
        cmsg_ptr = CMSG_NXTHDR(&msg, cmsg_ptr);
        a_add_integer(cmsg_ptr, fd);
    }

    res = sendmsg(sock_fd, &msg, 0);
    if (res == -1) {
        free(cmsg);
        return 1;
    }

    free(cmsg);
    return 0;
}

int aura_send_resp(int sock_fd, void *data, size_t len) {
    errno = 0;
    int res;
    struct msghdr msg;
    struct iovec iov[2];
    struct aura_msg_hdr aura_hdr;

    memset(&iov, 0, 2 * sizeof(struct iovec));
    memset(&msg, 0, sizeof(struct msghdr));
    a_init_msg_hdr(aura_hdr, len, A_MSG_RESPONSE, 0);
    iov[0].iov_base = &aura_hdr;
    iov[0].iov_len = sizeof(struct aura_msg_hdr);
    if (data) {
        iov[1].iov_base = data;
        iov[1].iov_len = len;
    }
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    res = sendmsg(sock_fd, &msg, 0);
    if (res < 0)
        return 1;

    return 0;
}

/**
 * Receive message into an aura message structure
 * NOTE: user must check header length if > 0 and free memory allocated for data
 */
int aura_recv_msg(int sock_fd, struct aura_msg *aura_msg) {
    size_t ctrl_len = control_space(int) + control_space(struct sock_cred); /* we assume both are passed */
    struct msghdr msg;
    struct cmsghdr *cmsg_ptr;
    struct sock_cred *cred;
    struct cmsghdr cmsg[ctrl_len];
    struct iovec iov[1];
    size_t iov_len = 1;
    char *payload;
    ssize_t n_received;

    memset(aura_msg, 0, sizeof(struct aura_msg));

#if defined(CREDOPT)
    const int on = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, CREDOPT, &on, sizeof(int)) < 0) {
        return -1;
    }
#endif
    iov[0].iov_base = &aura_msg->hdr;
    iov[0].iov_len = sizeof(struct aura_msg_hdr);

    msg.msg_control = cmsg;
    msg.msg_controllen = ctrl_len;
    msg.msg_iov = iov;
    msg.msg_iovlen = iov_len;

    /* read header */
    do {
        n_received = recvmsg(sock_fd, &msg, 0);
    } while (n_received == -1 && (errno == EINTR || errno == EAGAIN)); /* ignore interrupt signal */

    if (n_received < 0) {
        return -2;
    }

    if (n_received == 0) {
        return 0;
    }

    /* body was sent, process body */
    if (aura_msg->hdr.len > 0) {
        payload = malloc(aura_msg->hdr.len);
        if (payload == NULL)
            return -3;

        iov[0].iov_base = payload;
        iov[0].iov_len = aura_msg->hdr.len;

        msg.msg_iov = iov;
        msg.msg_iovlen = iov_len;

        /* read payload */
        do {
            n_received = recvmsg(sock_fd, &msg, 0);
        } while (n_received == -1 && (errno == EINTR || errno == EAGAIN)); /* ignore interrupt signal */

        if (n_received < 0) {
            return -4;
        }

        if (n_received == 0) {
            return 0;
        }

        aura_msg->data.iov_base = payload;
        aura_msg->data.iov_len = aura_msg->hdr.len;
    }

    /* extract credentials */
    cmsg_ptr = CMSG_FIRSTHDR(&msg);
    if (cmsg_ptr->cmsg_type != SCM_CRED_TYPE) {
        // report invalid ancillary format
        return -1;
    }
    cred = (struct sock_cred *)CMSG_DATA(cmsg_ptr);
    aura_msg->cred.uid = cred->uid;
    aura_msg->cred.gid = cred->gid;
    aura_msg->cred.pid = cred->pid;

    cmsg_ptr = CMSG_NXTHDR(&msg, cmsg_ptr);
    if (cmsg_ptr != NULL && cmsg_ptr->cmsg_type == SCM_RIGHTS) {
        /* file desc exists */
        aura_msg->fd = *(int *)CMSG_DATA(cmsg_ptr);
    }

    return 1;
}

void *aura_recv_resp(int sock_fd) {
    errno = 0;
    struct aura_msg_hdr hdr;
    struct msghdr msg;
    struct iovec iov[1];
    int n_received;
    char *payload;

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(struct aura_msg_hdr);
    memset(&msg, 0, sizeof(struct msghdr));

    /* read header */
    do {
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        n_received = recvmsg(sock_fd, &msg, 0);
    } while (n_received == -1 && (errno == EINTR || errno == EAGAIN)); /* ignore interrupt signal */
    if (n_received < 0) {
        return NULL;
    }

    /* body was sent, process body */
    if (hdr.len > 0) {
        if ((payload = malloc(hdr.len)) == NULL)
            return NULL;
        iov[0].iov_base = payload;
        iov[0].iov_len = hdr.len;

        /* read payload */
        do {
            msg.msg_iov = iov;
            msg.msg_iovlen = 1;
            n_received = recvmsg(sock_fd, &msg, 0);
        } while (n_received == -1 && (errno == EINTR || errno == EAGAIN)); /* ignore interrupt signal */
        if (n_received < 0) {
            return NULL;
        }

        if (n_received == 0) {
            return 0;
        }

        return payload;
    }

    return NULL;
}

/**/
static inline unsigned int a_unix_sock_addr_init(struct sockaddr_un *addr, const char *name, size_t len) {
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;

    memcpy(addr->sun_path, name, len);
    return offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path);
}

static inline void a_unix_sock_init(struct aura_unix_socket *st, const char *name, size_t len) {
    st->domain = AF_UNIX;
    st->flags = 0;
    st->sock_fd = INVALID_UNIX_SOCKET;
    st->sock_len = a_unix_sock_addr_init(&st->addr, name, len);
}

/**/
int aura_unix_server_listen(struct aura_unix_socket *st, const char *name) {
    errno = 0;
    int res;
    size_t name_len = strlen(name);

    if (name_len >= sizeof(st->addr.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memset(st, 0, sizeof(struct aura_unix_socket));
    a_unix_sock_init(st, name, name_len);

    st->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (st->sock_fd < 0)
        return -1;

    unlink(name); /* delete if file exists */

    res = bind(st->sock_fd, (struct sockaddr *)&st->addr, st->sock_len);
    if (res < 0)
        goto err_out;

    res = listen(st->sock_fd, 10);
    if (res < 0)
        goto err_out;

    return 0;

err_out:
    res = errno;
    close(st->sock_fd);
    errno = res;
    return -1;
}

/**/
int aura_unix_cli_connect(struct aura_unix_socket *cli, const char *serv_name, const char *cli_name, int cli_perm) {
    errno = 0;
    int res, len;
    bool unlink_file;
    struct sockaddr_un server_addr;

    unlink_file = false;
    if (strlen(serv_name) >= sizeof(server_addr.sun_path)) {
        errno = ENAMETOOLONG;
        return UNIX_SOCK_ERR_NAMETOOLONG;
    }

    memset(cli, 0, sizeof(struct aura_unix_socket));
    a_unix_sock_init(cli, cli_name, strlen(cli_name));

    cli->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli->sock_fd < 0)
        return UNIX_SOCK_ERR_CREATE;

    unlink(cli->addr.sun_path);

    res = bind(cli->sock_fd, (struct sockaddr_in *)&cli->addr, cli->sock_len);
    if (res < 0) {
        goto err_out;
    }

    res = chmod(cli->addr.sun_path, cli_perm);
    if (res < 0) {
        unlink_file = true;
        goto err_out;
    }

    len = a_unix_sock_addr_init(&server_addr, serv_name, strlen(serv_name));

    res = connect(cli->sock_fd, (struct sockaddr *)&server_addr, len);
    if (res < 0) {
        if (errno == ENOENT) {
            goto err_out;
        }
        unlink_file = true;
        goto err_out;
    }

    return 0;

err_out:
    res = errno;
    if (unlink_file)
        unlink(cli->addr.sun_path);
    close(cli->sock_fd);
    errno = res;
    return -1;
}

/**
 * @todo: not used
 */
void aura_unix_sock_close(int fd) {
    if (fd != INVALID_UNIX_SOCKET)
        close(fd);
}

int aura_unix_server_accept(int fd, uid_t *uid_ptr) {
    errno = 0;
    struct sockaddr_un cli_addr;
    struct stat statbuf;
    socklen_t len;
    int res, cli_fd, name_len = sizeof(cli_addr.sun_path) + 1;
    char name[name_len];

    len = sizeof(cli_addr);

    cli_fd = accept(fd, (struct sockaddr *)&cli_addr, &len);
    if (cli_fd < 0) {
        return -2;
    }

    len -= offsetof(struct sockaddr_un, sun_path);
    memcpy(name, cli_addr.sun_path, len);
    name[len] = 0;
    if (stat(name, &statbuf) < 0) {
        goto err_out;
    }

#ifdef S_ISSOCK
    if (S_ISSOCK(statbuf.st_mode) == 0) {
        goto err_out;
    }
#endif

    if ((statbuf.st_mode & (S_IRWXG | S_IRWXO)) || (statbuf.st_mode & S_IRWXU) != S_IRWXU) {
        goto err_out;
    }

    if (uid_ptr)
        *uid_ptr = getuid();

    return cli_fd;

err_out:
    res = errno;
    close(cli_fd);
    errno = res;
    return -1;
}

/**
 * Tries to connect to daemon or errors
 */
void aura_try_connect_or_error(int *fd) {
    struct aura_unix_socket cli_socket;
    int res;

    res = aura_unix_cli_connect(&cli_socket, AURA_SOCKET, AURA_SOCKET_CLI, CLI_FILE_PERM);
    if (res < 0) {
        *fd = -1;
        return;
    }
    *fd = cli_socket.sock_fd;
}
