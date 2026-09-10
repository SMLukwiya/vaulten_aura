#if defined(SOLARIS) /* Solaris 10 */
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 700
#endif
#include "utils_lib.h"
#include <syslog.h>

int aura_set_fd_flag(int fd, int flag) {
    int val;

    val = fcntl(fd, F_GETFL, 0);
    if (val < 0)
        return -1;

    val |= flag;
    return fcntl(fd, F_SETFL, val);
}

int aura_clear_fd_flag(int fd, int flag) {
    int val;

    val = fcntl(fd, F_GETFL, 0);
    if (val < 0)
        return -1;

    val &= ~flag;
    return fcntl(fd, F_SETFL, val);
}

int aura_read_n(int fd, char *buf, size_t size) {
    int n_left;
    int n_read = 0;
    char *ptr = buf;

    n_left = size;
    while (n_left > 0) {
        if ((n_read = read(fd, buf, n_left)) < 0) {
            if (errno == EINTR) {
                n_read = 0;
                continue; /* try again */
            } else
                return -1;
        } else if (n_read == 0)
            break; /* EOF */

        n_left -= n_read;
        ptr += n_read;
    }

    return (size - n_left); /* return how much was read */
}

int aura_write_n(int fd, char *buf, size_t size) {
    int n_left;
    int n_written = 0;
    char *ptr = buf;

    n_left = size;
    while (n_left > 0) {
        if ((n_written = write(fd, buf, n_left)) < 0) {
            if (errno = EINTR) {
                n_written = 0;
                continue; /* try again */
            } else
                return -1;
        } else if (n_written == 0)
            break; /* EOF */

        n_left -= n_written;
        ptr += n_written;
    }

    return (size - n_left); /* return how much was written */
}

/**
 * Scan
 */
int aura_scan_str(const char *value, const char *fmt, ...) {
    va_list vp;
    int res, err;

    err = errno;
    errno = 0;
    va_start(vp, fmt);
    res = vsscanf(value, fmt, vp);
    va_end(vp);

    if (errno != 0)
        return -1;
    errno = err;
    return res;
}

/**
 *
 */
int aura_install_signal_handler(int signo, void (*handler)(int signo)) {
    struct sigaction action;

    action.sa_handler = handler;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    return sigaction(signo, &action, NULL);
}

void aura_hex_dump(const void *addr, size_t len) {
    const unsigned char *buf = (const unsigned char *)addr;

    for (size_t i = 0; i < len; i += 16) {
        printf("%08zx  ", i);

        for (size_t j = 0; j < 8; j++) {
            if (i + j < len)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        }

        printf(" ");

        for (size_t j = 8; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        }

        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = buf[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

void aura_hex_dump_syslog(int priority, const char *prefix, const void *addr, size_t len) {
    const unsigned char *buf = (const unsigned char *)addr;
    char line_buf[128];

    for (size_t i = 0; i < len; i += 16) {
        int off = 0;

        /* Prefix Bytes(0-7) */
        off += snprintf(line_buf + off, sizeof(line_buf) - off, "%s [%08zx]  ", prefix ? prefix : "HEX", i);

        /* First quad word */
        for (size_t j = 0; j < 8; j++) {
            if (i + j < len)
                off += snprintf(line_buf + off, sizeof(line_buf) - off, "%02x ", buf[i + j]);
            else
                off += snprintf(line_buf + off, sizeof(line_buf) - off, "   ");
        }

        /* quad word space separator */
        off += snprintf(line_buf + off, sizeof(line_buf) - off, " ");

        /* Second quad word (Bytes 8-15) */
        for (size_t j = 8; j < 16; j++) {
            if (i + j < len)
                off += snprintf(line_buf + off, sizeof(line_buf) - off, "%02x ", buf[i + j]);
            else
                off += snprintf(line_buf + off, sizeof(line_buf) - off, "   ");
        }

        // 4. Print Printable ASCII
        off += snprintf(line_buf + off, sizeof(line_buf) - off, " |");
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = buf[i + j];
            off += snprintf(line_buf + off, sizeof(line_buf) - off, "%c", isprint(c) ? c : '.');
        }
        off += snprintf(line_buf + off, sizeof(line_buf) - off, "|");

        // 5. Emit the single complete line to syslog (DO NOT include '\n')
        syslog(priority, "%s", line_buf);
    }
}
