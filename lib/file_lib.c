#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "file_lib.h"

int aura_get_absolute_path(const char *path, char *resolved_path) {
    if (realpath(path, resolved_path) == NULL)
        return 1;

    return 0;
}

bool aura_open_file(char *filename, int *fd) {
    char resolved_file_path[1024];
    int res;

    if (!filename)
        return false;

    res = aura_get_absolute_path(filename, resolved_file_path);
    if (res != 0)
        return false;

    *fd = open(resolved_file_path, O_RDONLY);
    if (*fd < 0)
        return false;

    return true;
}

uint8_t *aura_load_file(int fd, u_int64_t *len) {
    FILE *fp;
    int64_t _len;
    uint8_t *buf;
    size_t res;

    *len = 0;
    fp = fdopen(fd, "rb");
    if (!fp || ferror(fp) != 0)
        return NULL;

    if (fseek(fp, 0, SEEK_END) < 0) {
        fclose(fp);
        return NULL;
    }

    _len = ftell(fp);
    /** @todo: check what ftell returns for a DIR */
    if (_len < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    buf = malloc(_len);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    res = fread(buf, 1, _len, fp);

    if (res != _len) {
        free(buf);
        fclose(fp);
        return NULL;
    }

    buf[_len] = '\0';
    fclose(fp);
    *len = _len;
    return buf;
}

const struct stat get_file_stat(const char *filename) {
    /* may get absolute path then open file, use fstat */
}

int aura_lock_file(int fd, int cmd, int type, off_t offset, int whence, off_t len) {
    struct flock lock;

    lock.l_type = type;
    lock.l_start = offset;
    lock.l_whence = whence;
    lock.l_len = len;

    return (fcntl(fd, cmd, &lock));
}

pid_t aura_lock_test(int fd, int type, off_t offset, int whence, off_t len) {
    struct flock lock;

    lock.l_type = type;
    lock.l_start = offset;
    lock.l_whence = whence;
    lock.l_len = len;

    if (fcntl(fd, F_GETLK, &lock) < 0)
        return -1;

    if (lock.l_type == F_UNLCK)
        return 0;

    return lock.l_pid;
}
