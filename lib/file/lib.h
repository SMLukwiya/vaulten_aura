#ifndef AURA_FILE_H
#define AURA_FILE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define a_read_lock(fd, offset, whence, len) aura_lock_file((fd), F_SETLK, F_RDLCK, (offset), (whence), (len))
#define a_readw_lock(fd, offset, whence, len) aura_lock_file((fd), F_SETLKW, F_RDLCK, (offset), (whence), (len))
#define a_write_lock(fd, offset, whence, len) aura_lock_file((fd), F_SETLK, F_WRLCK, (offset), (whence), (len))
#define a_writew_lock(fd, offset, whence, len) aura_lock_file((fd), F_SETLKW, F_WRLCK, (offset), (whence), (len))
#define a_unlock(fd, offset, whence, len) aura_lock_file((fd), F_SETLK, F_UNLCK, (offset), (whence), (len))
#define a_lockfile(fd) a_write_lock((fd), 0, SEEK_SET, 0)

#define a_is_read_lockable(fd, offset, whence, len) (aura_lock_test((fd), F_RDLCK, (offset), (whence), (len)) == 0)
#define a_is_write_lockable(fd, offset, whence, len) (aura_lock_test((fd), F_WRLCK, (offset), (whence), (len)) == 0)

int aura_lock_file(int, int, int, off_t, int, off_t);
int aura_get_absolute_path(const char *path, char *resolved_path);
bool aura_open_file(char *filename, int *fd);
uint8_t *aura_load_file(int fd, size_t *len);

/* Get current file directory */
int aura_get_dir_from_file_path(const char *fp, char *buf, size_t len);

pid_t aura_lock_test(int, int, off_t, int, off_t);

#endif