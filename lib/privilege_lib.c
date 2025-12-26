#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * drop privileges permanently
 * We return 2 when trying to run as root,
 * 1 for any other error, and 0 for success
 */
int aura_drop_privileges(const char *name) {
    struct passwd *pw_ptr;

    if ((pw_ptr = getpwnam(name)) == NULL)
        return 2;

    if (pw_ptr->pw_uid == 0)
        /* trying to run as root a*/
        return 1;

    if (setuid(pw_ptr->pw_uid) != 0)
        return 1;

    if (setgid(pw_ptr->pw_gid))
        return 1;

    return 0;
}