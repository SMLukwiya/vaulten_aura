#include "user.h"

int aura_usr_get_rec(struct aura_user_rec *rec) {
    struct passwd *_rec;

    _rec = getpwuid(getuid());
    if (!_rec)
        return -1;

    rec->username = _rec->pw_name;
    rec->user_id = _rec->pw_uid;
    rec->group_id = _rec->pw_gid;
    return 0;
}

int aura_usr_get_rec_by_name(struct aura_user_rec *rec, const char *username) {
    struct passwd *_rec;

    _rec = getpwnam(username);
    if (!_rec)
        return -1;

    rec->username = _rec->pw_name;
    rec->user_id = _rec->pw_uid;
    rec->group_id = _rec->pw_gid;
    return 0;
}

int aura_usr_drop_priv(uid_t uid, gid_t gid) {
    if (setuid(uid) != 0)
        return -1;

    if (setgid(gid))
        return -1;

    return 0;
}