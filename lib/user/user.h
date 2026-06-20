#ifndef AURA_PRIVILEGE_H
#define AURA_PRIVILEGE_H

#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

/* User record structure */
struct aura_user_rec {
    const char *username;
    uid_t user_id;  /* User UID */
    gid_t group_id; /* User GID */
};

/* Get user record from pw file using uid */
int aura_usr_get_rec(struct aura_user_rec *rec);

/* Get user rec from pw file using username */
int aura_usr_get_rec_by_name(struct aura_user_rec *rec, const char *username);

/* Drop to given user level */
int aura_usr_drop_priv(uid_t uid, gid_t gid);

#endif