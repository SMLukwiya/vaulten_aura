/** @todo: I probably need this */

#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

/* null terminated array */
static char *restricted_env_vars[] = {
  /* perhaps a list of should be restricted */
  /* "PATH=" _PATH_STDPATH */
  NULL};

/* null terminated array */
static char *to_preserve[] = {
  /* perhaps a list of what should be preserved, e.g, timezone */
  /* "TZ" */
  NULL};

/**
 * We can pass additional values we want to preserve as required
 */
int sanitize_env_vars(int preserve_count, char **preserve_env_vars) {
    char **new_environ, *env, *value, *new_env_ptr;
    int env_size = 0, env_count = 1, new_env_idx = 0;
    int err, i, len;

    for (i = 0; (env = restricted_env_vars[i]) != NULL; ++i) {
        env_size += strlen(env) + 1; /* null terminated */
        env_count++;
    }

    for (i = 0; (env = to_preserve[i]) != NULL; ++i) {
        if ((value = getenv(env)) == NULL)
            continue;
        env_size += strlen(env) + strlen(value) + 2;
        env_count++;
    }

    if (preserve_count > 0 && preserve_env_vars) {
        for (i = 0; i < preserve_count && (env = preserve_env_vars[i]) != NULL; ++i) {
            if ((value = getenv(env)) == NULL)
                continue;
            env_size += strlen(env) + strlen(value) + 2;
            env_count++;
        }
    }

    env_size += sizeof(char *) * env_count;
    if ((new_environ = malloc(env_size)) == NULL) {
        errno = ENOMEM;
        return -1;
    }

    new_env_ptr = (char *)new_environ + sizeof(char *) * env_count;
    for (i = 0; (env = restricted_env_vars[i]) != 0; ++i) {
        len = strlen(env);
        memcpy(new_env_ptr, env, len);
        *(new_env_ptr + len) = '\0';
        new_environ[new_env_idx++] = new_env_ptr;
        new_env_ptr += len + 1;
    }

    for (i = 0; (env = to_preserve[i]) != NULL; ++i) {
        if ((value = getenv(env)) == NULL)
            continue;
        len = strlen(env);
        memcpy(new_env_ptr, env, len);
        new_env_ptr += len;
        *new_env_ptr = '=';
        len = strlen(value);
        memcpy(new_env_ptr + 1, value, len);
        *(new_env_ptr + 1 + len) = '\0';
        new_env_ptr += len + 2;
    }

    if (preserve_count > 0 && preserve_env_vars) {
        for (i = 0; i < preserve_count && (env = preserve_env_vars[i]) != NULL; ++i) {
                }
    }
}
