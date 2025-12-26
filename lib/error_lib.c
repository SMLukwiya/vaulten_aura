#include "error_lib.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void aura_log(bool daemon, int level, aura_log_action log_action, aura_log_type type, int error, const char *fmt, ...) {
    char buf[ERROR_BUFFER_SZ];
    va_list ap;
    bool should_exit = log_action == ACT_EXIT || log_action == ACT_DUMP;
    bool is_app = type == LOG_APP;
    bool is_sys = type == LOG_SYS;
    char *app_prefix = "[APP] ";
    char *sys_prefix = "[SYS] ";
    int prefix_len = strlen(app_prefix);

    if (is_app)
        memcpy(buf, app_prefix, prefix_len);
    else if (is_sys)
        memcpy(buf, sys_prefix, prefix_len);

    va_start(ap, fmt);
    vsnprintf(buf + prefix_len, ERROR_BUFFER_SZ - prefix_len - 1, fmt, ap);
    va_end(ap);

    if (error)
        if (is_app)
            snprintf(buf + strlen(buf), ERROR_BUFFER_SZ - prefix_len - strlen(buf) - 1, ": %s", "aura app error");
        else if (is_sys)
            snprintf(buf + strlen(buf), ERROR_BUFFER_SZ - prefix_len - strlen(buf) - 1, " %s", strerror(error));

    strcat(buf, "\n");

    if (daemon)
        syslog(level, "%s", buf);
    else {
        fflush(stdout);
        fputs(buf, stderr);
        fflush(stderr);
    }

    if (log_action == ACT_DUMP)
        abort(); // dump core and terminate

    if (should_exit)
        exit(error);
}
