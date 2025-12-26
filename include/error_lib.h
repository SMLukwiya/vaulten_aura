#ifndef AURA_ERROR_H
#define AURA_ERROR_H

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>

#define ERROR_BUFFER_SZ 4096

typedef enum {
    ACT_CONT, /* log and continue */
    ACT_EXIT, /* log and exit */
    ACT_DUMP  /* log and dump */
} aura_log_action;

typedef enum {
    LOG_APP,
    LOG_SYS
} aura_log_type;

void aura_log(bool daemon, int level, aura_log_action log_action, aura_log_type type, int error, const char *fmt, ...);

/* System level errors */
#define sys_debug(daemon, error, fmt, ...) aura_log(daemon, LOG_DEBUG, ACT_CONT, LOG_SYS, error, fmt, ##__VA_ARGS__)
#define sys_info(daemon, error, fmt, ...) aura_log(daemon, LOG_INFO, ACT_CONT, LOG_SYS, error, fmt, ##__VA_ARGS__)
#define sys_notice(daemon, error, fmt, ...) aura_log(daemon, LOG_NOTICE, ACT_CONT, LOG_SYS, error, fmt, ##__VA_ARGS__)
#define sys_warn(daemon, error, fmt, ...) aura_log(daemon, LOG_WARNING, ACT_CONT, LOG_SYS, error, fmt, ##__VA_ARGS__)
#define sys_alert(daemon, error, fmt, ...) aura_log(daemon, LOG_ALERT, ACT_CONT, LOG_SYS, error, fmt, ##__VA_ARGS__)
#define sys_exit(daemon, error, fmt, ...) aura_log(daemon, LOG_ERR, ACT_EXIT, LOG_SYS, error, fmt, ##__VA_ARGS__)

/* Application level errors */
#define app_debug(daemon, error, fmt, ...) aura_log(daemon, LOG_DEBUG, ACT_CONT, LOG_APP, error, fmt, ##__VA_ARGS__)
#define app_info(daemon, error, fmt, ...) aura_log(daemon, LOG_INFO, ACT_CONT, LOG_APP, error, fmt, ##__VA_ARGS__)
#define app_notice(daemon, error, fmt, ...) aura_log(daemon, LOG_NOTICE, ACT_CONT, LOG_APP, error, fmt, ##__VA_ARGS__)
#define app_warn(daemon, error, fmt, ...) aura_log(daemon, LOG_WARNING, ACT_CONT, LOG_APP, error, fmt, ##__VA_ARGS__)
#define app_alert(daemon, error, fmt, ...) aura_log(daemon, LOG_ALERT, ACT_CONT, LOG_APP, error, fmt, ##__VA_ARGS__)
#define app_exit(daemon, error, fmt, ...) aura_log(daemon, LOG_ERR, ACT_EXIT, LOG_APP, error, fmt, ##__VA_ARGS__)

#endif