#ifndef AURA_SRV_COMMON_H
#define AURA_SRV_COMMON_H

typedef enum {
    A_PROGRESS_DONE = 0,
    A_PROGRESS_BLOCKED,
    A_PROGRESS_ERROR,
} aura_process_error;

typedef enum {
    A_ERR_NONE,
    A_ERR_AGAIN,
    A_ERR_FATAL
} aura_error_t;

#endif