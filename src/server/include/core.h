#ifndef AURA_SRV_COMMON_H
#define AURA_SRV_COMMON_H

#define A_APP_ERR_BASE 100

typedef enum {
    A_ERR_NONE = 0,
    A_ERR_AGAIN = 1 - A_APP_ERR_BASE,
    A_ERR_FATAL = 2 - A_APP_ERR_BASE,
} aura_error_t;

/* Polling event types */
typedef enum {
    A_EV_TYPE_NONE,
    A_EV_TYPE_IPC,
    A_EV_TYPE_LISTENER,
    A_EV_TYPE_CONN,
} aura_ev_type_t;

/**
 * Event type structure
 * Must be the first field on
 * every structure using it.
 */
struct aura_evt_source {
    aura_ev_type_t ev_type;
};

#endif