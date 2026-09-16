#ifndef AURA_CONN_SEN_H
#define AURA_CONN_SEN_H

#include "h2/session.h"
#include <stdint.h>

/**
 * Underlying protocol sentinel action
 */
struct aura_conn_sen_decision {
    int sen_action;
    union {
        struct {
            uint32_t duration_ms;
        } throttle;

        struct {
            int error_code;
            uint32_t drain;
        } goaway;

        struct {
            bool immediate;
        } close;
    };
};

/* Connection sentinel structure */
struct aura_conn_sentinel {
    uint64_t last_event_ms;
    struct aura_conn_sen_decision decision;
};

static inline void aura_conn_sen_update(struct aura_conn_sentinel *sen, uint8_t action, void *arg) {
    sen->decision.sen_action = action;

    switch (action) {
    case A_CONN_SEN_ACT_THROTTLE:
        sen->decision.throttle.duration_ms = (uint64_t)arg;
        break;

    case A_CONN_SEN_ACT_HARD_CLOSE:
        sen->decision.close.immediate = true;
        break;

    default:
        break;
    }
}

#endif