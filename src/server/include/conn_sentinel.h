#ifndef AURA_CONN_SEN_H
#define AURA_CONN_SEN_H

#include "h2/session.h"
#include <stdint.h>

#define A_CONN_SEN_SCALE 3
#define A_CONN_SEN_MIN_SCORE -128
#define A_CONN_SEN_MAX_SCORE 127

/* conn sentinel events */
typedef enum {
    A_CONN_SEN_EVT_NONE = 0,
    A_CONN_SEN_EVT_COMPLETED,
} aura_conn_sen_events_t;

/* conn sentinel actions */
typedef enum {
    // A_CONN_SEN_ACT_ALLOW,    /* Allow request (Strike LVL 0) */
    // A_CONN_SEN_ACT_THROTTLE, /* Throttle connection  */
    // A_CONN_SEN_ACT_CLOSE,    /* Hard error, stop connection */
    A
} aura_conn_sen_action;

/* Connection sentinel structure */
struct aura_conn_sentinel {
    uint64_t last_event_ms;
    int8_t score;    /* reputation score (-128->127) */
    uint8_t strikes; /* escalation level */
};

/* initialize conn sentinel structure */
static inline void aura_conn_sen_init(struct aura_conn_sentinel *sen) {
    memset(sen, 0, sizeof(*sen));
}

/* update generic conn sentinel score */
static inline void aura_conn_sen_score_update(struct aura_conn_sentinel *sen, int n) {
    sen->score += n;
    sen->score = a_clamp(n, A_CONN_SEN_MIN_SCORE, A_CONN_SEN_MAX_SCORE);
}

static inline uint32_t aura_conn_sen_ewma_read(uint32_t ema) {
    return ema >> A_CONN_SEN_SCALE;
}

static inline int aura_conn_sen_get_action(struct aura_conn_sentinel *sen) {
    if (sen->score < -40)
        return A_CONN_SEN_ACT_HARD_CLOSE; /* Hard penalty, stop connection */

    if (sen->score < -20)
        return A_CONN_SEN_ACT_GOAWAY; /* Send connection packing */

    if (sen->score < -10)
        return A_CONN_SEN_ACT_THROTTLE;

    if (sen->score < -5)
        return A_CONN_SEN_ACT_PING; /* Ping connection */

    return A_CONN_SEN_ACT_ALLOW; /* Throttle connection */
}

static inline void aura_conn_sen_score_decay(struct aura_conn_sentinel *sen) {
    if (sen->score < 0)
        sen->score++;
    else if (sen->score > 0)
        sen->score--;
}

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

static void aura_conn_sen_evaluate(struct aura_conn_sentinel *sen, int prot_type) {
    uint32_t action;

    action = aura_conn_sen_get_action(sen);
    switch (action) {
    case A_CONN_SEN_ACT_ALLOW:
        break;

    case A_CONN_SEN_ACT_THROTTLE:
        break;

    default:
        break;
    }

    switch (prot_type) {
    case A_PROTOCOL_TCP:
        break;
    default:
        break;
    }
}

#endif