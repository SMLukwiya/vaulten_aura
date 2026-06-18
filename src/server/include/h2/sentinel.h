#ifndef AURA_H2_SEN_H
#define AURA_H2_SEN_H

#include "time_lib.h"
#include "utils_lib.h"

#include <stdint.h>
#include <string.h>

#define A_H2_SEN_SCALE 3
#define A_H2_EWMA_SMALL_FRAME_SIZE_THRESHOLD (16 << A_H2_SEN_SCALE)
/* Expect 10ms interval for settings updates */
#define A_H2_SETTINGS_MIN_DELTA_MS 10UL
/* Expect 2ms internal for ping, assuming bad network */
#define A_H2_PING_MIN_DELTA_MS 2UL

/* Expect less than 2 updates per header */
#define A_H2_SETTINGS_CHURN_MAX_RATIO 2
#define A_H2_SEN_MIN_SCORE -128
#define A_H2_SEN_MAX_SCORE 127

#define A_H2_SEN_MAX_GLITCH_THRESHOLD (80 >> A_H2_SEN_SCALE)

/* conn sentinel events */
typedef enum {
    A_H2_SEN_EVT_NONE = 0,
    A_H2_SEN_EVT_COMPLETED,             /* request completed successfully */
    A_H2_SEN_EVT_RST,                   /* RST frame received */
    A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM, /* Header only stream with empty headers */
    A_H2_SEN_EVT_TINY_FRAME_FLOOD,      /* Too many small sized frames */
    A_H2_SEN_EVT_SETTINGS_FLOOD,
    A_H2_SEN_EVT_WIND_UPDATE_FLOOD,
    A_H2_SEN_EVT_PING_FLOOD,
    A_H2_SEN_EVT_HPACK_ANOMALY, /* Invalid hpack decoding sequence */
    A_H2_SEN_EVT_STALE,         /* Stale data or frame or packet... */
    A_H2_SEN_EVT_RAPID_RST_CHURN,
} aura_h2_conn_sen_events_t;

/* H2 sentinel flags */
typedef enum {
    A_H2_SEN_FLAG_RST = 1,
    A_H2_SEN_FLAG_HPACK = 1 << 1,
    A_H2_SEN_FLAG_SETTINGS = 1 << 2,
    A_H2_SEN_FLAG_PING = 1 << 3,
    A_H2_SEN_FLAG_FRAMES = 1 << 4,
    A_H2_SEN_FLAG_WIND = 1 << 5,
} aura_h2_conn_sen_flag;

/* conn sentinel actions */
typedef enum {
    A_CONN_SEN_ACT_ALLOW,            /* Allow request (Strike LVL 0) */
    A_CONN_SEN_ACT_PING,             /* Ping connection (Strike LVL 1) */
    A_CONN_SEN_ACT_THROTTLE,         /* Throttle connection  */
    A_CONN_SEN_ACT_GOAWAY,           /* Send conn packing */
    A_CONN_SEN_ACT_IMMEDIATE_GOAWAY, /* Send conn packing immediately */
    A_CONN_SEN_ACT_HARD_CLOSE,       /* Hard error, stop connection */
} aura_conn_sen_action_t;

/**
 * conn sentinel events score
 * Maintain same order as aura_conn_sen_events_t
 * enum above since they index directly here
 */
static int aura_h2_sen_evt_score[] = {
  [A_H2_SEN_EVT_NONE] = 0,
  [A_H2_SEN_EVT_COMPLETED] = 5,
  [A_H2_SEN_EVT_RST] = -5,
  [A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM] = -15,
  [A_H2_SEN_EVT_TINY_FRAME_FLOOD] = -4,
  [A_H2_SEN_EVT_SETTINGS_FLOOD] = -25,
  [A_H2_SEN_EVT_WIND_UPDATE_FLOOD] = -12,
  [A_H2_SEN_EVT_PING_FLOOD] = -10,
  [A_H2_SEN_EVT_HPACK_ANOMALY] = -15,
  [A_H2_SEN_EVT_STALE] = -4,
  [A_H2_SEN_EVT_RAPID_RST_CHURN] = -15,
};

/* H2 sentinel structure */
struct aura_h2_sentinel {
    uint32_t glitch_ewma;         /* Glitch tracker */
    uint32_t frames_cnt;          /* Received frame count */
    uint32_t ema_frame_sz;        /* scaled moving average(frame size) */
    uint32_t completed_streams;   /* Completed streams (success or error) */
    uint32_t reset_cnt;           /* Reset frame count */
    uint32_t settings_cnt;        /* Settings frame count */
    uint32_t wind_update_cnt;     /* Window update count */
    uint32_t ping_cnt;            /* Ping frame count */
    uint32_t hpack_errors;        /* Hpack errors count */
    uint64_t last_settings_ms;    /* Time of last recd settings frame */
    uint64_t last_ping_ms;        /* Time of last recd ping frame */
    uint64_t last_wind_update_ms; /* Time of last wind update recd */
    uint64_t last_evt_ms;         /* Time of last sentinal update */

    int8_t score;  /* reputation score */
    uint8_t flags; /* how to treat defaulters */
};

/* initialize conn sentinel structure */
static inline void aura_h2_conn_sen_init(struct aura_h2_sentinel *sen) {
    memset(sen, 0, sizeof(*sen));
}

/* update generic conn sentinel score */
static inline void aura_h2_sen_score_update(uint8_t *score, int n) {
    *score += n;
    *score = a_clamp(n, A_H2_SEN_MIN_SCORE, A_H2_SEN_MAX_SCORE);
}

static inline void aura_conn_sen_update_ewma_u32(uint32_t *ema, uint32_t sample) {
    int64_t m;

    if (*ema == 0) {
        *ema = sample << A_H2_SEN_SCALE;
        return;
    }

    *ema += ((sample << A_H2_SEN_SCALE) - *ema) >> A_H2_SEN_SCALE;
}

static inline uint32_t aura_h2_conn_sen_ewma_read(uint32_t ema) {
    return ema >> A_H2_SEN_SCALE;
}

static inline bool aura_h2_conn_sen_detect_small_frame_abuse(struct aura_h2_sentinel *sen) {
    return (sen->ema_frame_sz < A_H2_EWMA_SMALL_FRAME_SIZE_THRESHOLD && sen->frames_cnt > 1000);
}

static inline uint64_t aura_h2_conn_sen_calc_throttle_delay(struct aura_h2_sentinel *sen) {
    uint64_t delay;

    // delay = a_max(2 * sen->rtt_ms, 100);
    delay = 2500;
    return a_clamp(delay, 100, 3000); /* ms */
}

/* Detect if peer is sending higher reset cnt */
static inline bool aura_h2_conn_sen_detect_rapid_reset_abuse(struct aura_h2_sentinel *sen) {
    if ((sen->completed_streams + sen->reset_cnt) < 100)
        return false;

    return ((sen->reset_cnt * 100) > (sen->completed_streams + 4) * 50);
}

static inline int aura_h2_sen_get_action(struct aura_h2_sentinel *sen) {
    if (sen->score < -127)
        return A_CONN_SEN_ACT_HARD_CLOSE; /* Hard penalty, stop connection */

    if (sen->score < -110)
        return A_CONN_SEN_ACT_IMMEDIATE_GOAWAY;

    if (sen->score < -90)
        return A_CONN_SEN_ACT_GOAWAY; /* Send connection packing */

    if (sen->score < -60)
        return A_CONN_SEN_ACT_THROTTLE;

    if (sen->score < -30)
        return A_CONN_SEN_ACT_PING; /* Ping connection */

    return A_CONN_SEN_ACT_ALLOW; /* Throttle connection */
}

static inline void aura_h2_conn_sen_score_decay(struct aura_h2_sentinel *sen) {
    if (sen->score < 0)
        sen->score++;
    else if (sen->score > 0)
        sen->score--;
}

static inline void aura_h2_sen_update_control_flood(struct aura_h2_sentinel *sen, uint64_t *last_ms,
                                                    uint64_t min_delta_ms, int val) {
    uint64_t now = aura_now_ms(CLOCK_MONOTONIC);
    uint64_t delta = now - *last_ms;

    if (*last_ms != 0 && delta < min_delta_ms) {
        aura_h2_sen_score_update(&sen->score, val);
    }
    *last_ms = now;
}

static inline void aura_h2_sen_update(struct aura_h2_sentinel *sen, aura_h2_conn_sen_events_t evt,
                                      uint64_t val) {

    switch (evt) {
    case A_H2_SEN_EVT_COMPLETED:
        sen->completed_streams++;
        aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_COMPLETED]);
        break;

    case A_H2_SEN_EVT_RST:
        sen->reset_cnt++;
        sen->flags |= A_H2_SEN_FLAG_RST;
        aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_RST]);
        break;

    case A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM:
        aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM]);
        break;

    case A_H2_SEN_EVT_TINY_FRAME_FLOOD:
        sen->frames_cnt++;
        // sen->payload_rx += val;
        aura_conn_sen_update_ewma_u32(&sen->ema_frame_sz, val);
        sen->flags |= A_H2_SEN_FLAG_FRAMES;
        break;

    case A_H2_SEN_EVT_SETTINGS_FLOOD:
        sen->settings_cnt++;
        sen->flags |= A_H2_SEN_FLAG_SETTINGS;
        aura_h2_sen_update_control_flood(
          sen,
          &sen->last_settings_ms,
          A_H2_SETTINGS_MIN_DELTA_MS,
          aura_h2_sen_evt_score[A_H2_SEN_EVT_SETTINGS_FLOOD]);
        break;

    case A_H2_SEN_EVT_WIND_UPDATE_FLOOD:
        sen->wind_update_cnt++;
        sen->flags |= A_H2_SEN_FLAG_WIND;
        aura_h2_sen_update_control_flood(
          sen,
          &sen->last_wind_update_ms,
          A_H2_SETTINGS_MIN_DELTA_MS,
          aura_h2_sen_evt_score[A_H2_SEN_EVT_WIND_UPDATE_FLOOD]);
        break;

    case A_H2_SEN_EVT_PING_FLOOD:
        sen->ping_cnt++;
        sen->flags |= A_H2_SEN_FLAG_PING;
        aura_h2_sen_update_control_flood(
          sen,
          &sen->last_ping_ms,
          A_H2_PING_MIN_DELTA_MS,
          aura_h2_sen_evt_score[A_H2_SEN_EVT_PING_FLOOD]);
        break;

    case A_H2_SEN_EVT_HPACK_ANOMALY:
        sen->hpack_errors++;
        sen->flags |= A_H2_SEN_FLAG_HPACK;
        break;

    case A_H2_SEN_EVT_STALE:
        aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_STALE]);
        break;

    default:
        break;
    }
    sen->last_evt_ms = aura_now_ms(CLOCK_MONOTONIC);
}

static aura_conn_sen_action_t aura_h2_sen_evaluate(struct aura_h2_sentinel *sen) {
    if (sen->flags & A_H2_SEN_FLAG_FRAMES) {
        if (aura_h2_conn_sen_detect_small_frame_abuse(sen))
            aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_TINY_FRAME_FLOOD]);
    }

    if (sen->flags & A_H2_SEN_FLAG_RST)
        if (aura_h2_conn_sen_detect_rapid_reset_abuse(sen))
            aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_RAPID_RST_CHURN]);

    if (sen->flags & A_H2_SEN_FLAG_HPACK && sen->hpack_errors > 5)
        aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_HPACK_ANOMALY]);

    if (sen->flags & A_H2_SEN_FLAG_SETTINGS) {
        /**
         * Multiply by 100 to avoid floating point math
         * and add 1 to completed streams to avoid zero div.
         */
        uint32_t churn_ratio = (sen->settings_cnt * 100) / (sen->completed_streams + 1);
        if (sen->settings_cnt > 5 && churn_ratio > A_H2_SETTINGS_CHURN_MAX_RATIO * 100) {
            aura_h2_sen_score_update(&sen->score, aura_h2_sen_evt_score[A_H2_SEN_EVT_SETTINGS_FLOOD]);
        }
    }

    return aura_h2_sen_get_action(sen);
}

#endif
