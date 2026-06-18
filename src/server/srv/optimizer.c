#include "optimizer.h"
#include "socket_srv.h"
#include <math.h>

#define a_opt_clamp(val, min, max) ((val) < (min) ? (min) : (val) > (max) ? (max) \
                                                                          : (val))
void aura_srv_opt_init(struct aura_srv_optimizer *opt) {
    opt->alpha = 0.2f;
    opt->slope_alpha = 0.3f;
    opt->target_latency_us = 50000.0f; /* 50ms */
    opt->min_accept = 1;
    opt->max_accept = 128;
    opt->kp = 0.5f;
    opt->ki = 0.01f;
    opt->kf = 0.3f;
    opt->error_integral = 0.0f;
    opt->prev_tp = 0.0f;
    opt->prev_conc = 0.0f;
    opt->prev_latency = 0.0f;
    opt->tp_threshold = 0.1f;       /* 10% slope change */
    opt->tp_drop_threshold = 0.15f; /* 15% drop detection */
    opt->tp_slope_ema = 0.0f;
    opt->latency_slope_ema = 0.0f;
    opt->latency_threshold = 0.2f; /* 20% latency drop */
    opt->ewma_latency = opt->target_latency_us;
    opt->min_consecutive_cnt = 3;
    opt->knee_counter = 0;
    opt->knee_detected = false;
    opt->knee_margin_ratio = 0.8f; /* Operating at 80% of knee conc */
    opt->knee_holdoff = 10;        /* Hold knee for 10 ticks */
    opt->knee_holdoff_counter = 0;
    opt->knee_concurrency = 40; /* 0.8 of starting conc */
    opt->error_deadzone = 2.0f; /* Ignore errors less than 2ms */
    opt->last_timestamp_us = aura_now_us(CLOCK_MONOTONIC);
    opt->current_accept_budget = 8;
    opt->min_delta_conc = 2; /**/
    opt->conc = 50;
    opt->conc_min = 1;
    opt->conc_max = 100;
}

static inline void a_opt_ewma_latency_update(struct aura_srv_optimizer *opt, double latency_us) {
    opt->ewma_latency = opt->alpha * latency_us + ((1.0 - opt->alpha) * opt->ewma_latency);
}

static inline void a_opt_knee_detect(struct aura_srv_optimizer *opt, double throughput) {
    bool knee_this_tick = false;

    /* only update slopes if concurrency changes significantly */
    int d_conc = opt->conc - opt->prev_conc;
    if (abs(d_conc) >= opt->min_delta_conc) {
        float d_tp = throughput - opt->prev_tp;
        float d_latency = opt->ewma_latency - opt->prev_latency;

        /* Get slopes with sign handling */
        float tp_slope = d_tp / d_conc;           /* Throughput per conc unit */
        float latency_slope = d_latency / d_conc; /* Latency per conc unit */

        /* Filter slopes for noise reduction */
        if (opt->tp_slope_ema == 0.0)
            opt->tp_slope_ema = tp_slope;
        else
            opt->tp_slope_ema = opt->slope_alpha * tp_slope + ((1 - opt->slope_alpha) * opt->tp_slope_ema);

        if (opt->latency_slope_ema == 0.0)
            opt->latency_slope_ema = latency_slope;
        else
            opt->latency_slope_ema = opt->slope_alpha * latency_slope + ((1 - opt->slope_alpha) * opt->latency_slope_ema);

        /* Detect knee using filtered slopes */
        bool tp_flat = fabs(opt->tp_slope_ema) < opt->tp_threshold;
        bool latency_rising = opt->latency_slope_ema > opt->latency_threshold;

        /* Detect throughput drop off */
        bool tp_dropping = opt->tp_slope_ema < -opt->tp_drop_threshold;

        knee_this_tick = (tp_flat && latency_rising) || tp_dropping;
    }

    if (knee_this_tick) {
        if (opt->knee_counter < UINT8_MAX)
            opt->knee_counter++;
    } else {
        /* Decay slowly to prevent rapid toggling */
        if (opt->knee_counter > 0)
            opt->knee_counter--;
    }

    /* Detect knee with hysteresis */
    if (opt->knee_counter >= opt->min_consecutive_cnt) {
        opt->knee_detected = true;
        opt->knee_concurrency = opt->conc;
        opt->knee_holdoff_counter = opt->knee_holdoff; /* Start holdoff */
    }

    /* Clear knee detection after holdoff period */
    if (opt->knee_holdoff_counter > 0) {
        opt->knee_holdoff_counter--;
    } else if (opt->knee_counter == 0 && opt->knee_detected) {
        /* Only clear if we have been stable for a while */
        opt->knee_detected = false;
    }
}

static inline int a_opt_pi_output_compute(struct aura_srv_optimizer *opt, uint64_t now_us, uint64_t inflight) {
    double raw_error = opt->target_latency_us - opt->ewma_latency;
    double error = raw_error;

    if (fabs(raw_error) < opt->error_deadzone)
        error = 0;

    int t_delta = a_time_us_to_s(now_us - opt->last_timestamp_us);

    float adaptive_kp = opt->kp;
    float adaptive_ki = opt->ki;

    /* Reduce gains when near knee */
    if (opt->knee_detected) {
        float near_knee_ratio = (float)opt->conc / opt->knee_concurrency;
        if (near_knee_ratio > 0.8f) {
            adaptive_kp *= 0.5f; /* Reduce P near knee */
            adaptive_ki *= 0.3f; /* Reduce I near knee */
        }
    }

    double p_term = opt->kp * error;

    opt->error_integral += error * t_delta;
    /* anti windup: integral clamped based on output limits */
    float integral_max = (opt->conc_max - opt->conc_min) / opt->ki;
    a_opt_clamp(opt->error_integral, -integral_max, integral_max);

    double i_term = opt->ki * opt->error_integral;
    int adjustment = (int)(p_term + i_term + opt->kf * (inflight - opt->conc_max));

    /* Rate limit the adjustment (prevent large jumps) */
    // a_opt_clamp(adjustment, -opt->max_adjustment, opt->max_adjustment);

    return adjustment;
}

void aura_srv_opt_update(struct aura_srv_optimizer *opt, uint64_t now,
                         double throughput, uint32_t inflight) {
    double new_conc;
    int adjustment;

    adjustment = a_opt_pi_output_compute(opt, now, inflight);
    new_conc += adjustment;

    /* Apply guardrail of knee detected */
    if (opt->knee_detected) {
        /* Use ratio based ceiling instead of fixed value */
        int ceiling = (int)(opt->knee_concurrency * opt->knee_margin_ratio);
        if (ceiling < opt->conc_min + 1)
            ceiling = opt->conc_min + 1;

        if (new_conc > ceiling) {
            new_conc = ceiling;
            // opt->error_integral *= 0.95f;
            /* conditional integration */
            // opt->error_integral -= error;
        }
    }

    // if (adjustment > 0 && a_opt_at_upper_bound) {
    // opt->error_integral *= 0.95f;
    /* conditional integration */
    // opt->error_integral -= error;
    // }

    /* Global clamp */
    a_opt_clamp(new_conc, opt->conc_min, opt->conc_max);

    /* Update history only if concurrency changed */
    if (abs(new_conc - opt->conc) >= opt->min_delta_conc) {
        opt->prev_tp = throughput;
        opt->prev_latency = opt->ewma_latency;
        opt->prev_conc = opt->conc;
    }

    opt->conc = new_conc;
}

int64_t aura_srv_opt_get_candidate_epoll_timeout(struct aura_srv_optimizer *opt) {
    if (opt->ewma_latency > opt->target_latency_us * 1.5)
        return 0;

    if (opt->current_accept_budget <= 2)
        return 0;

    return 5;
}

uint64_t aura_srv_opt_get_accept_budget(struct aura_srv_optimizer *opt, uint64_t inflight) {
    int available;

    available = a_min(opt->conc - inflight, opt->conc_max);
    return available;
}