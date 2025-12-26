#include "metrics_srv.h"

static inline void a_record_rtt_sample(struct aura_srv_core_metrics *cm, uint64_t rtt_us) {
    cm->rtt_samples[cm->rtt_sample_idx] = rtt_us;
    cm->rtt_sample_idx = (++cm->rtt_sample_idx) % A_CORE_METRICS_SAMPLES;
    cm->sample_cnt++;
}

static inline void a_record_throughout(struct aura_srv_core_metrics *cm, uint32_t bytes, uint64_t now_us) {
    cm->bw_samples[cm->bw_sample_idx] = bytes;
    cm->bw_timestamps[cm->bw_sample_idx] = now_us;
    cm->bw_sample_idx = (++cm->bw_sample_idx) % A_CORE_METRICS_SAMPLES;
}

/* Exponential moving average */
static inline uint64_t calculate_smoothed_rtt(struct aura_srv_core_metrics *cm) {
    uint64_t smoothed_rtt;

    /* default to 100us */
    smoothed_rtt = 100000000;
    if (cm->sample_cnt == 0)
        return smoothed_rtt;

    smoothed_rtt = cm->rtt_samples[0];
    for (int i = 1; i < A_CORE_METRICS_SAMPLES; ++i)
        smoothed_rtt = (smoothed_rtt * 7 + cm->rtt_samples[i]) >> 3;

    return smoothed_rtt;
}

static inline uint64_t a_calculate_bandwidth_bps(struct aura_srv_core_metrics *cm) {
    uint32_t idx1, idx2;
    uint64_t bytes, time_us;

    if (cm->sample_cnt < 2)
        return 1000000; /* 1Mbps */

    /* use the last 2 samples for instant bw */
    idx1 = (cm->bw_sample_idx - 1) % A_CORE_METRICS_SAMPLES;
    idx2 = (cm->bw_sample_idx - 2) % A_CORE_METRICS_SAMPLES;

    bytes = cm->bw_samples[idx1] + cm->bw_samples[idx2];
    time_us = cm->bw_timestamps[idx1] - cm->bw_timestamps[idx2];

    if (time_us == 0)
        return 1000000;

    /* convert from bytes/sec to bits/sec */
    return (bytes * 8 * 1000000) / time_us;
}

static aura_srv_conn_priority_t detect_priority(struct aura_srv_conn_metrics *m) {
    /* Fast lane */
    if (m->req_cnt > 5 && m->avg_latency_us < 50000 && m->bytes_transfered / m->req_cnt < 4096)
        return A_PRIORITY_FAST_LANE;

    /* Background and luxurious lane */
    if (m->bytes_transfered > 1000000 || m->avg_latency_us > 200000 && m->req_cnt < 3)
        return A_PRIORITY_BACKGROUND;

    return A_PRIORITY_STANDARD;
}

/* -------------------------------------------------- */
static inline float a_calculate_dynamic_scaling(struct aura_srv_conn_metrics *m) {
    float scale = 1.0f;

    /**
     * we favor short-lived conns (that's edge after all)
     * and boost new connections
     */
    if (m->req_cnt < 10) {
        scale *= 1.3f;
    }

    /* we favour small reqs and boost them */
    if (m->avg_req_size < 4096) {
        scale *= 1.2f;
    }

    /**
     * we penelize large, slow reqs and throttle them
     */
    if (m->avg_req_size > 65536 && m->trans_rate_bps < (500 * 1024)) {
        scale *= 0.7f;
    }

    return a_clamp(scale, 0.5f, 2.0f);
}

uint32_t aura_calculate_target_window(struct aura_srv_conn_metrics *m) {
    uint32_t bdp_window; /* Bandwidth delay product */
    uint32_t mem_limited_window;
    float scale;

    /* get dynamic window converting bytes to bits and micro-secs to secs */
    bdp_window = (m->trans_rate_bps * m->smoothed_rtt_us) / (8 * 1000000);
    /* apply mem constraints */
    mem_limited_window = a_min(bdp_window, A_MEMORY_CAP_PER_CONNECTION);
    scale = aura_calculate_dynamic_scaling(m);

    return (uint32_t)mem_limited_window * scale;
}

static inline void update_connection_metrics(struct aura_srv_conn_metrics *m, uint32_t resp_size, uint32_t latency_us) {
    m->bytes_transfered += resp_size;
    m->req_cnt++;
    m->avg_latency_us = (m->avg_latency_us * 7 + latency_us) >> 3;
}
