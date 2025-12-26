#ifndef AURA_SRV_METRICS_H
#define AURA_SRV_METRICS_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "list_lib.h"

#define a_clamp(val, min, max) ((val) < (min) ? (min) : (val) > (max) ? (max) \
                                                                      : (val))

#define A_METRICS_WINDOW_SIZE 60   /* 60 second sliding window */
#define A_METRICS_GRANULARITY 1000 /* 1ms granularity (1000 slots per second) */

#define A_MEMORY_CAP_PER_CONNECTION 9863168 /* 8MBs */

#define A_TOTAL_ADMISSIONS_PRIORITY_LEVELS 3 /* See priority enum somewhere below */

/* General Metrics structure */
struct aura_srv_metrics_bucket {
    uint64_t connections; /* Total connections on server */
    uint64_t requests;    /* Total requests */
    uint64_t bytes_in;    /* Total bytes read */
    uint64_t bytes_out;   /* Total bytes written */
    uint64_t error_count; /* Total errors */
};

/* Sliding metrics structure */
struct aura_srv_sliding_metrics {
    struct aura_srv_metrics_bucket buckets[A_METRICS_WINDOW_SIZE * A_METRICS_GRANULARITY];
    uint32_t current_slot;
    uint64_t last_update_ms;

    struct aura_srv_metrics_bucket last_second;
    struct aura_srv_metrics_bucket last_minute;
};

/* Rate limiter structure */
struct aura_rate_limiter {
    struct aura_srv_sliding_metrics *metrics;
    uint64_t max_req_per_sec;
    uint64_t max_connections; /* Max concurrent connections */
    uint64_t max_burst;       /* Max burst allowed */
};

#define A_CORE_METRICS_SAMPLES 8

/* aura_conn_metrics */
struct aura_srv_core_metrics {
    uint64_t timestamp;
    uint32_t sample_cnt;

    uint32_t rtt_samples[A_CORE_METRICS_SAMPLES];
    uint32_t rtt_sample_idx;

    /* Bandwidth */
    uint64_t bw_samples[A_CORE_METRICS_SAMPLES];
    uint64_t bw_timestamps[A_CORE_METRICS_SAMPLES];
    uint32_t bw_sample_idx;
};

/* Priority Based Admissions */
typedef enum {
    A_PRIORITY_FAST_LANE,  /*  Perhaps API reqs, possibly websockets */
    A_PRIORITY_STANDARD,   /* Perhaps static assets, user interactions */
    A_PRIORITY_BACKGROUND, /* Perhaps video streaming, large uploads (that kind of luxury living) */
} aura_srv_conn_priority_t;

/**/
struct aura_srv_conn_metrics {
    /* RTT */
    uint64_t smoothed_rtt_us; /* smoothed round trip time micro sec */
    uint32_t rtt_var_us;      /* RTT variance */
    uint64_t min_rtt_us;      /* Minimum observed RTT */
    uint64_t avg_latency_us;

    /* Bandwidth estimation */
    uint64_t trans_rate_bps;    /* Transmission rate(bits) */
    uint32_t bandwidth_est_age; /* How fresh is our estimate, we should wait more than UINT32_MAX */

    /* Conn x-tics */
    uint64_t start_time;
    uint32_t bytes_transfered;
    uint32_t req_cnt;
    uint32_t avg_req_size;
    uint64_t avg_latency_ms; /* Rolling average */
    uint32_t total_requests;
    uint32_t active_connections;

    uint32_t rst_frames_received;
    uint32_t rst_frames_sent;
    uint32_t consecutive_timeouts;
    uint32_t average_stream_lifetime_ms;
    uint32_t streams_accepted;
    uint32_t streams_abandoned;
    uint32_t backpressure_events;
    uint32_t zero_copy_frames;
    uint8_t health_score;
};

struct aura_srv_adaptive_window {
    uint32_t current_window; /* Current window (bytes) */
    uint32_t target_window;  /* Our optimal window */
    uint32_t max_window;     /* Memory-enforced max */
    uint32_t min_window;     /* Smallest for progress */
    uint32_t scaling_factor; /* Dynamic scaling (0.5 - 2.0), hoping we are intelligent */
};

struct aura_srv_admissions_controller {
    uint32_t total_conn;
    uint32_t max_conn;
    uint32_t total_mem_cap;
    uint32_t used_mem;
    uint32_t priority_limits[A_TOTAL_ADMISSIONS_PRIORITY_LEVELS]; /* Mem limits per priority */
    uint32_t conn_cnt[A_TOTAL_ADMISSIONS_PRIORITY_LEVELS];
    uint32_t conn_limits[A_TOTAL_ADMISSIONS_PRIORITY_LEVELS]; /* Conn limits per priority */
};

/**/
struct aura_srv_network_path_profile {
    uint8_t quality_grade;          /* Grading on a scale A-F, (Brings back memories, doesn't it?)*/
    uint32_t typical_rtt_us;        /* RTT recorded overtime */
    uint32_t typical_bandwidth_bps; /* BPS recorded overtime */
    uint32_t loss_rate;             /* 0-1000 (per milli) */
    uint32_t jitter_us;
};

/**/
void aura_metrics_unit(struct aura_srv_sliding_metrics *metrics);

/**/
void aura_metrics_record_connection(struct aura_srv_sliding_metrics *metrics);

/**/
void aura_metrics_record_request(struct aura_srv_sliding_metrics *metrics, size_t bytes, bool inbound);

/**/
void aura_metrics_update(struct aura_srv_sliding_metrics *metrics, size_t current_time_ms);

/**/
int aura_rate_limiter_allow_connecton(struct aura_rate_limiter *limiter);

/**/
int aura_rate_limiter_allow_request(struct aura_rate_limiter *limiter);

/**/
uint32_t aura_calculate_target_window(struct aura_srv_conn_metrics *m);

/**/
bool aura_admit_connection(struct aura_srv_admissions_controller *ac, aura_srv_conn_priority_t prio, uint32_t estimated_mem);

/**/
void aura_adapt_to_network_path(struct aura_srv_conn_metrics *cm, struct aura_srv_network_path_profile *npp);

#endif